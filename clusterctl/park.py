"""Park with verified checkpoint manifest (issue #28).

``clusterctl park <name>`` produces a complete, immutable handoff point
before a daimon relinquishes its lease. Fail-closed per stage, ordered,
idempotent — resumable via a ``park-state/v1`` file at
``state_dir/park/<name>.json``.

Sequence:

  1. stop accepting new work — spec ``status: parking`` (spec-store API,
     never a direct YAML write)
  2. critical jobs — v1 policy is refuse-all (``critical_jobs: refused``);
     ``--abandon-critical`` records ``human-abandoned`` + actor, never
     silently
  3. bridge outbox — ``state_dir/bridge-outbox/`` missing → no-op
     (``not-configured``); non-empty → refuse (exit 6) unless
     ``--force-outbox``
  4. HMK checkpoint — wal_checkpoint(TRUNCATE) + integrity_check in
     container when the spec has ``hmk_path`` (else ``hmk: absent``)
  5. state files — NOW.md + DIALOGUE-HANDOFF.md copied to
     ``state_dir/park/<name>/state/`` when the spec has ``state_files``,
     sha256 recorded per file
  6. state repo commit — git add+commit in the container when the spec has
     ``state_repo``; staged content scanned against lifecycle
     REDACT_PATTERNS — any match refuses (fail-closed)
  7. verification — recompute every recorded hash, sqlite integrity must
     be ok, commit sha must resolve via git rev-parse, backup ids listed,
     active lease required (or explicit ``--no-lease``)
  8. lease transition + manifest — spec status parking → parked ONLY after
     all verifications pass; signed ``checkpoint-manifest/v1`` written to
     ``state_dir/park/<name>/manifest-<fence_epoch>.json``
  9. stop — the container is stopped only after the manifest is written
     and verified

Interruption at any step: the park-state file records completed steps and
their outputs; re-running park resumes — idempotent steps check their
outputs before redoing. Any failure rolls the spec status back to its
pre-park value (default ``active``); the lease is never touched.

Exit codes (clusterctl.cli contract): 0 ok, 3 undeclared, 6 conflict
(refusals: outbox non-empty, secrets, lock), 10 internal (verification
failures).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

from . import audit, idempotency, leases
from .inventory import load_spec_raw, load_specs, update_spec
from .lifecycle import (
    EXIT_CONFLICT,  # noqa: F401  (re-exported for callers/tests)
    EXIT_INTERNAL,
    EXIT_NOT_FOUND,
    EXIT_OK,
    REDACT_PATTERNS,
    _actor,
    _audit_ok,
    _check_idempotency,
    _emit,
    _fail,
    _idem_key,
    _lock_or_fail,
    _record_idempotency,
    _stale_detail,
)

logger = logging.getLogger("clusterctl.park")

PARK_STATE_SCHEMA = "park-state/v1"
MANIFEST_SCHEMA = "checkpoint-manifest/v1"
STATE_FILES = ("NOW.md", "DIALOGUE-HANDOFF.md")
DEFAULT_STATE_FILES_DIR = "/home/agent"
DEFAULT_STATE_REPO_PATH = "/home/agent/state"
STOP_TIMEOUT_S = 30

STEPS = (
    "spec-parking",
    "critical-jobs",
    "outbox",
    "hmk-checkpoint",
    "state-files",
    "state-repo",
    "verify",
    "manifest",
    "stop",
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ParkError(Exception):
    """Internal park failure (verification, adapter, io). Exit 10."""

    def __init__(self, message: str, detail: dict | None = None):
        super().__init__(message)
        self.detail = detail or {}


class ParkRefused(ParkError):
    """Policy refusal (non-empty outbox, secret material). Exit 6."""


# ---------------------------------------------------------------------------
# park-state persistence
# ---------------------------------------------------------------------------


def _park_dir(cfg, name: str) -> Path:
    return Path(cfg.state_dir) / "park"


def _state_path(cfg, name: str) -> Path:
    return _park_dir(cfg, name) / f"{name}.json"


def _load_state(cfg, name: str) -> dict:
    path = _state_path(cfg, name)
    if path.is_file():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and raw.get("schema") == PARK_STATE_SCHEMA:
                return raw
        except (OSError, json.JSONDecodeError):
            pass
    return {
        "schema": PARK_STATE_SCHEMA,
        "name": name,
        "started_ms": audit.now_ms(),
        "previous_status": "active",
        "completed": [],
        "outputs": {},
        "failed_step": None,
        "error": None,
    }


def _save_state(cfg, name: str, state: dict) -> None:
    d = _park_dir(cfg, name)
    d.mkdir(parents=True, exist_ok=True)
    path = _state_path(cfg, name)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, sort_keys=True, indent=2) + "\n",
                   encoding="utf-8")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# manifest signing / verification
# ---------------------------------------------------------------------------


def sign_manifest(manifest: dict, signer: leases.Signer) -> dict:
    """Return a copy of ``manifest`` with a signature over the canonical
    record (manifest minus ``signature``)."""
    signed = dict(manifest)
    signed["signature"] = signer.sign(leases._canonical(manifest))
    return signed


def verify_manifest(manifest: dict, signer: leases.Signer) -> bool:
    """True when ``manifest`` carries a valid signature over its canonical
    body. Unsigned or tampered manifests are rejected."""
    sig = manifest.get("signature")
    if not sig or not isinstance(sig, str):
        return False
    if manifest.get("schema") != MANIFEST_SCHEMA:
        return False
    return signer.verify(leases._canonical(manifest), sig, "")


def load_manifest(path: str | Path, signer: leases.Signer) -> dict:
    """Load and verify a checkpoint manifest file. Raises
    ``leases.InvalidSignature`` when unsigned or tampered."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not verify_manifest(raw, signer):
        raise leases.InvalidSignature(
            f"checkpoint manifest {path} is unsigned or tampered")
    return raw


# ---------------------------------------------------------------------------
# step helpers
# ---------------------------------------------------------------------------


def _daimon_id(spec: dict, name: str) -> str:
    return str(spec.get("daimon_id") or name)


def _read_backup_ids(state_dir, name: str):
    """List backup ids from existing cluster-backup-manifest/v1 files under
    ``state_dir/backups/<name>/`` (same files ``clusterctl snapshot create``
    writes). Absent directory → ``"not-configured"``."""
    bdir = Path(state_dir) / "backups" / name
    if not bdir.is_dir():
        return "not-configured"
    ids = []
    for path in sorted(bdir.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if raw.get("schema") == "cluster-backup-manifest/v1":
            ids.append(raw.get("snap_name") or path.stem)
    return ids


def _contains_secret(text: str) -> str | None:
    low = text.lower()
    for pattern in REDACT_PATTERNS:
        if pattern in low:
            return pattern
    return None


def _rollback_active(cfg, name: str, state: dict) -> None:
    """Roll the spec status back to its pre-park value. Best effort — the
    rollback itself must never mask the original failure."""
    try:
        update_spec(cfg.instances_dir, name,
                    {"status": state.get("previous_status") or "active"})
    except Exception:  # pragma: no cover - defensive
        logger.exception("park rollback failed for %s", name)


# ---------------------------------------------------------------------------
# run_park — the resumable sequence
# ---------------------------------------------------------------------------


def run_park(
    name: str,
    cfg,
    adapter,
    *,
    actor: str,
    abandon_critical: bool = False,
    force_outbox: bool = False,
    no_lease: bool = False,
    signer: leases.Signer | None = None,
    stop_timeout: int = STOP_TIMEOUT_S,
    on_step=None,
) -> dict:
    """Run the park sequence for ``name``. Resumable: steps already
    completed (per the park-state file) check their outputs and skip.

    ``on_step`` (tests only) is invoked with the step name after each
    step's state is durably persisted — raising inside it simulates a
    kill between steps.

    Returns the result payload (includes the verified manifest).
    Raises ``ParkRefused`` (policy refusal, exit 6) or ``ParkError``
    (verification/internal failure, exit 10); both roll the spec status
    back to its pre-park value.
    """
    signer = signer or leases.FakeSigner()
    state = _load_state(cfg, name)
    outputs = state.setdefault("outputs", {})
    completed = state.setdefault("completed", [])

    def _spec() -> dict:
        spec = load_spec_raw(cfg.instances_dir, name)
        if spec is None:
            raise ParkError(f"instance {name!r} is not declared")
        return spec

    def _done(step: str, **extra) -> None:
        outputs.update(extra)
        if step not in completed:
            completed.append(step)
        state["failed_step"] = None
        _save_state(cfg, name, state)
        if on_step is not None:
            on_step(step)

    try:
        # 1. stop accepting new work — spec status parking (spec-store API).
        spec = _spec()
        status = spec.get("status")
        if status == "parking":
            pass  # resume: already parking
        elif status == "parked" and "manifest" in completed:
            pass  # fully parked already — idempotent no-op
        else:
            state["previous_status"] = status or "active"
            update_spec(cfg.instances_dir, name, {"status": "parking"})
        _done("spec-parking")

        # 2. critical jobs — v1 policy: refuse all. Human abandonment only
        #    via the explicit flag, recorded with the actor, never silent.
        if "critical_jobs" not in outputs:
            if abandon_critical:
                _done("critical-jobs",
                      critical_jobs="human-abandoned",
                      critical_jobs_actor=actor)
            else:
                _done("critical-jobs", critical_jobs="refused",
                      critical_jobs_actor=None)
        else:
            _done("critical-jobs")

        # 3. bridge outbox — v1 the bridge is external: inspect
        #    state_dir/bridge-outbox/. Non-empty refuses unless forced.
        outbox_dir = Path(cfg.state_dir) / "bridge-outbox"
        if not outbox_dir.is_dir():
            outbox = "not-configured"
        elif any(outbox_dir.iterdir()):
            if not force_outbox:
                raise ParkRefused(
                    "bridge outbox is non-empty; flush it or re-run with "
                    "--force-outbox",
                    {"outbox": "non-empty"})
            outbox = "force-flushed"
            logger.warning("park %s: non-empty bridge outbox overridden "
                           "by --force-outbox (actor %s)", name, actor)
        else:
            outbox = "flushed"
        _done("outbox", outbox=outbox)

        # 4. HMK checkpoint — wal_checkpoint(TRUNCATE) + integrity_check in
        #    container (exec_quiesce_verify pattern), only when the spec
        #    declares hmk_path.
        spec = _spec()
        if "hmk" not in outputs:
            if spec.get("hmk_path"):
                try:
                    quiesce = adapter.exec_quiesce_verify(name)
                except Exception as exc:
                    raise ParkError(f"hmk checkpoint failed: {exc}") from exc
                if not quiesce.get("sqlite_ok"):
                    raise ParkError(
                        "hmk integrity_check not ok; fail-closed, no park",
                        {"quiesce": quiesce})
                _done("hmk-checkpoint", hmk="ok", hmk_integrity="ok")
            else:
                _done("hmk-checkpoint", hmk="absent", hmk_integrity="absent")
        else:
            _done("hmk-checkpoint")

        # 5. state files — copy NOW.md + DIALOGUE-HANDOFF.md out of the
        #    container, sha256 recorded per file.
        spec = _spec()
        if "state_files" not in outputs:
            if spec.get("state_files"):
                base = str(spec.get("state_files_dir")
                           or DEFAULT_STATE_FILES_DIR).rstrip("/")
                dest = _park_dir(cfg, name) / name / "state"
                dest.mkdir(parents=True, exist_ok=True)
                shas = {}
                for fname in STATE_FILES:
                    content = adapter.exec(name, ["cat", f"{base}/{fname}"])
                    data = content.encode("utf-8")
                    (dest / fname).write_bytes(data)
                    shas[fname] = hashlib.sha256(data).hexdigest()
                _done("state-files", state_files=shas)
            else:
                _done("state-files", state_files="not-configured")
        else:
            _done("state-files")

        # 6. state repo commit — staged content is scanned for secrets
        #    BEFORE committing (fail-closed).
        spec = _spec()
        if "state_commit" not in outputs:
            if spec.get("state_repo"):
                repo = str(spec.get("state_repo_path")
                           or DEFAULT_STATE_REPO_PATH)
                adapter.exec(name, ["git", "-C", repo, "add", "-A"])
                staged = adapter.exec(
                    name, ["git", "-C", repo, "diff", "--cached"])
                hit = _contains_secret(staged)
                if hit is not None:
                    adapter.exec(name, ["git", "-C", repo, "reset", "-q"])
                    raise ParkRefused(
                        f"secret material in staged state-repo changes "
                        f"(matched {hit!r}); refusing to commit",
                        {"redact_pattern": hit})
                adapter.exec(name, ["git", "-C", repo, "commit", "-q",
                                    "--allow-empty", "-m",
                                    f"park: checkpoint {name}"])
                sha = adapter.exec(
                    name, ["git", "-C", repo, "rev-parse", "HEAD"]).strip()
                _done("state-repo", state_commit=sha, state_repo_path=repo)
            else:
                _done("state-repo", state_commit=None)
        else:
            _done("state-repo")

        # 7. verification — recompute every recorded hash; fail-closed.
        problems = []
        if isinstance(outputs.get("state_files"), dict):
            dest = _park_dir(cfg, name) / name / "state"
            for fname, recorded in outputs["state_files"].items():
                try:
                    data = (dest / fname).read_bytes()
                except OSError:
                    problems.append(f"state file {fname} missing")
                    continue
                if hashlib.sha256(data).hexdigest() != recorded:
                    problems.append(f"state file {fname} hash mismatch")
        if _spec().get("hmk_path") and outputs.get("hmk_integrity") != "ok":
            problems.append("hmk integrity not ok")
        if outputs.get("state_commit"):
            current = adapter.exec(
                name, ["git", "-C", outputs.get("state_repo_path")
                       or DEFAULT_STATE_REPO_PATH,
                       "rev-parse", "HEAD"]).strip()
            if current != outputs["state_commit"]:
                problems.append("state repo commit sha does not resolve")
        backup_ids = _read_backup_ids(cfg.state_dir, name)
        if no_lease:
            lease_epoch, lease_state = None, "no-lease-pre-m7"
        else:
            st = leases.LeaseStore(cfg.state_dir, signer).status(
                _daimon_id(_spec(), name))
            if not st["present"] or st["expired"]:
                problems.append("no active lease held by the daimon "
                                "(or pass --no-lease for pre-M7 instances)")
            lease_epoch = st["last_epoch"]
            lease_state = "active"
        if problems:
            raise ParkError("park verification failed: " + "; ".join(problems),
                            {"problems": problems})
        _done("verify", backup_ids=backup_ids, lease_epoch=lease_epoch,
              lease=lease_state)

        # 8. lease transition parking → parked, then signed manifest.
        fence_epoch = outputs.get("lease_epoch")
        manifest_path = (_park_dir(cfg, name) / name
                         / f"manifest-{fence_epoch if fence_epoch is not None else 'nolease'}.json")
        if not (manifest_path.is_file() and "manifest" in completed):
            update_spec(cfg.instances_dir, name, {"status": "parked"})
            steps_record = []
            for step in completed:
                entry = {"name": step, "result": "ok"}
                if step == "state-files" and isinstance(
                        outputs.get("state_files"), dict):
                    entry["sha256"] = dict(outputs["state_files"])
                steps_record.append(entry)
            manifest = sign_manifest({
                "schema": MANIFEST_SCHEMA,
                "name": name,
                "fence_epoch": fence_epoch,
                "actor": actor,
                "created_ms": audit.now_ms(),
                "steps": steps_record,
                "hmk_integrity": outputs.get("hmk_integrity", "absent"),
                "state_commit": outputs.get("state_commit"),
                "state_files": outputs.get("state_files"),
                "backup_ids": outputs.get("backup_ids"),
                "critical_jobs": outputs.get("critical_jobs"),
                "critical_jobs_actor": outputs.get("critical_jobs_actor"),
                "outbox": outputs.get("outbox"),
                "lease_epoch": fence_epoch,
                "lease": outputs.get("lease"),
            }, signer)
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = manifest_path.with_name(manifest_path.name + ".tmp")
            tmp.write_text(json.dumps(manifest, sort_keys=True, indent=2)
                           + "\n", encoding="utf-8")
            os.replace(tmp, manifest_path)
            # Read back and verify before declaring the handoff immutable.
            load_manifest(manifest_path, signer)
        _done("manifest", manifest_path=str(manifest_path))

        # 9. stop — only after the manifest is written and verified.
        if "stop" not in completed:
            adapter.stop(name, stop_timeout)
        _done("stop")

    except ParkError as exc:
        state["failed_step"] = next(
            (s for s in STEPS if s not in completed), None)
        state["error"] = str(exc)
        if state["failed_step"] == "verify":
            # Verification compares recorded values against LIVE state.
            # A verify failure means the recorded commit point is not
            # trustworthy — drop the volatile recorded value so a resume
            # re-runs the commit step instead of comparing a stale sha
            # against a moved HEAD forever (resume must converge).
            outputs.pop("state_commit", None)
        _save_state(cfg, name, state)
        _rollback_active(cfg, name, state)
        raise

    manifest = load_manifest(outputs["manifest_path"], signer)
    return {
        "operation": "park",
        "name": name,
        "result": "ok",
        "state": "parked",
        "manifest": outputs["manifest_path"],
        "checkpoint": manifest,
        "idempotency_key": None,
    }


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


def cmd_park(args, cfg, adapter) -> int:
    name, operation = args.name, "park"
    store = idempotency.load_store(cfg.state_dir)
    rc = _check_idempotency(args, cfg, operation, name, store)
    if rc is not None:
        return rc

    specs = load_specs(cfg.instances_dir)
    if name not in specs:
        return _fail(args, cfg, operation, name,
                     f"instance {name!r} is not declared", EXIT_NOT_FOUND)

    lock_ctx = _lock_or_fail(args, cfg, operation, name)
    if isinstance(lock_ctx, int):
        return lock_ctx
    with lock_ctx as acquired:
        stale = _stale_detail(acquired)
        try:
            result = run_park(
                name, cfg, adapter,
                actor=_actor(args),
                abandon_critical=bool(getattr(args, "abandon_critical", False)),
                force_outbox=bool(getattr(args, "force_outbox", False)),
                no_lease=bool(getattr(args, "no_lease", False)),
                stop_timeout=int(getattr(args, "timeout", STOP_TIMEOUT_S)),
            )
        except ParkRefused as exc:
            return _fail(args, cfg, operation, name, str(exc), EXIT_CONFLICT,
                         detail={**exc.detail, **stale})
        except ParkError as exc:
            return _fail(args, cfg, operation, name, str(exc), EXIT_INTERNAL,
                         audit_result="error",
                         detail={**exc.detail, **stale})

        result["idempotency_key"] = _idem_key(args)
        _record_idempotency(args, cfg, operation, name, store, result)
        _audit_ok(args, cfg, operation, name, {
            "state": "parked",
            "manifest": result["manifest"],
            "critical_jobs": result["checkpoint"].get("critical_jobs"),
            "outbox": result["checkpoint"].get("outbox"),
            "lease_epoch": result["checkpoint"].get("lease_epoch"),
            **stale,
        })
        _emit(args, result,
              f"parked {name}: checkpoint manifest {result['manifest']} "
              f"(lease_epoch {result['checkpoint'].get('lease_epoch')}, "
              f"critical_jobs {result['checkpoint'].get('critical_jobs')}, "
              f"container stopped)")
        return EXIT_OK
