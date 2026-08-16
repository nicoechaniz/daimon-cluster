"""Park with verified checkpoint manifest (issue #28).

``clusterctl park <name>`` produces a complete, immutable handoff point
before a daimon relinquishes its concrete resource fence. Fail-closed per stage, ordered,
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
     an authority-signed current fence for the exact enrolled holder is required
  8. resource-fence transition + manifest — spec status parking → parked ONLY after
     all verifications pass; signed ``checkpoint-manifest/v1`` written to
     ``state_dir/park/<name>/manifest-<resource_fence_epoch>.json``
  9. stop — the container is stopped only after the manifest is written
     and verified

Interruption at any step: the park-state file records completed steps and
their outputs; re-running park resumes — idempotent steps check their
outputs before redoing. Any failure rolls the spec status back to its
pre-park value (default ``active``); the resource fence is never touched.

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
from typing import Any

from . import audit, embodiments, fences, handoff_auth
from .adapters import FakeAdapter
from .admission import AdmissionError
from .inventory import load_spec_raw, load_specs, update_spec
from .lifecycle import (
    EXIT_CONFLICT,
    EXIT_INTERNAL,
    EXIT_NOT_FOUND,
    EXIT_OK,
    REDACT_PATTERNS,
    _actor,
    _complete_resumable_journal,
    _emit,
    _fail,
    _lock_or_fail,
    _prepare_resumable_journal,
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


def sign_manifest(manifest: dict, signer: fences.Signer) -> dict:
    """Return a copy of ``manifest`` with a signature over the canonical
    record (manifest minus ``signature``)."""
    signed = dict(manifest)
    signed["signature"] = signer.sign(fences._canonical(manifest))
    return signed


def verify_manifest(manifest: dict, signer: fences.Signer) -> bool:
    """True when ``manifest`` carries a valid signature over its canonical
    body. Unsigned or tampered manifests are rejected."""
    sig = manifest.get("signature")
    if not sig or not isinstance(sig, str):
        return False
    if manifest.get("schema") != MANIFEST_SCHEMA:
        return False
    return signer.verify(
        fences._canonical(manifest), sig, str(getattr(signer, "public_key", ""))
    )


def load_manifest(path: str | Path, signer: fences.Signer) -> dict:
    """Load and verify a checkpoint manifest file. Raises
    ``fences.InvalidSignature`` when unsigned or tampered."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not verify_manifest(raw, signer):
        raise fences.InvalidSignature(
            f"checkpoint manifest {path} is unsigned or tampered")
    return raw


# ---------------------------------------------------------------------------
# step helpers
# ---------------------------------------------------------------------------


def _resource_ref(spec: dict, name: str) -> str:
    """Return the concrete body resource fenced during handoff.

    Older fixture specs may use ``daimon_id`` as an opaque resource label;
    newly created specs always carry ``body_ref``.
    """
    return str(spec.get("body_ref") or spec.get("daimon_id") or f"resource:body:{name}")


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
    signer: fences.Signer | None = None,
    fence_store: Any | None = None,
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
    # Direct FakeAdapter calls are an explicit unit-fixture boundary.  Every
    # live caller must inject production custody and the signed remote client.
    if signer is None or fence_store is None:
        if isinstance(adapter, FakeAdapter):
            signer = signer or fences.FakeSigner()
            fence_store = fence_store or fences.SyntheticResourceFenceStore(
                cfg.state_dir, signer
            )
        else:
            raise ParkRefused("signed handoff holder/authority configuration is required")
    if not isinstance(adapter, FakeAdapter) and (
        not isinstance(signer, fences.Ed25519Signer)
        or not isinstance(fence_store, handoff_auth.FenceMutationClient)
    ):
        raise ParkRefused(
            "live handoff requires Ed25519 custody and a shared FenceMutationClient"
        )
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
        store: Any = fence_store
        resource_ref = _resource_ref(_spec(), name)
        current = store.verify_current(resource_ref)
        if current is None:
            problems.append("shared authority reports no current resource holder")
            current = {}
        expected_holder = None
        try:
            expected_holder = handoff_auth.holder_identity(_spec())
        except handoff_auth.HandoffAuthorizationError:
            if not isinstance(adapter, FakeAdapter):
                problems.append("exact enrolled fence holder identity is missing")
        if expected_holder is not None and any(
            current.get(field) != expected_holder[identity_field]
            for field, identity_field in (
                ("body_ref", "body_ref"),
                ("holder_embodiment_id", "embodiment_id"),
                ("holder_incarnation_id", "incarnation_id"),
            )
        ):
            problems.append("shared authority current holder is not the exact enrolled holder")
        expected_key_id = getattr(signer, "key_id", None)
        if expected_key_id is not None and current.get("holder_key_id") != expected_key_id:
            problems.append("shared authority current holder key is not the configured holder")
        fence_epoch = current.get("epoch")
        fence_state = "authority-current"
        fence_acquired_ms = current.get("acquired_ms")
        fence_proof = store.proof_ref(current) if current else None
        receipt_reader = getattr(store, "current", None)
        fence_receipt = (
            receipt_reader(resource_ref) if callable(receipt_reader) else None
        )
        if problems:
            raise ParkError("park verification failed: " + "; ".join(problems),
                            {"problems": problems})
        _done("verify", backup_ids=backup_ids,
              resource_fence_epoch=fence_epoch,
              resource_fence=fence_state,
              resource_fence_proof=fence_proof,
              resource_fence_receipt=fence_receipt)

        # 8. resource-fence transition parking → parked, then signed manifest.
        fence_epoch = outputs.get("resource_fence_epoch")
        manifest_path = (_park_dir(cfg, name) / name
                         / f"manifest-{fence_epoch if fence_epoch is not None else 'nofence'}.json")
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
                "resource_fence_epoch": fence_epoch,
                "resource_fence": outputs.get("resource_fence"),
                "resource_fence_proof": outputs.get("resource_fence_proof"),
                "resource_fence_receipt": outputs.get("resource_fence_receipt"),
                "resource_fence_acquired_ms": fence_acquired_ms,
                "fence_holder": expected_holder,
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
            stopped_spec = _spec()
            embodiment_id = (
                stopped_spec.get("embodiment_id")
                if stopped_spec.get("instance_kind") == "matrix-embodiment"
                else None
            )
            if embodiment_id:
                try:
                    embodiments.Registry(cfg.state_dir).stop(embodiment_id)
                    update_spec(
                        cfg.instances_dir, name,
                        {"current_incarnation_id": None},
                    )
                except embodiments.RegistryError as exc:
                    raise ParkError(
                        f"cannot close embodiment incarnation: {exc}"
                    ) from exc
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
    specs = load_specs(cfg.instances_dir)
    if name not in specs:
        return _fail(args, cfg, operation, name,
                     f"instance {name!r} is not declared", EXIT_NOT_FOUND)

    # Resolve custody and prove the exact current holder before any journal,
    # spec, staging, or adapter mutation.
    raw_spec = load_spec_raw(cfg.instances_dir, name) or {}
    try:
        fence_client = handoff_auth.configured_client(cfg.state_dir, raw_spec)
        manifest_signer = fence_client.holder_signer
        if fence_client.verify_current(_resource_ref(raw_spec, name)) is None:
            raise handoff_auth.HandoffAuthorizationError(
                "shared authority reports no current resource holder"
            )
    except (AdmissionError, handoff_auth.HandoffAuthorizationError) as exc:
        return _fail(
            args, cfg, operation, name,
            f"handoff authorization refused: {exc}", EXIT_CONFLICT,
            detail={"authorization": "missing-or-invalid"},
        )

    lock_ctx = _lock_or_fail(args, cfg, operation, name)
    if isinstance(lock_ctx, int):
        return lock_ctx
    with lock_ctx as acquired:
        stale = _stale_detail(acquired)
        prepared = _prepare_resumable_journal(
            args,
            cfg,
            adapter,
            operation=operation,
            target=name,
            runtime_call={
                "method": "park-handoff",
                "name": name,
                "abandon_critical": bool(getattr(args, "abandon_critical", False)),
                "force_outbox": bool(getattr(args, "force_outbox", False)),
                "stop_timeout": int(getattr(args, "timeout", STOP_TIMEOUT_S)),
            },
            audit_context=stale,
        )
        if isinstance(prepared, int):
            return prepared
        journal, record, _recovered = prepared
        try:
            if record["state"] == "runtime-dispatching":
                result = run_park(
                    name, cfg, adapter,
                    actor=_actor(args),
                    abandon_critical=bool(getattr(args, "abandon_critical", False)),
                    force_outbox=bool(getattr(args, "force_outbox", False)),
                    signer=manifest_signer,
                    fence_store=fence_client,
                    stop_timeout=int(getattr(args, "timeout", STOP_TIMEOUT_S)),
                )
            else:
                result = dict(record.get("result") or {})
        except ParkRefused as exc:
            journal.advance(
                record["operation_id"],
                "compensated",
                result={"result": "denied"},
                last_error=str(exc),
            )
            return _fail(args, cfg, operation, name, str(exc), EXIT_CONFLICT,
                         detail={**exc.detail, **stale})
        except ParkError as exc:
            journal.advance(
                record["operation_id"],
                "compensated",
                result={"result": "error"},
                last_error=str(exc),
            )
            return _fail(args, cfg, operation, name, str(exc), EXIT_INTERNAL,
                         audit_result="error",
                         detail={**exc.detail, **stale})

        result["idempotency_key"] = record["idempotency_key"]
        result["operation_id"] = record["operation_id"]
        record = _complete_resumable_journal(
            args,
            cfg,
            operation=operation,
            target=name,
            journal=journal,
            record=record,
            result=result,
            audit_target=name,
            audit_detail={
                "state": "parked",
                "manifest": result["manifest"],
                "critical_jobs": result["checkpoint"].get("critical_jobs"),
                "outbox": result["checkpoint"].get("outbox"),
                "resource_fence_epoch": result["checkpoint"].get(
                    "resource_fence_epoch"
                ),
            },
        )
        _emit(args, result,
              f"parked {name}: checkpoint manifest {result['manifest']} "
              f"(resource_fence_epoch {result['checkpoint'].get('resource_fence_epoch')}, "
              f"critical_jobs {result['checkpoint'].get('critical_jobs')}, "
              f"container stopped)")
        return EXIT_OK
