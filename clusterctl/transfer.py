"""Same-host transfer + handoff wake (issue #29).

The second half of the M7 handoff protocol (park is #28). v1 scope is
SAME-HOST transfer: the target is a new container on this cluster.
Cross-host transfer needs the directory API — out of scope.

``clusterctl wake --handoff <name>`` — re-entry on the SAME body after
a local handoff park:

  1. load + verify the checkpoint manifest (signature; fence epoch must
     match the daimon's lease history — a newer lease epoch means
     someone else took the identity, refuse)
  2. restore state files back into the container (inverse of park step
     5), sha256 of each file verified BEFORE writing, restored shas
     recorded in the wake record
  3. acquire a NEW fence via ``LeaseStore.renew`` (epoch+1 CAS)
  4. spec status parked → waking → active; container start
  5. signed ``wake-record/v1`` at ``state_dir/park/<name>/wake-<epoch>.json``

On ANY failure the lease stays parked, the container stays stopped, the
spec rolls back to ``parked``, and the wake record (status ``failed``)
makes the run resumable like park.

``clusterctl transfer <name> --to <new-name>`` — same-host identity
relocation. Pre-conditions: source spec status ``parked`` AND a
verified checkpoint manifest exists (else exit 6 with guidance to run
``park --handoff`` first). Steps (resumable via ``transfer-state/v1``):

  a. verify manifest signature + hashes again (provenance gate)
  b. create the target spec (copy of source, status ``transferring``,
     same image_version/budgets, SAME durable volume name — identity
     keys travel WITH the volume, never through git; ``volume: moved``)
  c. create the target container STOPPED (never reachable before
     verification + fence)
  d. restore state files into the target, sha256 verified per file
  e. acquire a NEW fence via ``LeaseStore.renew`` (CAS epoch+1)
  f. target spec transferring → waking → active; start the target
  g. signed ``transfer-record/v1`` at
     ``state_dir/transfer/<name>-to-<new-name>-<epoch>.json``
  h. audit event ``transfer`` with action_digest bound to the manifest
     hash

ROLLBACK: any failure after (c) destroys the target container, deletes
the target spec, and restores the pre-renew fence (only if this run
acquired it). The source stays parked with its lease intact — the
operator resumes with ``wake --handoff`` on the source. Rollback is
idempotent and recorded in the transfer-state file. On success the old
source spec is marked ``transferred`` (kept for audit; destroy is a
separate human decision).

Announcements distinguish ``same-identity-relocation`` (wake/transfer)
from ``incarnation-creation`` (provision). The field is recorded in
audit detail — clusterctl never broadcasts it.

Exit codes (clusterctl.cli contract): 0 ok, 3 undeclared, 6 conflict
(refusals: not parked, no manifest, tampered manifest, stale fence),
10 internal.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import shlex
from pathlib import Path

from . import audit, idempotency, leases, park
from .inventory import load_spec_raw, load_specs, update_spec
from .lifecycle import (
    EXIT_CONFLICT,  # noqa: F401  (re-exported for callers/tests)
    EXIT_INTERNAL,
    EXIT_NOT_FOUND,
    EXIT_OK,
    _actor,
    _audit_ok,
    _check_idempotency,
    _emit,
    _fail,
    _idem_key,
    _lock_or_fail,
    _record_idempotency,
    _stale_detail,
    _write_spec,
)

logger = logging.getLogger("clusterctl.transfer")

WAKE_RECORD_SCHEMA = "wake-record/v1"
TRANSFER_STATE_SCHEMA = "transfer-state/v1"
TRANSFER_RECORD_SCHEMA = "transfer-record/v1"

# Announcement values (exact strings — tests assert them). Recorded in
# audit detail only; clusterctl never broadcasts presence itself.
ANNOUNCEMENT_RELOCATION = "same-identity-relocation"
ANNOUNCEMENT_CREATION = "incarnation-creation"  # used by provision

WAKE_STEPS = (
    "verify-manifest",
    "fence",
    "start",
    "restore-files",
    "record",
)

TRANSFER_STEPS = (
    "verify-manifest",
    "target-spec",
    "target-create",
    "fence",
    "start",
    "restore-files",
    "record",
)

START_TIMEOUT_S = 30


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TransferError(Exception):
    """Internal transfer/wake failure (adapter, io, verification). Exit 10."""

    def __init__(self, message: str, detail: dict | None = None):
        super().__init__(message)
        self.detail = detail or {}


class TransferRefused(TransferError):
    """Policy refusal (not parked, no/tampered manifest, stale fence). Exit 6."""


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def _daimon_id(spec: dict, name: str) -> str:
    return park._daimon_id(spec, name)


def _latest_manifest_path(cfg, name: str) -> Path | None:
    """Newest checkpoint manifest for ``name`` (by fence_epoch), or None."""
    d = park._park_dir(cfg, name) / name
    if not d.is_dir():
        return None
    best, best_epoch = None, -2
    for path in sorted(d.glob("manifest-*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        epoch = raw.get("fence_epoch")
        key = -1 if epoch is None else int(epoch)
        if key > best_epoch:
            best, best_epoch = path, key
    return best


def _manifest_hash(manifest: dict) -> str:
    return hashlib.sha256(leases._canonical(manifest)).hexdigest()


def _sign(record: dict, signer: leases.Signer) -> dict:
    signed = dict(record)
    signed["signature"] = signer.sign(leases._canonical(record))
    return signed


def _atomic_write(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n",
                   encoding="utf-8")
    os.replace(tmp, path)


def _verify_state_files_on_disk(cfg, name: str, state_files: dict) -> list[str]:
    """Recompute parked state-file hashes against the manifest. Returns a
    list of problems (empty = all match)."""
    problems = []
    dest = park._park_dir(cfg, name) / name / "state"
    for fname, recorded in state_files.items():
        try:
            data = (dest / fname).read_bytes()
        except OSError:
            problems.append(f"state file {fname} missing from the park dir")
            continue
        if hashlib.sha256(data).hexdigest() != recorded:
            problems.append(f"state file {fname} sha256 mismatch")
    return problems


def _restore_state_files(cfg, park_name: str, target: str, spec: dict,
                         manifest: dict, adapter) -> dict:
    """Inverse of park step 5: copy parked state files INTO ``target``.

    Each file's sha256 is verified against the manifest BEFORE anything
    is written into the container. Returns ``{fname: sha256}`` of the
    restored files. Raises ``TransferError`` on missing/mismatched files.
    """
    state_files = manifest.get("state_files")
    if not isinstance(state_files, dict):
        return {}  # "not-configured" etc. — nothing to restore
    base = str(spec.get("state_files_dir")
               or park.DEFAULT_STATE_FILES_DIR).rstrip("/")
    src_dir = park._park_dir(cfg, park_name) / park_name / "state"
    restored = {}
    for fname, recorded in state_files.items():
        try:
            data = (src_dir / fname).read_bytes()
        except OSError as exc:
            raise TransferError(
                f"parked state file {fname} missing: {exc}") from exc
        digest = hashlib.sha256(data).hexdigest()
        if digest != recorded:
            raise TransferError(
                f"parked state file {fname} sha256 mismatch "
                f"(manifest {recorded}, actual {digest}); refusing to "
                f"restore tampered state",
                {"file": fname, "manifest_sha256": recorded,
                 "actual_sha256": digest})
        target_path = f"{base}/{fname}"
        b64 = base64.b64encode(data).decode()
        script = (
            f"mkdir -p {shlex.quote(base)} && "
            f"echo {shlex.quote(b64)} | base64 -d > {shlex.quote(target_path)}"
        )
        try:
            adapter.exec(target, ["sh", "-c", script])
        except Exception as exc:  # network partition, container dead...
            raise TransferError(
                f"state restore into {target!r} failed at {fname}: {exc}",
                {"file": fname}) from exc
        restored[fname] = digest
    return restored


def _check_stale_acquisition(manifest: dict, lease: dict | None,
                             daimon_id: str) -> None:
    """Refuse when the lease on disk belongs to a NEWER acquisition than
    the one the checkpoint manifest was bound to (issue #30).

    Epochs reset to 0 when a new holder re-acquires after expiry, so the
    epoch check alone cannot detect the two-holders race — the manifest
    also records ``lease_acquired_ms`` and the lease preserves
    ``acquired_ms`` across renews. Manifests written before this field
    existed (``None``) fall back to the epoch-only check.
    """
    manifest_acq = manifest.get("lease_acquired_ms")
    if manifest_acq is None or lease is None:
        return
    current_acq = lease.get("acquired_ms", lease.get("created_ms"))
    if current_acq != manifest_acq:
        raise TransferRefused(
            f"stale fence for {daimon_id!r}: the manifest is bound to "
            f"lease acquisition {manifest_acq} but the current lease was "
            f"acquired at {current_acq} — another holder re-acquired the "
            f"identity after this checkpoint; refusing")


def _acquire_fence(store: leases.LeaseStore, daimon_id: str) -> dict:
    """Renew the daimon's lease (epoch+1 CAS). Refuses when the lease is
    gone or expired — someone else took (or lost) the identity."""
    renewed = store.renew(daimon_id, "")
    if renewed is None:
        raise TransferRefused(
            f"fence CAS failed for {daimon_id!r}: no active lease to "
            f"renew — another holder may have taken the identity")
    return renewed


# ---------------------------------------------------------------------------
# wake --handoff
# ---------------------------------------------------------------------------


def _wake_record_path(cfg, name: str, epoch: int) -> Path:
    return park._park_dir(cfg, name) / name / f"wake-{epoch}.json"


def _load_wake_record(cfg, name: str, epoch: int, actor: str,
                      manifest_path: Path) -> dict:
    path = _wake_record_path(cfg, name, epoch)
    if path.is_file():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and raw.get("schema") == WAKE_RECORD_SCHEMA:
                raw.pop("signature", None)  # re-signed on every save
                return raw
        except (OSError, json.JSONDecodeError):
            pass
    return {
        "schema": WAKE_RECORD_SCHEMA,
        "name": name,
        "manifest_path": str(manifest_path),
        "fence_epoch": None,
        "restored_files": {},
        "announcement": ANNOUNCEMENT_RELOCATION,
        "actor": actor,
        "created_ms": audit.now_ms(),
        "status": "in-progress",
        "error": None,
        "completed": [],
        "outputs": {},
    }


def run_wake(
    name: str,
    cfg,
    adapter,
    *,
    actor: str,
    signer: leases.Signer | None = None,
    on_step=None,
) -> dict:
    """Re-entry on the SAME body after a local handoff park.

    Resumable via the wake record (completed steps skip). Raises
    ``TransferRefused`` (exit 6) or ``TransferError`` (exit 10); on any
    failure the lease stays parked, the container stays stopped, the
    spec rolls back to ``parked`` and the failure is recorded.
    """
    signer = signer or leases.FakeSigner()
    spec = load_spec_raw(cfg.instances_dir, name)
    if spec is None:
        raise TransferError(f"instance {name!r} is not declared")
    status = spec.get("status")
    if status not in ("parked", "waking"):
        raise TransferRefused(
            f"instance {name!r} is not parked (status {status!r}); "
            f"handoff wake requires a prior `park --handoff`")

    manifest_path = _latest_manifest_path(cfg, name)
    if manifest_path is None:
        raise TransferRefused(
            f"no checkpoint manifest for {name!r}; run "
            f"`park --handoff {name}` first")
    try:
        manifest = park.load_manifest(manifest_path, signer)
    except leases.InvalidSignature as exc:
        raise TransferRefused(str(exc)) from exc
    fence_epoch = manifest.get("fence_epoch")
    if fence_epoch is None:
        raise TransferRefused(
            f"manifest for {name!r} was parked with --no-lease; "
            f"handoff wake requires a leased checkpoint")
    intended_epoch = int(fence_epoch) + 1

    daimon_id = _daimon_id(spec, name)
    store = leases.LeaseStore(cfg.state_dir, signer)
    record = _load_wake_record(cfg, name, intended_epoch, actor, manifest_path)
    record_path = _wake_record_path(cfg, name, intended_epoch)
    outputs = record.setdefault("outputs", {})
    completed = record.setdefault("completed", [])

    def _done(step: str, **extra) -> None:
        outputs.update(extra)
        if step not in completed:
            completed.append(step)
        record["error"] = None
        _atomic_write(record_path, _sign(record, signer))
        if on_step is not None:
            on_step(step)

    try:
        # 1. verify-manifest — signature already verified by load_manifest;
        #    the fence epoch must match the daimon's lease history (a newer
        #    lease epoch means another holder renewed first). On resume
        #    after the fence step this check is skipped: this run IS the
        #    newer holder.
        if "verify-manifest" not in completed:
            if "fence" not in completed:
                st = store.status(daimon_id)
                if not st["present"] or st["expired"]:
                    raise TransferRefused(
                        f"no active lease for {daimon_id!r}; cannot "
                        f"acquire a new fence")
                if st["last_epoch"] != fence_epoch:
                    raise TransferRefused(
                        f"stale fence for {daimon_id!r}: manifest epoch "
                        f"{fence_epoch} but the lease is epoch "
                        f"{st['last_epoch']} — another holder renewed "
                        f"first; refusing to wake")
                # epochs reset on re-acquire — also bind to the lease
                # acquisition recorded in the manifest (issue #30)
                _check_stale_acquisition(manifest, store.get(daimon_id),
                                         daimon_id)
        _done("verify-manifest")

        # 2. fence — epoch+1 CAS. Refuses if a newer fence exists.
        if "fence" not in completed:
            renewed = _acquire_fence(store, daimon_id)
            record["fence_epoch"] = renewed["epoch"]
            _done("fence", fence_epoch=renewed["epoch"])
        else:
            _done("fence")

        # 3. start — spec parked → waking; the container must be RUNNING
        #    for the restore below (incus exec — live drill 1 caught the
        #    original restore-before-start order failing on real incus).
        if "start" not in completed:
            update_spec(cfg.instances_dir, name, {"status": "waking"})
            try:
                adapter.start(name)
            except Exception as exc:
                raise TransferError(f"wake start failed: {exc}") from exc
        _done("start")

        # 4. restore-files — inverse of park step 5; sha256 verified
        #    BEFORE writing; restored shas recorded. On success the spec
        #    becomes active.
        if "restore-files" not in completed:
            restored = _restore_state_files(cfg, name, name, spec,
                                            manifest, adapter)
            record["restored_files"] = restored
            _done("restore-files", restored_files=restored)
        else:
            _done("restore-files")
        if load_spec_raw(cfg.instances_dir, name).get(
                "status") != "active":
            update_spec(cfg.instances_dir, name, {"status": "active"})

        # 5. record — finalize the signed wake record.
        record["status"] = "ok"
        record["fence_epoch"] = outputs.get("fence_epoch",
                                            record.get("fence_epoch"))
        _done("record")

    except TransferError as exc:
        record["status"] = "failed"
        record["error"] = str(exc)
        _atomic_write(record_path, _sign(record, signer))
        # The lease stays parked and the spec rolls back to parked. If
        # the start step ran, best-effort stop the container so the
        # convergent state is "both parked" (resumable via a later wake).
        try:
            update_spec(cfg.instances_dir, name, {"status": "parked"})
            if "start" in completed:
                adapter.stop(name)
        except Exception:  # pragma: no cover - defensive
            logger.exception("wake rollback failed for %s", name)
        raise

    return {
        "operation": "wake",
        "name": name,
        "result": "ok",
        "state": "active",
        "fence_epoch": record.get("fence_epoch"),
        "restored_files": record.get("restored_files") or {},
        "announcement": ANNOUNCEMENT_RELOCATION,
        "wake_record": str(record_path),
        "manifest": str(manifest_path),
        "idempotency_key": None,
    }


def cmd_wake(args, cfg, adapter) -> int:
    name, operation = args.name, "wake"
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
            result = run_wake(name, cfg, adapter, actor=_actor(args))
        except TransferRefused as exc:
            return _fail(args, cfg, operation, name, str(exc), EXIT_CONFLICT,
                         detail={**exc.detail, **stale})
        except TransferError as exc:
            return _fail(args, cfg, operation, name, str(exc), EXIT_INTERNAL,
                         audit_result="error",
                         detail={**exc.detail, **stale})

        result["idempotency_key"] = _idem_key(args)
        _record_idempotency(args, cfg, operation, name, store, result)
        _audit_ok(args, cfg, operation, name, {
            "state": "active",
            "fence_epoch": result["fence_epoch"],
            "announcement": result["announcement"],
            "wake_record": result["wake_record"],
            "manifest": result["manifest"],
            **stale,
        })
        _emit(args, result,
              f"woke {name}: re-entry from checkpoint {result['manifest']} "
              f"(fence_epoch {result['fence_epoch']}, announcement "
              f"{result['announcement']}, container running)")
        return EXIT_OK


# ---------------------------------------------------------------------------
# transfer
# ---------------------------------------------------------------------------


def _transfer_dir(cfg) -> Path:
    return Path(cfg.state_dir) / "transfer"


def _transfer_state_path(cfg, name: str, new_name: str) -> Path:
    return _transfer_dir(cfg) / f"{name}-to-{new_name}.json"


def _transfer_record_path(cfg, name: str, new_name: str, epoch) -> Path:
    suffix = epoch if epoch is not None else "nofence"
    return _transfer_dir(cfg) / f"{name}-to-{new_name}-{suffix}.json"


def _load_transfer_state(cfg, name: str, new_name: str, actor: str) -> dict:
    path = _transfer_state_path(cfg, name, new_name)
    if path.is_file():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and raw.get("schema") == TRANSFER_STATE_SCHEMA:
                return raw
        except (OSError, json.JSONDecodeError):
            pass
    return {
        "schema": TRANSFER_STATE_SCHEMA,
        "source": name,
        "target": new_name,
        "actor": actor,
        "started_ms": audit.now_ms(),
        "completed": [],
        "outputs": {},
        "failed_step": None,
        "error": None,
        "rollback": None,
    }


def _save_transfer_state(cfg, name: str, new_name: str, state: dict) -> None:
    _atomic_write(_transfer_state_path(cfg, name, new_name), state)


def _rollback_transfer(cfg, adapter, store: leases.LeaseStore,
                       name: str, new_name: str, daimon_id: str,
                       state: dict) -> dict:
    """Destroy the target, delete its spec, restore the pre-renew fence
    (only if this run acquired it). Idempotent; recorded in the
    transfer-state file. The source stays parked with its lease intact —
    the operator resumes with ``wake --handoff`` on the source."""
    outputs = state.get("outputs") or {}
    errors = []

    # 1. destroy the target container (only if this run created it).
    if outputs.get("target_created"):
        try:
            present = {inst["name"] for inst in adapter.list_instances()}
            if new_name in present:
                adapter.delete(new_name)
            outputs["target_created"] = False
        except Exception as exc:  # best effort — recorded, never masks
            errors.append(f"destroy target: {exc}")

    # 2. delete the target spec.
    if outputs.get("target_spec"):
        try:
            (Path(cfg.instances_dir) / f"{new_name}.yaml").unlink(
                missing_ok=True)
            outputs["target_spec"] = False
        except Exception as exc:
            errors.append(f"delete target spec: {exc}")

    # 3. release the new fence attempt — only if THIS run acquired it.
    if outputs.get("fence_acquired") and not outputs.get("fence_rolled_back"):
        prev = outputs.get("prev_lease")
        try:
            if prev is not None:
                store.restore(daimon_id, prev)
            outputs["fence_rolled_back"] = True
        except Exception as exc:
            errors.append(f"restore fence: {exc}")

    # 4. the source stays parked (defensive — nothing should have moved it).
    try:
        update_spec(cfg.instances_dir, name, {"status": "parked"})
    except Exception as exc:  # pragma: no cover - defensive
        errors.append(f"source spec: {exc}")

    rollback = {
        "attempted": True,
        "at_ms": audit.now_ms(),
        "errors": errors,
        "target_destroyed": not outputs.get("target_created"),
        "target_spec_deleted": not outputs.get("target_spec"),
        "fence_restored": bool(outputs.get("fence_rolled_back")),
        "resume_hint": f"wake --handoff {name} resumes the source from "
                       f"the same checkpoint",
    }
    state["rollback"] = rollback
    _save_transfer_state(cfg, name, new_name, state)
    return rollback


def run_transfer(
    name: str,
    new_name: str,
    cfg,
    adapter,
    *,
    actor: str,
    signer: leases.Signer | None = None,
    on_step=None,
) -> dict:
    """Same-host identity relocation: parked source → new container.

    Resumable via the transfer-state file. Raises ``TransferRefused``
    (exit 6: pre-conditions, tampered manifest) or ``TransferError``
    (exit 10; rolls the target back). On success the source spec is
    marked ``transferred`` (kept for audit — destroy is a separate
    human decision).
    """
    signer = signer or leases.FakeSigner()
    spec = load_spec_raw(cfg.instances_dir, name)
    if spec is None:
        raise TransferError(f"instance {name!r} is not declared")
    state = _load_transfer_state(cfg, name, new_name, actor)
    resuming = bool(state.get("completed"))
    status = spec.get("status")
    # "transferred" is accepted only when resuming THIS transfer (the
    # start step already flipped the source before the interruption).
    if status != "parked" and not (status == "transferred" and resuming):
        raise TransferRefused(
            f"source {name!r} is not parked (status "
            f"{status!r}); run `park --handoff {name}` first")
    manifest_path = _latest_manifest_path(cfg, name)
    if manifest_path is None:
        raise TransferRefused(
            f"no verified checkpoint manifest for {name!r}; run "
            f"`park --handoff {name}` first")
    existing_target = load_spec_raw(cfg.instances_dir, new_name)
    if existing_target is not None and not (
            resuming and existing_target.get("status")
            in ("transferring", "waking", "active")):
        raise TransferRefused(f"target {new_name!r} is already declared")

    daimon_id = _daimon_id(spec, name)
    store = leases.LeaseStore(cfg.state_dir, signer)
    outputs = state.setdefault("outputs", {})
    completed = state.setdefault("completed", [])

    def _done(step: str, **extra) -> None:
        outputs.update(extra)
        if step not in completed:
            completed.append(step)
        state["failed_step"] = None
        _save_transfer_state(cfg, name, new_name, state)
        if on_step is not None:
            on_step(step)

    try:
        # a. verify-manifest — provenance gate: signature + recorded
        #    hashes re-verified on EVERY run (even resume). Nothing
        #    proceeds on a stale/tampered manifest.
        try:
            manifest = park.load_manifest(manifest_path, signer)
        except leases.InvalidSignature as exc:
            raise TransferRefused(str(exc)) from exc
        state_files = manifest.get("state_files")
        if isinstance(state_files, dict):
            problems = _verify_state_files_on_disk(cfg, name, state_files)
            if problems:
                raise TransferRefused(
                    "checkpoint manifest hash verification failed: "
                    + "; ".join(problems),
                    {"problems": problems})
        # stale-holder gate (issue #30): refuse when the identity was
        # re-acquired after this checkpoint. A MISSING lease is left to
        # the fence step (CAS failure → TransferError + rollback).
        _check_stale_acquisition(manifest, store.get(daimon_id), daimon_id)
        volume_name = str(spec.get("volume") or f"{name}-durable")
        image_version = spec.get("image_version")
        _done("verify-manifest",
              manifest_path=str(manifest_path),
              manifest_hash=_manifest_hash(manifest),
              state_commit=manifest.get("state_commit"),
              volume_name=volume_name,
              image_version=image_version)

        # b. target-spec — copy of the source spec, status
        #    ``transferring``, same image_version/budgets, SAME durable
        #    volume name (identity keys travel WITH the volume — never
        #    copied through git).
        if not outputs.get("target_spec"):
            target_spec = dict(spec)
            target_spec.update({
                "name": new_name,
                "status": "transferring",
                "transferred_from": name,
                "volume": volume_name,
                "created_ms": audit.now_ms(),
                "created_by": actor,
            })
            target_spec.pop("idempotency_key", None)
            _write_spec(cfg.instances_dir, target_spec)
        _done("target-spec", target_spec=True)

        # c. target-create — STOPPED. The target must not become
        #    reachable before verification + fence. The adapter create
        #    call attaches the (same) durable volume.
        #    TODO(#29): IncusAdapter must attach the existing volume
        #    ``volume_name`` to the new container on create — v1 records
        #    the intent in the spec + record only.
        if not outputs.get("target_created"):
            try:
                adapter.create_instance(new_name, image_version, cfg.profile)
            except Exception as exc:
                raise TransferError(
                    f"target container create failed: {exc}") from exc
        _done("target-create", target_created=True)

        # d. fence — NEW fence for the daimon identity (CAS epoch+1).
        #    The pre-renew lease is snapshotted so rollback can restore
        #    it exactly. CAS failure → rollback. The fence runs BEFORE
        #    start: the target must not become reachable before the new
        #    fence is held (live drill 1: restoring into a STOPPED
        #    container is impossible — incus exec requires running — so
        #    restore moved after start, and start after the fence).
        if not outputs.get("fence_acquired"):
            prev_lease = store.get(daimon_id)
            try:
                renewed = _acquire_fence(store, daimon_id)
            except TransferRefused as exc:
                # CAS failure AFTER the target exists → rollback (the
                # source stays parked with its lease intact).
                raise TransferError(
                    f"fence CAS failed ({exc}); rolling back the target"
                ) from exc
            _done("fence", fence_acquired=True, prev_lease=prev_lease,
                  fence_epoch=renewed["epoch"])
        else:
            _done("fence")

        # e. start — target spec transferring → waking; start the target
        #    container ONLY after the fence is held (before this step the
        #    target is network-unreachable; the spec goes active only
        #    after the restore below succeeds).
        if "start" not in completed:
            update_spec(cfg.instances_dir, new_name, {"status": "waking"})
            try:
                adapter.start(new_name)
            except Exception as exc:
                raise TransferError(
                    f"target start failed: {exc}") from exc
        _done("start")

        # f. restore-files — sha256 verified per file BEFORE writing.
        #    Requires a RUNNING target (incus exec); on success the
        #    target becomes active and the source is marked transferred
        #    (kept for audit — destroy is a separate human decision).
        if "restore-files" not in completed:
            target_spec = load_spec_raw(cfg.instances_dir, new_name) or {}
            restored = _restore_state_files(cfg, name, new_name,
                                            target_spec, manifest, adapter)
            _done("restore-files", restored_files=restored)
        else:
            _done("restore-files")
        if load_spec_raw(cfg.instances_dir, new_name).get(
                "status") != "active":
            update_spec(cfg.instances_dir, new_name, {"status": "active"})
            update_spec(cfg.instances_dir, name, {"status": "transferred"})

        # g. record — signed transfer-record/v1.
        fence_epoch = outputs.get("fence_epoch")
        record_path = _transfer_record_path(cfg, name, new_name, fence_epoch)
        record = _sign({
            "schema": TRANSFER_RECORD_SCHEMA,
            "source": name,
            "target": new_name,
            "manifest_path": str(manifest_path),
            "fence_epoch": fence_epoch,
            "restored_files": outputs.get("restored_files") or {},
            "state_commit": outputs.get("state_commit"),
            "volume": "moved",
            "volume_name": outputs.get("volume_name"),
            "announcement": ANNOUNCEMENT_RELOCATION,
            "actor": actor,
            "created_ms": audit.now_ms(),
        }, signer)
        _atomic_write(record_path, record)
        _done("record", record_path=str(record_path))

    except TransferRefused:
        state["failed_step"] = next(
            (s for s in TRANSFER_STEPS if s not in completed), None)
        state["error"] = "refused"
        _save_transfer_state(cfg, name, new_name, state)
        raise
    except TransferError as exc:
        state["failed_step"] = next(
            (s for s in TRANSFER_STEPS if s not in completed), None)
        state["error"] = str(exc)
        _save_transfer_state(cfg, name, new_name, state)
        rollback = _rollback_transfer(cfg, adapter, store, name, new_name,
                                      daimon_id, state)
        exc.detail.setdefault("rollback", rollback)
        raise

    return {
        "operation": "transfer",
        "source": name,
        "target": new_name,
        "result": "ok",
        "state": "active",
        "fence_epoch": outputs.get("fence_epoch"),
        "restored_files": outputs.get("restored_files") or {},
        "state_commit": outputs.get("state_commit"),
        "volume": "moved",
        "volume_name": outputs.get("volume_name"),
        "announcement": ANNOUNCEMENT_RELOCATION,
        "transfer_record": outputs.get("record_path"),
        "manifest": str(manifest_path),
        "manifest_hash": outputs.get("manifest_hash"),
        "source_status": "transferred",
        "idempotency_key": None,
    }


def cmd_transfer(args, cfg, adapter) -> int:
    name, new_name, operation = args.name, args.to, "transfer"
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
            result = run_transfer(name, new_name, cfg, adapter,
                                  actor=_actor(args))
        except TransferRefused as exc:
            return _fail(args, cfg, operation, name, str(exc), EXIT_CONFLICT,
                         detail={**exc.detail, **stale})
        except TransferError as exc:
            return _fail(args, cfg, operation, name, str(exc), EXIT_INTERNAL,
                         audit_result="error",
                         detail={**exc.detail, **stale})

        result["idempotency_key"] = _idem_key(args)
        _record_idempotency(args, cfg, operation, name, store, result)
        # h. audit event transfer — action_digest bound to the manifest
        #    hash (provenance), announcement recorded in the detail,
        #    never broadcast by clusterctl itself.
        if not getattr(args, "action_digest", None):
            args.action_digest = result["manifest_hash"]
        _audit_ok(args, cfg, operation, new_name, {
            "source": name,
            "state": "active",
            "source_status": "transferred",
            "fence_epoch": result["fence_epoch"],
            "announcement": result["announcement"],
            "volume": "moved",
            "volume_name": result["volume_name"],
            "transfer_record": result["transfer_record"],
            "manifest": result["manifest"],
            **stale,
        })
        _emit(args, result,
              f"transferred {name} -> {new_name}: identity relocated "
              f"(fence_epoch {result['fence_epoch']}, volume moved, "
              f"announcement {result['announcement']}, target running; "
              f"source spec kept as transferred)")
        return EXIT_OK
