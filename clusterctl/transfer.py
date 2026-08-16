"""Same-host transfer + handoff wake (issue #29).

The second half of the M7 handoff protocol (park is #28). v1 scope is
SAME-HOST transfer: the target is a new container on this cluster.
Cross-host transfer needs the directory API — out of scope.

``clusterctl wake --handoff <name>`` — re-entry on the SAME body after
a local handoff park:

  1. load + verify the checkpoint manifest (signature; fence epoch must
     match the resource's fence history — a newer epoch means another
     holder won that resource, refuse)
  2. restore state files back into the container (inverse of park step
     5), sha256 of each file verified BEFORE writing, restored shas
     recorded in the wake record
  3. persist a signed prepared successor and commit it through the shared
     authority (epoch+1 CAS)
  4. spec status parked → waking → active; container start
  5. signed ``wake-record/v1`` at ``state_dir/park/<name>/wake-<epoch>.json``

On ANY failure the resource remains fenced safely, the container stays stopped, the
spec rolls back to ``parked``, and the wake record (status ``failed``)
makes the run resumable like park.

``clusterctl transfer <name> --to <new-name>`` — same-host embodiment
relocation. Pre-conditions: source spec status ``parked`` AND a
verified checkpoint manifest exists (else exit 6 with guidance to run
``park --handoff`` first). Steps (resumable via ``transfer-state/v1``):

  a. verify manifest signature + hashes again (provenance gate)
  b. close manifest hash, exact volume identity/attachment and immutable
     fence epoch/proof in the operation journal; lock source and target
  c. create the target spec and container STOPPED, without a home device
  d. detach the source and attach that same existing durable volume to the
     target, observing exact identity and one writable attachment after each
     response (including response loss)
  e. verify the bound fence position and commit its exact CAS successor
  f. start the target, reconcile one preallocated incarnation, and verify the
     same volume identity/bytes again
  g. restore state files into the running target, sha256 verified per file
  h. signed ``transfer-record/v1`` at
     ``state_dir/transfer/<name>-to-<new-name>-<epoch>.json``
  i. audit event ``transfer`` with action_digest bound to the manifest
     hash

ROLLBACK: stop the target, move the exact volume back to one stopped source
attachment, close the intended target incarnation, and only then destroy the
target/spec. A committed fence successor is preserved and verified; no
backend may lower the epoch or restore predecessor bytes. On success the old
source spec is marked ``transferred``
(kept for audit; destroy is a separate human decision).

Announcements distinguish ``embodiment-relocation`` (wake/transfer)
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
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import audit, embodiments, fences, handoff_auth, locks, operation_journal, park
from .adapters import FakeAdapter
from .admission import AdmissionError
from .inventory import load_spec_raw, load_specs, update_spec
from .lifecycle import (
    EXIT_CONFLICT,
    EXIT_INTERNAL,
    EXIT_NOT_FOUND,
    EXIT_OK,
    _actor,
    _complete_resumable_journal,
    _emit,
    _fail,
    _lock_or_fail,
    _prepare_resumable_journal,
    _stale_detail,
    _write_spec,
)

logger = logging.getLogger("clusterctl.transfer")

WAKE_RECORD_SCHEMA = "wake-record/v1"
TRANSFER_STATE_SCHEMA = "transfer-state/v1"
TRANSFER_RECORD_SCHEMA = "transfer-record/v1"

# Announcement values (exact strings — tests assert them). Recorded in
# audit detail only; clusterctl never broadcasts lifecycle itself.
ANNOUNCEMENT_RELOCATION = "embodiment-relocation"
ANNOUNCEMENT_CREATION = "incarnation-creation"  # used by provision

WAKE_STEPS = (
    "verify-manifest",
    "fence-prepared",
    "fence",
    "start",
    "restore-files",
    "record",
)

TRANSFER_STEPS = (
    "verify-manifest",
    "fence-prepared",
    "fence",
    "target-spec",
    "target-create",
    "detach-source-volume",
    "attach-target-volume",
    "verify-volume",
    "start",
    "post-start-volume",
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


def _resource_ref(spec: dict, name: str) -> str:
    return park._resource_ref(spec, name)


def _volume_contract(spec: dict, name: str) -> tuple[str, str, str]:
    volume_name = str(spec.get("volume") or f"{name}-home")
    device = str(spec.get("volume_device") or "home")
    mount = str(spec.get("volume_mount") or "/home/agent")
    if not volume_name or device != "home" or mount != "/home/agent":
        raise TransferRefused("durable volume contract is not the allowlisted home mount")
    return volume_name, device, mount


def _attachment(instance: str, device: str, mount: str) -> dict:
    return {
        "instance": instance,
        "device": device,
        "path": mount,
        "writable": True,
    }


def _verify_volume(
    observation: dict,
    *,
    volume_name: str,
    identity: str | None = None,
    attachments: list[dict] | None = None,
) -> dict:
    if not observation.get("present"):
        raise TransferRefused(f"durable volume {volume_name!r} is absent")
    if observation.get("name") != volume_name:
        raise TransferRefused("volume observation names a different volume")
    if identity is not None and observation.get("identity") != identity:
        raise TransferRefused("durable volume identity changed during transfer")
    if attachments is not None and observation.get("attachments") != attachments:
        raise TransferRefused(
            "durable volume attachment contradicts the transfer stage",
            {
                "expected_attachments": attachments,
                "observed_attachments": observation.get("attachments"),
            },
        )
    return observation


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
    return hashlib.sha256(fences._canonical(manifest)).hexdigest()


def _sign(record: dict, signer: fences.Signer) -> dict:
    signed = dict(record)
    signed["signature"] = signer.sign(fences._canonical(record))
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


def _check_stale_acquisition(manifest: dict, fence: dict | None,
                             resource_ref: str) -> None:
    """Refuse when the fence on disk belongs to a NEWER acquisition than
    the one the checkpoint manifest was bound to (issue #30).

    The monotonic epoch already catches normal stale holders. The acquisition
    binding is a second invariant that also detects restored or manually
    replaced fence bytes. Manifests written before this field existed
    (``None``) fall back to the epoch-only check.
    """
    manifest_acq = manifest.get("resource_fence_acquired_ms")
    if manifest_acq is None or fence is None:
        return
    current_acq = fence.get("acquired_ms", fence.get("created_ms"))
    if current_acq != manifest_acq:
        raise TransferRefused(
            f"stale fence for {resource_ref!r}: the manifest is bound to "
            f"resource acquisition {manifest_acq} but the current fence was "
            f"acquired at {current_acq} — another holder re-acquired the "
            f"resource after this checkpoint; refusing")


def _acquire_fence(store: fences.ResourceFenceStore, resource_ref: str) -> dict:
    """Renew one concrete resource fence (epoch+1 CAS)."""
    renewed = store.renew(resource_ref, "")
    if renewed is None:
        raise TransferRefused(
            f"fence CAS failed for {resource_ref!r}: no active resource "
            f"fence to renew — another holder may have acquired it")
    return renewed


def _closed_fence_position(store: Any, resource_ref: str) -> dict:
    """Return the immutable CAS coordinate, never a time-relative status.

    Production exposes ``position`` directly.  The compatibility backend has
    no tombstone position API, so an active signed record is closed to the
    same epoch/proof shape.  H3 only relocates an actively fenced resource.
    """
    position_reader = getattr(store, "position", None)
    if callable(position_reader):
        position = position_reader(resource_ref)
        return {
            "resource_ref": resource_ref,
            "epoch": position["epoch"],
            "proof": position["proof"],
            "current": bool(position["current"]),
        }
    current = store.verify_current(resource_ref)
    if current is None:
        return {
            "resource_ref": resource_ref,
            "epoch": -1,
            "proof": None,
            "current": False,
        }
    return {
        "resource_ref": resource_ref,
        "epoch": int(current["epoch"]),
        "proof": store.proof_ref(current),
        "current": True,
    }


def _require_fence_position(
    observed: dict, expected: dict, *, context: str
) -> None:
    if observed != expected:
        raise TransferRefused(
            f"production fence position changed {context}",
            {"expected_fence_position": expected, "observed_fence_position": observed},
        )


def _recover_fence_successor(
    store: Any,
    resource_ref: str,
    before_position: dict,
    before_record: dict | None,
    expected_authorization_ref: str | None = None,
) -> tuple[dict, dict] | None:
    """Adopt only the exact next position for the same signed holder.

    This closes the commit/response-loss window of both fence backends.  A
    different holder, resource, acquisition, key or skipped epoch is never
    interpreted as our transition.
    """
    if before_record is None:
        return None
    after_position = _closed_fence_position(store, resource_ref)
    after_record = store.get(resource_ref)
    if (
        after_record is None
        or not after_position["current"]
        or after_position["epoch"] != before_position["epoch"] + 1
        or after_position["proof"] != store.proof_ref(after_record)
    ):
        return None
    identity_fields = (
        "resource_ref",
        "body_ref",
        "holder_embodiment_id",
        "holder_incarnation_id",
        "holder_key_id",
        "holder_pubkey",
        "fingerprint",
        "acquired_ms",
    )
    if any(before_record.get(key) != after_record.get(key) for key in identity_fields):
        return None
    if after_record.get("state", "held") != "held":
        return None
    if after_record.get("operation", "renew") != "renew":
        return None
    if (
        expected_authorization_ref is not None
        and after_record.get("authorization_ref") != expected_authorization_ref
    ):
        return None
    return after_record, after_position


def _open_incarnation(
    cfg, name: str, spec: dict, incarnation_id: str | None = None
) -> str | None:
    if spec.get("instance_kind") != "matrix-embodiment":
        return None
    embodiment_id = spec.get("embodiment_id")
    if not embodiment_id:
        return None
    incarnation_id = incarnation_id or embodiments.new_id("incarnation")
    registry = embodiments.Registry(cfg.state_dir)
    current = registry.status(embodiment_id)
    if current["status"] == "stopped":
        registry.start(embodiment_id, incarnation_id=incarnation_id)
    elif (
        current["status"] != "running"
        or current.get("current_incarnation_id") != incarnation_id
    ):
        raise TransferError("embodiment registry contradicts target incarnation")
    update_spec(
        cfg.instances_dir, name,
        {"current_incarnation_id": incarnation_id},
    )
    return incarnation_id


def _close_incarnation(cfg, name: str, spec: dict) -> None:
    if spec.get("instance_kind") != "matrix-embodiment":
        return
    embodiment_id = spec.get("embodiment_id")
    if not embodiment_id:
        return
    embodiments.Registry(cfg.state_dir).stop(embodiment_id)
    if load_spec_raw(cfg.instances_dir, name) is not None:
        update_spec(cfg.instances_dir, name, {"current_incarnation_id": None})


def _require_shared_embodiment_admission(
    store: Any, spec: dict, *, expected_incarnation_id: str
) -> dict | None:
    """Acquire/prove shared launch admission for Matrix-managed starts."""

    if spec.get("instance_kind") != "matrix-embodiment":
        return None
    current_reader = getattr(store, "embodiment_current", None)
    acquire = getattr(store, "acquire", None)
    if not callable(current_reader) or not callable(acquire):
        raise TransferRefused("Matrix-managed start requires shared embodiment admission")
    receipt = current_reader()
    if receipt is None:
        receipt = acquire()
    confirmed = current_reader()
    if (
        confirmed is None
        or confirmed.get("proof_ref") != receipt.get("proof_ref")
        or confirmed.get("lease_expires_at_ms", 0) <= audit.now_ms()
        or confirmed.get("incarnation_id") != expected_incarnation_id
    ):
        raise TransferRefused("Matrix-managed shared embodiment admission is not current")
    return confirmed


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
    signer: fences.Signer | None = None,
    fence_store: Any | None = None,
    on_step=None,
) -> dict:
    """Re-entry on the SAME body after a local handoff park.

    Resumable via the wake record (completed steps skip). Raises
    ``TransferRefused`` (exit 6) or ``TransferError`` (exit 10); on any
    failure the resource remains fenced, the container stays stopped, the
    spec rolls back to ``parked`` and the failure is recorded.
    """
    if signer is None or fence_store is None:
        if isinstance(adapter, FakeAdapter):
            signer = signer or fences.FakeSigner()
            fence_store = fence_store or fences.SyntheticResourceFenceStore(
                cfg.state_dir, signer
            )
        else:
            raise TransferRefused(
                "signed handoff holder/authority configuration is required"
            )
    if not isinstance(adapter, FakeAdapter) and (
        not isinstance(signer, fences.Ed25519Signer)
        or not isinstance(fence_store, handoff_auth.FenceMutationClient)
    ):
        raise TransferRefused(
            "live wake requires Ed25519 custody and a shared FenceMutationClient"
        )
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
    except fences.InvalidSignature as exc:
        raise TransferRefused(str(exc)) from exc
    fence_epoch = manifest.get("fence_epoch")
    if fence_epoch is None:
        raise TransferRefused(
            f"manifest for {name!r} has no resource-fenced position; "
            "handoff wake requires a current authority checkpoint"
        )
    intended_epoch = int(fence_epoch) + 1

    resource_ref = _resource_ref(spec, name)
    store = fence_store
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
        #    the epoch must match this resource's fence history. On resume
        #    after the fence step this check is skipped: this run IS the
        #    newer holder.
        if "verify-manifest" not in completed and "fence" not in completed:
            st = store.status(resource_ref)
            if not st["present"] or st["expired"]:
                raise TransferRefused(
                    f"no active resource fence for {resource_ref!r}; cannot "
                    f"acquire a new fence")
            if st["last_epoch"] != fence_epoch:
                raise TransferRefused(
                    f"stale fence for {resource_ref!r}: manifest epoch "
                    f"{fence_epoch} but the resource fence is epoch "
                    f"{st['last_epoch']} — another holder renewed "
                    f"first; refusing to wake")
            # Also bind to the acquisition recorded in the manifest.
            _check_stale_acquisition(manifest, store.get(resource_ref),
                                     resource_ref)
        _done("verify-manifest")

        # 2. prepare the exact signed successor and persist it before CAS.
        if "fence-prepared" not in completed:
            prepare = getattr(store, "prepare", None)
            prepared_fence = (
                prepare(resource_ref, operation="renew")
                if callable(prepare)
                else None
            )
            _done("fence-prepared", prepared_fence=prepared_fence)
        else:
            _done("fence-prepared")

        # 3. commit the prepared CAS before any spec or runtime write.
        if "fence" not in completed:
            commit = getattr(store, "commit", None)
            if callable(commit):
                receipt = commit(outputs["prepared_fence"])
                renewed = receipt["evidence"]
                fence_receipt = receipt
            else:
                renewed = _acquire_fence(store, resource_ref)
                fence_receipt = None
            record["fence_epoch"] = renewed["epoch"]
            _done(
                "fence", fence_epoch=renewed["epoch"],
                fence_receipt=fence_receipt,
            )
        else:
            _done("fence")

        # 3. start — spec parked → waking; the container must be RUNNING
        #    for the restore below (incus exec — live drill 1 caught the
        #    original restore-before-start order failing on real incus).
        if "start" not in completed:
            intended_incarnation_id = outputs.get("intended_incarnation_id")
            if spec.get("instance_kind") == "matrix-embodiment":
                intended_incarnation_id = intended_incarnation_id or embodiments.new_id(
                    "incarnation"
                )
                outputs["intended_incarnation_id"] = intended_incarnation_id
            admission_receipt = _require_shared_embodiment_admission(
                store, spec, expected_incarnation_id=str(intended_incarnation_id)
            )
            if admission_receipt is not None:
                _done("embodiment-admission", embodiment_admission=admission_receipt)
            update_spec(cfg.instances_dir, name, {"status": "waking"})
            try:
                adapter.start(name)
                incarnation_id = _open_incarnation(
                    cfg, name, spec, intended_incarnation_id
                )
            except Exception as exc:
                raise TransferError(f"wake start failed: {exc}") from exc
            _done("start", incarnation_id=incarnation_id)
        else:
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
        if (load_spec_raw(cfg.instances_dir, name) or {}).get(
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
        # The resource remains fenced and the spec rolls back to parked. If
        # the start step ran, best-effort stop the container so the
        # convergent state is "both parked" (resumable via a later wake).
        try:
            update_spec(cfg.instances_dir, name, {"status": "parked"})
            if "start" in completed:
                adapter.stop(name)
                _close_incarnation(cfg, name, spec)
        except Exception:  # pragma: no cover - defensive
            logger.exception("wake rollback failed for %s", name)
        raise

    return {
        "operation": "wake",
        "name": name,
        "result": "ok",
        "state": "active",
        "fence_epoch": record.get("fence_epoch"),
        "incarnation_id": outputs.get("incarnation_id"),
        "restored_files": record.get("restored_files") or {},
        "announcement": ANNOUNCEMENT_RELOCATION,
        "wake_record": str(record_path),
        "manifest": str(manifest_path),
        "idempotency_key": None,
    }


def cmd_wake(args, cfg, adapter) -> int:
    name, operation = args.name, "wake"
    specs = load_specs(cfg.instances_dir)
    if name not in specs:
        return _fail(args, cfg, operation, name,
                     f"instance {name!r} is not declared", EXIT_NOT_FOUND)

    raw_spec = load_spec_raw(cfg.instances_dir, name) or {}
    try:
        manifest_path = _latest_manifest_path(cfg, name)
        if manifest_path is None:
            raise handoff_auth.HandoffAuthorizationError("checkpoint manifest is absent")
        manifest_bytes = json.loads(manifest_path.read_text(encoding="utf-8"))
        fence_client = handoff_auth.configured_client(
            cfg.state_dir, raw_spec, manifest=manifest_bytes
        )
        manifest_signer = fence_client.holder_signer
        manifest = park.load_manifest(manifest_path, manifest_signer)
        current_receipt = fence_client.current(_resource_ref(raw_spec, name))
        if (
            current_receipt is None
            or current_receipt.get("fencing_token")
            != manifest.get("resource_fence_epoch")
            or current_receipt.get("proof_ref")
            != manifest.get("resource_fence_proof")
        ):
            raise handoff_auth.HandoffAuthorizationError(
                "checkpoint is not bound to the exact current authority position"
            )
    except Exception as exc:  # noqa: BLE001 - best-effort rollback observation
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
            runtime_call={"method": "wake-handoff", "name": name},
            audit_context=stale,
        )
        if isinstance(prepared, int):
            return prepared
        journal, record, _recovered = prepared
        try:
            if record["state"] == "runtime-dispatching":
                result = run_wake(
                    name, cfg, adapter, actor=_actor(args),
                    signer=manifest_signer, fence_store=fence_client,
                )
            else:
                result = dict(record.get("result") or {})
        except TransferRefused as exc:
            journal.advance(
                record["operation_id"],
                "compensated",
                result={"result": "denied"},
                last_error=str(exc),
            )
            return _fail(args, cfg, operation, name, str(exc), EXIT_CONFLICT,
                         detail={**exc.detail, **stale})
        except TransferError as exc:
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
                "state": "active",
                "fence_epoch": result["fence_epoch"],
                "announcement": result["announcement"],
                "wake_record": result["wake_record"],
                "manifest": result["manifest"],
            },
        )
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


def _rollback_transfer(cfg, adapter, store: fences.ResourceFenceStore,
                       name: str, new_name: str, resource_ref: str,
                       state: dict) -> dict:
    """Restore one stopped source attachment or report degraded custody."""
    outputs = state.get("outputs") or {}
    errors = []
    volume_name = outputs.get("volume_name")
    volume_identity = outputs.get("volume_identity")
    device = outputs.get("volume_device") or "home"
    mount = outputs.get("volume_mount") or "/home/agent"

    # 1. close any incarnation and stop the target before touching storage.
    intended_incarnation = (
        outputs.get("incarnation_id") or outputs.get("intended_incarnation_id")
    )
    if intended_incarnation:
        try:
            target_spec = load_spec_raw(cfg.instances_dir, new_name) or {}
            embodiment_id = target_spec.get("embodiment_id")
            if embodiment_id:
                current = embodiments.Registry(cfg.state_dir).status(embodiment_id)
                if current.get("current_incarnation_id") == intended_incarnation:
                    _close_incarnation(cfg, new_name, target_spec)
            outputs["incarnation_id"] = None
        except Exception as exc:  # noqa: BLE001 - compensation records all failures
            errors.append(f"close target incarnation: {exc}")
    try:
        present = {
            item["name"]: item for item in adapter.list_instances()
        }
        if new_name in present:
            outputs["target_created"] = True
        if present.get(new_name, {}).get("state") == "running":
            adapter.stop(new_name, START_TIMEOUT_S)
    except Exception as exc:  # noqa: BLE001 - best-effort rollback observation
        errors.append(f"stop target: {exc}")

    # 2. move the exact volume back before deleting the target.
    attachment_safe = False
    if volume_name and volume_identity:
        try:
            observed = _verify_volume(
                adapter.volume_observation(volume_name),
                volume_name=volume_name,
                identity=volume_identity,
            )
            target_attachment = _attachment(new_name, device, mount)
            source_attachment = _attachment(name, device, mount)
            if target_attachment in observed["attachments"]:
                observed = adapter.detach_volume(
                    volume_name, new_name, device=device
                )
            if source_attachment not in observed["attachments"]:
                observed = adapter.attach_volume(
                    volume_name, name, device=device, path=mount
                )
            _verify_volume(
                observed,
                volume_name=volume_name,
                identity=volume_identity,
                attachments=[source_attachment],
            )
            attachment_safe = True
            outputs["volume_attached_to"] = name
        except Exception as exc:  # noqa: BLE001 - compensation records all failures
            errors.append(f"restore source volume: {exc}")
    else:
        errors.append("restore source volume: missing closed volume identity")

    # 3. destroy the stopped target only after storage custody is safe.
    if outputs.get("target_created") and attachment_safe:
        try:
            present_names = {inst["name"] for inst in adapter.list_instances()}
            if new_name in present_names:
                adapter.delete(new_name)
            outputs["target_created"] = False
        except Exception as exc:  # noqa: BLE001 - best-effort compensation
            errors.append(f"destroy target: {exc}")

    # 4. delete the target spec only when its container is gone.
    if outputs.get("target_spec") and not outputs.get("target_created"):
        try:
            (Path(cfg.instances_dir) / f"{new_name}.yaml").unlink(
                missing_ok=True)
            outputs["target_spec"] = False
        except Exception as exc:  # noqa: BLE001 - compensation records all failures
            errors.append(f"delete target spec: {exc}")

    # 5. Never lower a fence epoch.  When this transfer committed a
    # successor, safe compensation preserves that exact signed successor
    # while the source stays parked.  H1 production explicitly forbids byte
    # restore; the compatibility high-water would make a restored predecessor
    # invalid as well.
    fence_safe = True
    fence_advanced = bool(outputs.get("fence_acquired"))
    if fence_advanced:
        try:
            expected_position = outputs.get("fence_after")
            if not isinstance(expected_position, dict):
                raise TransferError("missing committed fence successor position")
            _require_fence_position(
                _closed_fence_position(store, resource_ref),
                expected_position,
                context="during rollback",
            )
            current_fence = store.get(resource_ref)
            if (
                current_fence is None
                or store.proof_ref(current_fence) != expected_position["proof"]
            ):
                raise TransferError("committed fence successor is not current")
            outputs["fence_successor_preserved"] = True
        except Exception as exc:  # noqa: BLE001 - compensation records all failures
            fence_safe = False
            errors.append(f"preserve fence successor: {exc}")

    # 6. the source stays parked and non-writable until an explicit wake.
    try:
        update_spec(cfg.instances_dir, name, {"status": "parked"})
    except Exception as exc:  # noqa: BLE001  # pragma: no cover - defensive
        errors.append(f"source spec: {exc}")

    rollback = {
        "attempted": True,
        "at_ms": audit.now_ms(),
        "errors": errors,
        "target_destroyed": not outputs.get("target_created"),
        "target_spec_deleted": not outputs.get("target_spec"),
        "fence_restored": False,
        "fence_advanced": fence_advanced,
        "fence_safe": fence_safe,
        "fence_position": outputs.get("fence_after") or outputs.get("fence_before"),
        "attachment_safe": attachment_safe,
        "volume_identity": volume_identity,
        "volume_attached_to": outputs.get("volume_attached_to"),
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
    signer: fences.Signer | None = None,
    fence_store: Any | None = None,
    expected_fence_position: dict | None = None,
    expected_manifest_hash: str | None = None,
    expected_volume_identity: str | None = None,
    fence_transition: Callable[[fences.ResourceFenceStore, str, dict], dict]
    | None = None,
    on_step=None,
) -> dict:
    """Same-host embodiment relocation: parked source → new container.

    Resumable via the transfer-state file. Raises ``TransferRefused``
    (exit 6: pre-conditions, tampered manifest) or ``TransferError``
    (exit 10; rolls the target back). On success the source spec is
    marked ``transferred`` (kept for audit — destroy is a separate
    human decision).
    """
    if signer is None or fence_store is None:
        if isinstance(adapter, FakeAdapter):
            signer = signer or fences.FakeSigner()
            fence_store = fence_store or fences.SyntheticResourceFenceStore(
                cfg.state_dir, signer
            )
        else:
            raise TransferRefused(
                "signed handoff holder/authority configuration is required"
            )
    if not isinstance(adapter, FakeAdapter) and (
        not isinstance(signer, fences.Ed25519Signer)
        or not isinstance(fence_store, handoff_auth.FenceMutationClient)
    ):
        raise TransferRefused(
            "live transfer requires Ed25519 custody and a shared FenceMutationClient"
        )
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

    resource_ref = _resource_ref(spec, name)
    store = fence_store
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
        except fences.InvalidSignature as exc:
            raise TransferRefused(str(exc)) from exc
        manifest_hash = _manifest_hash(manifest)
        if (
            expected_manifest_hash is not None
            and manifest_hash != expected_manifest_hash
        ):
            raise TransferRefused("checkpoint manifest changed after journal prepare")
        state_files = manifest.get("state_files")
        if isinstance(state_files, dict):
            problems = _verify_state_files_on_disk(cfg, name, state_files)
            if problems:
                raise TransferRefused(
                    "checkpoint manifest hash verification failed: "
                    + "; ".join(problems),
                    {"problems": problems})
        # stale-holder gate (issue #30): refuse when the resource was
        # re-acquired after this checkpoint. A missing fence is left to
        # the fence step (CAS failure → TransferError + rollback).
        observed_fence_position = _closed_fence_position(store, resource_ref)
        if expected_fence_position is not None:
            if observed_fence_position != expected_fence_position:
                recovered_fence = (
                    _recover_fence_successor(
                        store,
                        resource_ref,
                        expected_fence_position,
                        outputs.get("previous_resource_fence"),
                        (outputs.get("prepared_fence") or {}).get(
                            "authorization_ref"
                        ),
                    )
                    if outputs.get("fence_transition_prepared")
                    else None
                )
                if recovered_fence is None:
                    _require_fence_position(
                        observed_fence_position,
                        expected_fence_position,
                        context="before relocation",
                    )
                else:
                    renewed, fence_after = recovered_fence
                    outputs.update(
                        {
                            "fence_acquired": True,
                            "fence_epoch": renewed["epoch"],
                            "fence_after": fence_after,
                        }
                    )
                    _save_transfer_state(cfg, name, new_name, state)
            if (
                not expected_fence_position["current"]
                or manifest.get("resource_fence_epoch")
                != expected_fence_position["epoch"]
            ):
                raise TransferRefused(
                    "checkpoint manifest is not bound to the current fence epoch"
                )
        else:
            _check_stale_acquisition(manifest, store.get(resource_ref), resource_ref)
        volume_name, volume_device, volume_mount = _volume_contract(spec, name)
        image_version = spec.get("image_version")
        runtime = {
            item["name"]: item for item in adapter.list_instances()
        }
        if new_name in runtime and not outputs.get("target_spec"):
            raise TransferRefused("target container already exists outside this transfer")
        if runtime.get(name, {}).get("state") != "stopped":
            raise TransferRefused("source must be stopped before volume relocation")
        volume = _verify_volume(
            adapter.volume_observation(volume_name),
            volume_name=volume_name,
            identity=outputs.get("volume_identity") or expected_volume_identity,
        )
        source_attachment = _attachment(name, volume_device, volume_mount)
        target_attachment = _attachment(new_name, volume_device, volume_mount)
        if not outputs.get("volume_identity"):
            _verify_volume(
                volume,
                volume_name=volume_name,
                attachments=[source_attachment],
            )
        elif volume["attachments"] not in (
            [], [source_attachment], [target_attachment]
        ):
            raise TransferRefused("volume has an attachment outside this transfer")
        verify_outputs = {
            "manifest_path": str(manifest_path),
            "manifest_hash": manifest_hash,
            "state_commit": manifest.get("state_commit"),
            "volume_name": volume_name,
            "volume_device": volume_device,
            "volume_mount": volume_mount,
            "volume_identity": volume["identity"],
            "image_version": image_version,
        }
        if not outputs.get("volume_before"):
            verify_outputs["volume_before"] = volume
            verify_outputs["fence_before"] = observed_fence_position
            verify_outputs["volume_content_sha256"] = volume.get("content_sha256")
        _done("verify-manifest", **verify_outputs)

        # Prepare and commit the exact successor before target spec/create or
        # any detach/attach/start effect.  The signed authorization bytes are
        # durable, so response-loss recovery cannot perform a second logical
        # transition or adopt somebody else's successor.
        previous_fence = outputs.get("previous_resource_fence")
        if "fence-prepared" not in completed:
            previous_fence = store.get(resource_ref)
            prepare = getattr(store, "prepare", None)
            prepared_fence = (
                prepare(resource_ref, operation="renew")
                if callable(prepare)
                else None
            )
            _done(
                "fence-prepared",
                previous_resource_fence=previous_fence,
                fence_transition_prepared=True,
                prepared_fence=prepared_fence,
            )
        else:
            _done("fence-prepared")
        if not outputs.get("fence_acquired"):
            try:
                _require_fence_position(
                    _closed_fence_position(store, resource_ref),
                    outputs["fence_before"],
                    context="before fence transition",
                )
                commit = getattr(store, "commit", None)
                try:
                    if callable(commit):
                        fence_receipt = commit(outputs["prepared_fence"])
                        renewed = fence_receipt["evidence"]
                    else:
                        fence_receipt = None
                        renewed = (
                            fence_transition(store, resource_ref, outputs["fence_before"])
                            if fence_transition is not None
                            else _acquire_fence(store, resource_ref)
                        )
                except Exception:
                    recovered = _recover_fence_successor(
                        store,
                        resource_ref,
                        outputs["fence_before"],
                        previous_fence,
                        (outputs.get("prepared_fence") or {}).get(
                            "authorization_ref"
                        ),
                    )
                    if recovered is None:
                        raise
                    renewed, fence_after = recovered
                    fence_receipt = None
                else:
                    fence_after = _closed_fence_position(store, resource_ref)
                if (
                    not fence_after["current"]
                    or fence_after["epoch"] != outputs["fence_before"]["epoch"] + 1
                    or fence_after["proof"] != store.proof_ref(renewed)
                ):
                    raise TransferRefused(
                        "fence transition did not commit the exact expected successor"
                    )
            except (TransferRefused, fences.FenceError) as exc:
                raise TransferRefused(f"fence CAS failed before relocation: {exc}") from exc
            _done(
                "fence", fence_acquired=True, fence_epoch=renewed["epoch"],
                fence_after=fence_after, fence_receipt=fence_receipt,
            )
        else:
            _done("fence")

        # b. target-spec — copy of the source spec, status
        #    ``transferring``, same image_version/budgets, SAME durable
        #    volume name (embodiment keys travel WITH the volume — never
        #    copied through git).
        if not outputs.get("target_spec"):
            target_spec = dict(spec)
            target_spec.update({
                "name": new_name,
                "status": "transferring",
                "transferred_from": name,
                "volume": volume_name,
                "volume_device": volume_device,
                "volume_mount": volume_mount,
                "created_ms": audit.now_ms(),
                "created_by": actor,
            })
            target_spec.pop("idempotency_key", None)
            if target_spec.get("instance_kind") != "matrix-embodiment":
                for identity_field in (
                    "being_ref", "body_ref", "embodiment_id",
                    "current_incarnation_id", "activation_id", "credential_id",
                    "manifest_hash",
                ):
                    target_spec.pop(identity_field, None)
            _write_spec(cfg.instances_dir, target_spec)
        intended_incarnation_id = outputs.get("intended_incarnation_id")
        if spec.get("embodiment_id") and intended_incarnation_id is None:
            intended_incarnation_id = embodiments.new_id("incarnation")
        _done(
            "target-spec",
            target_spec=True,
            intended_incarnation_id=intended_incarnation_id,
        )

        # c. target-create — STOPPED and deliberately without a home device.
        if not outputs.get("target_created"):
            runtime = {item["name"]: item for item in adapter.list_instances()}
            create_error = None
            if new_name not in runtime:
                try:
                    adapter.create_instance(new_name, image_version, cfg.profile)
                except Exception as exc:  # noqa: BLE001 - observe response loss
                    create_error = exc
                runtime = {
                    item["name"]: item for item in adapter.list_instances()
                }
            if runtime.get(new_name, {}).get("state") != "stopped":
                message = "target container create did not converge to stopped"
                if create_error is not None:
                    message += f": {create_error}"
                raise TransferError(message)
            actual_image = runtime[new_name].get("image_version")
            if actual_image and image_version and actual_image != image_version:
                raise TransferError("target container image contradicts transfer intent")
            target_devices = adapter.instance_volume_devices(new_name)
            if any(
                item.get("device") == volume_device
                or item.get("path") == volume_mount
                for item in target_devices
            ):
                raise TransferError(
                    "target container was not created without a durable home",
                    {"target_volume_devices": target_devices},
                )
        _done("target-create", target_created=True)

        # d. detach/attach — response-loss safe because every retry first
        #    observes exact identity and attachments. Both containers remain
        #    stopped; there is never more than one writable attachment.
        expected_source = _attachment(name, volume_device, volume_mount)
        expected_target = _attachment(new_name, volume_device, volume_mount)
        if "detach-source-volume" not in completed:
            observed = _verify_volume(
                adapter.volume_observation(volume_name),
                volume_name=volume_name,
                identity=outputs["volume_identity"],
            )
            if observed["attachments"] == [expected_source]:
                observed = adapter.detach_volume(
                    volume_name, name, device=volume_device
                )
            if observed["attachments"] not in ([], [expected_target]):
                raise TransferRefused("source volume detach did not converge")
            _done("detach-source-volume", volume_after_detach=observed)
        else:
            _done("detach-source-volume")

        if "attach-target-volume" not in completed:
            observed = _verify_volume(
                adapter.volume_observation(volume_name),
                volume_name=volume_name,
                identity=outputs["volume_identity"],
            )
            if observed["attachments"] == []:
                observed = adapter.attach_volume(
                    volume_name,
                    new_name,
                    device=volume_device,
                    path=volume_mount,
                )
            _verify_volume(
                observed,
                volume_name=volume_name,
                identity=outputs["volume_identity"],
                attachments=[expected_target],
            )
            _done(
                "attach-target-volume",
                volume_after_attach=observed,
                volume_attached_to=new_name,
            )
        else:
            _done("attach-target-volume")

        observed = _verify_volume(
            adapter.volume_observation(volume_name),
            volume_name=volume_name,
            identity=outputs["volume_identity"],
            attachments=[expected_target],
        )
        _done("verify-volume", volume_verified=observed)

        # f. start — target spec transferring → waking; start the target
        #    container ONLY after the fence is held (before this step the
        #    target is network-unreachable; the spec goes active only
        #    after the restore below succeeds).
        if "start" not in completed:
            target_spec = load_spec_raw(cfg.instances_dir, new_name) or {}
            admission_receipt = _require_shared_embodiment_admission(
                store,
                target_spec,
                expected_incarnation_id=str(outputs.get("intended_incarnation_id")),
            )
            if admission_receipt is not None:
                _done("embodiment-admission", embodiment_admission=admission_receipt)
            update_spec(cfg.instances_dir, new_name, {"status": "waking"})
            runtime = {item["name"]: item for item in adapter.list_instances()}
            start_error = None
            if runtime.get(new_name, {}).get("state") == "stopped":
                try:
                    adapter.start(new_name)
                except Exception as exc:  # noqa: BLE001 - observe response loss
                    start_error = exc
                runtime = {
                    item["name"]: item for item in adapter.list_instances()
                }
            if runtime.get(new_name, {}).get("state") != "running":
                message = "target start did not converge to running"
                if start_error is not None:
                    message += f": {start_error}"
                raise TransferError(message)
            try:
                target_spec = load_spec_raw(cfg.instances_dir, new_name) or {}
                incarnation_id = _open_incarnation(
                    cfg,
                    new_name,
                    target_spec,
                    outputs.get("intended_incarnation_id"),
                )
            except Exception as exc:
                raise TransferError(f"target incarnation failed: {exc}") from exc
            _done("start", incarnation_id=incarnation_id)
        else:
            _done("start")

        post_start_volume = _verify_volume(
            adapter.volume_observation(volume_name),
            volume_name=volume_name,
            identity=outputs["volume_identity"],
            attachments=[expected_target],
        )
        if (
            outputs.get("volume_content_sha256") is not None
            and post_start_volume.get("content_sha256")
            != outputs["volume_content_sha256"]
        ):
            raise TransferError("durable volume content identity changed after start")
        _done("post-start-volume", volume_after_start=post_start_volume)

        # g. restore-files — sha256 verified per file BEFORE writing.
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
        if (load_spec_raw(cfg.instances_dir, new_name) or {}).get(
                "status") != "active":
            update_spec(cfg.instances_dir, new_name, {"status": "active"})
            update_spec(cfg.instances_dir, name, {"status": "transferred"})

        # h. record — signed transfer-record/v1.
        fence_epoch = outputs.get("fence_epoch")
        record_path = _transfer_record_path(cfg, name, new_name, fence_epoch)
        if "record" not in completed:
            record = _sign({
                "schema": TRANSFER_RECORD_SCHEMA,
                "source": name,
                "target": new_name,
                "manifest_path": str(manifest_path),
                "fence_epoch": fence_epoch,
                "incarnation_id": outputs.get("incarnation_id"),
                "restored_files": outputs.get("restored_files") or {},
                "state_commit": outputs.get("state_commit"),
                "volume": "moved",
                "volume_name": outputs.get("volume_name"),
                "volume_identity": outputs.get("volume_identity"),
                "volume_before": outputs.get("volume_before"),
                "volume_after": outputs.get("volume_after_start"),
                "fence_before": outputs.get("fence_before"),
                "announcement": ANNOUNCEMENT_RELOCATION,
                "actor": actor,
                "created_ms": audit.now_ms(),
            }, signer)
            _atomic_write(record_path, record)
            _done(
                "record",
                record_path=str(record_path),
                record_sha256=hashlib.sha256(record_path.read_bytes()).hexdigest(),
            )
        else:
            if (
                not record_path.is_file()
                or hashlib.sha256(record_path.read_bytes()).hexdigest()
                != outputs.get("record_sha256")
            ):
                raise TransferRefused("durable transfer record changed after commit")
            _done("record")

    except TransferRefused as exc:
        state["failed_step"] = next(
            (s for s in TRANSFER_STEPS if s not in completed), None)
        state["error"] = "refused"
        _save_transfer_state(cfg, name, new_name, state)
        # A refusal is a conflict only while the workflow is still
        # observation-only.  Once target state exists, it is a failed
        # mutation and must run the same custody-preserving compensation
        # as every other post-effect failure.  Otherwise a contradictory
        # attachment discovered after target creation could strand the
        # durable home outside both the source and the journal's rollback.
        if outputs.get("target_spec") or outputs.get("target_created"):
            rollback = _rollback_transfer(
                cfg, adapter, store, name, new_name, resource_ref, state
            )
            detail = dict(exc.detail)
            detail["rollback"] = rollback
            raise TransferError(
                f"transfer verification failed after mutation: {exc}", detail
            ) from exc
        raise
    except TransferError as exc:
        state["failed_step"] = next(
            (s for s in TRANSFER_STEPS if s not in completed), None)
        state["error"] = str(exc)
        _save_transfer_state(cfg, name, new_name, state)
        rollback = _rollback_transfer(cfg, adapter, store, name, new_name,
                                      resource_ref, state)
        exc.detail.setdefault("rollback", rollback)
        raise

    return {
        "operation": "transfer",
        "source": name,
        "target": new_name,
        "result": "ok",
        "state": "active",
        "fence_epoch": outputs.get("fence_epoch"),
        "incarnation_id": outputs.get("incarnation_id"),
        "restored_files": outputs.get("restored_files") or {},
        "state_commit": outputs.get("state_commit"),
        "volume": "moved",
        "volume_name": outputs.get("volume_name"),
        "volume_identity": outputs.get("volume_identity"),
        "volume_before": outputs.get("volume_before"),
        "volume_after": outputs.get("volume_after_start"),
        "announcement": ANNOUNCEMENT_RELOCATION,
        "transfer_record": outputs.get("record_path"),
        "manifest": str(manifest_path),
        "manifest_hash": outputs.get("manifest_hash"),
        "source_status": "transferred",
        "idempotency_key": None,
    }


def cmd_transfer(args, cfg, adapter) -> int:
    name, new_name, operation = args.name, args.to, "transfer"
    if name == new_name:
        return _fail(
            args, cfg, operation, name,
            "transfer source and target must be distinct", EXIT_CONFLICT,
        )
    specs = load_specs(cfg.instances_dir)
    if name not in specs:
        return _fail(args, cfg, operation, name,
                     f"instance {name!r} is not declared", EXIT_NOT_FOUND)

    source_spec = load_spec_raw(cfg.instances_dir, name) or {}
    try:
        manifest_path = _latest_manifest_path(cfg, name)
        if manifest_path is None:
            raise handoff_auth.HandoffAuthorizationError("checkpoint manifest is absent")
        manifest_bytes = json.loads(manifest_path.read_text(encoding="utf-8"))
        fence_client = handoff_auth.configured_client(
            cfg.state_dir, source_spec, manifest=manifest_bytes
        )
        manifest_signer = fence_client.holder_signer
        manifest = park.load_manifest(manifest_path, manifest_signer)
        current_receipt = fence_client.current(_resource_ref(source_spec, name))
        if (
            current_receipt is None
            or current_receipt.get("fencing_token")
            != manifest.get("resource_fence_epoch")
            or current_receipt.get("proof_ref")
            != manifest.get("resource_fence_proof")
        ):
            raise handoff_auth.HandoffAuthorizationError(
                "checkpoint is not bound to the exact current authority position"
            )
    except (
        AdmissionError,
        fences.FenceError,
        handoff_auth.HandoffAuthorizationError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        return _fail(
            args, cfg, operation, name,
            f"handoff authorization refused: {exc}", EXIT_CONFLICT,
            detail={"authorization": "missing-or-invalid"},
        )

    lock_ctx = locks.acquire_many(
        cfg.state_dir,
        [(name, operation), (new_name, "transfer-target")],
    )
    with lock_ctx as acquired:
        stale = {
            **_stale_detail(acquired[name]),
            **(
                {"target_stale_lock": acquired[new_name].stale_holder}
                if acquired[new_name].stale_holder
                else {}
            ),
        }
        existing_journal = operation_journal.OperationJournal.existing(cfg.state_dir)
        pending = (
            None if existing_journal is None else existing_journal.open_for_target(name)
        )
        if pending is not None and pending["operation"] == operation:
            runtime_call = pending["intent"]["runtime_call"]
            try:
                current_volume = adapter.volume_observation(
                    runtime_call["volume_name"]
                )
                _verify_volume(
                    current_volume,
                    volume_name=runtime_call["volume_name"],
                    identity=runtime_call["volume_identity"],
                )
            except Exception as exc:  # noqa: BLE001 - stable preflight refusal
                return _fail(
                    args, cfg, operation, name,
                    f"pending transfer volume cannot be verified: {exc}",
                    EXIT_CONFLICT,
                )
        else:
            try:
                volume_name, volume_device, volume_mount = _volume_contract(
                    source_spec, name
                )
                observed_volume = _verify_volume(
                    adapter.volume_observation(volume_name),
                    volume_name=volume_name,
                    attachments=[_attachment(name, volume_device, volume_mount)],
                )
                manifest_path = _latest_manifest_path(cfg, name)
                if manifest_path is None:
                    raise TransferRefused("verified checkpoint manifest is absent")
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                resource_ref = _resource_ref(source_spec, name)
                fence_position = _closed_fence_position(
                    fence_client, resource_ref
                )
                runtime_call = {
                    "method": "transfer-handoff",
                    "source": name,
                    "target": new_name,
                    "volume_name": volume_name,
                    "volume_identity": observed_volume["identity"],
                    "volume_device": volume_device,
                    "volume_mount": volume_mount,
                    "manifest_hash": _manifest_hash(manifest),
                    "fence_position": fence_position,
                }
            except Exception as exc:  # noqa: BLE001 - stable preflight refusal
                return _fail(
                    args, cfg, operation, name,
                    f"transfer preflight refused: {exc}", EXIT_CONFLICT,
                )
        prepared = _prepare_resumable_journal(
            args,
            cfg,
            adapter,
            operation=operation,
            target=name,
            runtime_call=runtime_call,
            audit_context=stale,
        )
        if isinstance(prepared, int):
            return prepared
        journal, record, _recovered = prepared
        try:
            if record["state"] == "runtime-dispatching":
                result = run_transfer(
                    name,
                    new_name,
                    cfg,
                    adapter,
                    actor=_actor(args),
                    signer=manifest_signer,
                    fence_store=fence_client,
                    expected_fence_position=runtime_call["fence_position"],
                    expected_manifest_hash=runtime_call["manifest_hash"],
                    expected_volume_identity=runtime_call["volume_identity"],
                )
            else:
                result = dict(record.get("result") or {})
        except TransferRefused as exc:
            journal.advance(
                record["operation_id"],
                "compensated",
                result={"result": "denied"},
                last_error=str(exc),
            )
            return _fail(args, cfg, operation, name, str(exc), EXIT_CONFLICT,
                         detail={**exc.detail, **stale})
        except TransferError as exc:
            rollback = exc.detail.get("rollback") or {}
            compensated = (
                rollback.get("attachment_safe") is True
                and rollback.get("target_destroyed") is True
                and rollback.get("fence_safe") is True
                and not rollback.get("errors")
            )
            journal.advance(
                record["operation_id"],
                "compensated" if compensated else "degraded",
                result={
                    "result": "error",
                    "compensated": compensated,
                    "reversed": compensated
                    and rollback.get("fence_advanced") is not True,
                },
                last_error=str(exc),
            )
            return _fail(args, cfg, operation, name, str(exc), EXIT_INTERNAL,
                         audit_result="error",
                         detail={**exc.detail, **stale})

        result["idempotency_key"] = record["idempotency_key"]
        result["operation_id"] = record["operation_id"]
        # h. audit event transfer — action_digest bound to the manifest
        #    hash (provenance), announcement recorded in the detail,
        #    never broadcast by clusterctl itself.
        record = _complete_resumable_journal(
            args,
            cfg,
            operation=operation,
            target=name,
            journal=journal,
            record=record,
            result=result,
            audit_target=new_name,
            audit_detail={
                "source": name,
                "state": "active",
                "source_status": "transferred",
                "fence_epoch": result["fence_epoch"],
                "announcement": result["announcement"],
                "volume": "moved",
                "volume_name": result["volume_name"],
                "transfer_record": result["transfer_record"],
                "manifest": result["manifest"],
            },
            derived_action_digest=result["manifest_hash"],
        )
        _emit(args, result,
              f"transferred {name} -> {new_name}: embodiment relocated "
              f"(fence_epoch {result['fence_epoch']}, volume moved, "
              f"announcement {result['announcement']}, target running; "
              f"source spec kept as transferred)")
        return EXIT_OK
