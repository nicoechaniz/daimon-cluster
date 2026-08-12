"""Journaled canonical-ledger restore into one fresh recovered embodiment."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

from . import audit
from .locks import acquire
from .matrix_host import (
    MATRIX_CONTRACT_COMMIT,
    _matrix_api,
    matrix_root,
    verify_portable_snapshot,
)
from .operation_journal import (
    INTENT_SCHEMA,
    JournalConflict,
    OperationJournal,
    canonical_bytes,
)
from .rebirth import _owner_directory, _read_json, _sha, install_rebirth_package

RESULT_SCHEMA: Final = "dm.cluster.recovery-rebirth-result/v1"
RECOVERY_SNAPSHOT_EXPORT_SCHEMA: Final = "dm.cluster.recovery-snapshot-export/v1"
MAX_RECOVERY_BUNDLE_BYTES: Final = 4 * 1024 * 1024


class RecoveryRebirthError(RuntimeError):
    """Stable refusal at the recovery restore boundary."""


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _stage_snapshot_file(
    source: Path,
    destination: Path,
    row: dict[str, Any],
    *,
    capture: bool = False,
) -> bytes | None:
    """Copy one manifest-bound file through a stable no-follow descriptor."""

    if (
        set(row) != {"name", "sha256", "size"}
        or not isinstance(row["sha256"], str)
        or len(row["sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in row["sha256"])
        or not isinstance(row["size"], int)
        or isinstance(row["size"], bool)
        or row["size"] < 0
        or (capture and row["size"] > MAX_RECOVERY_BUNDLE_BYTES)
    ):
        raise RecoveryRebirthError("recovery_rebirth_snapshot_rejected")
    try:
        before = source.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size != row["size"]
        ):
            raise RecoveryRebirthError("recovery_rebirth_snapshot_rejected")
        source_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except RecoveryRebirthError:
        raise
    except OSError as exception:
        raise RecoveryRebirthError("recovery_rebirth_snapshot_rejected") from exception
    try:
        after = os.fstat(source_descriptor)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or not stat.S_ISREG(after.st_mode)
            or after.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) & 0o077
            or after.st_size != row["size"]
        ):
            raise RecoveryRebirthError("recovery_rebirth_snapshot_rejected")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        digest = hashlib.sha256()
        size = 0
        captured: list[bytes] = []
        try:
            while chunk := os.read(source_descriptor, 1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
                if size > row["size"]:
                    raise RecoveryRebirthError("recovery_rebirth_snapshot_rejected")
                if capture:
                    captured.append(chunk)
                offset = 0
                while offset < len(chunk):
                    written = os.write(destination_descriptor, chunk[offset:])
                    if written == 0:
                        raise RecoveryRebirthError("recovery_rebirth_snapshot_rejected")
                    offset += written
            os.fsync(destination_descriptor)
        finally:
            os.close(destination_descriptor)
        if size != row["size"] or digest.hexdigest() != row["sha256"]:
            raise RecoveryRebirthError("recovery_rebirth_snapshot_rejected")
        return b"".join(captured) if capture else None
    except RecoveryRebirthError:
        raise
    except OSError as exception:
        raise RecoveryRebirthError("recovery_rebirth_snapshot_rejected") from exception
    finally:
        os.close(source_descriptor)


def export_recovery_snapshot(
    snapshot_dir: str | Path, destination: str | Path
) -> dict[str, Any]:
    """Derive a custody-free recovery transfer from a verified full snapshot."""

    source = _owner_directory(Path(snapshot_dir))
    snapshot, payload, _verified = verify_portable_snapshot(source)
    target = Path(os.path.abspath(destination))
    parent = _owner_directory(target.parent)
    if target.exists() or target.is_symlink():
        raise RecoveryRebirthError("recovery_snapshot_destination_exists")
    temporary = Path(tempfile.mkdtemp(prefix=f".{target.name}.recovery-", dir=parent))
    try:
        temporary.chmod(0o700)
        target_payload = temporary / "payload"
        target_payload.mkdir(mode=0o700)
        files = {row["name"]: row for row in snapshot["files"]}
        bundle_name = snapshot["bundle"]
        bundle_row = files[bundle_name]
        bundle_raw = _stage_snapshot_file(
            payload / bundle_name,
            target_payload / bundle_name,
            bundle_row,
            capture=True,
        )
        if bundle_raw is None:
            raise RecoveryRebirthError("recovery_snapshot_source_rejected")
        bundle = json.loads(bundle_raw)
        if not isinstance(bundle, dict) or canonical_bytes(bundle) != bundle_raw.rstrip(
            b"\n"
        ):
            raise RecoveryRebirthError("recovery_snapshot_source_rejected")
        ledger_name = bundle.get("ledger")
        if (
            not isinstance(ledger_name, str)
            or ledger_name == bundle_name
            or ledger_name not in files
        ):
            raise RecoveryRebirthError("recovery_snapshot_source_rejected")
        ledger_row = files[ledger_name]
        _stage_snapshot_file(
            payload / ledger_name,
            target_payload / ledger_name,
            ledger_row,
        )
        selected = [dict(files[name]) for name in sorted((bundle_name, ledger_name))]
        recovery_snapshot = {
            "schema": snapshot["schema"],
            "matrix_contract_commit": snapshot["matrix_contract_commit"],
            "bundle": bundle_name,
            "origin": snapshot["origin"],
            "files": selected,
        }
        manifest = temporary / "snapshot.json"
        descriptor = os.open(
            manifest,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            value = canonical_bytes(recovery_snapshot) + b"\n"
            offset = 0
            while offset < len(value):
                written = os.write(descriptor, value[offset:])
                if written == 0:
                    raise RecoveryRebirthError("recovery_snapshot_export_failed")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(target_payload)
        _fsync_directory(temporary)
        os.replace(temporary, target)
        _fsync_directory(parent)
        return {
            "schema": RECOVERY_SNAPSHOT_EXPORT_SCHEMA,
            "source_snapshot_sha256": _sha(snapshot),
            "recovery_snapshot_sha256": _sha(recovery_snapshot),
            "origin": snapshot["origin"],
            "files": [row["name"] for row in selected],
            "omitted_file_count": len(files) - len(selected),
            "custody_files_exported": False,
        }
    except RecoveryRebirthError:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    except (KeyError, TypeError, json.JSONDecodeError, OSError) as exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise RecoveryRebirthError("recovery_snapshot_export_failed") from exception


def _load_inputs(
    package_dir: Path, snapshot_dir: Path, staged_payload: Path
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    Path,
    dict[str, Any],
    bool,
]:
    package = _owner_directory(package_dir)
    activation = _read_json(package / "activation.json")
    request = _read_json(package / "request.json")
    receipt = _read_json(package / "receipt.json")
    target_bundle = _read_json(_owner_directory(package / "runtime") / "runtime.json")
    snapshot, payload, _verified = verify_portable_snapshot(snapshot_dir)
    try:
        files = {row["name"]: row for row in snapshot["files"]}
        bundle_row = files[snapshot["bundle"]]
        bundle_raw = _stage_snapshot_file(
            payload / snapshot["bundle"],
            staged_payload / snapshot["bundle"],
            bundle_row,
            capture=True,
        )
        if bundle_raw is None:
            raise RecoveryRebirthError("recovery_rebirth_snapshot_rejected")
        source_bundle = json.loads(bundle_raw)
        if not isinstance(source_bundle, dict) or canonical_bytes(
            source_bundle
        ) != bundle_raw.rstrip(b"\n"):
            raise RecoveryRebirthError("recovery_rebirth_snapshot_rejected")
        ledger_row = files[source_bundle["ledger"]]
        _stage_snapshot_file(
            payload / source_bundle["ledger"],
            staged_payload / source_bundle["ledger"],
            ledger_row,
        )
        source_evidence = {
            "bundle_sha256": bundle_row["sha256"],
            "bundle_size": bundle_row["size"],
            "ledger_sha256": ledger_row["sha256"],
            "ledger_size": ledger_row["size"],
        }
        custody_free_transfer = len(files) == 2 and set(files) == {
            snapshot["bundle"],
            source_bundle["ledger"],
        }
    except RecoveryRebirthError:
        raise
    except (KeyError, TypeError, json.JSONDecodeError) as exception:
        raise RecoveryRebirthError("recovery_rebirth_snapshot_rejected") from exception
    api = _matrix_api()["operator_rebirth"]
    try:
        previous = api.authority_from_runtime_bundle(source_bundle)
        verified_activation, successor, _history = api.validate_recovery_activation(
            activation, previous, request=request
        )
        target = api.authority_from_runtime_bundle(target_bundle)
    except Exception as exception:
        raise RecoveryRebirthError("recovery_rebirth_authority_rejected") from exception
    origin = target_bundle.get("local_origin")
    snapshot_origin = snapshot.get("origin")
    if (
        activation.get("schema") != "dm.operator.recovery-activation/v1"
        or verified_activation != activation
        or target.manifest.digest != successor.manifest.digest
        or not isinstance(origin, dict)
        or receipt.get("origin") != origin
        or receipt.get("activation_id") != activation.get("activation_id")
        or receipt.get("previous_manifest_hash") != previous.manifest.digest
        or receipt.get("successor_manifest_hash") != successor.manifest.digest
        or receipt.get("empty_writable_state") is not True
        or snapshot.get("matrix_contract_commit") != MATRIX_CONTRACT_COMMIT
        or not isinstance(snapshot_origin, dict)
        or snapshot_origin != source_bundle.get("local_origin")
        or snapshot_origin.get("embodiment_id")
        not in verified_activation["body"]["recovery_artifact"]["body"][
            "revoked_embodiments"
        ]
        or any(
            row.get("status") == "active"
            and row.get("embodiment_id") != origin.get("embodiment_id")
            for row in successor.manifest.value["embodiments"]
        )
    ):
        raise RecoveryRebirthError("recovery_rebirth_input_rejected")
    return (
        activation,
        receipt,
        snapshot,
        staged_payload,
        source_evidence,
        custody_free_transfer,
    )


def _install_recovery_rebirth_from_inputs(
    state_dir: str | Path,
    package: Path,
    activation: dict[str, Any],
    receipt: dict[str, Any],
    snapshot: dict[str, Any],
    payload: Path,
    source_evidence: dict[str, Any],
    custody_free_transfer: bool,
    password_reader: Callable[[], bytearray],
    *,
    idempotency_key: str,
    actor: str = "clusterctl-recovery-rebirth",
) -> dict[str, Any]:
    state = _owner_directory(Path(state_dir), create=True)
    origin = receipt["origin"]
    embodiment_id = origin["embodiment_id"]
    activation_id = activation["activation_id"]
    snapshot_sha256 = _sha(snapshot)
    intent = {
        "schema": "dm.cluster.recovery-rebirth-intent/v1",
        "activation_id": activation_id,
        "embodiment_id": embodiment_id,
        "previous_manifest_hash": receipt["previous_manifest_hash"],
        "successor_manifest_hash": receipt["successor_manifest_hash"],
        "snapshot_sha256": snapshot_sha256,
        "custody_free_transfer": custody_free_transfer,
        "package_receipt_sha256": _sha(receipt),
        "runtime_call": {
            "operation": "restore-recovery-canonical-ledger",
            "matrix_contract_commit": MATRIX_CONTRACT_COMMIT,
        },
    }
    target = f"recovery-rebirth:{receipt['being_ref']}:{activation_id}"
    journal = OperationJournal(state)
    closed_intent = {"schema": INTENT_SCHEMA, **intent}
    matches = {
        row["operation_id"]: row
        for row in (
            journal.latest_for_target(target),
            journal.latest_for_idempotency_key(idempotency_key),
        )
        if row is not None
    }
    for row in matches.values():
        if (
            row["operation"] != "rebirth-recovery-restore"
            or row["intent"] != closed_intent
        ):
            raise JournalConflict("recovery rebirth identity has different bytes")
        if row["state"] == "completed" and isinstance(row["result"], dict):
            return row["result"]

    # Target installation is independently durable.  Its retry key is derived
    # from the content-addressed recovery activation, never caller-controlled.
    installed = install_rebirth_package(
        state,
        package,
        {},
        idempotency_key=f"recovery-target-install:{activation_id}",
        actor=actor,
    )
    if installed.get("state") != "installed-stopped":
        raise RecoveryRebirthError("recovery_rebirth_install_rejected")

    with acquire(state, embodiment_id, "recovery-ledger-restore"):
        record = journal.latest_for_target(target)
        if record is None:
            record = journal.plan(
                operation="rebirth-recovery-restore",
                target=target,
                idempotency_key=idempotency_key,
                intent=intent,
                expected_precondition={
                    "target_install_state": "installed-stopped",
                    "snapshot_sha256": snapshot_sha256,
                    "custody_free_transfer": custody_free_transfer,
                },
                intended_transition={
                    "canonical_ledger": "restored",
                    "target_status": "stopped",
                },
                audit_identity={"actor": actor, "target": embodiment_id},
                allow_terminal_successor=True,
            )
        if record["intent"] != closed_intent:
            raise JournalConflict("recovery rebirth identity has different bytes")
        if record["state"] == "completed" and isinstance(record["result"], dict):
            return record["result"]
        if record["state"] == "planned":
            record = journal.advance(record["operation_id"], "runtime-dispatching")
        try:
            matrix_receipt = _matrix_api()["operator_rebirth"].restore_recovery_ledger(
                matrix_root(state, embodiment_id),
                payload,
                password_reader,
                source_evidence=source_evidence,
            )
        except Exception as exception:
            raise RecoveryRebirthError(
                "recovery_rebirth_restore_rejected"
            ) from exception
        if record["state"] == "runtime-dispatching":
            record = journal.advance(
                record["operation_id"],
                "runtime-applied",
                runtime_observation=dict(matrix_receipt),
            )
        if record["state"] == "runtime-applied":
            record = journal.advance(
                record["operation_id"],
                "logical-committed",
                logical_observation={
                    "embodiment_id": embodiment_id,
                    "event_count": matrix_receipt["event_count"],
                    "event_set_sha256": matrix_receipt["event_set_sha256"],
                    "custody_free_transfer": custody_free_transfer,
                    "status": "stopped",
                },
            )
        audit.append_event(
            state,
            actor=actor,
            action="rebirth-recovery-restore",
            target=embodiment_id,
            result="ok",
            detail={
                "activation_id": activation_id,
                "event_count": matrix_receipt["event_count"],
                "event_set_sha256": matrix_receipt["event_set_sha256"],
                "snapshot_sha256": snapshot_sha256,
                "custody_free_transfer": custody_free_transfer,
            },
            idempotency_key=idempotency_key,
            event_id=record["audit_event_id"],
        )
        if record["state"] == "logical-committed":
            record = journal.advance(record["operation_id"], "audited")
        result = {
            "schema": RESULT_SCHEMA,
            "operation_id": record["operation_id"],
            "activation_id": activation_id,
            "being_ref": receipt["being_ref"],
            "embodiment_id": embodiment_id,
            "incarnation_id": origin["incarnation_id"],
            "predecessor_manifest_hash": receipt["previous_manifest_hash"],
            "successor_manifest_hash": receipt["successor_manifest_hash"],
            "snapshot_sha256": snapshot_sha256,
            "custody_free_transfer": custody_free_transfer,
            "event_count": matrix_receipt["event_count"],
            "event_set_sha256": matrix_receipt["event_set_sha256"],
            "state": "installed-restored-stopped",
        }
        if record["state"] == "audited":
            record = journal.advance(record["operation_id"], "completed", result=result)
        if record["result"] != result:
            raise RecoveryRebirthError("recovery_rebirth_result_conflict")
        return result


def install_recovery_rebirth(
    state_dir: str | Path,
    package_dir: str | Path,
    snapshot_dir: str | Path,
    password_reader: Callable[[], bytearray],
    *,
    idempotency_key: str,
    actor: str = "clusterctl-recovery-rebirth",
) -> dict[str, Any]:
    """Install a target-only recovery and restore only verified old events."""

    package = _owner_directory(Path(package_dir))
    snapshot_root = _owner_directory(Path(snapshot_dir))
    state = Path(os.path.abspath(state_dir))
    staging_parent: Path | None = None
    try:
        parent_info = state.parent.lstat()
        if (
            stat.S_ISDIR(parent_info.st_mode)
            and parent_info.st_uid == os.geteuid()
            and not stat.S_IMODE(parent_info.st_mode) & 0o077
            and os.access(state.parent, os.W_OK | os.X_OK)
        ):
            staging_parent = state.parent
    except OSError:
        pass
    staged = Path(
        tempfile.mkdtemp(prefix=".recovery-rebirth-snapshot-", dir=staging_parent)
    )
    try:
        staged.chmod(0o700)
        (
            activation,
            receipt,
            snapshot,
            payload,
            source_evidence,
            custody_free_transfer,
        ) = _load_inputs(package, snapshot_root, staged)
        return _install_recovery_rebirth_from_inputs(
            state,
            package,
            activation,
            receipt,
            snapshot,
            payload,
            source_evidence,
            custody_free_transfer,
            password_reader,
            idempotency_key=idempotency_key,
            actor=actor,
        )
    finally:
        shutil.rmtree(staged)


__all__ = [
    "RECOVERY_SNAPSHOT_EXPORT_SCHEMA",
    "RESULT_SCHEMA",
    "RecoveryRebirthError",
    "export_recovery_snapshot",
    "install_recovery_rebirth",
]
