"""Journaled canonical-ledger restore into one fresh recovered embodiment."""

from __future__ import annotations

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
from .operation_journal import INTENT_SCHEMA, JournalConflict, OperationJournal
from .rebirth import _owner_directory, _read_json, _sha, install_rebirth_package

RESULT_SCHEMA: Final = "dm.cluster.recovery-rebirth-result/v1"


class RecoveryRebirthError(RuntimeError):
    """Stable refusal at the recovery restore boundary."""


def _load_inputs(
    package_dir: Path, snapshot_dir: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Path, dict[str, Any]]:
    package = _owner_directory(package_dir)
    activation = _read_json(package / "activation.json")
    request = _read_json(package / "request.json")
    receipt = _read_json(package / "receipt.json")
    target_bundle = _read_json(_owner_directory(package / "runtime") / "runtime.json")
    snapshot, payload, _verified = verify_portable_snapshot(snapshot_dir)
    source_bundle = _read_json(payload / str(snapshot.get("bundle")))
    try:
        files = {row["name"]: row for row in snapshot["files"]}
        bundle_row = files[snapshot["bundle"]]
        ledger_row = files[source_bundle["ledger"]]
        source_evidence = {
            "bundle_sha256": bundle_row["sha256"],
            "bundle_size": bundle_row["size"],
            "ledger_sha256": ledger_row["sha256"],
            "ledger_size": ledger_row["size"],
        }
    except (KeyError, TypeError) as exception:
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
    return activation, receipt, snapshot, payload, source_evidence


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

    state = _owner_directory(Path(state_dir), create=True)
    package = _owner_directory(Path(package_dir))
    snapshot_root = _owner_directory(Path(snapshot_dir))
    activation, receipt, snapshot, payload, source_evidence = _load_inputs(
        package, snapshot_root
    )
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
            "event_count": matrix_receipt["event_count"],
            "event_set_sha256": matrix_receipt["event_set_sha256"],
            "state": "installed-restored-stopped",
        }
        if record["state"] == "audited":
            record = journal.advance(record["operation_id"], "completed", result=result)
        if record["result"] != result:
            raise RecoveryRebirthError("recovery_rebirth_result_conflict")
        return result


__all__ = ["RESULT_SCHEMA", "RecoveryRebirthError", "install_recovery_rebirth"]
