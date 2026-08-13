"""Forward-only rollout of one public rebirth activation across hosts."""

from __future__ import annotations

import base64
import hashlib
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from . import audit
from .embodiments import Registry
from .locks import acquire
from .matrix_host import (
    MATRIX_CONTRACT_COMMIT,
    _matrix_api,
    matrix_client,
    matrix_client_root,
    matrix_root,
)
from .operation_journal import OperationJournal, canonical_bytes
from .rebirth import (
    RESULT_SCHEMA,
    _atomic_json,
    _install_directory,
    _owner_directory,
    _read_json,
    _sha,
)

ROLLOUT_SCHEMA: Final = "dm.cluster.distributed-rebirth-rollout/v1"
APPLICATION_SCHEMA: Final = "dm.cluster.distributed-rebirth-application/v1"
ACK_SCHEMA: Final = "dm.cluster.distributed-rebirth-ack/v1"
ADMISSION_SCHEMA: Final = "dm.cluster.distributed-rebirth-admission/v1"
ROLLOUT_ID_PREFIX: Final = "dm:cluster-rebirth-rollout:v1:"
ADMISSION_ID_PREFIX: Final = "dm:cluster-rebirth-admission:v1:"


class DistributedRebirthError(RuntimeError):
    """Stable refusal at the distributed rebirth boundary."""


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise DistributedRebirthError(code)
    return value


def _bounded(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 2048
        or any(ord(character) < 0x20 for character in value)
    ):
        raise DistributedRebirthError(code)
    return value


def _hex_hash(value: Any, code: str) -> str:
    text = _bounded(value, code)
    if len(text) != 64 or any(
        character not in "0123456789abcdef" for character in text
    ):
        raise DistributedRebirthError(code)
    return text


def _content_id(value: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        b"dm.cluster.distributed-rebirth-rollout/v1\0" + canonical_bytes(dict(value))
    ).digest()
    return ROLLOUT_ID_PREFIX + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _without_rollout_id(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "rollout_id"}


def validate_rollout(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return one closed, content-addressed public rollout."""

    row = _closed(
        value,
        {
            "schema",
            "rollout_id",
            "matrix_contract_commit",
            "request_id",
            "activation_id",
            "previous_manifest_hash",
            "successor_manifest_hash",
            "target_runtime_sha256",
            "target",
            "participant_embodiment_ids",
            "activation",
            "target_profile",
        },
        "distributed_rollout_rejected",
    )
    if row["schema"] != ROLLOUT_SCHEMA:
        raise DistributedRebirthError("distributed_rollout_rejected")
    canonical = dict(row)
    if row["rollout_id"] != _content_id(_without_rollout_id(canonical)):
        raise DistributedRebirthError("distributed_rollout_id_mismatch")
    activation = _closed(
        row["activation"],
        {"schema", "activation_id", "body"},
        "distributed_rollout_rejected",
    )
    body = _closed(
        activation["body"],
        {
            "being_ref",
            "control_head",
            "credential",
            "incarnation",
            "issued_at_ms",
            "origin",
            "previous_manifest_hash",
            "request_id",
            "successor_manifest",
            "transition",
        },
        "distributed_rollout_rejected",
    )
    origin = _closed(
        body["origin"],
        {"body_ref", "embodiment_id", "incarnation_id", "principal_id"},
        "distributed_rollout_rejected",
    )
    target = _closed(
        row["target"],
        {
            "being_ref",
            "body_ref",
            "embodiment_id",
            "incarnation_id",
            "principal_id",
            "advertised_endpoint",
        },
        "distributed_rollout_rejected",
    )
    profile = _closed(
        row["target_profile"],
        {
            "schema",
            "label",
            "body_ref",
            "principal_id",
            "listen_host",
            "listen_port",
            "advertised_endpoint",
            "targets",
        },
        "distributed_rollout_rejected",
    )
    participants = row["participant_embodiment_ids"]
    successor = _closed(
        body["successor_manifest"],
        {
            "schema",
            "being_ref",
            "control_head",
            "revision",
            "history_binding_id",
            "embodiments",
        },
        "distributed_rollout_rejected",
    )
    embodiments = successor["embodiments"]
    if not isinstance(embodiments, list):
        raise DistributedRebirthError("distributed_rollout_rejected")
    try:
        expected_participants = sorted(
            embodiment["embodiment_id"]
            for embodiment in embodiments
            if embodiment["status"] == "active"
            and embodiment["embodiment_id"] != origin["embodiment_id"]
        )
    except (KeyError, TypeError) as exception:
        raise DistributedRebirthError("distributed_rollout_rejected") from exception
    profile_targets = profile["targets"]
    if not isinstance(profile_targets, list):
        raise DistributedRebirthError("distributed_rollout_rejected")
    try:
        profile_participants = [item["embodiment_id"] for item in profile_targets]
        profile_shape_valid = all(
            isinstance(item, dict)
            and set(item) == {"embodiment_id", "endpoint", "timeout_ms"}
            and isinstance(item["endpoint"], str)
            and isinstance(item["timeout_ms"], int)
            and not isinstance(item["timeout_ms"], bool)
            and 1 <= item["timeout_ms"] <= 30_000
            for item in profile_targets
        )
    except (KeyError, TypeError) as exception:
        raise DistributedRebirthError("distributed_rollout_rejected") from exception
    if (
        activation["schema"] != "dm.operator.embodiment-activation/v1"
        or row["matrix_contract_commit"] != MATRIX_CONTRACT_COMMIT
        or row["activation_id"] != activation["activation_id"]
        or row["request_id"] != body["request_id"]
        or row["previous_manifest_hash"] != body["previous_manifest_hash"]
        or row["successor_manifest_hash"] != _sha(successor)
        or target
        != {
            "being_ref": body["being_ref"],
            **dict(origin),
            "advertised_endpoint": profile["advertised_endpoint"],
        }
        or not isinstance(participants, list)
        or participants != expected_participants
        or len(participants) != len(set(participants))
        or profile["schema"] != "dm.operator.rebirth-target-profile/v1"
        or profile["body_ref"] != origin["body_ref"]
        or profile["principal_id"] != origin["principal_id"]
        or profile_participants != expected_participants
        or not profile_shape_valid
    ):
        raise DistributedRebirthError("distributed_rollout_rejected")
    for item in (
        row["request_id"],
        row["activation_id"],
        target["being_ref"],
        target["body_ref"],
        target["embodiment_id"],
        target["incarnation_id"],
        target["principal_id"],
        target["advertised_endpoint"],
        *participants,
    ):
        _bounded(item, "distributed_rollout_rejected")
    _hex_hash(row["previous_manifest_hash"], "distributed_rollout_rejected")
    _hex_hash(row["successor_manifest_hash"], "distributed_rollout_rejected")
    _hex_hash(row["target_runtime_sha256"], "distributed_rollout_rejected")
    return canonical


def create_rollout_bundle(
    package_dir: str | Path, output_path: str | Path | None = None
) -> dict[str, Any]:
    """Derive the public rollout from a target-only activated package."""

    package = _owner_directory(Path(package_dir))
    receipt = _read_json(package / "receipt.json")
    request = _read_json(package / "request.json")
    activation = _read_json(package / "activation.json")
    profile = _read_json(package / "target-profile.json")
    runtime = _read_json(_owner_directory(package / "runtime") / "runtime.json")
    try:
        authority = _matrix_api()["operator_rebirth"].authority_from_runtime_bundle(
            runtime
        )
        origin = dict(runtime["local_origin"])
    except Exception as exception:
        raise DistributedRebirthError("distributed_package_rejected") from exception
    target_id = origin.get("embodiment_id")
    participants = sorted(
        embodiment["embodiment_id"]
        for embodiment in authority.manifest.value["embodiments"]
        if embodiment["status"] == "active" and embodiment["embodiment_id"] != target_id
    )
    if (
        receipt.get("schema") != "dm.operator.rebirth-runtime-receipt/v1"
        or receipt.get("request_id") != request.get("request_id")
        or receipt.get("activation_id") != activation.get("activation_id")
        or receipt.get("origin") != origin
        or receipt.get("successor_manifest_hash") != authority.manifest.digest
        or receipt.get("runtime_sha256") != _sha(runtime)
        or profile.get("schema") != "dm.operator.rebirth-target-profile/v1"
    ):
        raise DistributedRebirthError("distributed_package_rejected")
    body: dict[str, Any] = {
        "schema": ROLLOUT_SCHEMA,
        "matrix_contract_commit": MATRIX_CONTRACT_COMMIT,
        "request_id": request["request_id"],
        "activation_id": activation["activation_id"],
        "previous_manifest_hash": receipt["previous_manifest_hash"],
        "successor_manifest_hash": receipt["successor_manifest_hash"],
        "target_runtime_sha256": receipt["runtime_sha256"],
        "target": {
            "being_ref": authority.manifest.being_ref,
            **origin,
            "advertised_endpoint": profile["advertised_endpoint"],
        },
        "participant_embodiment_ids": participants,
        "activation": activation,
        "target_profile": profile,
    }
    rollout = validate_rollout({**body, "rollout_id": _content_id(body)})
    if output_path is not None:
        output = Path(output_path)
        _owner_directory(output.parent, create=True)
        if output.exists() or output.is_symlink():
            if _read_json(output) != rollout:
                raise DistributedRebirthError("distributed_rollout_output_conflict")
        else:
            _atomic_json(output, rollout)
    return rollout


def _load_rollout(value: Mapping[str, Any] | str | Path) -> dict[str, Any]:
    return validate_rollout(
        _read_json(Path(value)) if isinstance(value, (str, Path)) else value
    )


def _record_for_peer(
    journal: OperationJournal, rollout: Mapping[str, Any], embodiment_id: str
) -> dict[str, Any] | None:
    return journal.latest_for_target(
        f"distributed-rebirth:{rollout['rollout_id']}:{embodiment_id}"
    )


def apply_peer_rollout(
    state_dir: str | Path,
    rollout_value: Mapping[str, Any] | str | Path,
    embodiment_id: str,
    *,
    actor: str = "clusterctl-distributed-rebirth",
) -> dict[str, Any]:
    """Apply one successor locally and leave an open restart-required journal."""

    state = _owner_directory(Path(state_dir), create=True)
    rollout = _load_rollout(rollout_value)
    if embodiment_id not in rollout["participant_embodiment_ids"]:
        raise DistributedRebirthError("distributed_peer_not_participant")
    root = _owner_directory(matrix_root(state, embodiment_id))
    bundle_path = root / "runtime.json"
    journal = OperationJournal(state)
    target = f"distributed-rebirth:{rollout['rollout_id']}:{embodiment_id}"
    with acquire(state, embodiment_id, "distributed-rebirth"):
        bundle = _read_json(bundle_path)
        origin = bundle.get("local_origin")
        if not isinstance(origin, dict) or origin.get("embodiment_id") != embodiment_id:
            raise DistributedRebirthError("distributed_peer_origin_mismatch")
        intent = {
            "schema": "dm.cluster.distributed-rebirth-peer-intent/v1",
            "rollout_id": rollout["rollout_id"],
            "embodiment_id": embodiment_id,
            "incarnation_id": origin.get("incarnation_id"),
            "previous_manifest_hash": rollout["previous_manifest_hash"],
            "successor_manifest_hash": rollout["successor_manifest_hash"],
            "matrix_contract_commit": MATRIX_CONTRACT_COMMIT,
        }
        record = _record_for_peer(journal, rollout, embodiment_id)
        if record is None:
            record = journal.plan(
                operation="distributed-rebirth-peer",
                target=target,
                idempotency_key=f"{rollout['rollout_id']}:{embodiment_id}",
                intent=intent,
                expected_precondition={
                    "manifest_hash": rollout["previous_manifest_hash"]
                },
                intended_transition={
                    "manifest_hash": rollout["successor_manifest_hash"],
                    "restart_required": True,
                },
                audit_identity={"actor": actor, "target": embodiment_id},
            )
        elif (
            record["operation"] != "distributed-rebirth-peer"
            or record["intent"] != intent
        ):
            raise DistributedRebirthError("distributed_peer_journal_conflict")
        if record["state"] == "completed":
            return {
                "schema": APPLICATION_SCHEMA,
                "rollout_id": rollout["rollout_id"],
                "embodiment_id": embodiment_id,
                "operation_id": record["operation_id"],
                "state": "already-acknowledged",
            }
        if record["state"] == "planned":
            record = journal.advance(record["operation_id"], "runtime-dispatching")
        try:
            authority = _matrix_api()["operator_rebirth"].authority_from_runtime_bundle(
                bundle
            )
            if authority.manifest.digest == rollout["previous_manifest_hash"]:
                bundle = _matrix_api()[
                    "operator_rebirth"
                ].apply_activation_to_runtime_bundle(
                    bundle,
                    rollout["activation"],
                    authority,
                    target_endpoint=rollout["target"]["advertised_endpoint"],
                )
                _atomic_json(bundle_path, bundle)
            successor = _matrix_api()["operator_rebirth"].authority_from_runtime_bundle(
                bundle
            )
        except Exception as exception:
            raise DistributedRebirthError(
                "distributed_peer_update_rejected"
            ) from exception
        if successor.manifest.digest != rollout["successor_manifest_hash"]:
            raise DistributedRebirthError("distributed_peer_manifest_mismatch")
        if record["state"] == "runtime-dispatching":
            record = journal.advance(
                record["operation_id"],
                "runtime-applied",
                runtime_observation={
                    "runtime_sha256": _sha(bundle),
                    "successor_manifest_hash": successor.manifest.digest,
                },
            )
        if record["state"] != "runtime-applied":
            raise DistributedRebirthError("distributed_peer_journal_conflict")
        return {
            "schema": APPLICATION_SCHEMA,
            "rollout_id": rollout["rollout_id"],
            "embodiment_id": embodiment_id,
            "operation_id": record["operation_id"],
            "state": "restart-required",
        }


def _response(call: Any, code: str) -> dict[str, Any]:
    try:
        response = call()[1]
    except Exception as exception:
        raise DistributedRebirthError(code) from exception
    if response.get("ok") is not True or not isinstance(response.get("result"), dict):
        raise DistributedRebirthError(code)
    return response["result"]


def acknowledge_peer_rollout(
    state_dir: str | Path,
    rollout_value: Mapping[str, Any] | str | Path,
    embodiment_id: str,
    *,
    actor: str = "clusterctl-distributed-rebirth",
) -> dict[str, Any]:
    """Authenticate the restarted local daemon and emit one exact acknowledgement."""

    state = _owner_directory(Path(state_dir), create=True)
    rollout = _load_rollout(rollout_value)
    journal = OperationJournal(state)
    with acquire(state, embodiment_id, "distributed-rebirth"):
        record = _record_for_peer(journal, rollout, embodiment_id)
        if record is None or record["operation"] != "distributed-rebirth-peer":
            raise DistributedRebirthError("distributed_peer_application_missing")
        if record["state"] == "completed" and isinstance(record["result"], dict):
            return record["result"]
        if record["state"] != "runtime-applied":
            raise DistributedRebirthError("distributed_peer_restart_not_ready")
        bundle = _read_json(matrix_root(state, embodiment_id) / "runtime.json")
        origin = bundle.get("local_origin")
        client = matrix_client(state, embodiment_id)
        status = _response(client.runtime_status, "distributed_peer_status_rejected")
        me = _response(client.scope_me, "distributed_peer_me_rejected")
        we = _response(client.scope_we, "distributed_peer_we_rejected")
        active_values: list[str] = []
        for item in we.get("embodiments", []):
            if isinstance(item, dict) and item.get("manifest_status") == "active":
                active_id = item.get("embodiment_id")
                if not isinstance(active_id, str):
                    raise DistributedRebirthError("distributed_peer_readiness_mismatch")
                active_values.append(active_id)
        active = sorted(active_values)
        expected_active = sorted(
            [*rollout["participant_embodiment_ids"], rollout["target"]["embodiment_id"]]
        )
        if (
            not isinstance(origin, dict)
            or origin.get("embodiment_id") != embodiment_id
            or origin.get("incarnation_id") != record["intent"]["incarnation_id"]
            or status.get("integrity") != "ok"
            or status.get("manifest_hash") != rollout["successor_manifest_hash"]
            or status.get("local_origin") != origin
            or me.get("origin") != origin
            or me.get("body", {}).get("state") != "running"
            or active != expected_active
        ):
            raise DistributedRebirthError("distributed_peer_readiness_mismatch")
        observation = {
            "integrity": "ok",
            "origin": origin,
            "successor_manifest_hash": status["manifest_hash"],
            "active_embodiment_ids": active,
            "runtime_sha256": _sha(bundle),
        }
        record = journal.advance(
            record["operation_id"], "logical-committed", logical_observation=observation
        )
        audit.append_event(
            state,
            actor=actor,
            action="distributed-rebirth-peer-ack",
            target=embodiment_id,
            result="ok",
            detail={
                "rollout_id": rollout["rollout_id"],
                "successor_manifest_hash": rollout["successor_manifest_hash"],
            },
            idempotency_key=f"{rollout['rollout_id']}:{embodiment_id}",
            event_id=record["audit_event_id"],
        )
        record = journal.advance(record["operation_id"], "audited")
        result = {
            "schema": ACK_SCHEMA,
            "rollout_id": rollout["rollout_id"],
            "embodiment_id": embodiment_id,
            "incarnation_id": origin["incarnation_id"],
            "successor_manifest_hash": rollout["successor_manifest_hash"],
            "runtime_sha256": observation["runtime_sha256"],
            "operation_id": record["operation_id"],
            "audit_event_id": record["audit_event_id"],
            "state": "completed",
        }
        journal.advance(record["operation_id"], "completed", result=result)
        return result


def install_distributed_target(
    state_dir: str | Path,
    package_dir: str | Path,
    rollout_value: Mapping[str, Any] | str | Path,
    *,
    idempotency_key: str,
    actor: str = "clusterctl-distributed-rebirth",
) -> dict[str, Any]:
    """Install target custody without importing any predecessor runtime root."""

    state = _owner_directory(Path(state_dir), create=True)
    package = _owner_directory(Path(package_dir))
    rollout = _load_rollout(rollout_value)
    if create_rollout_bundle(package) != rollout:
        raise DistributedRebirthError("distributed_target_package_mismatch")
    runtime_source = _owner_directory(package / "runtime")
    client_source = _owner_directory(package / "host-client")
    target = rollout["target"]
    embodiment_id = target["embodiment_id"]
    journal_target = f"rebirth:{target['being_ref']}:{rollout['activation_id']}"
    journal = OperationJournal(state)
    intent = {
        "schema": "dm.cluster.distributed-rebirth-target-intent/v1",
        "rollout_id": rollout["rollout_id"],
        "activation_id": rollout["activation_id"],
        "target_embodiment_id": embodiment_id,
        "successor_manifest_hash": rollout["successor_manifest_hash"],
        "participant_embodiment_ids": rollout["participant_embodiment_ids"],
        "matrix_contract_commit": MATRIX_CONTRACT_COMMIT,
    }
    with acquire(state, embodiment_id, "distributed-rebirth-target"):
        record = journal.latest_for_target(journal_target)
        if record is None:
            record = journal.plan(
                operation="rebirth-install",
                target=journal_target,
                idempotency_key=idempotency_key,
                intent=intent,
                expected_precondition={"target_absent_or_exact": True},
                intended_transition={
                    "successor_manifest_hash": rollout["successor_manifest_hash"],
                    "target_status": "stopped-admission-required",
                },
                audit_identity={"actor": actor, "target": embodiment_id},
            )
        elif record["operation"] != "rebirth-install" or record["intent"] != intent:
            raise DistributedRebirthError("distributed_target_journal_conflict")
        if record["state"] == "completed" and isinstance(record["result"], dict):
            return record["result"]
        if record["state"] == "planned":
            record = journal.advance(record["operation_id"], "runtime-dispatching")
        target_manifest = _install_directory(
            runtime_source, matrix_root(state, embodiment_id)
        )
        client_manifest = _install_directory(
            client_source,
            matrix_client_root(state, embodiment_id),
        )
        if record["state"] == "runtime-dispatching":
            record = journal.advance(
                record["operation_id"],
                "runtime-applied",
                runtime_observation={
                    "target_files": target_manifest,
                    "client_files": client_manifest,
                    "target_runtime_sha256": rollout["target_runtime_sha256"],
                },
            )
        registry = Registry(state)
        registered = registry.load()["embodiments"].get(embodiment_id)
        if registered is None:
            registered = registry.register(
                body_ref=target["body_ref"], embodiment_id=embodiment_id
            )
        if (
            registered.get("body_ref") != target["body_ref"]
            or registered.get("status") != "stopped"
            or registered.get("current_incarnation_id") is not None
        ):
            raise DistributedRebirthError("distributed_target_registry_conflict")
        if record["state"] == "runtime-applied":
            record = journal.advance(
                record["operation_id"],
                "logical-committed",
                logical_observation={
                    "embodiment_id": embodiment_id,
                    "status": "stopped-admission-required",
                    "rollout_id": rollout["rollout_id"],
                },
            )
        audit.append_event(
            state,
            actor=actor,
            action="distributed-rebirth-target-install",
            target=embodiment_id,
            result="ok",
            detail={
                "rollout_id": rollout["rollout_id"],
                "successor_manifest_hash": rollout["successor_manifest_hash"],
                "participant_count": len(rollout["participant_embodiment_ids"]),
            },
            idempotency_key=idempotency_key,
            event_id=record["audit_event_id"],
        )
        if record["state"] == "logical-committed":
            record = journal.advance(record["operation_id"], "audited")
        result = {
            "schema": RESULT_SCHEMA,
            "operation_id": record["operation_id"],
            "request_id": rollout["request_id"],
            "activation_id": rollout["activation_id"],
            "being_ref": target["being_ref"],
            "embodiment_id": embodiment_id,
            "incarnation_id": target["incarnation_id"],
            "successor_manifest_hash": rollout["successor_manifest_hash"],
            "peer_bundle_sha256": {},
            "rollout_id": rollout["rollout_id"],
            "participant_embodiment_ids": rollout["participant_embodiment_ids"],
            "admission_required": True,
            "state": "installed-stopped",
        }
        if record["state"] == "audited":
            record = journal.advance(record["operation_id"], "completed", result=result)
        if record["state"] != "completed" or record["result"] != result:
            raise DistributedRebirthError("distributed_target_result_conflict")
        return result


def _validate_acknowledgement(
    value: Mapping[str, Any], rollout: Mapping[str, Any]
) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "schema",
            "rollout_id",
            "embodiment_id",
            "incarnation_id",
            "successor_manifest_hash",
            "runtime_sha256",
            "operation_id",
            "audit_event_id",
            "state",
        },
        "distributed_ack_rejected",
    )
    participant = row["embodiment_id"]
    expected_incarnations = {
        item["embodiment_id"]: item["incarnation_id"]
        for item in rollout["activation"]["body"]["successor_manifest"]["embodiments"]
        if item["embodiment_id"] in rollout["participant_embodiment_ids"]
    }
    if (
        row["schema"] != ACK_SCHEMA
        or row["rollout_id"] != rollout["rollout_id"]
        or participant not in rollout["participant_embodiment_ids"]
        or row["incarnation_id"] != expected_incarnations.get(participant)
        or row["successor_manifest_hash"] != rollout["successor_manifest_hash"]
        or row["state"] != "completed"
    ):
        raise DistributedRebirthError("distributed_ack_rejected")
    _hex_hash(row["runtime_sha256"], "distributed_ack_rejected")
    for field in ("operation_id", "audit_event_id"):
        _bounded(row[field], "distributed_ack_rejected")
    return dict(row)


def _admission_path(state: Path, rollout_id: str) -> Path:
    name = hashlib.sha256(rollout_id.encode()).hexdigest() + ".json"
    return state / "distributed-rebirth-admissions" / name


def _admission_id(value: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        b"dm.cluster.distributed-rebirth-admission/v1\0" + canonical_bytes(dict(value))
    ).digest()
    return ADMISSION_ID_PREFIX + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def record_target_admission(
    state_dir: str | Path,
    rollout_value: Mapping[str, Any] | str | Path,
    acknowledgements: Sequence[Mapping[str, Any] | str | Path],
) -> dict[str, Any]:
    """Persist the exact all-predecessor gate consumed by the H8 supervisor."""

    state = _owner_directory(Path(state_dir), create=True)
    rollout = _load_rollout(rollout_value)
    unique: dict[str, dict[str, Any]] = {}
    for value in acknowledgements:
        acknowledgement = _validate_acknowledgement(
            _read_json(Path(value)) if isinstance(value, (str, Path)) else value,
            rollout,
        )
        embodiment_id = acknowledgement["embodiment_id"]
        previous = unique.get(embodiment_id)
        if previous is not None and previous != acknowledgement:
            raise DistributedRebirthError("distributed_ack_duplicate_conflict")
        unique[embodiment_id] = acknowledgement
    expected = rollout["participant_embodiment_ids"]
    if sorted(unique) != expected:
        raise DistributedRebirthError("distributed_ack_set_incomplete")
    body = {
        "schema": ADMISSION_SCHEMA,
        "rollout": rollout,
        "acknowledgements": [unique[item] for item in expected],
    }
    admission_id = _admission_id(body)
    admission = {**body, "admission_id": admission_id}
    path = _admission_path(state, rollout["rollout_id"])
    _owner_directory(path.parent, create=True)
    if path.exists() or path.is_symlink():
        if _read_json(path) != admission:
            raise DistributedRebirthError("distributed_admission_conflict")
    else:
        _atomic_json(path, admission)
    audit.append_event(
        state,
        actor="clusterctl-distributed-rebirth",
        action="distributed-rebirth-target-admit",
        target=rollout["target"]["embodiment_id"],
        result="ok",
        detail={
            "admission_id": admission["admission_id"],
            "rollout_id": rollout["rollout_id"],
            "participant_count": len(expected),
        },
        idempotency_key=admission_id,
        event_id=str(uuid.uuid5(uuid.NAMESPACE_URL, admission_id)),
    )
    return admission


def require_target_admission(
    state_dir: str | Path,
    rollout_id: str,
    participant_embodiment_ids: Sequence[str],
    successor_manifest_hash: str,
) -> dict[str, Any]:
    """Fail closed unless an exact durable admission exists for this target."""

    state = _owner_directory(Path(state_dir))
    try:
        admission = _read_json(_admission_path(state, rollout_id))
        row = _closed(
            admission,
            {"schema", "admission_id", "rollout", "acknowledgements"},
            "distributed_admission_rejected",
        )
        if row["schema"] != ADMISSION_SCHEMA:
            raise DistributedRebirthError("distributed_admission_rejected")
        body = {key: value for key, value in row.items() if key != "admission_id"}
        if row["admission_id"] != _admission_id(body):
            raise DistributedRebirthError("distributed_admission_rejected")
        rollout = validate_rollout(row["rollout"])
        if (
            rollout["rollout_id"] != rollout_id
            or rollout["participant_embodiment_ids"] != list(participant_embodiment_ids)
            or rollout["successor_manifest_hash"] != successor_manifest_hash
            or record_target_admission(state, rollout, row["acknowledgements"])
            != admission
        ):
            raise DistributedRebirthError("distributed_admission_rejected")
        return dict(row)
    except DistributedRebirthError:
        raise
    except Exception as exception:
        raise DistributedRebirthError("distributed_admission_missing") from exception


__all__ = [
    "ACK_SCHEMA",
    "ADMISSION_SCHEMA",
    "APPLICATION_SCHEMA",
    "ROLLOUT_SCHEMA",
    "DistributedRebirthError",
    "acknowledge_peer_rollout",
    "apply_peer_rollout",
    "create_rollout_bundle",
    "install_distributed_target",
    "record_target_admission",
    "require_target_admission",
    "validate_rollout",
]
