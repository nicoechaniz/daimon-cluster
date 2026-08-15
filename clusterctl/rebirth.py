"""Journaled host installation for one Matrix-authorized fresh embodiment."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from . import audit
from .embodiments import Registry
from .locks import acquire_many
from .matrix_host import _matrix_api, matrix_client_root, matrix_root
from .matrix_host import MATRIX_CONTRACT_COMMIT
from .operation_journal import JournalConflict, OperationJournal, canonical_bytes

INSTALL_SCHEMA = "dm.cluster.rebirth-install/v1"
RESULT_SCHEMA = "dm.cluster.rebirth-result/v1"
_MUTATION_BOUNDARY_HOOK: Callable[[str, Mapping[str, Any]], None] | None = None


class RebirthInstallError(RuntimeError):
    """Stable refusal at the Cluster-owned installation boundary."""


def _boundary(name: str, record: Mapping[str, Any]) -> None:
    hook = _MUTATION_BOUNDARY_HOOK
    if hook is not None:
        hook(name, record)


def _owner_directory(path: Path, *, create: bool = False) -> Path:
    absolute = Path(os.path.abspath(path))
    if create:
        absolute.mkdir(parents=True, mode=0o700, exist_ok=True)
        absolute.chmod(0o700)
    try:
        info = absolute.lstat()
    except FileNotFoundError as exception:
        raise RebirthInstallError("rebirth_directory_missing") from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RebirthInstallError("rebirth_directory_not_owner_only")
    return absolute


def _read_json(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 1 <= info.st_size <= 16 * 1024 * 1024
        ):
            raise RebirthInstallError("rebirth_artifact_rejected")
        raw = path.read_bytes()
        value = json.loads(raw)
        if not isinstance(value, dict) or canonical_bytes(value) != raw.rstrip(b"\n"):
            raise RebirthInstallError("rebirth_artifact_rejected")
        return value
    except RebirthInstallError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise RebirthInstallError("rebirth_artifact_rejected") from exception


def _sha(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(dict(value))).hexdigest()


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.rebirth-tmp")
    if temporary.exists() or temporary.is_symlink():
        raise RebirthInstallError("rebirth_staging_collision")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        raw = canonical_bytes(dict(value))
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _directory_manifest(path: Path) -> dict[str, str]:
    root = _owner_directory(path)
    result: dict[str, str] = {}
    for item in sorted(root.iterdir(), key=lambda candidate: candidate.name):
        info = item.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise RebirthInstallError("rebirth_package_file_rejected")
        result[item.name] = hashlib.sha256(item.read_bytes()).hexdigest()
    if not result:
        raise RebirthInstallError("rebirth_package_empty")
    return result


def _install_directory(source: Path, target: Path) -> dict[str, str]:
    expected = _directory_manifest(source)
    if target.exists() or target.is_symlink():
        if _directory_manifest(target) != expected:
            raise RebirthInstallError("rebirth_installation_conflict")
        return expected
    parent = _owner_directory(target.parent, create=True)
    staging = parent / f".{target.name}.rebirth-install"
    if staging.exists() or staging.is_symlink():
        raise RebirthInstallError("rebirth_staging_collision")
    staging.mkdir(mode=0o700)
    try:
        for item in source.iterdir():
            destination = staging / item.name
            shutil.copyfile(item, destination)
            destination.chmod(0o600)
        descriptor = os.open(staging, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(staging, target)
        descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return expected


def _existing_result(
    journal: OperationJournal,
    idempotency_key: str,
    intent_sha256: str,
    target: str,
) -> dict[str, Any] | None:
    matches = {
        record["operation_id"]: record
        for record in (
            journal.latest_for_idempotency_key(idempotency_key),
            journal.latest_for_target(target),
        )
        if record is not None
    }
    for record in matches.values():
        if record["operation"] != "rebirth-install":
            raise JournalConflict("idempotency identity has different operation")
        if record["intent_hash"] != intent_sha256:
            raise JournalConflict("idempotency identity has different rebirth bytes")
        if record["state"] == "completed" and isinstance(record["result"], dict):
            return record["result"]
        return None
    return None


def install_rebirth_package(
    state_dir: str | Path,
    package_dir: str | Path,
    peer_roots: Mapping[str, str | Path],
    *,
    idempotency_key: str,
    actor: str = "clusterctl-rebirth",
) -> dict[str, Any]:
    """Install the target and forward-update every existing peer exactly once."""

    state = _owner_directory(Path(state_dir), create=True)
    package = _owner_directory(Path(package_dir))
    runtime_source = _owner_directory(package / "runtime")
    client_source = _owner_directory(package / "host-client")
    receipt = _read_json(package / "receipt.json")
    request = _read_json(package / "request.json")
    activation = _read_json(package / "activation.json")
    profile = _read_json(package / "target-profile.json")
    target_bundle = _read_json(runtime_source / "runtime.json")
    if receipt.get("schema") != "dm.operator.rebirth-runtime-receipt/v1":
        raise RebirthInstallError("rebirth_receipt_rejected")
    api = _matrix_api()["operator_rebirth"]
    try:
        successor = api.authority_from_runtime_bundle(target_bundle)
    except Exception as exception:
        raise RebirthInstallError("rebirth_target_runtime_rejected") from exception
    origin = receipt.get("origin")
    if (
        not isinstance(origin, dict)
        or set(origin)
        != {"body_ref", "embodiment_id", "incarnation_id", "principal_id"}
        or target_bundle.get("local_origin") != origin
        or receipt.get("request_id") != request.get("request_id")
        or receipt.get("activation_id") != activation.get("activation_id")
        or receipt.get("successor_manifest_hash") != successor.manifest.digest
        or receipt.get("runtime_sha256") != _sha(target_bundle)
        or receipt.get("empty_writable_state") is not True
        or profile.get("schema") != "dm.operator.rebirth-target-profile/v1"
    ):
        raise RebirthInstallError("rebirth_receipt_rejected")
    target_id = origin["embodiment_id"]
    active_old = {
        row["embodiment_id"]
        for row in successor.manifest.value["embodiments"]
        if row["status"] == "active" and row["embodiment_id"] != target_id
    }
    if set(peer_roots) != active_old:
        raise RebirthInstallError("rebirth_peer_set_mismatch")
    peer_bundles: dict[str, tuple[Path, dict[str, Any], Any | None]] = {}
    previous_hash = receipt.get("previous_manifest_hash")
    if not isinstance(previous_hash, str):
        raise RebirthInstallError("rebirth_receipt_rejected")
    for embodiment_id, root_value in sorted(peer_roots.items()):
        root = _owner_directory(Path(root_value))
        bundle_path = root / "runtime.json"
        bundle = _read_json(bundle_path)
        try:
            authority = api.authority_from_runtime_bundle(bundle)
        except Exception as exception:
            raise RebirthInstallError("rebirth_peer_runtime_rejected") from exception
        if authority.manifest.digest not in {
            previous_hash,
            successor.manifest.digest,
        }:
            raise RebirthInstallError("rebirth_peer_manifest_mismatch")
        if bundle.get("local_origin", {}).get("embodiment_id") != embodiment_id:
            raise RebirthInstallError("rebirth_peer_origin_mismatch")
        peer_bundles[embodiment_id] = (
            bundle_path,
            bundle,
            authority if authority.manifest.digest == previous_hash else None,
        )

    target_endpoint = profile.get("advertised_endpoint")
    if not isinstance(target_endpoint, str):
        raise RebirthInstallError("rebirth_target_endpoint_rejected")
    intent = {
        "schema": INSTALL_SCHEMA,
        "request_id": request["request_id"],
        "activation_id": activation["activation_id"],
        "target_embodiment_id": target_id,
        "body_ref": origin["body_ref"],
        "previous_manifest_hash": previous_hash,
        "successor_manifest_hash": successor.manifest.digest,
        "package_receipt_sha256": _sha(receipt),
        "target_endpoint_sha256": hashlib.sha256(target_endpoint.encode()).hexdigest(),
        "peer_embodiment_ids": sorted(peer_roots),
        "runtime_call": {
            "operation": "install-additional-embodiment",
            "matrix_contract_commit": MATRIX_CONTRACT_COMMIT,
        },
    }
    journal = OperationJournal(state)
    intent_sha256 = hashlib.sha256(
        canonical_bytes({"schema": "cluster-operation-intent/v1", **intent})
    ).hexdigest()
    journal_target = (
        f"rebirth:{successor.manifest.being_ref}:{activation['activation_id']}"
    )
    replay = _existing_result(journal, idempotency_key, intent_sha256, journal_target)
    if replay is not None:
        return replay
    lock_requests = [(target_id, "rebirth-install")]
    lock_requests.extend(
        (embodiment_id, "rebirth-peer-update") for embodiment_id in peer_roots
    )
    with acquire_many(state, lock_requests):
        replay = _existing_result(
            journal, idempotency_key, intent_sha256, journal_target
        )
        if replay is not None:
            return replay
        record = journal.plan(
            operation="rebirth-install",
            target=journal_target,
            idempotency_key=idempotency_key,
            intent=intent,
            expected_precondition={
                "previous_manifest_hash": previous_hash,
                "target_absent_or_exact": True,
            },
            intended_transition={
                "successor_manifest_hash": successor.manifest.digest,
                "target_status": "stopped",
            },
            audit_identity={"actor": actor, "target": target_id},
        )
        _boundary("after-plan", record)
        if record["state"] == "planned":
            record = journal.advance(record["operation_id"], "runtime-dispatching")
        _boundary("after-runtime-dispatch", record)
        target_manifest = _install_directory(
            runtime_source, matrix_root(state, target_id)
        )
        client_manifest = _install_directory(
            client_source, matrix_client_root(state, target_id)
        )
        _boundary("after-target-install", record)
        updated_peers: dict[str, str] = {}
        for embodiment_id, (bundle_path, bundle, authority) in peer_bundles.items():
            if authority is None:
                updated = bundle
            else:
                try:
                    updated = api.apply_activation_to_runtime_bundle(
                        bundle,
                        activation,
                        authority,
                        target_endpoint=target_endpoint,
                    )
                except Exception as exception:
                    raise RebirthInstallError(
                        "rebirth_peer_update_rejected"
                    ) from exception
                _atomic_json(bundle_path, updated)
            updated_peers[embodiment_id] = _sha(updated)
            _boundary(f"after-peer-update:{embodiment_id}", record)
        runtime_observation = {
            "target_files": target_manifest,
            "client_files": client_manifest,
            "peer_bundle_sha256": updated_peers,
            "successor_manifest_hash": successor.manifest.digest,
        }
        if record["state"] == "runtime-dispatching":
            record = journal.advance(
                record["operation_id"],
                "runtime-applied",
                runtime_observation=runtime_observation,
            )
        _boundary("after-runtime-observation", record)
        registry = Registry(state)
        registered = registry.load()["embodiments"].get(target_id)
        if registered is None:
            registered = registry.register(
                body_ref=origin["body_ref"], embodiment_id=target_id
            )
        if (
            registered.get("body_ref") != origin["body_ref"]
            or registered.get("status") != "stopped"
            or registered.get("current_incarnation_id") is not None
        ):
            raise RebirthInstallError("rebirth_registry_conflict")
        if record["state"] == "runtime-applied":
            record = journal.advance(
                record["operation_id"],
                "logical-committed",
                logical_observation={
                    "embodiment_id": target_id,
                    "body_ref": origin["body_ref"],
                    "status": "stopped",
                },
            )
        _boundary("after-registry", record)
        detail = {
            "activation_id": activation["activation_id"],
            "successor_manifest_hash": successor.manifest.digest,
            "peer_count": len(updated_peers),
            "target_runtime_sha256": receipt["runtime_sha256"],
        }
        audit.append_event(
            state,
            actor=actor,
            action="rebirth-install",
            target=target_id,
            result="ok",
            detail=detail,
            idempotency_key=idempotency_key,
            event_id=record["audit_event_id"],
        )
        if record["state"] == "logical-committed":
            record = journal.advance(record["operation_id"], "audited")
        _boundary("after-audit", record)
        result = {
            "schema": RESULT_SCHEMA,
            "operation_id": record["operation_id"],
            "request_id": request["request_id"],
            "activation_id": activation["activation_id"],
            "being_ref": successor.manifest.being_ref,
            "embodiment_id": target_id,
            "incarnation_id": origin["incarnation_id"],
            "successor_manifest_hash": successor.manifest.digest,
            "peer_bundle_sha256": updated_peers,
            "state": "installed-stopped",
        }
        if record["state"] == "audited":
            record = journal.advance(record["operation_id"], "completed", result=result)
        _boundary("after-completed", record)
        return result


__all__ = [
    "INSTALL_SCHEMA",
    "RESULT_SCHEMA",
    "RebirthInstallError",
    "install_rebirth_package",
]
