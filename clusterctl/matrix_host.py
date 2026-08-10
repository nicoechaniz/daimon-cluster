"""Cluster-owned host boundary for the pinned :mod:`daimon_matrix` runtime.

Cluster owns physical body lifecycle, the embodiment registry, resource
fences, and portable storage.  Matrix owns identity, ledger semantics, local
scope resolution, and effect receipts.  This module is the deliberately small
adapter between those authorities; it does not duplicate Matrix protocol code.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import shutil
import signal
import stat
import sys
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .embodiments import Registry, RegistryError
from .fences import FenceError, ResourceFenceStore

MATRIX_CONTRACT_COMMIT = "f0181f7117859f3f9cc4afc7dfbdaf9b06e74754"
MATRIX_ROOT_SCHEMA = "dm.cluster-matrix-root/v1"
MATRIX_SNAPSHOT_SCHEMA = "dm.cluster-matrix-snapshot/v1"
MATRIX_STATUS_SCHEMA = "dm.cluster-matrix-status/v1"
_LOCK_NAME = ".daimon-matrixd.lock"
_MAX_PASSWORD_BYTES = 4096
_MAX_BUNDLE_BYTES = 4 * 1024 * 1024
_MAX_UNIX_SOCKET_BYTES = 107
_CLUSTERD_MATRIX_METHODS = frozenset(
    {
        "runtime.status",
        "scope.me",
        "scope.we",
        "scope.we.diff",
        "scope.we.sync-plan",
    }
)


class MatrixHostError(RuntimeError):
    """Stable, disclosure-safe refusal at the Matrix hosting boundary."""


def _matrix_api() -> dict[str, Any]:
    """Load the optional, pinned dependency and reject a schema downgrade."""

    try:
        from daimon_matrix import cluster as cluster_api
        from daimon_matrix import client, daemon, runtime
    except ImportError as exception:  # base clusterctl remains usable without it
        raise MatrixHostError("daimon_matrix_dependency_unavailable") from exception
    try:
        distribution = importlib.metadata.distribution("daimon-matrix")
        direct_url = json.loads(distribution.read_text("direct_url.json") or "null")
        installed_commit = direct_url["vcs_info"]["commit_id"]
    except (
        importlib.metadata.PackageNotFoundError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
    ) as exception:
        raise MatrixHostError("daimon_matrix_commit_unverifiable") from exception
    if installed_commit != MATRIX_CONTRACT_COMMIT:
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    expected = {
        "BODY_SNAPSHOT_SCHEMA": "dm.cluster-body-snapshot/v1",
        "FENCE_EVIDENCE_SCHEMA": "dm.cluster-resource-fence-evidence/v1",
        "FENCE_VERIFICATION_SCHEMA": "dm.cluster-resource-fence-verification/v1",
        "FENCE_POSITION_SCHEMA": "dm.cluster-resource-fence-position/v1",
        "EFFECT_RECEIPT_SCHEMA": "dm.cluster-effect-receipt/v1",
        "EFFECT_RECONCILIATION_SCHEMA": "dm.cluster-effect-reconciliation/v1",
    }
    if any(
        getattr(cluster_api, name, None) != value for name, value in expected.items()
    ):
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if getattr(runtime, "BUNDLE_SCHEMA", None) != "dm.runtime.bundle/v1":
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if getattr(runtime, "BUNDLE_SCHEMA_V2", None) != "dm.runtime.bundle/v2":
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if getattr(runtime, "BUNDLE_SCHEMA_V3", None) != "dm.runtime.bundle/v3":
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if getattr(runtime, "BUNDLE_SCHEMA_V4", None) != "dm.runtime.bundle/v4":
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if getattr(runtime, "BUNDLE_SCHEMA_V5", None) != "dm.runtime.bundle/v5":
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if getattr(runtime, "BUNDLE_SCHEMA_V6", None) != "dm.runtime.bundle/v6":
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if getattr(runtime, "BUNDLE_SCHEMA_V7", None) != "dm.runtime.bundle/v7":
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if getattr(client, "CLIENT_CONFIG_SCHEMA", None) != "dm.local.client-config/v1":
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if getattr(client, "CLIENT_CONFIG_SCHEMA_V2", None) != "dm.local.client-config/v2":
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    return {
        "client": client,
        "cluster": cluster_api,
        "daemon": daemon,
        "runtime": runtime,
    }


def matrix_root(state_dir: str | Path, embodiment_id: str) -> Path:
    """Return an opaque, stable per-embodiment root without leaking its ID."""

    if not isinstance(embodiment_id, str) or not embodiment_id.startswith(
        "embodiment:"
    ):
        raise MatrixHostError("invalid_embodiment_id")
    # 128 opaque bits keep roots compact enough for sockaddr_un on normal
    # /var/lib deployments while retaining collision resistance at this scale.
    key = hashlib.sha256(embodiment_id.encode("utf-8")).hexdigest()[:32]
    return Path(os.path.abspath(state_dir)) / "matrix" / key


def matrix_client_root(state_dir: str | Path, embodiment_id: str) -> Path:
    """Return the host-local clusterd capability root for one embodiment."""

    if not isinstance(embodiment_id, str) or not embodiment_id.startswith(
        "embodiment:"
    ):
        raise MatrixHostError("invalid_embodiment_id")
    key = hashlib.sha256(embodiment_id.encode("utf-8")).hexdigest()[:32]
    return Path(os.path.abspath(state_dir)) / "matrix-clients" / key


def _owner_directory(path: Path, *, create: bool = False) -> Path:
    absolute = Path(os.path.abspath(path))
    if create:
        absolute.mkdir(parents=True, mode=0o700, exist_ok=True)
        absolute.chmod(0o700)
    try:
        info = absolute.lstat()
    except FileNotFoundError as exception:
        raise MatrixHostError("matrix_root_missing") from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise MatrixHostError("matrix_root_not_owner_only")
    return absolute


def _owner_file_descriptor(path: Path) -> int:
    """Open one stable owner-only regular file without following a symlink."""

    absolute = Path(os.path.abspath(path))
    try:
        before = absolute.lstat()
    except FileNotFoundError as exception:
        raise MatrixHostError("matrix_client_material_missing") from exception
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & 0o077
    ):
        raise MatrixHostError("matrix_client_material_not_owner_only")
    try:
        descriptor = os.open(absolute, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise MatrixHostError("matrix_client_material_replaced")
        return descriptor
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


def _public_bundle(root: Path, bundle_name: str) -> dict[str, Any]:
    if (
        not isinstance(bundle_name, str)
        or not bundle_name
        or Path(bundle_name).name != bundle_name
    ):
        raise MatrixHostError("unsafe_matrix_bundle_name")
    path = root / bundle_name
    try:
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size > _MAX_BUNDLE_BYTES
        ):
            raise MatrixHostError("matrix_bundle_not_owner_only")
        value = json.loads(path.read_text(encoding="utf-8"))
    except MatrixHostError:
        raise
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exception:
        raise MatrixHostError("matrix_bundle_unreadable") from exception
    if not isinstance(value, dict) or value.get("schema") not in {
        "dm.runtime.bundle/v1",
        "dm.runtime.bundle/v2",
        "dm.runtime.bundle/v3",
        "dm.runtime.bundle/v4",
        "dm.runtime.bundle/v5",
        "dm.runtime.bundle/v6",
        "dm.runtime.bundle/v7",
    }:
        raise MatrixHostError("matrix_bundle_rejected")
    return value


def _origin(value: Any) -> dict[str, str]:
    fields = {"body_ref", "embodiment_id", "incarnation_id", "principal_id"}
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or any(
            not isinstance(value[field], str) or not value[field] for field in fields
        )
    ):
        raise MatrixHostError("matrix_origin_rejected")
    return {field: value[field] for field in sorted(fields)}


class MatrixHostAdapter:
    """Exact injected readers/verifiers for one guarded embodiment."""

    def __init__(
        self,
        state_dir: str | Path,
        embodiment_id: str,
        *,
        fence_store: ResourceFenceStore | None = None,
        clock: Any = lambda: time.time_ns() // 1_000_000,
    ) -> None:
        self.state_dir = Path(os.path.abspath(state_dir))
        self.embodiment_id = embodiment_id
        self.registry = Registry(self.state_dir)
        self.fences = fence_store or ResourceFenceStore(self.state_dir)
        self.clock = clock

    def require_origin(self, value: Mapping[str, Any]) -> dict[str, Any]:
        origin = _origin(value)
        if origin["embodiment_id"] != self.embodiment_id:
            raise MatrixHostError("matrix_embodiment_mismatch")
        try:
            record = self.registry.status(self.embodiment_id)
        except RegistryError as exception:
            raise MatrixHostError("matrix_registry_unavailable") from exception
        if (
            record.get("body_ref") != origin["body_ref"]
            or record.get("status") != "running"
            or record.get("current_incarnation_id") != origin["incarnation_id"]
        ):
            raise MatrixHostError("matrix_origin_registry_mismatch")
        return record

    def body_snapshot(
        self,
        body_ref: str,
        embodiment_id: str,
        incarnation_id: str,
        evaluated_at_ms: int | None = None,
    ) -> dict[str, Any]:
        observed_at_ms = (
            int(self.clock()) if evaluated_at_ms is None else evaluated_at_ms
        )
        if (
            isinstance(observed_at_ms, bool)
            or not isinstance(observed_at_ms, int)
            or observed_at_ms < 0
        ):
            raise MatrixHostError("matrix_evaluation_time_rejected")
        self.require_origin(
            {
                "body_ref": body_ref,
                "embodiment_id": embodiment_id,
                "incarnation_id": incarnation_id,
                "principal_id": "cluster-internal-validation",
            }
        )
        try:
            held = self.fences.current_for_holder(embodiment_id, at_ms=observed_at_ms)
        except (FenceError, OSError) as exception:
            raise MatrixHostError("resource_fence_registry_unavailable") from exception
        return {
            "schema": "dm.cluster-body-snapshot/v1",
            "body_ref": body_ref,
            "embodiment_id": embodiment_id,
            "incarnation_id": incarnation_id,
            "observed_at_ms": observed_at_ms,
            "state": "running",
            "resource_fences": [
                {"resource_ref": item["resource_ref"], "epoch": item["epoch"]}
                for item in held
            ],
        }

    def fence_evidence(self, resource_ref: str) -> dict[str, Any] | None:
        observed_at_ms = int(self.clock())
        try:
            current = self.fences.verify_current(resource_ref, at_ms=observed_at_ms)
            record = self.registry.status(self.embodiment_id)
        except (FenceError, RegistryError, OSError) as exception:
            raise MatrixHostError("resource_fence_registry_unavailable") from exception
        if current is None:
            return None
        incarnation_id = record.get("current_incarnation_id")
        if (
            record.get("status") != "running"
            or current.get("holder_embodiment_id") != self.embodiment_id
            or not isinstance(incarnation_id, str)
        ):
            return None
        matrix = _matrix_api()["cluster"]
        return matrix.create_resource_fence_evidence(
            body_ref=record["body_ref"],
            holder_embodiment_id=self.embodiment_id,
            holder_incarnation_id=incarnation_id,
            resource_ref=current["resource_ref"],
            epoch=current["epoch"],
            observed_at_ms=observed_at_ms,
            expires_at_ms=current["created_ms"] + current["ttl_s"] * 1000,
            verification_ref=self.fences.proof_ref(current),
        )

    def verify_fence(self, evidence: Mapping[str, Any], at_ms: int) -> dict[str, Any]:
        matrix = _matrix_api()["cluster"]
        try:
            current = self.fences.verify_current(
                str(evidence.get("resource_ref") or ""), at_ms=at_ms
            )
            record = self.registry.status(self.embodiment_id)
        except (FenceError, RegistryError, OSError) as exception:
            raise matrix.FenceVerificationUnavailable() from exception
        matches = bool(
            current is not None
            and record.get("status") == "running"
            and record.get("body_ref") == evidence.get("body_ref")
            and record.get("current_incarnation_id")
            == evidence.get("holder_incarnation_id")
            and current.get("holder_embodiment_id")
            == evidence.get("holder_embodiment_id")
            == self.embodiment_id
            and current.get("resource_ref") == evidence.get("resource_ref")
            and current.get("epoch") == evidence.get("epoch")
            and self.fences.proof_ref(current) == evidence.get("verification_ref")
        )
        return {
            "schema": "dm.cluster-resource-fence-verification/v1",
            "content_hash": evidence.get("content_hash"),
            "resource_ref": evidence.get("resource_ref"),
            "holder_embodiment_id": evidence.get("holder_embodiment_id"),
            "epoch": evidence.get("epoch"),
            "verified_at_ms": at_ms,
            "current": matches,
        }

    @staticmethod
    def create_effect_receipt(**fields: Any) -> dict[str, Any]:
        return _matrix_api()["cluster"].create_effect_receipt(**fields)

    def reconcile_effect(
        self,
        receipt: Mapping[str, Any],
        *,
        intent: Any,
        observed_postcondition: Mapping[str, Any] | None,
        at_ms: int | None = None,
    ) -> dict[str, Any]:
        matrix = _matrix_api()["cluster"]
        checked_at = int(self.clock()) if at_ms is None else at_ms
        position = receipt.get("resource_fence")
        evidence = None
        if isinstance(position, Mapping):
            evidence = self.fence_evidence(str(position.get("resource_ref") or ""))
        return matrix.reconcile_effect_receipt(
            receipt,
            intent=intent,
            observed_postcondition=observed_postcondition,
            at_ms=checked_at,
            current_fence_evidence=evidence,
            fence_verifier=self.verify_fence if evidence is not None else None,
        )

    def support_status(self) -> dict[str, Any]:
        return {
            "schema": MATRIX_STATUS_SCHEMA,
            "matrix_contract_commit": MATRIX_CONTRACT_COMMIT,
            "embodiment_id": self.embodiment_id,
            "resource_fences": self.fences.support_status(),
        }


def matrix_client(state_dir: str | Path, embodiment_id: str) -> Any:
    """Load clusterd's least-authority local client for a running Matrix host.

    The descriptor and 32-byte capability key live outside the portable Matrix
    root.  Snapshots therefore carry encrypted Matrix custody and ledger state,
    but never the host-local capability used by clusterd's status projection.
    """

    api = _matrix_api()
    adapter = MatrixHostAdapter(state_dir, embodiment_id)
    root = _owner_directory(matrix_root(state_dir, embodiment_id))
    bundle = _public_bundle(root, "runtime.json")
    origin = _origin(bundle.get("local_origin"))
    adapter.require_origin(origin)
    socket_name = bundle.get("socket")
    if (
        not isinstance(socket_name, str)
        or not socket_name
        or Path(socket_name).name != socket_name
        or len(os.fsencode(root / socket_name)) > _MAX_UNIX_SOCKET_BYTES
    ):
        raise MatrixHostError("matrix_socket_path_rejected")
    client_root = _owner_directory(matrix_client_root(state_dir, embodiment_id))
    key_descriptor = _owner_file_descriptor(client_root / "capability.key")
    try:
        key = api["client"].read_capability_key(key_descriptor)
    except Exception as exception:
        raise MatrixHostError("matrix_client_key_rejected") from exception
    try:
        config = api["client"].ClientConfig.load(client_root / "client.json", key)
    except Exception as exception:
        raise MatrixHostError("matrix_client_config_rejected") from exception
    if frozenset(config.capability.methods) != _CLUSTERD_MATRIX_METHODS:
        raise MatrixHostError("matrix_client_authority_rejected")
    if dict(config.expected_server) != origin:
        raise MatrixHostError("matrix_client_origin_mismatch")
    return api["client"].LocalClient(root / socket_name, config)


def matrix_client_factory(state_dir: str | Path) -> Any:
    """Build the production factory consumed by clusterd handlers."""

    absolute = Path(os.path.abspath(state_dir))

    def load(embodiment_id: str) -> Any:
        return matrix_client(absolute, embodiment_id)

    return load


def _snapshot_files(root: Path, bundle_name: str) -> tuple[dict[str, Any], list[Path]]:
    bundle = _public_bundle(root, bundle_name)
    socket_name = bundle.get("socket")
    excluded = {_LOCK_NAME, socket_name}
    files: list[Path] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if path.name in excluded or path.name.endswith((".tmp", "-wal", "-shm")):
            continue
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise MatrixHostError("matrix_snapshot_source_unsafe")
        files.append(path)
    return bundle, files


def create_portable_snapshot(
    root: str | Path, destination: str | Path, *, bundle_name: str = "runtime.json"
) -> dict[str, Any]:
    """Copy a quiesced Matrix root into a closed, hashed snapshot directory."""

    api = _matrix_api()
    source = _owner_directory(Path(root))
    target = Path(os.path.abspath(destination))
    if target.exists() or target.is_symlink():
        raise MatrixHostError("matrix_snapshot_destination_exists")
    lock_descriptor: int | None = None
    temporary = target.with_name(f".{target.name}.snapshot-{uuid.uuid4()}")
    temporary_created = False
    try:
        lock_descriptor = api["daemon"].acquire_lock(source)
        bundle, files = _snapshot_files(source, bundle_name)
        temporary.mkdir(parents=True, mode=0o700)
        temporary_created = True
        temporary.chmod(0o700)
        payload = temporary / "payload"
        payload.mkdir(mode=0o700)
        entries = []
        for path in files:
            copied = payload / path.name
            shutil.copyfile(path, copied)
            copied.chmod(0o600)
            entries.append(
                {
                    "name": path.name,
                    "sha256": hashlib.sha256(copied.read_bytes()).hexdigest(),
                    "size": copied.stat().st_size,
                }
            )
        manifest = {
            "schema": MATRIX_SNAPSHOT_SCHEMA,
            "matrix_contract_commit": MATRIX_CONTRACT_COMMIT,
            "bundle": bundle_name,
            "origin": _origin(bundle.get("local_origin")),
            "files": entries,
        }
        manifest_path = temporary / "snapshot.json"
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        manifest_path.chmod(0o600)
        os.replace(temporary, target)
        return manifest
    except BlockingIOError as exception:
        raise MatrixHostError("matrix_runtime_not_quiesced") from exception
    except BaseException:
        if temporary_created:
            shutil.rmtree(temporary, ignore_errors=True)
        raise
    finally:
        if lock_descriptor is not None:
            os.close(lock_descriptor)


def restore_portable_snapshot(
    snapshot: str | Path, destination: str | Path
) -> dict[str, Any]:
    """Verify and restore a portable snapshot to a fresh owner-only root."""

    source = _owner_directory(Path(snapshot))
    target = Path(os.path.abspath(destination))
    if target.exists() or target.is_symlink():
        raise MatrixHostError("matrix_restore_destination_exists")
    try:
        manifest = json.loads((source / "snapshot.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exception:
        raise MatrixHostError("matrix_snapshot_manifest_unreadable") from exception
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {"schema", "matrix_contract_commit", "bundle", "origin", "files"}
        or manifest.get("schema") != MATRIX_SNAPSHOT_SCHEMA
        or manifest.get("matrix_contract_commit") != MATRIX_CONTRACT_COMMIT
        or not isinstance(manifest.get("files"), list)
    ):
        raise MatrixHostError("matrix_snapshot_manifest_rejected")
    _origin(manifest.get("origin"))
    payload = _owner_directory(source / "payload")
    verified: list[tuple[Path, str]] = []
    names: set[str] = set()
    for row in manifest["files"]:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"name", "sha256", "size"}
            or not isinstance(row["name"], str)
            or Path(row["name"]).name != row["name"]
            or row["name"] in names
            or not isinstance(row["size"], int)
            or isinstance(row["size"], bool)
            or row["size"] < 0
        ):
            raise MatrixHostError("matrix_snapshot_manifest_rejected")
        path = payload / row["name"]
        try:
            info = path.lstat()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except (FileNotFoundError, OSError) as exception:
            raise MatrixHostError("matrix_snapshot_payload_unreadable") from exception
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size != row["size"]
            or digest != row["sha256"]
        ):
            raise MatrixHostError("matrix_snapshot_payload_rejected")
        names.add(row["name"])
        verified.append((path, row["name"]))
    if {path.name for path in payload.iterdir()} != names:
        raise MatrixHostError("matrix_snapshot_payload_rejected")
    temporary = target.with_name(f".{target.name}.restore-{uuid.uuid4()}")
    temporary.mkdir(parents=True, mode=0o700)
    temporary.chmod(0o700)
    try:
        for path, name in verified:
            copied = temporary / name
            shutil.copyfile(path, copied)
            copied.chmod(0o600)
        os.replace(temporary, target)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return manifest


def _password_reader(descriptor: int) -> Any:
    used = False

    def read() -> bytearray:
        nonlocal used
        if used:
            raise MatrixHostError("password_descriptor_reused")
        used = True
        try:
            value = os.read(descriptor, _MAX_PASSWORD_BYTES + 1)
        finally:
            os.close(descriptor)
        if not value or len(value) > _MAX_PASSWORD_BYTES:
            raise MatrixHostError("invalid_password_descriptor")
        return bytearray(value)

    return read


def _diagnostic(code: str) -> None:
    value = {"schema": "dm.cluster-matrix-host-diagnostic/v1", "code": code}
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--embodiment-id", required=True)
    parser.add_argument("--bundle", default="runtime.json")
    parser.add_argument("--password-fd", type=int, required=True)
    parser.add_argument("--ready-fd", type=int)
    args = parser.parse_args(argv)
    lock_descriptor: int | None = None
    stopping = threading.Event()
    try:
        api = _matrix_api()
        adapter = MatrixHostAdapter(args.state_dir, args.embodiment_id)
        root = _owner_directory(matrix_root(args.state_dir, args.embodiment_id))
        bundle = _public_bundle(root, args.bundle)
        adapter.require_origin(_origin(bundle.get("local_origin")))
        socket_name = bundle.get("socket")
        if (
            not isinstance(socket_name, str)
            or not socket_name
            or Path(socket_name).name != socket_name
            or len(os.fsencode(root / socket_name)) > _MAX_UNIX_SOCKET_BYTES
        ):
            raise MatrixHostError("matrix_socket_path_rejected")
        lock_descriptor = api["daemon"].acquire_lock(root)
        runtime = api["runtime"].load_runtime(
            root,
            args.bundle,
            _password_reader(args.password_fd),
            clock=lambda: time.time_ns() // 1_000_000,
            body_reader=adapter.body_snapshot,
        )

        def request_stop(_number: int, _frame: object) -> None:
            stopping.set()

        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        api["daemon"].serve_forever(
            runtime, stop=stopping, ready_descriptor=args.ready_fd
        )
        return 0
    except Exception as exception:  # noqa: BLE001 - one closed process boundary
        code = exception.args[0] if exception.args else "matrix_host_startup_refused"
        _diagnostic(code if isinstance(code, str) else "matrix_host_startup_refused")
        return 1
    finally:
        if lock_descriptor is not None:
            os.close(lock_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MATRIX_CONTRACT_COMMIT",
    "MATRIX_SNAPSHOT_SCHEMA",
    "MATRIX_STATUS_SCHEMA",
    "MatrixHostAdapter",
    "MatrixHostError",
    "create_portable_snapshot",
    "main",
    "matrix_client",
    "matrix_client_factory",
    "matrix_client_root",
    "matrix_root",
    "restore_portable_snapshot",
]
