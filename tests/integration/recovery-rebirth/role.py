"""Role-local helpers for the disposable recovery-rebirth host proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.runtime import load_runtime

from clusterctl.admission import (
    AdmissionAuthority,
    AdmissionClient,
    AdmissionServer,
    serve_in_thread,
)
from clusterctl.fences import Ed25519Signer, ResourceFenceStore
from clusterctl.matrix_host import create_portable_snapshot, matrix_root
from clusterctl.production_fences import create_holder_enrollment
from clusterctl.rebirth_host import (
    ADMISSION_CLIENT_SCHEMA,
    _installed_identity,
    launch_rebirth_host,
)
from clusterctl.recovery_rebirth import export_recovery_snapshot


def _document(path: Path) -> dict:
    raw = path.read_bytes()
    value = json.loads(raw)
    encoded = canonical_bytes(value) if isinstance(value, dict) else b""
    if not isinstance(value, dict) or raw not in {encoded, encoded + b"\n"}:
        raise RuntimeError("noncanonical_role_document")
    return value


def _local_object(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError("invalid_local_role_document")
    return value


def _password(path: Path) -> bytes:
    value = path.read_bytes()
    if not value or len(value) > 4096 or b"\n" in value or b"\x00" in value:
        raise RuntimeError("invalid_role_password")
    return value


def _write_new(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_absent(paths: list[Path]) -> None:
    if any(path.exists() or path.is_symlink() for path in paths):
        raise RuntimeError("foreign_role_mount_visible")


def export_bootstrap(arguments: argparse.Namespace) -> dict:
    bootstrap = arguments.bootstrap.resolve(strict=True)
    public = arguments.public.resolve(strict=True)
    root = arguments.root.resolve(strict=True)
    source = arguments.source.resolve(strict=True)
    _require_absent(arguments.require_absent)

    authority = bootstrap / "authority.json"
    receipt = bootstrap / "receipt.json"
    old_root = bootstrap / "offline/root-custody.json"
    source_runtime = bootstrap / f"runtimes/{arguments.label}"
    for document in (authority, receipt, source_runtime / "runtime.json"):
        _document(document)

    _write_new(public / "authority.json", authority.read_bytes())
    _write_new(public / "bootstrap-receipt.json", receipt.read_bytes())
    _write_new(
        public / "base-runtime.json", (source_runtime / "runtime.json").read_bytes()
    )
    _write_new(root / "old-root-custody.json", old_root.read_bytes())
    shutil.copytree(source_runtime, source / "runtime")

    return {
        "schema": "dm.recovery-disposable-role/v1",
        "role": "bootstrap-export",
        "authority_sha256": _sha256(public / "authority.json"),
        "base_runtime_sha256": _sha256(public / "base-runtime.json"),
        "foreign_mounts_absent": True,
    }


def publish_document(arguments: argparse.Namespace) -> dict:
    _require_absent(arguments.require_absent)
    source = arguments.source.resolve(strict=True)
    value = _document(source)
    _write_new(arguments.destination, canonical_bytes(value))
    return {
        "schema": "dm.recovery-disposable-role/v1",
        "role": "public-document-export",
        "sha256": _sha256(arguments.destination),
        "foreign_mounts_absent": True,
    }


def source_snapshot(arguments: argparse.Namespace) -> dict:
    _require_absent(arguments.require_absent)
    source = arguments.source.resolve(strict=True)
    snapshot = arguments.snapshot.resolve()
    now_ms = time.time_ns() // 1_000_000
    hosted = load_runtime(
        source / "runtime",
        "runtime.json",
        lambda: bytearray(_password(source / "runtime.password")),
        clock=lambda: now_ms,
    )
    old_event = hosted.service.ledger.append_local(
        kind="experience.observed",
        subject="before-disposable-recovery",
        payload={"summary": "survives isolated recovery"},
        signer=hosted.service.signer,
        occurred_at_ms=now_ms,
    )
    portable = source / "full-portable-snapshot"
    create_portable_snapshot(source / "runtime", portable)
    snapshot_receipt = export_recovery_snapshot(portable, snapshot)
    evidence = {
        "schema": "dm.recovery-disposable-source/v1",
        "event_id": old_event["event_id"],
        "source_snapshot_sha256": snapshot_receipt["source_snapshot_sha256"],
        "snapshot_sha256": snapshot_receipt["recovery_snapshot_sha256"],
        "custody_files_exported": snapshot_receipt["custody_files_exported"],
        "source_origin": hosted.service.ledger.local_origin,
        "foreign_mounts_absent": True,
    }
    _write_new(arguments.evidence, canonical_bytes(evidence))
    return evidence


def _descriptor(value: bytes) -> int:
    reader, writer = os.pipe()
    try:
        os.write(writer, value)
    finally:
        os.close(writer)
    return reader


def _provision_disposable_fence_authority(
    state: Path, embodiment_id: str
) -> tuple[AdmissionServer, threading.Thread]:
    """Provision the real verifier DB that a cluster operator normally supplies."""

    key = state / ".disposable-fence-owner.pem"
    _write_new(
        key,
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    signer = Ed25519Signer(key, "disposable-recovery-cluster-owner")
    ResourceFenceStore.production(state, signer=signer, key_id=signer.key_id)
    key.unlink()

    identity = _installed_identity(state, embodiment_id)
    admission_root = state.parent / "synthetic-admission-authority"

    def admission_signer(name: str) -> tuple[Path, Ed25519Signer]:
        path = admission_root / f"{name}.pem"
        _write_new(
            path,
            Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        return path, Ed25519Signer(path, f"synthetic-recovery-{name}")

    _authority_path, authority_signer = admission_signer("authority")
    _registrar_path, registrar = admission_signer("registrar")
    holder_path, holder = admission_signer("holder")
    authority = AdmissionAuthority(
        admission_root / "state",
        signer=authority_signer,
        holder_registrars={registrar.key_id: registrar.public_key},
    )
    socket_path = admission_root / "run/admission.sock"
    server = AdmissionServer(socket_path, authority)
    thread = serve_in_thread(server)
    origin = identity["origin"]
    client = AdmissionClient(
        socket_path,
        holder_signer=holder,
        authority_key_id=authority_signer.key_id,
        authority_public_key=authority_signer.public_key,
        being_ref=identity["being_ref"],
        body_ref=origin["body_ref"],
        embodiment_id=origin["embodiment_id"],
        incarnation_id=origin["incarnation_id"],
        activation_id=identity["activation_id"],
        credential_id=identity["credential_id"],
        manifest_hash=identity["manifest_hash"],
        lease_ttl_s=3,
    )
    client.enroll(
        create_holder_enrollment(
            registrar,
            holder_key_id=holder.key_id,
            holder_pubkey=holder.public_key,
            being_ref=identity["being_ref"],
            body_ref=origin["body_ref"],
            embodiment_id=origin["embodiment_id"],
            incarnation_id=origin["incarnation_id"],
            activation_id=identity["activation_id"],
            credential_id=identity["credential_id"],
            manifest_hash=identity["manifest_hash"],
            issued_ms=time.time_ns() // 1_000_000,
            nonce="synthetic-recovery-holder-enrollment",
        )
    )
    _write_new(
        state / "admission-client.json",
        json.dumps(
            {
                "schema": ADMISSION_CLIENT_SCHEMA,
                "socket_path": str(socket_path),
                "holder_key_path": str(holder_path),
                "holder_key_id": holder.key_id,
                "authority_key_id": authority_signer.key_id,
                "authority_public_key": authority_signer.public_key,
                "lease_ttl_s": 3,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"),
    )
    return server, thread


def verify_target(arguments: argparse.Namespace) -> dict:
    _require_absent(arguments.require_absent)
    target = arguments.target.resolve(strict=True)
    restore = _local_object(target / "restore-result.json")
    if restore.get("custody_free_transfer") is not True:
        raise RuntimeError("target_received_nonminimal_recovery_snapshot")
    source_evidence = _document(arguments.source_evidence.resolve(strict=True))
    password = _password(target / "target.password")
    embodiment_id = restore["embodiment_id"]
    runtime_root = matrix_root(target / "state", embodiment_id)
    now_ms = time.time_ns() // 1_000_000
    hosted = load_runtime(
        runtime_root,
        "runtime.json",
        lambda: bytearray(password),
        clock=lambda: now_ms,
    )
    before = hosted.service.ledger.events()
    if [row["event_id"] for row in before] != [source_evidence["event_id"]]:
        raise RuntimeError("restored_event_set_mismatch")

    admission_server, admission_thread = _provision_disposable_fence_authority(
        target / "state", embodiment_id
    )
    descriptor = _descriptor(password)
    process, started = launch_rebirth_host(target / "state", embodiment_id, descriptor)
    try:
        if started["state"] != "running-ready":
            raise RuntimeError("recovered_runtime_not_ready")
    finally:
        process.terminate()
        _stdout, stderr = process.communicate(timeout=10)
        admission_server.shutdown()
        admission_server.server_close()
        admission_thread.join(timeout=5)
        if process.returncode != 0:
            diagnostic = stderr.decode("utf-8", errors="replace")[:4096]
            raise RuntimeError(f"recovered_runtime_stop_failed:{diagnostic}")

    recovered = load_runtime(
        runtime_root,
        "runtime.json",
        lambda: bytearray(password),
        clock=lambda: now_ms + 1,
    )
    fresh = recovered.service.ledger.append_local(
        kind="experience.observed",
        subject="after-disposable-recovery",
        payload={"summary": "fresh isolated embodiment writes forward"},
        signer=recovered.service.signer,
        occurred_at_ms=now_ms + 1,
    )
    event_ids = [row["event_id"] for row in recovered.service.ledger.events()]
    if len(event_ids) != 2 or set(event_ids) != {
        source_evidence["event_id"],
        fresh["event_id"],
    }:
        raise RuntimeError("forward_event_set_mismatch")
    return {
        "schema": "dm.recovery-disposable-host-proof/v1",
        "state": "running-ready-then-stopped",
        "old_event_restored": True,
        "fresh_event_authored": True,
        "event_count": len(event_ids),
        "active_embodiment_ids": started["active_embodiment_ids"],
        "target_embodiment_id": embodiment_id,
        "foreign_mounts_absent": True,
        "network": "none",
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)

    export = commands.add_parser("export-bootstrap")
    export.add_argument("--bootstrap", type=Path, required=True)
    export.add_argument("--public", type=Path, required=True)
    export.add_argument("--root", type=Path, required=True)
    export.add_argument("--source", type=Path, required=True)
    export.add_argument("--label", required=True)
    export.add_argument("--require-absent", action="append", type=Path, default=[])
    export.set_defaults(handler=export_bootstrap)

    publish = commands.add_parser("publish-document")
    publish.add_argument("--source", type=Path, required=True)
    publish.add_argument("--destination", type=Path, required=True)
    publish.add_argument("--require-absent", action="append", type=Path, default=[])
    publish.set_defaults(handler=publish_document)

    snapshot = commands.add_parser("source-snapshot")
    snapshot.add_argument("--source", type=Path, required=True)
    snapshot.add_argument("--snapshot", type=Path, required=True)
    snapshot.add_argument("--evidence", type=Path, required=True)
    snapshot.add_argument("--require-absent", action="append", type=Path, default=[])
    snapshot.set_defaults(handler=source_snapshot)

    target = commands.add_parser("verify-target")
    target.add_argument("--target", type=Path, required=True)
    target.add_argument("--source-evidence", type=Path, required=True)
    target.add_argument("--require-absent", action="append", type=Path, default=[])
    target.set_defaults(handler=verify_target)
    return result


def main() -> int:
    arguments = parser().parse_args()
    result = arguments.handler(arguments)
    print(canonical_bytes(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
