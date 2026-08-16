from __future__ import annotations

import multiprocessing
import os
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from clusterctl.admission import (
    AdmissionAuthority,
    AdmissionClient,
    AdmissionConflict,
    AdmissionError,
    AdmissionServer,
    AdmissionUnavailable,
    admission_resource_ref,
    serve_in_thread,
)
from clusterctl.fences import Ed25519Signer
from clusterctl.production_fences import create_holder_enrollment


class MutableClock:
    def __init__(self, value: int):
        self.value = value

    def __call__(self) -> int:
        return self.value


def _key(path: Path, key_id: str) -> Ed25519Signer:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return Ed25519Signer(path, key_id)


def _coordinates(label: str, *, being_ref: str = "dm:being:shared") -> dict[str, str]:
    return {
        "being_ref": being_ref,
        "body_ref": f"cluster:body:{label}",
        "embodiment_id": f"dm:embodiment:{label}",
        "incarnation_id": f"dm:incarnation:{label}",
        "activation_id": f"dm:activation:{label}",
        "credential_id": f"dm:credential:{label}",
        "manifest_hash": f"sha256:{label}",
    }


def _client(
    socket_path: Path,
    holder: Ed25519Signer,
    authority: Ed25519Signer,
    coordinates: Mapping[str, str],
) -> AdmissionClient:
    return AdmissionClient(
        socket_path,
        holder_signer=holder,
        authority_key_id=authority.key_id,
        authority_public_key=authority.public_key,
        being_ref=coordinates["being_ref"],
        body_ref=coordinates["body_ref"],
        embodiment_id=coordinates["embodiment_id"],
        incarnation_id=coordinates["incarnation_id"],
        activation_id=coordinates["activation_id"],
        credential_id=coordinates["credential_id"],
        manifest_hash=coordinates["manifest_hash"],
    )


def _enroll(
    client: AdmissionClient,
    registrar: Ed25519Signer,
    holder: Ed25519Signer,
    coordinates: Mapping[str, str],
    now_ms: int,
) -> None:
    enrollment = create_holder_enrollment(
        registrar,
        holder_key_id=holder.key_id,
        holder_pubkey=holder.public_key,
        being_ref=coordinates["being_ref"],
        body_ref=coordinates["body_ref"],
        embodiment_id=coordinates["embodiment_id"],
        incarnation_id=coordinates["incarnation_id"],
        activation_id=coordinates["activation_id"],
        credential_id=coordinates["credential_id"],
        manifest_hash=coordinates["manifest_hash"],
        issued_ms=now_ms,
        nonce=str(uuid.uuid4()),
    )
    assert client.enroll(enrollment)["admitted"] is True


@pytest.fixture
def authority_fixture(tmp_path: Path):
    now_ms = time.time_ns() // 1_000_000
    clock = MutableClock(now_ms)
    authority_signer = _key(tmp_path / "keys/authority.pem", "admission-authority")
    registrar = _key(tmp_path / "keys/registrar.pem", "matrix-registrar")
    authority = AdmissionAuthority(
        tmp_path / "authority",
        signer=authority_signer,
        holder_registrars={registrar.key_id: registrar.public_key},
        clock=clock,
    )
    socket_path = tmp_path / "run/admission.sock"
    server = AdmissionServer(socket_path, authority)
    thread = serve_in_thread(server)
    try:
        yield {
            "authority": authority_signer,
            "registrar": registrar,
            "clock": clock,
            "server": server,
            "thread": thread,
            "socket": socket_path,
            "state": tmp_path / "authority",
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _race_worker(
    socket_path: str,
    holder_key: str,
    holder_key_id: str,
    authority_key_id: str,
    authority_public_key: str,
    coordinates: dict[str, str],
    gate: Any,
    results: Any,
) -> None:
    client = AdmissionClient(
        socket_path,
        holder_signer=Ed25519Signer(holder_key, holder_key_id),
        authority_key_id=authority_key_id,
        authority_public_key=authority_public_key,
        being_ref=coordinates["being_ref"],
        body_ref=coordinates["body_ref"],
        embodiment_id=coordinates["embodiment_id"],
        incarnation_id=coordinates["incarnation_id"],
        activation_id=coordinates["activation_id"],
        credential_id=coordinates["credential_id"],
        manifest_hash=coordinates["manifest_hash"],
    )
    gate.wait()
    try:
        receipt = client.acquire(ttl_s=10)
        results.put(("ready", receipt["fencing_token"]))
    except AdmissionConflict:
        results.put(("conflict", None))


def test_same_embodiment_race_across_processes_has_one_winner(
    authority_fixture: dict[str, Any], tmp_path: Path
) -> None:
    socket_path = authority_fixture["socket"]
    authority = authority_fixture["authority"]
    registrar = authority_fixture["registrar"]
    coordinates = _coordinates("one")
    holder_path = tmp_path / "holder-state-a/holder.pem"
    holder = _key(holder_path, "holder-one")
    client = _client(socket_path, holder, authority, coordinates)
    _enroll(client, registrar, holder, coordinates, authority_fixture["clock"].value)

    # The contenders intentionally use distinct local state directories.  Only
    # their enrolled holder credential and the shared authority coordinate join them.
    (tmp_path / "holder-state-b").mkdir(mode=0o700)
    context = multiprocessing.get_context("spawn")
    gate = context.Barrier(3)
    results = context.Queue()
    arguments = (
        str(socket_path),
        str(holder_path),
        holder.key_id,
        authority.key_id,
        authority.public_key,
        coordinates,
        gate,
        results,
    )
    workers = [context.Process(target=_race_worker, args=arguments) for _ in range(2)]
    for worker in workers:
        worker.start()
    gate.wait()
    outcomes = [results.get(timeout=10)[0] for _ in workers]
    for worker in workers:
        worker.join(timeout=10)
        assert worker.exitcode == 0
    assert sorted(outcomes) == ["conflict", "ready"]


def test_distinct_embodiments_of_same_being_do_not_contend(
    authority_fixture: dict[str, Any], tmp_path: Path
) -> None:
    receipts = []
    for label in ("alpha", "beta"):
        coordinates = _coordinates(label)
        holder = _key(tmp_path / f"{label}/holder.pem", f"holder-{label}")
        client = _client(
            authority_fixture["socket"],
            holder,
            authority_fixture["authority"],
            coordinates,
        )
        _enroll(
            client,
            authority_fixture["registrar"],
            holder,
            coordinates,
            authority_fixture["clock"].value,
        )
        receipts.append(client.acquire())
    assert receipts[0]["being_ref"] == receipts[1]["being_ref"]
    assert receipts[0]["resource_ref"] != receipts[1]["resource_ref"]


def test_receipt_tamper_hostile_holder_replay_and_outage_fail_closed(
    authority_fixture: dict[str, Any], tmp_path: Path
) -> None:
    coordinates = _coordinates("secure")
    holder = _key(tmp_path / "secure/holder.pem", "holder-secure")
    client = _client(
        authority_fixture["socket"],
        holder,
        authority_fixture["authority"],
        coordinates,
    )
    hostile = _key(tmp_path / "hostile/holder.pem", "holder-hostile")
    hostile_client = _client(
        authority_fixture["socket"],
        hostile,
        authority_fixture["authority"],
        coordinates,
    )
    with pytest.raises(AdmissionError, match="absent|unknown"):
        hostile_client.acquire()
    _enroll(
        client,
        authority_fixture["registrar"],
        holder,
        coordinates,
        authority_fixture["clock"].value,
    )
    receipt = client.acquire()
    copied_session = _client(
        authority_fixture["socket"],
        holder,
        authority_fixture["authority"],
        coordinates,
    )
    assert copied_session.current() is None
    with pytest.raises(AdmissionConflict, match="session"):
        copied_session.renew()
    with pytest.raises(AdmissionConflict, match="session"):
        copied_session.release()
    tampered = dict(receipt)
    tampered["fencing_token"] += 1
    with pytest.raises(AdmissionUnavailable, match="signature"):
        client.verify_receipt(tampered)

    renewed = client.renew()
    assert renewed["fencing_token"] == receipt["fencing_token"] + 1
    with pytest.raises(AdmissionConflict):
        client.acquire()

    authority_fixture["server"].shutdown()
    authority_fixture["server"].server_close()
    authority_fixture["thread"].join(timeout=5)
    with pytest.raises(AdmissionUnavailable, match="unavailable"):
        client.renew()


def test_crash_expiry_restart_and_high_water_preserve_fencing_token(
    authority_fixture: dict[str, Any], tmp_path: Path
) -> None:
    coordinates = _coordinates("restart")
    holder = _key(tmp_path / "restart/holder.pem", "holder-restart")
    client = _client(
        authority_fixture["socket"],
        holder,
        authority_fixture["authority"],
        coordinates,
    )
    _enroll(
        client,
        authority_fixture["registrar"],
        holder,
        coordinates,
        authority_fixture["clock"].value,
    )
    first = client.acquire(ttl_s=1)
    authority_fixture["server"].shutdown()
    authority_fixture["server"].server_close()
    authority_fixture["thread"].join(timeout=5)
    authority_fixture["clock"].value += 1_001

    restarted_authority = AdmissionAuthority(
        authority_fixture["state"],
        signer=authority_fixture["authority"],
        holder_registrars={
            authority_fixture["registrar"].key_id: authority_fixture[
                "registrar"
            ].public_key
        },
        clock=authority_fixture["clock"],
    )
    server = AdmissionServer(authority_fixture["socket"], restarted_authority)
    thread = serve_in_thread(server)
    authority_fixture["server"] = server
    authority_fixture["thread"] = thread
    second = client.acquire(ttl_s=10)
    assert second["fencing_token"] > first["fencing_token"]
    assert second["proof_ref"] != first["proof_ref"]
    assert admission_resource_ref(
        coordinates["being_ref"], coordinates["embodiment_id"]
    ) == second["resource_ref"]


def test_client_has_no_authority_signer_or_database(
    authority_fixture: dict[str, Any], tmp_path: Path
) -> None:
    coordinates = _coordinates("separation")
    holder = _key(tmp_path / "separation/holder.pem", "holder-separation")
    client = _client(
        authority_fixture["socket"],
        holder,
        authority_fixture["authority"],
        coordinates,
    )
    assert not hasattr(client, "_store")
    assert not hasattr(client, "_signer")
    assert all(
        value != authority_fixture["authority"]
        for value in vars(client).values()
    )
    assert os.stat(authority_fixture["socket"]).st_mode & 0o777 == 0o600
