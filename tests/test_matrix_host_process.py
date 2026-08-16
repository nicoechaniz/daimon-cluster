from __future__ import annotations

import copy
import contextlib
import hashlib
import json
import os
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytest.importorskip("daimon_matrix")

from daimon_matrix.authority_epochs import create_authority_epoch
from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.client import ClientConfig, LocalClient
from daimon_matrix.cluster import resource_fence_position
from daimon_matrix.curator import create_curator_item
from daimon_matrix.identity import (
    create_embodiment_credential,
    create_genesis,
    create_incarnation_authorization,
    ed25519_public,
    key_descriptor,
    verify_genesis,
    x25519_public,
)
from daimon_matrix.keystore import EncryptedKeystore
from daimon_matrix.local_api import LocalApiError, create_capability, encode_frame
from daimon_matrix.service import CURATOR_METHODS, METHODS, SCOPE_METHODS
from daimon_matrix.weave import BeingManifest

from clusterctl.embodiments import Registry
from clusterctl.fences import Ed25519Signer, ResourceFenceStore
from clusterctl.matrix_host import (
    MatrixHostAdapter,
    MatrixHostError,
    create_portable_snapshot,
    matrix_client_factory,
    matrix_client_root,
    matrix_curator_client,
    matrix_curator_client_root,
    matrix_root,
    restore_portable_snapshot,
)
from clusterctl.production_fences import (
    create_holder_authorization,
    create_holder_enrollment,
    ed25519_fingerprint,
)

PASSWORD = b"cluster-matrix-process-password"
CLUSTERD_METHODS = {
    "runtime.status",
    "scope.me",
    "scope.we",
    "scope.we.diff",
    "scope.we.sync-plan",
}


@pytest.fixture
def short_tmp_path():
    with tempfile.TemporaryDirectory(prefix="dmc-host-") as name:
        yield Path(name)


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"cluster-matrix-process:{label}".encode()).digest()


def _fence_signer(root: Path, label: str, key_id: str) -> Ed25519Signer:
    path = root / f"{label}.pem"
    private = Ed25519PrivateKey.from_private_bytes(_seed(f"fence:{label}"))
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return Ed25519Signer(path, key_id)


def _ensure_production_fences(state_dir: Path) -> None:
    if (state_dir / "resource-fences.sqlite3").is_file():
        return
    owner = _fence_signer(
        state_dir, ".matrix-host-test-fence-owner", "matrix-host-test-owner"
    )
    ResourceFenceStore.production(state_dir, signer=owner, key_id=owner.key_id)


def _transport(label: str, principal_id: str) -> dict:
    return {
        "key": key_descriptor("Ed25519", ed25519_public(_seed(f"{label}-transport"))),
        "principal_id": principal_id,
        "scheme": "tribe-v1",
    }


def _authority(now_ms: int):
    root_seeds = [_seed("root-a"), _seed("root-b"), _seed("root-c")]
    genesis = create_genesis(
        root_seeds,
        2,
        [_seed("recovery-a"), _seed("recovery-b"), _seed("recovery-c")],
        2,
        created_at_ms=now_ms - 60_000,
        nonce=_seed("being"),
    )
    state = verify_genesis(genesis)
    credentials = {}
    incarnations = {}
    origins = {}
    rows = []
    signing_seeds = {}
    for index, label in enumerate(("legion", "daimonmatrix"), start=1):
        signing_seed = _seed(f"{label}-signing")
        signing_seeds[label] = signing_seed
        origin = {
            "body_ref": f"cluster:{label}:compaii",
            "embodiment_id": f"embodiment:00000000-0000-4000-8000-{index:012d}",
            "incarnation_id": f"incarnation:10000000-0000-4000-8000-{index:012d}",
            "principal_id": f"compaii@{label}",
        }
        credential = create_embodiment_credential(
            state,
            root_seeds,
            signing_seed,
            x25519_public(_seed(f"{label}-encryption")),
            embodiment_id=origin["embodiment_id"],
            body_ref=origin["body_ref"],
            purposes=["dm.we", "messages"],
            valid_from_ms=now_ms - 60_000,
            valid_until_ms=now_ms + 3_600_000,
            transport_principals=[_transport(label, origin["principal_id"])],
        )
        incarnation = create_incarnation_authorization(
            credential,
            signing_seed,
            incarnation_id=origin["incarnation_id"],
            incarnation_sequence=0,
            started_at_ms=now_ms - 1_000,
        )
        credentials[credential["artifact_id"]] = credential
        incarnations[incarnation["artifact_id"]] = incarnation
        origins[label] = origin
        rows.append(
            {
                "body_ref": origin["body_ref"],
                "embodiment_credential_id": credential["artifact_id"],
                "embodiment_id": origin["embodiment_id"],
                "incarnation_authorization_id": incarnation["artifact_id"],
                "incarnation_id": origin["incarnation_id"],
                "status": "active",
            }
        )
    rows.sort(key=lambda row: (row["embodiment_id"], row["incarnation_id"]))
    manifest = BeingManifest.from_value(
        {
            "schema": "being-manifest/v2",
            "being_ref": state.being_ref,
            "control_head": state.head,
            "history_binding_id": None,
            "revision": 1,
            "embodiments": rows,
        }
    )
    return {
        "root_seeds": root_seeds,
        "genesis": genesis,
        "state": state,
        "credentials": credentials,
        "incarnations": incarnations,
        "origins": origins,
        "rows": rows,
        "manifest": manifest,
        "signing_seeds": signing_seeds,
    }


def _write_runtime(state_dir: Path, authority: dict, label: str, now_ms: int):
    origin = authority["origins"][label]
    root = matrix_root(state_dir, origin["embodiment_id"])
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    capability = create_capability(
        _seed(f"{label}-capability"),
        client_id=f"client:clusterd:{label}",
        methods=sorted(METHODS | SCOPE_METHODS),
        not_before_ms=now_ms - 60_000,
        not_after_ms=now_ms + 3_600_000,
    )
    status_capability = create_capability(
        _seed(f"{label}-status-capability"),
        client_id=f"client:clusterd-status:{label}",
        methods=sorted(CLUSTERD_METHODS),
        not_before_ms=now_ms - 60_000,
        not_after_ms=now_ms + 3_600_000,
    )
    curator_capability = create_capability(
        _seed(f"{label}-curator-capability"),
        client_id=f"client:curator-worker:{label}",
        methods=sorted(CURATOR_METHODS),
        not_before_ms=now_ms - 60_000,
        not_after_ms=now_ms + 3_600_000,
    )
    signing_slot = f"runtime.signing.v1:{label}"
    capability_slot = f"runtime.capability.v1:{label}"
    status_capability_slot = f"runtime.capability.v1:status:{label}"
    curator_capability_slot = f"runtime.capability.v1:curator:{label}"
    EncryptedKeystore.create(
        root / "custody.json",
        lambda: bytearray(PASSWORD),
        control_head=authority["state"].head,
        secrets={
            signing_slot: authority["signing_seeds"][label],
            capability_slot: capability.key,
            status_capability_slot: status_capability.key,
            curator_capability_slot: curator_capability.key,
        },
    )
    bundle = {
        "schema": "dm.runtime.bundle/v1",
        "control_artifacts": [authority["genesis"]],
        "control_head": authority["state"].head,
        "manifest": authority["manifest"].value,
        "credentials": list(authority["credentials"].values()),
        "incarnations": list(authority["incarnations"].values()),
        "binding": None,
        "binding_activation": None,
        "provisional_history": None,
        "local_origin": origin,
        "ledger": "ledger.sqlite",
        "socket": "matrix.sock",
        "keystore": {
            "filename": "custody.json",
            "counter": 1,
            "signing_slot": signing_slot,
        },
        "capabilities": [
            {"descriptor": capability.descriptor, "secret_slot": capability_slot},
            {
                "descriptor": status_capability.descriptor,
                "secret_slot": status_capability_slot,
            },
            {
                "descriptor": curator_capability.descriptor,
                "secret_slot": curator_capability_slot,
            },
        ],
        "routing": None,
        "scopes": {
            "body_capabilities": ["incus.inspect/v1"],
            "relationships_filename": None,
        },
    }
    path = root / "runtime.json"
    path.write_bytes(canonical_bytes(bundle))
    path.chmod(0o600)
    return root, bundle, capability, status_capability, curator_capability


def _rewrite_bundle(root: Path, bundle: dict) -> None:
    path = root / "runtime.json"
    path.write_bytes(canonical_bytes(bundle))
    path.chmod(0o600)


def _write_client_config(
    state_dir: Path,
    capability,
    origin: dict,
    *,
    historical_servers: list[dict] | None = None,
    curator: bool = False,
) -> Path:
    root = (
        matrix_curator_client_root(state_dir, origin["embodiment_id"])
        if curator
        else matrix_client_root(state_dir, origin["embodiment_id"])
    )
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    root.chmod(0o700)
    config = root / "client.json"
    value = {
        "schema": (
            "dm.local.client-config/v1"
            if historical_servers is None
            else "dm.local.client-config/v2"
        ),
        "capability": capability.descriptor,
        "expected_server": origin,
    }
    if historical_servers is not None:
        value["historical_servers"] = historical_servers
    config.write_bytes(canonical_bytes(value))
    config.chmod(0o600)
    key = root / "capability.key"
    key.write_bytes(capability.key)
    key.chmod(0o600)
    return root


def _spawn(
    state_dir: Path,
    embodiment_id: str,
    *,
    production_fence_verifier: bool = False,
):
    _ensure_production_fences(state_dir)
    production_fence_verifier = True
    password_read, password_write = os.pipe()
    ready_read, ready_write = os.pipe()
    command = [
        sys.executable,
        "-m",
        "clusterctl.matrix_host",
        "--state-dir",
        str(state_dir),
        "--embodiment-id",
        embodiment_id,
        "--password-fd",
        str(password_read),
        "--ready-fd",
        str(ready_write),
    ]
    if production_fence_verifier:
        command.append("--production-fence-verifier")
    process = subprocess.Popen(
        command,
        pass_fds=(password_read, ready_write),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    os.close(password_read)
    os.close(ready_write)
    try:
        os.write(password_write, PASSWORD)
    finally:
        os.close(password_write)
    ready = os.read(ready_read, 64)
    os.close(ready_read)
    if ready != b"READY\n":
        _, stderr = process.communicate(timeout=10)
        raise AssertionError(f"matrix host refused startup: {stderr!r}")
    return process, command


def _stop(process: subprocess.Popen) -> bytes:
    process.terminate()
    _, stderr = process.communicate(timeout=10)
    assert process.returncode == 0, stderr
    return stderr


def _client(root: Path, capability, origin: dict) -> LocalClient:
    return LocalClient(root / "matrix.sock", ClientConfig(capability, origin))


def test_two_real_hosts_restart_and_relocate_without_secret_leaks(short_tmp_path):
    now_ms = time.time_ns() // 1_000_000
    state_dir = short_tmp_path / "cluster"
    authority = _authority(now_ms)
    registry = Registry(state_dir)
    runtimes = {}
    for label in ("legion", "daimonmatrix"):
        origin = authority["origins"][label]
        registry.register(
            body_ref=origin["body_ref"], embodiment_id=origin["embodiment_id"]
        )
        registry.start(
            origin["embodiment_id"],
            incarnation_id=origin["incarnation_id"],
            started_at_ms=now_ms - 1_000,
        )
        runtimes[label] = _write_runtime(state_dir, authority, label, now_ms)
        _write_client_config(state_dir, runtimes[label][3], authority["origins"][label])

    processes = {}
    commands = {}
    old_event = None
    try:
        for label in ("legion", "daimonmatrix"):
            process, command = _spawn(
                state_dir, authority["origins"][label]["embodiment_id"]
            )
            processes[label] = process
            commands[label] = command
        for label in ("legion", "daimonmatrix"):
            root, _, capability, _status_capability, _curator_capability = runtimes[
                label
            ]
            origin = authority["origins"][label]
            me_response = _client(root, capability, origin).scope_me()[1]
            we_response = _client(root, capability, origin).scope_we()[1]
            assert me_response["ok"] is True, me_response
            assert we_response["ok"] is True, we_response
            me = me_response["result"]
            we = we_response["result"]
            assert me["origin"] == origin
            assert me["body"]["state"] == "running"
            assert {row["embodiment_id"] for row in we["embodiments"]} == {
                value["embodiment_id"] for value in authority["origins"].values()
            }
            if label == "legion":
                observed = _client(root, capability, origin).we_observe(
                    {
                        "subject": "before-incarnation-restart",
                        "payload": {"summary": "durable across restart"},
                        "sensitivity": "personal",
                        "causal_parents": [],
                        "occurred_at_ms": now_ms - 500,
                        "event_id": None,
                    },
                    request_id="30000000-0000-4000-8000-000000000048",
                )[1]
                assert observed["ok"] is True
                old_event = observed["result"]["event"]
            hosted_client = matrix_client_factory(state_dir)(origin["embodiment_id"])
            assert hosted_client.scope_me()[1]["result"]["origin"] == origin
        assert runtimes["legion"][0] != runtimes["daimonmatrix"][0]
        assert (runtimes["legion"][0] / "ledger.sqlite") != (
            runtimes["daimonmatrix"][0] / "ledger.sqlite"
        )
        assert (runtimes["legion"][0] / "matrix.sock") != (
            runtimes["daimonmatrix"][0] / "matrix.sock"
        )
        assert (
            authority["signing_seeds"]["legion"]
            != authority["signing_seeds"]["daimonmatrix"]
        )
        assert runtimes["legion"][2].key != runtimes["daimonmatrix"][2].key
        assert runtimes["legion"][3].key != runtimes["daimonmatrix"][3].key
        assert matrix_client_root(
            state_dir, authority["origins"]["legion"]["embodiment_id"]
        ) != matrix_client_root(
            state_dir, authority["origins"]["daimonmatrix"]["embodiment_id"]
        )
        assert (runtimes["legion"][0] / "custody.json").read_bytes() != (
            runtimes["daimonmatrix"][0] / "custody.json"
        ).read_bytes()
        for command in commands.values():
            joined = "\0".join(command)
            assert PASSWORD.decode() not in joined
        for process in processes.values():
            environ = Path(f"/proc/{process.pid}/environ").read_bytes()
            assert PASSWORD not in environ
        with pytest.raises(MatrixHostError, match="matrix_runtime_not_quiesced"):
            create_portable_snapshot(
                runtimes["legion"][0], short_tmp_path / "live-snapshot-refused"
            )
    finally:
        logs = b"".join(_stop(process) for process in processes.values())
    assert PASSWORD not in logs

    label = "legion"
    root, old_bundle, capability, status_capability, _curator_capability = runtimes[
        label
    ]
    old_origin = authority["origins"][label]
    credential = next(
        item
        for item in authority["credentials"].values()
        if item["body"]["embodiment_id"] == old_origin["embodiment_id"]
    )
    new_incarnation_id = "incarnation:20000000-0000-4000-8000-000000000001"
    new_authorization = create_incarnation_authorization(
        credential,
        authority["signing_seeds"][label],
        incarnation_id=new_incarnation_id,
        incarnation_sequence=1,
        started_at_ms=now_ms,
    )
    rows = copy.deepcopy(authority["rows"])
    old_row = next(
        row for row in rows if row["embodiment_id"] == old_origin["embodiment_id"]
    )
    old_row["status"] = "retired"
    rows.append(
        {
            **old_row,
            "incarnation_authorization_id": new_authorization["artifact_id"],
            "incarnation_id": new_incarnation_id,
            "status": "active",
        }
    )
    rows.sort(key=lambda row: (row["embodiment_id"], row["incarnation_id"]))
    new_manifest = BeingManifest.from_value(
        {
            **authority["manifest"].value,
            "revision": 2,
            "embodiments": rows,
        }
    )
    transition = create_authority_epoch(
        authority["manifest"],
        new_manifest,
        embodiment_id=old_origin["embodiment_id"],
        previous_incarnation_id=old_origin["incarnation_id"],
        successor_authorization=new_authorization,
        signing_seed=authority["signing_seeds"][label],
        issued_at_ms=now_ms,
    )
    new_origin = {**old_origin, "incarnation_id": new_incarnation_id}
    new_bundle = {
        **old_bundle,
        "schema": "dm.runtime.bundle/v2",
        "authority_history": [
            {
                "manifest": authority["manifest"].value,
                "successor": transition,
            }
        ],
        "manifest": new_manifest.value,
        "incarnations": [
            *old_bundle["incarnations"],
            new_authorization,
        ],
        "local_origin": new_origin,
    }
    _rewrite_bundle(root, new_bundle)
    _write_client_config(state_dir, status_capability, new_origin)
    registry.stop(old_origin["embodiment_id"])
    registry.start(
        old_origin["embodiment_id"],
        incarnation_id=new_incarnation_id,
        started_at_ms=now_ms,
    )
    restarted, command = _spawn(state_dir, old_origin["embodiment_id"])
    retry_request = None
    retry_response = None
    try:
        client = _client(root, capability, new_origin)
        me = client.scope_me()[1]["result"]
        assert old_event is not None
        projection = client.projection_rebuild()[1]["result"]
        assert old_event["event_id"] in {
            entry["event_id"] for entry in projection["entries"]
        }
        retry_request = client.prepare(
            "we.observe",
            {
                "subject": "after-incarnation-restart",
                "payload": {"summary": "one effect across response replay"},
                "sensitivity": "personal",
                "causal_parents": [],
                "occurred_at_ms": now_ms + 1,
                "event_id": None,
            },
            request_id="30000000-0000-4000-8000-000000000049",
        )
        retry_response = client.send(retry_request)
        assert client.send(retry_request) == retry_response
        new_event = retry_response["result"]["event"]
        assert new_event["sequence"] == 1
        assert new_event["manifest_hash"] == new_manifest.digest
        status_before = client.runtime_status()[1]["result"]
        assert me["origin"]["embodiment_id"] == old_origin["embodiment_id"]
        assert me["origin"]["incarnation_id"] == new_incarnation_id
        assert me["incarnation_authorization_ref"] == new_authorization["artifact_id"]
        assert status_before["authority_epoch"] == {
            "schema": "dm.we.authority-epoch-status/v1",
            "active_manifest_hash": new_manifest.digest,
            "accepted_manifest_hashes": sorted(
                [authority["manifest"].digest, new_manifest.digest]
            ),
            "epoch_count": 2,
        }
        assert PASSWORD.decode() not in "\0".join(command)
    finally:
        assert PASSWORD not in _stop(restarted)

    snapshot = short_tmp_path / "portable"
    manifest = create_portable_snapshot(root, snapshot)
    snapshot_bytes = b"".join(
        path.read_bytes() for path in snapshot.rglob("*") if path.is_file()
    )
    assert PASSWORD not in snapshot_bytes
    assert {row["name"] for row in manifest["files"]}.isdisjoint(
        {"matrix.sock", ".daimon-matrixd.lock", "client.json", "capability.key"}
    )

    relocated_state = short_tmp_path / "relocated-cluster"
    relocated_registry = Registry(relocated_state)
    relocated_registry.register(
        body_ref=old_origin["body_ref"], embodiment_id=old_origin["embodiment_id"]
    )
    relocated_registry.start(
        old_origin["embodiment_id"],
        incarnation_id=new_incarnation_id,
        started_at_ms=now_ms,
    )
    relocated_root = matrix_root(relocated_state, old_origin["embodiment_id"])
    restore_portable_snapshot(snapshot, relocated_root)
    assert not matrix_client_root(relocated_state, old_origin["embodiment_id"]).exists()
    _write_client_config(relocated_state, status_capability, new_origin)
    assert stat.S_IMODE(relocated_root.stat().st_mode) == 0o700
    relocated, _ = _spawn(relocated_state, old_origin["embodiment_id"])
    try:
        relocated_client = _client(relocated_root, capability, new_origin)
        assert retry_request is not None
        assert retry_response is not None
        assert relocated_client.send(retry_request) == retry_response
        hosted_relocated = matrix_client_factory(relocated_state)(
            old_origin["embodiment_id"]
        )
        assert hosted_relocated.scope_me()[1]["result"]["origin"] == new_origin
        resumed = relocated_client.runtime_status()[1]["result"]
        assert resumed["integrity"] == "ok"
        assert resumed["counts"] == status_before["counts"]
        assert resumed["authority_epoch"] == status_before["authority_epoch"]
    finally:
        assert PASSWORD not in _stop(relocated)


def test_second_writer_and_registry_drift_fail_before_ready(short_tmp_path):
    now_ms = time.time_ns() // 1_000_000
    state_dir = short_tmp_path / "cluster"
    authority = _authority(now_ms)
    origin = authority["origins"]["legion"]
    registry = Registry(state_dir)
    registry.register(
        body_ref=origin["body_ref"], embodiment_id=origin["embodiment_id"]
    )
    registry.start(
        origin["embodiment_id"],
        incarnation_id=origin["incarnation_id"],
        started_at_ms=now_ms,
    )
    _write_runtime(state_dir, authority, "legion", now_ms)
    first, _ = _spawn(state_dir, origin["embodiment_id"])
    try:
        password_read, password_write = os.pipe()
        ready_read, ready_write = os.pipe()
        second = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "clusterctl.matrix_host",
                "--state-dir",
                str(state_dir),
                "--embodiment-id",
                origin["embodiment_id"],
                "--password-fd",
                str(password_read),
                "--ready-fd",
                str(ready_write),
            ],
            pass_fds=(password_read, ready_write),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.close(password_read)
        os.close(ready_write)
        os.write(password_write, PASSWORD)
        os.close(password_write)
        assert os.read(ready_read, 64) == b""
        os.close(ready_read)
        _, error = second.communicate(timeout=10)
        assert second.returncode == 1
        assert PASSWORD not in error
    finally:
        _stop(first)

    registry.stop(origin["embodiment_id"])
    password_read, password_write = os.pipe()
    ready_read, ready_write = os.pipe()
    refused = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "clusterctl.matrix_host",
            "--state-dir",
            str(state_dir),
            "--embodiment-id",
            origin["embodiment_id"],
            "--password-fd",
            str(password_read),
            "--ready-fd",
            str(ready_write),
        ],
        pass_fds=(password_read, ready_write),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(password_read)
    os.close(ready_write)
    os.write(password_write, PASSWORD)
    os.close(password_write)
    assert os.read(ready_read, 64) == b""
    os.close(ready_read)
    _, error = refused.communicate(timeout=10)
    assert refused.returncode == 1
    diagnostic = json.loads(error)
    assert diagnostic["code"] == "matrix_origin_registry_mismatch"
    assert PASSWORD not in error


def test_production_client_factory_rejects_host_local_key_and_origin_drift(
    short_tmp_path,
):
    now_ms = time.time_ns() // 1_000_000
    state_dir = short_tmp_path / "cluster"
    authority = _authority(now_ms)
    origin = authority["origins"]["legion"]
    registry = Registry(state_dir)
    registry.register(
        body_ref=origin["body_ref"], embodiment_id=origin["embodiment_id"]
    )
    registry.start(
        origin["embodiment_id"],
        incarnation_id=origin["incarnation_id"],
        started_at_ms=now_ms - 1_000,
    )
    _root, _bundle, _capability, status_capability, _curator_capability = (
        _write_runtime(state_dir, authority, "legion", now_ms)
    )
    client_root = _write_client_config(state_dir, status_capability, origin)
    _ensure_production_fences(state_dir)
    factory = matrix_client_factory(state_dir)
    assert factory(origin["embodiment_id"]).config.expected_server == origin

    historical = {
        **origin,
        "incarnation_id": "incarnation:matrix-client-retired",
    }
    _write_client_config(
        state_dir,
        status_capability,
        origin,
        historical_servers=[{"server": historical, "retired_at_ms": now_ms - 1}],
    )
    v2_config = factory(origin["embodiment_id"]).config
    assert v2_config.expected_server == origin
    assert v2_config.historical_servers == (
        {"server": historical, "retired_at_ms": now_ms - 1},
    )

    _write_client_config(state_dir, _capability, origin)
    with pytest.raises(MatrixHostError, match="matrix_client_authority_rejected"):
        factory(origin["embodiment_id"])
    _write_client_config(state_dir, status_capability, origin)

    key = client_root / "capability.key"
    key.chmod(0o644)
    with pytest.raises(MatrixHostError, match="matrix_client_material_not_owner_only"):
        factory(origin["embodiment_id"])

    key.chmod(0o600)
    key.write_bytes(_seed("substituted-capability"))
    with pytest.raises(MatrixHostError, match="matrix_client_config_rejected"):
        factory(origin["embodiment_id"])

    _write_client_config(
        state_dir,
        status_capability,
        {**origin, "principal_id": "compaii@substituted"},
    )
    with pytest.raises(MatrixHostError, match="matrix_client_origin_mismatch"):
        factory(origin["embodiment_id"])


def test_real_host_keeps_curator_worker_separate_and_replays_one_result(
    short_tmp_path,
):
    now_ms = time.time_ns() // 1_000_000
    state_dir = short_tmp_path / "cluster"
    authority = _authority(now_ms)
    origin = authority["origins"]["legion"]
    registry = Registry(state_dir)
    registry.register(
        body_ref=origin["body_ref"], embodiment_id=origin["embodiment_id"]
    )
    registry.start(
        origin["embodiment_id"],
        incarnation_id=origin["incarnation_id"],
        started_at_ms=now_ms - 1_000,
    )
    root, _bundle, _broad, status_capability, curator_capability = _write_runtime(
        state_dir, authority, "legion", now_ms
    )
    _write_client_config(state_dir, status_capability, origin)
    _write_client_config(state_dir, curator_capability, origin, curator=True)
    assert matrix_client_root(
        state_dir, origin["embodiment_id"]
    ) != matrix_curator_client_root(state_dir, origin["embodiment_id"])
    assert status_capability.key != curator_capability.key

    item = create_curator_item(
        subject_me_id=authority["state"].being_ref,
        resource_ref="queue:cluster-real-process",
        work_kind="memory-evaluation",
        input_ref="memory:cluster-real-process",
        input_hash="a" * 64,
        coordination_mode="queue-item",
        required_authority="daimon",
        effect_intent_hash=None,
        queued_at_ms=now_ms,
    )
    shared_intent = {"operation": "publish", "value": "must-stay-disabled"}
    shared_item = create_curator_item(
        subject_me_id=authority["state"].being_ref,
        resource_ref="volume:cluster-real-process",
        work_kind="publication",
        input_ref="proposal:cluster-resource-effect",
        input_hash="b" * 64,
        coordination_mode="resource-fence",
        required_authority="daimon",
        effect_intent_hash=hashlib.sha256(canonical_bytes(shared_intent)).hexdigest(),
        queued_at_ms=now_ms,
    )
    owner_signer = _fence_signer(
        short_tmp_path, "cluster-fence-owner", "cluster-fence-test-owner"
    )
    holder_signer = _fence_signer(
        short_tmp_path, "cluster-fence-holder", "cluster-fence-test-holder"
    )
    fences = ResourceFenceStore.production(
        state_dir,
        signer=owner_signer,
        key_id=owner_signer.key_id,
        holder_registrars={owner_signer.key_id: owner_signer.public_key},
    )
    fences.admit_holder(
        create_holder_enrollment(
            owner_signer,
            holder_key_id=holder_signer.key_id,
            holder_pubkey=holder_signer.public_key,
            being_ref="dm:being:matrix-host-process-test",
            body_ref=origin["body_ref"],
            embodiment_id=origin["embodiment_id"],
            incarnation_id=origin["incarnation_id"],
            activation_id="dm:activation:matrix-host-process-test",
            credential_id="dm:credential:matrix-host-process-test",
            manifest_hash="sha256:" + "b" * 64,
            issued_ms=now_ms - 1,
            nonce="matrix-host-process-holder-enrollment",
        )
    )
    fence_position = fences.position(shared_item["resource_ref"])
    fence_authorization = create_holder_authorization(
        holder_signer,
        operation="acquire",
        body_ref=origin["body_ref"],
        embodiment_id=origin["embodiment_id"],
        incarnation_id=origin["incarnation_id"],
        resource_ref=shared_item["resource_ref"],
        expected_epoch=fence_position["epoch"],
        expected_proof=fence_position["proof"],
        issued_ms=now_ms - 1,
        ttl_s=60,
        nonce="real-process-production-fence",
    )
    fences.acquire(
        shared_item["resource_ref"],
        holder_signer.public_key,
        ed25519_fingerprint(holder_signer.public_key),
        holder_embodiment_id=origin["embodiment_id"],
        body_ref=origin["body_ref"],
        holder_incarnation_id=origin["incarnation_id"],
        holder_key_id=holder_signer.key_id,
        expected_epoch=fence_position["epoch"],
        expected_proof=fence_position["proof"],
        authorization=fence_authorization,
    )
    fence_evidence = MatrixHostAdapter(
        state_dir, origin["embodiment_id"], fence_store=fences
    ).fence_evidence(shared_item["resource_ref"])
    assert fence_evidence is not None
    process, _ = _spawn(
        state_dir,
        origin["embodiment_id"],
        production_fence_verifier=True,
    )
    completion_request = None
    try:
        status_client = matrix_client_factory(state_dir)(origin["embodiment_id"])
        with pytest.raises(LocalApiError, match="authentication_failed"):
            status_client.curator_inspect(item["item_id"])

        curator_client = matrix_curator_client(state_dir, origin["embodiment_id"])
        enqueued = curator_client.curator_enqueue(
            item, request_id="33000000-0000-4000-8000-000000000001"
        )[1]
        assert enqueued["ok"] is True
        claim = curator_client.curator_claim(
            {
                "item_id": item["item_id"],
                "claim_id": "33000000-0000-4000-8000-000000000002",
                "expected_generation": 0,
                "lease_until_ms": now_ms + 30_000,
                "fence_evidence": None,
            },
            request_id="33000000-0000-4000-8000-000000000003",
        )[1]
        assert claim["ok"] is True

        shared_enqueue = curator_client.curator_enqueue(
            shared_item,
            request_id="33000000-0000-4000-8000-000000000005",
        )[1]
        assert shared_enqueue["ok"] is True
        shared_claim = curator_client.curator_claim(
            {
                "item_id": shared_item["item_id"],
                "claim_id": "33000000-0000-4000-8000-000000000006",
                "expected_generation": 0,
                "lease_until_ms": now_ms + 30_000,
                "fence_evidence": fence_evidence,
            },
            request_id="33000000-0000-4000-8000-000000000007",
        )[1]
        assert shared_claim["ok"] is True
        shared_receipt = MatrixHostAdapter.create_effect_receipt(
            effect_id="33000000-0000-4000-8000-000000000008",
            target_event_id="33000000-0000-4000-8000-000000000009",
            decision_event_id="33000000-0000-4000-8000-000000000010",
            adapter="unregistered-production-adapter/v1",
            preview_hash="c" * 64,
            intent_hash=shared_item["effect_intent_hash"],
            actor=origin["principal_id"],
            authority="daimon",
            resource_fence=resource_fence_position(fence_evidence),
            result="applied",
            observed_postcondition={"state": "present"},
            started_at_ms=now_ms,
            completed_at_ms=now_ms + 1,
        )
        refused_effect = curator_client.curator_complete(
            {
                "claim_id": shared_claim["result"]["claim_id"],
                "expected_generation": 1,
                "outcome": "completed",
                "output_refs": ["publication:must-stay-disabled"],
                "effect_receipt": shared_receipt,
            },
            request_id="33000000-0000-4000-8000-000000000011",
        )[1]
        assert refused_effect["ok"] is False
        assert refused_effect["error"]["code"] == "effect_truth_unverifiable"
        completion_request = curator_client.prepare(
            "curator.complete",
            {
                "claim_id": "33000000-0000-4000-8000-000000000002",
                "expected_generation": 1,
                "outcome": "completed",
                "output_refs": ["proposal:cluster-real-process"],
                "effect_receipt": None,
            },
            request_id="33000000-0000-4000-8000-000000000004",
        )
        # Dispatch the exact request and intentionally discard the response.
        # Poll only the durable semantic row, then restart the daemon.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(root / "matrix.sock"))
            connection.sendall(encode_frame(completion_request))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with contextlib.closing(
                sqlite3.connect(root / "ledger.sqlite")
            ) as database:
                committed = database.execute(
                    "SELECT COUNT(*) FROM curator_items "
                    "WHERE item_id=? AND result_json IS NOT NULL",
                    (item["item_id"],),
                ).fetchone()[0]
            if committed == 1:
                break
            time.sleep(0.01)
        assert committed == 1
    finally:
        assert PASSWORD not in _stop(process)

    assert completion_request is not None
    restarted, _ = _spawn(state_dir, origin["embodiment_id"])
    try:
        curator_client = matrix_curator_client(state_dir, origin["embodiment_id"])
        replayed_result = curator_client.send(completion_request)
        assert replayed_result["ok"] is True
        inspection = curator_client.curator_inspect(item["item_id"])[1]
        assert inspection["ok"] is True
        assert inspection["result"]["state"] == "completed"
        assert inspection["result"]["result"] == replayed_result["result"]
    finally:
        assert PASSWORD not in _stop(restarted)

    with contextlib.closing(sqlite3.connect(root / "ledger.sqlite")) as database:
        assert (
            database.execute(
                "SELECT COUNT(*) FROM curator_items WHERE result_json IS NOT NULL"
            ).fetchone()[0]
            == 1
        )
