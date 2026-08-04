from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

pytest.importorskip("daimon_matrix")

from daimon_matrix.authority_epochs import create_authority_epoch
from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.client import ClientConfig, LocalClient
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
from daimon_matrix.local_api import create_capability
from daimon_matrix.service import METHODS, SCOPE_METHODS
from daimon_matrix.weave import BeingManifest

from clusterctl.embodiments import Registry
from clusterctl.matrix_host import (
    MatrixHostError,
    create_portable_snapshot,
    matrix_client_factory,
    matrix_client_root,
    matrix_root,
    restore_portable_snapshot,
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
    signing_slot = f"runtime.signing.v1:{label}"
    capability_slot = f"runtime.capability.v1:{label}"
    status_capability_slot = f"runtime.capability.v1:status:{label}"
    EncryptedKeystore.create(
        root / "custody.json",
        lambda: bytearray(PASSWORD),
        control_head=authority["state"].head,
        secrets={
            signing_slot: authority["signing_seeds"][label],
            capability_slot: capability.key,
            status_capability_slot: status_capability.key,
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
    return root, bundle, capability, status_capability


def _rewrite_bundle(root: Path, bundle: dict) -> None:
    path = root / "runtime.json"
    path.write_bytes(canonical_bytes(bundle))
    path.chmod(0o600)


def _write_client_config(state_dir: Path, capability, origin: dict) -> Path:
    root = matrix_client_root(state_dir, origin["embodiment_id"])
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    root.chmod(0o700)
    config = root / "client.json"
    config.write_bytes(
        canonical_bytes(
            {
                "schema": "dm.local.client-config/v1",
                "capability": capability.descriptor,
                "expected_server": origin,
            }
        )
    )
    config.chmod(0o600)
    key = root / "capability.key"
    key.write_bytes(capability.key)
    key.chmod(0o600)
    return root


def _spawn(state_dir: Path, embodiment_id: str):
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
            root, _, capability, _status_capability = runtimes[label]
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
    root, old_bundle, capability, status_capability = runtimes[label]
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
    _root, _bundle, _capability, status_capability = _write_runtime(
        state_dir, authority, "legion", now_ms
    )
    client_root = _write_client_config(state_dir, status_capability, origin)
    factory = matrix_client_factory(state_dir)
    assert factory(origin["embodiment_id"]).config.expected_server == origin

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
