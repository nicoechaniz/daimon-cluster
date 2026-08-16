from __future__ import annotations

import atexit
import hashlib
import json
import multiprocessing
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from daimon_matrix.client import ClientConfig, LocalClient
from daimon_matrix.operator_bootstrap import PROFILE_SCHEMA, _create
from daimon_matrix.operator_rebirth import (
    activate_target_runtime,
    authority_from_document,
    authorize_from_root_custody,
    create_target_preparation,
)
from daimon_matrix.runtime import load_runtime

from clusterctl import audit, cli, distributed_rebirth, rebirth, rebirth_host
from clusterctl.admission import (
    AdmissionAuthority,
    AdmissionClient,
    AdmissionServer,
    serve_in_thread,
)
from clusterctl.embodiments import Registry
from clusterctl.fences import Ed25519Signer, ResourceFenceStore
from clusterctl.matrix_host import (
    MatrixHostError,
    create_portable_snapshot,
    matrix_client_root,
    matrix_curator_client_root,
    matrix_root,
)
from clusterctl.operation_journal import OperationJournal, canonical_bytes
from clusterctl.production_fences import create_holder_enrollment


class SimulatedCrash(BaseException):
    pass


_DISPOSABLE_ADMISSION_SERVERS: list[tuple[AdmissionServer, threading.Thread]] = []


def _close_disposable_admission_servers() -> None:
    for server, thread in _DISPOSABLE_ADMISSION_SERVERS:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    _DISPOSABLE_ADMISSION_SERVERS.clear()


atexit.register(_close_disposable_admission_servers)


def _ensure_production_fences(state: Path, embodiment_id: str | None = None) -> None:
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    state.chmod(0o700)
    if not (state / "resource-fences.sqlite3").is_file():
        key = state / ".rebirth-test-fence-owner.pem"
        key.write_bytes(
            Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key.chmod(0o600)
        signer = Ed25519Signer(key, "rebirth-test-cluster-owner")
        ResourceFenceStore.production(state, signer=signer, key_id=signer.key_id)
    if embodiment_id is None or (state / "admission-client.json").is_file():
        return
    identity = rebirth_host._installed_identity(state, embodiment_id)
    fixture = state.parent / f".synthetic-admission-{uuid.uuid4()}"
    fixture.mkdir(mode=0o700)

    def new_signer(name: str) -> Ed25519Signer:
        path = fixture / f"{name}.pem"
        path.write_bytes(
            Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        path.chmod(0o600)
        return Ed25519Signer(path, f"synthetic-{name}")

    authority_signer = new_signer("admission-authority")
    registrar = new_signer("matrix-registrar")
    holder = new_signer("embodiment-holder")
    authority = AdmissionAuthority(
        fixture / "authority-state",
        signer=authority_signer,
        holder_registrars={registrar.key_id: registrar.public_key},
    )
    socket_path = fixture / "run/admission.sock"
    server = AdmissionServer(socket_path, authority)
    thread = serve_in_thread(server)
    _DISPOSABLE_ADMISSION_SERVERS.append((server, thread))
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
    now_ms = time.time_ns() // 1_000_000
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
            issued_ms=now_ms,
            nonce=str(uuid.uuid4()),
        )
    )
    config = {
        "schema": rebirth_host.ADMISSION_CLIENT_SCHEMA,
        "endpoint": {
            "transport": "unix-local-fixture",
            "path": str(socket_path),
        },
        "holder_key_path": str(fixture / "embodiment-holder.pem"),
        "holder_key_id": holder.key_id,
        "authority_key_id": authority_signer.key_id,
        "authority_public_key": authority_signer.public_key,
        "lease_ttl_s": 3,
    }
    config_path = state / "admission-client.json"
    config_path.write_text(
        json.dumps(config, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    config_path.chmod(0o600)


@pytest.fixture
def short_tmp_path():
    with tempfile.TemporaryDirectory(prefix="dmc-rebirth-") as value:
        try:
            yield Path(value)
        finally:
            # Admission handlers may still be completing the supervisor's
            # final release.  Stop and join them before TemporaryDirectory
            # removes their SQLite state, never concurrently with teardown.
            _close_disposable_admission_servers()


def _descriptor(value: bytes) -> int:
    reader, writer = os.pipe()
    os.write(writer, value)
    os.close(writer)
    return reader


def _rebirth_race_worker(
    state: str,
    embodiment_id: str,
    password: bytes,
    gate,
    stop,
    results,
) -> None:
    gate.wait()
    try:
        process, ready = rebirth_host.launch_rebirth_host(
            state, embodiment_id, _descriptor(password), admission_lease_ttl_s=3
        )
    except rebirth_host.RebirthHostError as exception:
        results.put(("refused", str(exception)))
        return
    results.put(("ready", ready["admission"]["fencing_token"]))
    stop.wait(timeout=10)
    process.terminate()
    process.communicate(timeout=10)


def _launcher_kill_worker(
    state: str, embodiment_id: str, password: bytes, results
) -> None:
    process, ready = rebirth_host.launch_rebirth_host(
        state,
        embodiment_id,
        _descriptor(password),
        admission_lease_ttl_s=3,
    )
    results.put((process.pid, ready["admission"]["lease_expires_at_ms"]))
    while True:
        time.sleep(1)


def _ceremony(tmp_path: Path, *, now_ms: int = 1_800_000_000_000) -> dict:
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    profile = {
        "schema": PROFILE_SCHEMA,
        "embodiments": [
            {
                "label": label,
                "body_ref": f"cluster:{label}:compaii",
                "principal_id": f"compaii@{label}",
                "listen_host": "127.0.0.1",
                "listen_port": port,
                "advertised_endpoint": f"http://127.0.0.1:{port}/dm-peer/v1",
            }
            for label, port in (("host-a", 18686), ("host-b", 19686))
        ],
    }
    profile_path = source / "bootstrap-profile.json"
    profile_path.write_text(json.dumps(profile, sort_keys=True, separators=(",", ":")))
    root_password = b"h7-offline-root-password"
    passwords = {
        "host-a": b"h7-host-a-runtime-password",
        "host-b": b"h7-host-b-runtime-password",
    }
    output = source / "bootstrap"
    _create(
        output,
        profile_path,
        _descriptor(root_password),
        [
            f"{label}={_descriptor(password)}"
            for label, password in sorted(passwords.items())
        ],
    )
    authority_document = json.loads((output / "authority.json").read_bytes())
    authority = authority_from_document(authority_document)
    peers = {}
    peer_passwords = {}
    target_rows = []
    for label, port in (("host-a", 18686), ("host-b", 19686)):
        root = output / "runtimes" / label
        bundle = json.loads((root / "runtime.json").read_bytes())
        embodiment_id = bundle["local_origin"]["embodiment_id"]
        peers[embodiment_id] = root
        peer_passwords[embodiment_id] = passwords[label]
        target_rows.append(
            {
                "embodiment_id": embodiment_id,
                "endpoint": f"http://127.0.0.1:{port}/dm-peer/v1",
                "timeout_ms": 5_000,
            }
        )
    target_password = b"h7-fresh-target-password"
    preparation_root = source / "target-preparation"
    preparation = create_target_preparation(
        preparation_root,
        authority,
        {
            "schema": "dm.operator.rebirth-target-profile/v1",
            "label": "host-c",
            "body_ref": "cluster:host-c:compaii",
            "principal_id": "compaii@host-c",
            "listen_host": "127.0.0.1",
            "listen_port": 20686,
            "advertised_endpoint": "http://127.0.0.1:20686/dm-peer/v1",
            "targets": target_rows,
        },
        lambda: bytearray(target_password),
        created_at_ms=now_ms,
        expires_at_ms=now_ms + 60_000,
    )
    request = json.loads((preparation_root / "request.json").read_bytes())
    activation = authorize_from_root_custody(
        request,
        authority,
        output / "offline/root-custody.json",
        lambda: bytearray(root_password),
        issued_at_ms=now_ms + 10,
    )
    package = source / "target-package"
    activate_target_runtime(
        package,
        preparation_root,
        preparation,
        request,
        activation,
        json.loads((output / "runtimes/host-a/runtime.json").read_bytes()),
        lambda: bytearray(target_password),
    )
    return {
        "package": package,
        "peers": peers,
        "peer_passwords": peer_passwords,
        "password": target_password,
        "activation": activation,
    }


def _install(tmp_path: Path, *, ceremony_now_ms: int = 1_800_000_000_000, **changes):
    fixture = _ceremony(tmp_path, now_ms=ceremony_now_ms)
    state = tmp_path / "cluster-state"
    state.mkdir(mode=0o700)
    values = {
        "state_dir": state,
        "package_dir": fixture["package"],
        "peer_roots": fixture["peers"],
        "idempotency_key": str(uuid.uuid4()),
    }
    values.update(changes)
    return fixture, state, values


def _spawn_matrix_host(state: Path, embodiment_id: str, password: bytes):
    _ensure_production_fences(state)
    password_read, password_write = os.pipe()
    ready_read, ready_write = os.pipe()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "clusterctl.matrix_host",
            "--state-dir",
            str(state),
            "--embodiment-id",
            embodiment_id,
            "--password-fd",
            str(password_read),
            "--ready-fd",
            str(ready_write),
        ],
        pass_fds=(password_read, ready_write),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(password_read)
    os.close(ready_write)
    os.write(password_write, password)
    os.close(password_write)
    ready = os.read(ready_read, 64)
    os.close(ready_read)
    if ready != b"READY\n":
        _stdout, stderr = process.communicate(timeout=10)
        raise AssertionError(stderr)
    return process


def _operator_client(root: Path, profile: str = "observe") -> LocalClient:
    client_root = root if profile == "observe" else root / "operator-clients" / profile
    key_name = "client.key" if profile == "observe" else "capability.key"
    config = ClientConfig.load(
        client_root / "client.json", (client_root / key_name).read_bytes()
    )
    return LocalClient(root / "matrix.sock", config)


def test_recursive_package_install_preserves_owner_only_tree(short_tmp_path):
    source = short_tmp_path / "source"
    nested = source / "operator-clients" / "observe"
    nested.mkdir(parents=True, mode=0o700)
    source.chmod(0o700)
    nested.parent.chmod(0o700)
    nested.chmod(0o700)
    payload = nested / "client.json"
    payload.write_bytes(b"{}")
    payload.chmod(0o600)
    transient = nested / ".custody.json.lock"
    transient.write_bytes(b"")
    transient.chmod(0o600)

    target = short_tmp_path / "target"
    expected = rebirth._install_directory(source, target)

    assert expected == {
        "operator-clients/observe/client.json": hashlib.sha256(b"{}").hexdigest()
    }
    assert not (target / "operator-clients/observe/.custody.json.lock").exists()
    for directory in (
        target,
        target / "operator-clients",
        target / "operator-clients/observe",
    ):
        assert directory.stat().st_mode & 0o077 == 0
    assert (target / "operator-clients/observe/client.json").stat().st_mode & 0o077 == 0
    assert rebirth._install_directory(source, target) == expected


@pytest.mark.parametrize("unsafe_kind", ["symlink", "group-readable", "too-deep"])
def test_recursive_package_install_rejects_unsafe_source(short_tmp_path, unsafe_kind):
    source = short_tmp_path / "source"
    source.mkdir(mode=0o700)
    if unsafe_kind == "too-deep":
        parent = source
        for index in range(rebirth._MAX_PACKAGE_DEPTH + 1):
            parent = parent / f"level-{index}"
            parent.mkdir(mode=0o700)
        payload = parent / "client.json"
        payload.write_bytes(b"{}")
        payload.chmod(0o600)
    else:
        payload = source / "client.json"
        payload.write_bytes(b"{}")
        payload.chmod(0o640 if unsafe_kind == "group-readable" else 0o600)
        if unsafe_kind == "symlink":
            link = source / "linked.json"
            link.symlink_to(payload)

    with pytest.raises(
        rebirth.RebirthInstallError, match="rebirth_package_file_rejected"
    ):
        rebirth._install_directory(source, short_tmp_path / "target")


def test_recursive_package_install_rehashes_source_before_commit(
    short_tmp_path, monkeypatch
):
    source = short_tmp_path / "source"
    source.mkdir(mode=0o700)
    payload = source / "client.json"
    payload.write_bytes(b'{"version":1}')
    payload.chmod(0o600)
    original = rebirth._directory_files
    calls = 0

    def replace_after_manifest(path):
        nonlocal calls
        calls += 1
        if calls == 2:
            payload.write_bytes(b'{"version":2}')
            payload.chmod(0o600)
        return original(path)

    monkeypatch.setattr(rebirth, "_directory_files", replace_after_manifest)
    with pytest.raises(
        rebirth.RebirthInstallError, match="rebirth_package_file_replaced"
    ):
        rebirth._install_directory(source, short_tmp_path / "target")
    assert not (short_tmp_path / "target").exists()


def test_v7_snapshot_rejects_incomplete_profiles_and_excludes_all_client_keys(
    short_tmp_path,
):
    fixture = _ceremony(short_tmp_path)
    source = fixture["peers"][min(fixture["peers"])]
    bundle_path = source / "runtime.json"
    original_bundle = bundle_path.read_bytes()
    incomplete = json.loads(original_bundle)
    incomplete["capabilities"] = []
    bundle_path.write_bytes(canonical_bytes(incomplete))
    bundle_path.chmod(0o600)
    rejected = short_tmp_path / "incomplete-v7-snapshot"
    with pytest.raises(MatrixHostError, match="matrix_snapshot_source_unsafe"):
        create_portable_snapshot(source, rejected)
    assert not rejected.exists()
    bundle_path.write_bytes(original_bundle)
    bundle_path.chmod(0o600)

    client_secrets = [
        path.read_bytes()
        for path in source.rglob("*")
        if path.is_file() and path.name in {"client.key", "capability.key"}
    ]
    assert len(client_secrets) == 12
    restored_bundle = json.loads(original_bundle)
    ledger = source / restored_bundle["ledger"]
    ledger.write_bytes(b"")
    ledger.chmod(0o600)
    snapshot = short_tmp_path / "v7-snapshot"
    manifest = create_portable_snapshot(source, snapshot)
    copied = b"".join(
        path.read_bytes() for path in snapshot.rglob("*") if path.is_file()
    )
    assert all(secret not in copied for secret in client_secrets)
    assert {row["name"] for row in manifest["files"]}.isdisjoint(
        {"client.json", "client.key", "operator-clients", "host-clients"}
    )


def test_journaled_install_adds_stopped_target_and_loadable_empty_runtime(tmp_path):
    fixture, state, values = _install(tmp_path)
    result = rebirth.install_rebirth_package(**values)
    replay = rebirth.install_rebirth_package(**values)
    assert replay == result
    record = Registry(state).status(result["embodiment_id"])
    assert record["status"] == "stopped"
    assert record["current_incarnation_id"] is None
    assert matrix_client_root(state, result["embodiment_id"]).is_dir()
    root = matrix_root(state, result["embodiment_id"])
    hosted = load_runtime(
        root,
        "runtime.json",
        lambda: bytearray(fixture["password"]),
        clock=lambda: 1_800_000_000_020,
    )
    assert hosted.service.ledger.events() == []
    assert (
        hosted.service.ledger.local_origin["embodiment_id"] == result["embodiment_id"]
    )
    for peer_root in fixture["peers"].values():
        bundle = json.loads((peer_root / "runtime.json").read_bytes())
        assert bundle["manifest"]["revision"] == 2
        assert len(bundle["authority_history"]) == 1
        assert result["embodiment_id"] in {
            row["embodiment_id"] for row in bundle["peer_transport"]["targets"]
        }
    assert OperationJournal(state).list_all(limit=10)[0]["state"] == "completed"


def test_same_activation_with_a_new_idempotency_key_replays_one_result(tmp_path):
    _fixture, state, values = _install(tmp_path)
    result = rebirth.install_rebirth_package(**values)
    values["idempotency_key"] = str(uuid.uuid4())
    assert rebirth.install_rebirth_package(**values) == result
    assert len(OperationJournal(state).list_all(limit=10)) == 1
    assert (
        sum(event["action"] == "rebirth-install" for event in audit.read_events(state))
        == 1
    )


def test_concurrent_exact_invocations_converge_after_lock(tmp_path, monkeypatch):
    _fixture, state, values = _install(tmp_path)
    original_acquire_many = rebirth.acquire_many
    second_arrived = threading.Event()
    first_finished = threading.Event()
    ordinal_lock = threading.Lock()
    ordinal = 0

    @contextmanager
    def serialized_acquire(*args, **kwargs):
        nonlocal ordinal
        with ordinal_lock:
            current = ordinal
            ordinal += 1
        if current == 0:
            assert second_arrived.wait(timeout=10)
            with original_acquire_many(*args, **kwargs) as acquired:
                yield acquired
            first_finished.set()
        else:
            second_arrived.set()
            assert first_finished.wait(timeout=10)
            with original_acquire_many(*args, **kwargs) as acquired:
                yield acquired

    monkeypatch.setattr(rebirth, "acquire_many", serialized_acquire)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(rebirth.install_rebirth_package, **values) for _ in range(2)
        ]
        results = [future.result(timeout=20) for future in futures]
    assert results[0] == results[1]
    assert len(OperationJournal(state).list_all(limit=10)) == 1
    assert (
        sum(event["action"] == "rebirth-install" for event in audit.read_events(state))
        == 1
    )


def test_cli_installs_exact_peer_set_and_emits_receipt(tmp_path, capsys):
    fixture, state, values = _install(tmp_path)
    arguments = [
        "--state-dir",
        str(state),
        "rebirth-install",
        "--package-dir",
        str(fixture["package"]),
        "--idempotency-key",
        values["idempotency_key"],
        "--json",
    ]
    for embodiment_id, root in sorted(fixture["peers"].items()):
        arguments.extend(("--peer", f"{embodiment_id}={root}"))
    assert cli.run(arguments) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "installed-stopped"
    assert Registry(state).status(result["embodiment_id"])["status"] == "stopped"


def test_supervisor_starts_exact_authorized_incarnation_and_restarts(short_tmp_path):
    fixture, state, values = _install(
        short_tmp_path, ceremony_now_ms=time.time_ns() // 1_000_000
    )
    installed = rebirth.install_rebirth_package(**values)
    _ensure_production_fences(state, installed["embodiment_id"])
    process, ready = rebirth_host.launch_rebirth_host(
        state,
        installed["embodiment_id"],
        _descriptor(fixture["password"]),
    )
    try:
        assert ready["state"] == "running-ready"
        assert ready["incarnation_id"] == installed["incarnation_id"]
        assert ready["embodiment_id"] in ready["active_embodiment_ids"]
        registered = Registry(state).status(ready["embodiment_id"])
        assert registered["status"] == "running"
        assert registered["current_incarnation_id"] == ready["incarnation_id"]
        assert fixture["password"] not in b"\0".join(
            str(argument).encode() for argument in process.args
        )
        assert (
            fixture["password"] not in Path(f"/proc/{process.pid}/environ").read_bytes()
        )
    finally:
        process.terminate()
        _stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr

    client = rebirth_host._configured_admission_client(
        state, rebirth_host._installed_identity(state, installed["embodiment_id"])
    )
    deadline = time.monotonic() + 5
    while client.position()["current"] is True and time.monotonic() < deadline:
        time.sleep(0.01)
    assert client.position()["current"] is False
    restarted, replay = rebirth_host.launch_rebirth_host(
        state,
        installed["embodiment_id"],
        _descriptor(fixture["password"]),
    )
    try:
        assert {key: value for key, value in replay.items() if key != "admission"} == {
            key: value for key, value in ready.items() if key != "admission"
        }
        assert (
            replay["admission"]["fencing_token"] > ready["admission"]["fencing_token"]
        )
        assert len(OperationJournal(state).list_all(limit=10)) == 2
        assert (
            sum(
                event["action"] == "rebirth-start" for event in audit.read_events(state)
            )
            == 1
        )
    finally:
        restarted.terminate()
        _stdout, stderr = restarted.communicate(timeout=10)
        assert restarted.returncode == 0, stderr


def test_supervisor_fails_closed_without_shared_admission(short_tmp_path):
    fixture, state, values = _install(
        short_tmp_path, ceremony_now_ms=time.time_ns() // 1_000_000
    )
    installed = rebirth.install_rebirth_package(**values)
    descriptor = _descriptor(fixture["password"])
    with pytest.raises(rebirth_host.RebirthHostError, match="admission_config_missing"):
        rebirth_host.launch_rebirth_host(state, installed["embodiment_id"], descriptor)
    with pytest.raises(OSError):
        os.read(descriptor, 1)
    assert Registry(state).status(installed["embodiment_id"])["status"] == "stopped"


def test_repeated_clean_restart_has_no_socket_or_admission_race(short_tmp_path):
    fixture, state, values = _install(
        short_tmp_path, ceremony_now_ms=time.time_ns() // 1_000_000
    )
    installed = rebirth.install_rebirth_package(**values)
    _ensure_production_fences(state, installed["embodiment_id"])
    identity = rebirth_host._installed_identity(state, installed["embodiment_id"])
    tokens = []
    for _iteration in range(8):
        process, ready = rebirth_host.launch_rebirth_host(
            state,
            installed["embodiment_id"],
            _descriptor(fixture["password"]),
            admission_lease_ttl_s=3,
        )
        tokens.append(ready["admission"]["fencing_token"])
        process.terminate()
        _stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr
        observer = rebirth_host._configured_admission_client(state, identity)
        deadline = time.monotonic() + 3
        while observer.position()["current"] is True and time.monotonic() < deadline:
            time.sleep(0.01)
        assert observer.position()["current"] is False
    assert tokens == sorted(tokens)
    assert len(set(tokens)) == len(tokens)


def test_shared_admission_allows_only_one_ready_across_state_dirs(short_tmp_path):
    fixture, state_a, values = _install(
        short_tmp_path, ceremony_now_ms=time.time_ns() // 1_000_000
    )
    installed = rebirth.install_rebirth_package(**values)
    state_b = short_tmp_path / "cloned-state"
    shutil.copytree(state_a, state_b)
    _ensure_production_fences(state_a, installed["embodiment_id"])
    _ensure_production_fences(state_b)
    config_b = state_b / "admission-client.json"
    config_b.write_bytes((state_a / "admission-client.json").read_bytes())
    config_b.chmod(0o600)

    context = multiprocessing.get_context("spawn")
    gate = context.Barrier(3)
    stop = context.Event()
    results = context.Queue()
    workers = [
        context.Process(
            target=_rebirth_race_worker,
            args=(
                str(state),
                installed["embodiment_id"],
                fixture["password"],
                gate,
                stop,
                results,
            ),
        )
        for state in (state_a, state_b)
    ]
    for worker in workers:
        worker.start()
    gate.wait()
    outcomes = [results.get(timeout=20) for _ in workers]
    stop.set()
    for worker in workers:
        worker.join(timeout=15)
        assert worker.exitcode == 0
    assert sorted(outcome[0] for outcome in outcomes) == ["ready", "refused"]
    refusal = next(value for outcome, value in outcomes if outcome == "refused")
    assert refusal == "rebirth_host_admission_refused"


def test_supervisor_stops_runtime_before_lease_expiry_on_authority_loss(
    short_tmp_path, monkeypatch
):
    fixture, state, values = _install(
        short_tmp_path, ceremony_now_ms=time.time_ns() // 1_000_000
    )
    installed = rebirth.install_rebirth_package(**values)
    _ensure_production_fences(state, installed["embodiment_id"])
    process, ready = rebirth_host.launch_rebirth_host(
        state,
        installed["embodiment_id"],
        _descriptor(fixture["password"]),
        admission_lease_ttl_s=3,
    )
    server, thread = _DISPOSABLE_ADMISSION_SERVERS.pop()
    started = time.monotonic()
    real_time_ns = time.time_ns
    # Simulate the host wall clock stepping ten seconds backwards after READY.
    # Lease supervision must use elapsed monotonic time only.
    monkeypatch.setattr(time, "time_ns", lambda: real_time_ns() - 10_000_000_000)
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
    _stdout, stderr = process.communicate(timeout=5)
    assert process.returncode == -signal.SIGKILL, stderr
    assert time.monotonic() - started < 2.25
    assert ready["admission"]["lease_expires_at_ms"] > 0


def test_monotonic_watchdog_kills_while_renew_round_trip_is_stuck():
    class StuckClient:
        session_id = "test-session"

        def renew(self, *, ttl_s):
            del ttl_s
            time.sleep(1.5)
            raise rebirth_host.AdmissionError("stuck authority")

        def release(self):
            raise rebirth_host.AdmissionError("stuck authority")

    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    started = time.monotonic()
    supervisor = rebirth_host._AdmissionSupervisor(
        process,
        StuckClient(),  # type: ignore[arg-type]
        {"lease_expires_at_ms": -10_000_000},
        1,
        lease_started_monotonic=started,
    )
    supervisor.start()
    _stdout, _stderr = process.communicate(timeout=2)
    assert process.returncode == -signal.SIGKILL
    assert time.monotonic() - started < 0.9
    supervisor.thread.join(timeout=3)


def test_committed_renew_response_loss_releases_after_runtime_stops(
    short_tmp_path, monkeypatch
):
    fixture, state, values = _install(
        short_tmp_path, ceremony_now_ms=time.time_ns() // 1_000_000
    )
    installed = rebirth.install_rebirth_package(**values)
    _ensure_production_fences(state, installed["embodiment_id"])
    identity = rebirth_host._installed_identity(state, installed["embodiment_id"])
    client = rebirth_host._configured_admission_client(state, identity)
    real_renew = client.renew
    renew_committed = threading.Event()

    def renew_then_lose_response(*, ttl_s):
        real_renew(ttl_s=ttl_s)
        renew_committed.set()
        raise rebirth_host.AdmissionError("renew response lost")

    monkeypatch.setattr(client, "renew", renew_then_lose_response)
    process, _ready = rebirth_host.launch_rebirth_host(
        state,
        installed["embodiment_id"],
        _descriptor(fixture["password"]),
        admission_client=client,
        admission_lease_ttl_s=3,
    )
    supervisor = rebirth_host._SUPERVISORS[process.pid]
    _stdout, stderr = process.communicate(timeout=5)
    supervisor.thread.join(timeout=2)
    assert renew_committed.is_set()
    assert process.returncode == -signal.SIGKILL, stderr
    assert not supervisor.thread.is_alive()
    observer = rebirth_host._configured_admission_client(state, identity)
    deadline = time.monotonic() + 2
    while observer.position()["current"] is True and time.monotonic() < deadline:
        time.sleep(0.01)
    assert observer.position()["current"] is False


def test_launcher_sigkill_cannot_leave_executing_orphan_beyond_lease(
    short_tmp_path,
):
    fixture, state, values = _install(
        short_tmp_path, ceremony_now_ms=time.time_ns() // 1_000_000
    )
    installed = rebirth.install_rebirth_package(**values)
    _ensure_production_fences(state, installed["embodiment_id"])
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    launcher = context.Process(
        target=_launcher_kill_worker,
        args=(
            str(state),
            installed["embodiment_id"],
            fixture["password"],
            results,
        ),
    )
    launcher.start()
    child_pid, lease_expires_at_ms = results.get(timeout=20)
    os.kill(launcher.pid, signal.SIGKILL)
    launcher.join(timeout=5)
    assert launcher.exitcode == -signal.SIGKILL
    deadline = time.monotonic() + 2
    executing = True
    while time.monotonic() < deadline:
        stat_path = Path(f"/proc/{child_pid}/stat")
        if not stat_path.exists():
            executing = False
            break
        try:
            executing = stat_path.read_text().split()[2] != "Z"
        except FileNotFoundError:
            executing = False
        if not executing:
            break
        time.sleep(0.02)
    assert executing is False
    assert time.time_ns() // 1_000_000 < lease_expires_at_ms


def test_admission_is_rechecked_before_first_runtime_effect(
    short_tmp_path, monkeypatch
):
    fixture, state, values = _install(
        short_tmp_path, ceremony_now_ms=time.time_ns() // 1_000_000
    )
    installed = rebirth.install_rebirth_package(**values)
    _ensure_production_fences(state, installed["embodiment_id"])
    identity = rebirth_host._installed_identity(state, installed["embodiment_id"])
    client = rebirth_host._configured_admission_client(state, identity)
    monkeypatch.setattr(client, "current", lambda: None)

    def forbidden_spawn(*_args, **_kwargs):
        raise AssertionError("runtime spawn crossed a lost admission boundary")

    monkeypatch.setattr(rebirth_host.subprocess, "Popen", forbidden_spawn)
    with pytest.raises(rebirth_host.RebirthHostError, match="lost_before_effect"):
        rebirth_host.launch_rebirth_host(
            state,
            installed["embodiment_id"],
            _descriptor(fixture["password"]),
            admission_client=client,
            admission_lease_ttl_s=3,
        )
    assert Registry(state).status(installed["embodiment_id"])["status"] == "stopped"


def test_registry_start_is_compensated_if_admission_is_lost_in_race(
    short_tmp_path, monkeypatch
):
    fixture, state, values = _install(
        short_tmp_path, ceremony_now_ms=time.time_ns() // 1_000_000
    )
    installed = rebirth.install_rebirth_package(**values)
    _ensure_production_fences(state, installed["embodiment_id"])
    identity = rebirth_host._installed_identity(state, installed["embodiment_id"])
    client = rebirth_host._configured_admission_client(state, identity)
    original_start = Registry.start

    def start_then_lose_admission(self, *args, **kwargs):
        result = original_start(self, *args, **kwargs)
        client.release()
        return result

    monkeypatch.setattr(Registry, "start", start_then_lose_admission)

    def forbidden_spawn(*_args, **_kwargs):
        raise AssertionError("runtime spawned after admission loss")

    monkeypatch.setattr(rebirth_host.subprocess, "Popen", forbidden_spawn)
    with pytest.raises(rebirth_host.RebirthHostError, match="lost_after_registry"):
        rebirth_host.launch_rebirth_host(
            state,
            installed["embodiment_id"],
            _descriptor(fixture["password"]),
            admission_client=client,
            admission_lease_ttl_s=3,
        )
    registered = Registry(state).status(installed["embodiment_id"])
    assert registered["status"] == "stopped"
    assert registered["current_incarnation_id"] is None
    assert all(
        row["incarnation_id"] != installed["incarnation_id"]
        for row in registered["incarnations"]
    )
    journaled = OperationJournal(state).open_operations()[0]
    assert journaled["state"] == "runtime-dispatching"
    assert journaled["runtime_observation"] == {
        "registry_start_compensated": True,
        "embodiment_id": installed["embodiment_id"],
        "incarnation_id": installed["incarnation_id"],
        "reason": "rebirth_host_admission_lost_after_registry",
    }


def test_failed_password_resumes_same_admitted_incarnation(short_tmp_path):
    fixture, state, values = _install(
        short_tmp_path, ceremony_now_ms=time.time_ns() // 1_000_000
    )
    installed = rebirth.install_rebirth_package(**values)
    _ensure_production_fences(state, installed["embodiment_id"])
    with pytest.raises(rebirth_host.RebirthHostError, match="startup"):
        rebirth_host.launch_rebirth_host(
            state,
            installed["embodiment_id"],
            _descriptor(b"incorrect-target-password"),
        )
    record = Registry(state).status(installed["embodiment_id"])
    assert record["status"] == "running"
    assert record["current_incarnation_id"] == installed["incarnation_id"]
    pending = OperationJournal(state).open_operations()
    assert pending[0]["operation"] == "rebirth-start"
    assert pending[0]["state"] == "runtime-dispatching"

    process, result = rebirth_host.launch_rebirth_host(
        state,
        installed["embodiment_id"],
        _descriptor(fixture["password"]),
    )
    try:
        assert result["state"] == "running-ready"
        assert OperationJournal(state).open_operations() == []
    finally:
        process.terminate()
        _stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr


def test_three_processes_exchange_new_origin_events_without_implicit_adoption(
    short_tmp_path,
):
    now_ms = time.time_ns() // 1_000_000
    fixture, state, values = _install(short_tmp_path, ceremony_now_ms=now_ms)
    registry = Registry(state)
    hosted_peers = {}
    for embodiment_id, source in fixture["peers"].items():
        target = matrix_root(state, embodiment_id)
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        target.parent.chmod(0o700)
        shutil.copytree(source, target)
        bundle = json.loads((target / "runtime.json").read_bytes())
        origin = bundle["local_origin"]
        registry.register(
            body_ref=origin["body_ref"], embodiment_id=origin["embodiment_id"]
        )
        registry.start(
            origin["embodiment_id"],
            incarnation_id=origin["incarnation_id"],
            started_at_ms=now_ms,
        )
        hosted_peers[embodiment_id] = target
    values["peer_roots"] = hosted_peers
    installed = rebirth.install_rebirth_package(**values)
    _ensure_production_fences(state, installed["embodiment_id"])

    processes = []
    target_supervisor = None
    try:
        for embodiment_id, root in hosted_peers.items():
            processes.append(
                _spawn_matrix_host(
                    state, embodiment_id, fixture["peer_passwords"][embodiment_id]
                )
            )
            assert (
                _operator_client(root).runtime_status()[1]["result"]["integrity"]
                == "ok"
            )
        target_process, ready = rebirth_host.launch_rebirth_host(
            state,
            installed["embodiment_id"],
            _descriptor(fixture["password"]),
        )
        target_supervisor = rebirth_host._SUPERVISORS[target_process.pid]
        processes.append(target_process)
        target_root = matrix_root(state, installed["embodiment_id"])
        target_client = _operator_client(target_root)
        target_weave_client = _operator_client(target_root, "weave")
        peer_id = min(hosted_peers)
        peer_client = _operator_client(hosted_peers[peer_id])
        peer_weave_client = _operator_client(hosted_peers[peer_id], "weave")
        assert ready["active_embodiment_ids"] == sorted(
            [*hosted_peers, installed["embodiment_id"]]
        )
        assert target_client.scope_we()[1]["result"]["partial"] is False

        target_observation = target_client.we_observe(
            {
                "subject": "h8-target-origin",
                "payload": {"summary": "fresh embodiment event"},
                "sensitivity": "shareable",
                "causal_parents": [],
                "occurred_at_ms": now_ms + 20,
                "event_id": None,
            },
            request_id=str(uuid.uuid4()),
        )[1]["result"]["event"]
        pull_params = {
            "sync_request_id": str(uuid.uuid4()),
            "target_embodiment_id": installed["embodiment_id"],
            "limit": 16,
        }
        request_id = str(uuid.uuid4())
        prepared_pull = peer_weave_client.prepare(
            "we.sync.peer-pull", pull_params, request_id=request_id
        )
        first_pull = peer_weave_client.send(prepared_pull)
        assert first_pull["ok"] is True
        assert first_pull["result"]["events"] == 1
        assert peer_weave_client.send(prepared_pull) == first_pull

        peer_observation = peer_client.we_observe(
            {
                "subject": "h8-existing-origin",
                "payload": {"summary": "existing embodiment event"},
                "sensitivity": "shareable",
                "causal_parents": [],
                "occurred_at_ms": now_ms + 21,
                "event_id": None,
            },
            request_id=str(uuid.uuid4()),
        )[1]["result"]["event"]
        reverse = target_weave_client.sync_peer_pull(
            {
                "sync_request_id": str(uuid.uuid4()),
                "target_embodiment_id": peer_id,
                "limit": 16,
            },
            request_id=str(uuid.uuid4()),
        )[1]
        assert reverse["ok"] is True
        assert reverse["result"]["events"] >= 1
        target_projection = target_weave_client.projection_rebuild()[1]["result"]
        peer_projection = peer_weave_client.projection_rebuild()[1]["result"]
        assert (
            next(
                row
                for row in target_projection["entries"]
                if row["event_id"] == peer_observation["event_id"]
            )["state"]
            == "pending"
        )
        assert (
            next(
                row
                for row in peer_projection["entries"]
                if row["event_id"] == target_observation["event_id"]
            )["state"]
            == "pending"
        )
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in reversed(processes):
            _stdout, stderr = process.communicate(timeout=10)
            assert process.returncode == 0, stderr
        if target_supervisor is not None:
            target_supervisor.thread.join(timeout=2)
            assert not target_supervisor.thread.is_alive()


@pytest.mark.parametrize(
    "boundary",
    [
        "after-plan",
        "after-runtime-dispatch",
        "after-target-install",
        "after-first-peer-update",
        "after-runtime-observation",
        "after-registry",
        "after-audit",
        "after-completed",
    ],
)
def test_crash_and_response_loss_resume_one_exact_install(
    tmp_path, monkeypatch, boundary
):
    _fixture, state, values = _install(tmp_path)
    crashed = False

    def fail(name, _record):
        nonlocal crashed
        matches = name == boundary or (
            boundary == "after-first-peer-update"
            and name.startswith("after-peer-update:")
        )
        if matches and not crashed:
            crashed = True
            raise SimulatedCrash

    monkeypatch.setattr(rebirth, "_MUTATION_BOUNDARY_HOOK", fail)
    with pytest.raises(SimulatedCrash):
        rebirth.install_rebirth_package(**values)
    monkeypatch.setattr(rebirth, "_MUTATION_BOUNDARY_HOOK", None)
    result = rebirth.install_rebirth_package(**values)
    assert result["state"] == "installed-stopped"
    assert OperationJournal(state).list_all(limit=10)[0]["state"] == "completed"
    assert Registry(state).status(result["embodiment_id"])["status"] == "stopped"
    events = audit.read_events(state)
    assert sum(event["action"] == "rebirth-install" for event in events) == 1


def test_changed_package_or_incomplete_peer_set_fails_before_install(tmp_path):
    fixture, state, values = _install(tmp_path)
    missing = dict(values)
    missing["peer_roots"] = dict(list(fixture["peers"].items())[:1])
    with pytest.raises(rebirth.RebirthInstallError, match="peer_set_mismatch"):
        rebirth.install_rebirth_package(**missing)
    assert not (state / "matrix").exists()

    values["idempotency_key"] = str(uuid.uuid4())
    rebirth.install_rebirth_package(**values)
    receipt_path = fixture["package"] / "receipt.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt["successor_manifest_hash"] = "0" * 64
    receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    with pytest.raises(rebirth.RebirthInstallError, match="receipt_rejected"):
        rebirth.install_rebirth_package(
            state,
            fixture["package"],
            fixture["peers"],
            idempotency_key=str(uuid.uuid4()),
        )


def test_public_distributed_rollout_contains_no_target_custody(tmp_path, capsys):
    fixture, state, _values = _install(tmp_path)
    output = state / "public" / "rollout.json"
    assert (
        cli.run(
            [
                "--state-dir",
                str(state),
                "rebirth-rollout-create",
                "--package-dir",
                str(fixture["package"]),
                "--output",
                str(output),
                "--json",
            ]
        )
        == 0
    )
    rollout = json.loads(capsys.readouterr().out)
    assert (
        distributed_rebirth.create_rollout_bundle(fixture["package"], output) == rollout
    )
    assert rollout["participant_embodiment_ids"] == sorted(fixture["peers"])
    assert rollout["target"]["embodiment_id"] not in fixture["peers"]
    raw = output.read_bytes()
    assert raw == json.dumps(rollout, sort_keys=True, separators=(",", ":")).encode()
    assert fixture["password"] not in raw
    assert b"keystore" not in raw.lower()
    assert b"client.key" not in raw.lower()
    assert output.stat().st_mode & 0o077 == 0

    changed = json.loads(raw)
    changed["target"]["advertised_endpoint"] += "/changed"
    with pytest.raises(
        distributed_rebirth.DistributedRebirthError, match="rollout_id_mismatch"
    ):
        distributed_rebirth.validate_rollout(changed)


def test_peer_rollout_waits_for_authenticated_restarted_daemon(short_tmp_path):
    now_ms = time.time_ns() // 1_000_000
    fixture, state, _values = _install(short_tmp_path, ceremony_now_ms=now_ms)
    _ensure_production_fences(state)
    rollout = distributed_rebirth.create_rollout_bundle(fixture["package"])
    peer_id = min(fixture["peers"])
    source = fixture["peers"][peer_id]
    target = matrix_root(state, peer_id)
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    target.parent.chmod(0o700)
    shutil.copytree(source, target)
    client_target = matrix_client_root(state, peer_id)
    client_target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    shutil.copytree(source / "host-clients/status", client_target)
    curator_target = matrix_curator_client_root(state, peer_id)
    curator_target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    shutil.copytree(source / "host-clients/curator", curator_target)
    origin = json.loads((target / "runtime.json").read_bytes())["local_origin"]
    registry = Registry(state)
    registry.register(body_ref=origin["body_ref"], embodiment_id=peer_id)
    registry.start(
        peer_id,
        incarnation_id=origin["incarnation_id"],
        started_at_ms=now_ms,
    )

    application = distributed_rebirth.apply_peer_rollout(state, rollout, peer_id)
    assert application["state"] == "restart-required"
    record = OperationJournal(state).latest_for_target(
        f"distributed-rebirth:{rollout['rollout_id']}:{peer_id}"
    )
    assert record is not None
    assert record["state"] == "runtime-applied"
    with pytest.raises(
        distributed_rebirth.DistributedRebirthError, match="status_rejected"
    ):
        distributed_rebirth.acknowledge_peer_rollout(state, rollout, peer_id)

    process = _spawn_matrix_host(state, peer_id, fixture["peer_passwords"][peer_id])
    try:
        acknowledgement = distributed_rebirth.acknowledge_peer_rollout(
            state, rollout, peer_id
        )
        assert acknowledgement["state"] == "completed"
        assert acknowledgement["incarnation_id"] == origin["incarnation_id"]
        assert (
            acknowledgement["successor_manifest_hash"]
            == rollout["successor_manifest_hash"]
        )
        assert (
            distributed_rebirth.acknowledge_peer_rollout(state, rollout, peer_id)
            == acknowledgement
        )
        assert (
            distributed_rebirth.apply_peer_rollout(state, rollout, peer_id)["state"]
            == "already-acknowledged"
        )
        assert (
            sum(
                event["action"] == "distributed-rebirth-peer-ack"
                for event in audit.read_events(state)
            )
            == 1
        )
    finally:
        process.terminate()
        _stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr


def test_distributed_target_cannot_start_before_exact_all_peer_admission(
    short_tmp_path,
):
    now_ms = time.time_ns() // 1_000_000
    fixture, _unused_state, _values = _install(short_tmp_path, ceremony_now_ms=now_ms)
    rollout = distributed_rebirth.create_rollout_bundle(fixture["package"])
    state = short_tmp_path / "target-cluster-state"
    state.mkdir(mode=0o700)
    installed = distributed_rebirth.install_distributed_target(
        state,
        fixture["package"],
        rollout,
        idempotency_key=str(uuid.uuid4()),
    )
    assert installed["state"] == "installed-stopped"
    assert installed["admission_required"] is True
    assert installed["peer_bundle_sha256"] == {}
    with pytest.raises(rebirth_host.RebirthHostError, match="admission_missing"):
        rebirth_host.launch_rebirth_host(
            state,
            installed["embodiment_id"],
            _descriptor(fixture["password"]),
        )
    assert Registry(state).status(installed["embodiment_id"])["status"] == "stopped"

    incarnations = {
        item["embodiment_id"]: item["incarnation_id"]
        for item in rollout["activation"]["body"]["successor_manifest"]["embodiments"]
    }
    acknowledgements = [
        {
            "schema": distributed_rebirth.ACK_SCHEMA,
            "rollout_id": rollout["rollout_id"],
            "embodiment_id": embodiment_id,
            "incarnation_id": incarnations[embodiment_id],
            "successor_manifest_hash": rollout["successor_manifest_hash"],
            "runtime_sha256": hashlib.sha256(embodiment_id.encode()).hexdigest(),
            "operation_id": str(uuid.uuid4()),
            "audit_event_id": str(uuid.uuid4()),
            "state": "completed",
        }
        for embodiment_id in rollout["participant_embodiment_ids"]
    ]
    with pytest.raises(
        distributed_rebirth.DistributedRebirthError, match="ack_set_incomplete"
    ):
        distributed_rebirth.record_target_admission(
            state, rollout, acknowledgements[:-1]
        )
    admission = distributed_rebirth.record_target_admission(
        state, rollout, acknowledgements
    )
    _ensure_production_fences(state, installed["embodiment_id"])
    assert (
        distributed_rebirth.record_target_admission(
            state, rollout, [*acknowledgements, acknowledgements[0]]
        )
        == admission
    )

    process, result = rebirth_host.launch_rebirth_host(
        state,
        installed["embodiment_id"],
        _descriptor(fixture["password"]),
    )
    try:
        assert result["state"] == "running-ready"
        assert result["active_embodiment_ids"] == sorted(
            [
                *rollout["participant_embodiment_ids"],
                installed["embodiment_id"],
            ]
        )
    finally:
        process.terminate()
        _stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr
