from __future__ import annotations

import json
import os
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
from daimon_matrix.client import ClientConfig, LocalClient
from daimon_matrix.operator_bootstrap import PROFILE_SCHEMA, _create
from daimon_matrix.operator_rebirth import (
    activate_target_runtime,
    authority_from_document,
    authorize_from_root_custody,
    create_target_preparation,
)
from daimon_matrix.runtime import load_runtime

from clusterctl.embodiments import Registry
from clusterctl.matrix_host import matrix_client_root, matrix_root
from clusterctl.operation_journal import OperationJournal
from clusterctl import audit, cli, rebirth, rebirth_host


class SimulatedCrash(BaseException):
    pass


@pytest.fixture
def short_tmp_path():
    with tempfile.TemporaryDirectory(prefix="dmc-rebirth-") as value:
        yield Path(value)


def _descriptor(value: bytes) -> int:
    reader, writer = os.pipe()
    os.write(writer, value)
    os.close(writer)
    return reader


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


def _operator_client(root: Path) -> LocalClient:
    config = ClientConfig.load(root / "client.json", (root / "client.key").read_bytes())
    return LocalClient(root / "matrix.sock", config)


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

    restarted, replay = rebirth_host.launch_rebirth_host(
        state,
        installed["embodiment_id"],
        _descriptor(fixture["password"]),
    )
    try:
        assert replay == ready
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


def test_failed_password_resumes_same_admitted_incarnation(short_tmp_path):
    fixture, state, values = _install(
        short_tmp_path, ceremony_now_ms=time.time_ns() // 1_000_000
    )
    installed = rebirth.install_rebirth_package(**values)
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

    processes = []
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
        processes.append(target_process)
        target_root = matrix_root(state, installed["embodiment_id"])
        target_client = _operator_client(target_root)
        peer_id = sorted(hosted_peers)[0]
        peer_client = _operator_client(hosted_peers[peer_id])
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
        prepared_pull = peer_client.prepare(
            "we.sync.peer-pull", pull_params, request_id=request_id
        )
        first_pull = peer_client.send(prepared_pull)
        assert first_pull["ok"] is True
        assert first_pull["result"]["events"] == 1
        assert peer_client.send(prepared_pull) == first_pull

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
        reverse = target_client.sync_peer_pull(
            {
                "sync_request_id": str(uuid.uuid4()),
                "target_embodiment_id": peer_id,
                "limit": 16,
            },
            request_id=str(uuid.uuid4()),
        )[1]
        assert reverse["ok"] is True
        assert reverse["result"]["events"] >= 1
        target_projection = target_client.projection_rebuild()[1]["result"]
        peer_projection = peer_client.projection_rebuild()[1]["result"]
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
    fixture, state, values = _install(tmp_path)
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
