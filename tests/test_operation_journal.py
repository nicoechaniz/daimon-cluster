"""Crash/retry acceptance for the substrate mutation intent journal."""

from __future__ import annotations

import json
import sqlite3

import pytest

from clusterctl import audit, embodiments, idempotency, lifecycle
from clusterctl.adapters import FakeAdapter
from clusterctl.cli import run
from clusterctl.inventory import load_spec_raw
from clusterctl.operation_journal import JournalConflict, OperationJournal
from clusterd import handlers
from clusterd.handlers import _operation_journal_state

CREATE_KEY = "11111111-1111-4111-8111-111111111111"
START_KEY = "22222222-2222-4222-8222-222222222222"
STOP_KEY = "33333333-3333-4333-8333-333333333333"
RESTART_KEY = "44444444-4444-4444-8444-444444444444"


class SimulatedCrash(BaseException):
    pass


def _invoke(state_dir, adapter, *arguments):
    return run(
        ["--state-dir", str(state_dir), *arguments, "--json"], adapter=adapter
    )


def _created(state_dir, adapter):
    assert (
        _invoke(
            state_dir,
            adapter,
            "create",
            "daimon-x",
            "--species",
            "test",
            "--idempotency-key",
            CREATE_KEY,
        )
        == 0
    )
    return load_spec_raw(state_dir / "instances", "daimon-x")


@pytest.mark.parametrize(
    "boundary",
    [
        "after-plan",
        "after-runtime-dispatch-persist",
        "after-runtime-call",
        "after-runtime-observation",
        "after-registry",
        "after-spec",
        "after-logical-commit",
        "after-idempotency",
        "after-audit",
        "after-completed",
    ],
)
def test_start_crash_at_every_boundary_returns_one_incarnation_and_result(
    tmp_path, monkeypatch, capsys, boundary
):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()
    spec = _created(state_dir, adapter)
    capsys.readouterr()

    def crash(observed, _record):
        if observed == boundary:
            raise SimulatedCrash

    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", crash)
    with pytest.raises(SimulatedCrash):
        _invoke(
            state_dir,
            adapter,
            "start",
            "daimon-x",
            "--idempotency-key",
            START_KEY,
        )
    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", None)
    capsys.readouterr()
    assert (
        _invoke(
            state_dir,
            adapter,
            "start",
            "daimon-x",
            "--idempotency-key",
            START_KEY,
        )
        == 0
    )

    record = OperationJournal(state_dir).list_all(limit=10)[0]
    assert record["state"] == "completed"
    result = record["result"]
    assert result["operation_id"] == record["operation_id"]
    registry = embodiments.Registry(state_dir).status(spec["embodiment_id"])
    assert registry["status"] == "running"
    assert registry["current_incarnation_id"] == result["incarnation_id"]
    assert len(registry["incarnations"]) == 1
    final_spec = load_spec_raw(state_dir / "instances", "daimon-x")
    assert final_spec["current_incarnation_id"] == result["incarnation_id"]
    events = [
        json.loads(line)
        for line in (state_dir / "audit.jsonl").read_text().splitlines()
    ]
    successful = [
        event
        for event in events
        if event["action"] == "start" and event["result"] == "ok"
    ]
    assert successful
    assert sum(
        event["event_id"] == record["audit_event_id"] for event in successful
    ) == 1


@pytest.mark.parametrize(
    "boundary",
    [
        "after-plan",
        "after-runtime-dispatch-persist",
        "after-runtime-call",
        "after-runtime-observation",
        "after-spec",
        "after-registry",
        "after-logical-commit",
        "after-idempotency",
        "after-audit",
        "after-completed",
    ],
)
def test_create_crash_never_leaves_untracked_or_duplicate_container(
    tmp_path, monkeypatch, capsys, boundary
):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()

    def crash(observed, _record):
        if observed == boundary:
            raise SimulatedCrash

    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", crash)
    with pytest.raises(SimulatedCrash):
        _invoke(
            state_dir,
            adapter,
            "create",
            "daimon-x",
            "--species",
            "test",
            "--idempotency-key",
            CREATE_KEY,
        )
    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", None)
    capsys.readouterr()
    assert (
        _invoke(
            state_dir,
            adapter,
            "create",
            "daimon-x",
            "--species",
            "test",
            "--idempotency-key",
            CREATE_KEY,
        )
        == 0
    )
    assert [row["name"] for row in adapter.list_instances()] == ["daimon-x"]
    spec = load_spec_raw(state_dir / "instances", "daimon-x")
    registry = embodiments.Registry(state_dir).status(spec["embodiment_id"])
    assert registry["body_ref"] == spec["body_ref"]
    assert registry["status"] == "stopped"
    record = OperationJournal(state_dir).list_all(limit=10)[0]
    assert record["state"] == "completed"
    events = [
        json.loads(line)
        for line in (state_dir / "audit.jsonl").read_text().splitlines()
    ]
    assert sum(event["event_id"] == record["audit_event_id"] for event in events) == 1


@pytest.mark.parametrize(
    "boundary",
    [
        "after-plan",
        "after-runtime-dispatch-persist",
        "after-provision-create",
        "after-provision-start",
        "after-provision-volume",
        "after-provision-identity",
        "after-provision-seed",
        "after-runtime-observation",
        "after-spec",
        "after-confirmation",
        "after-logical-commit",
        "after-idempotency",
        "after-audit",
        "after-completed",
    ],
)
def test_provision_crash_converges_one_container_volume_credential_and_token(
    tmp_path, monkeypatch, capsys, boundary
):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()

    def crash(observed, _record):
        if observed == boundary:
            raise SimulatedCrash

    arguments = (
        "provision",
        "prepare",
        "daimon-x",
        "--species",
        "test",
        "--requested-by",
        "alice",
        "--sponsor",
        "bob",
        "--idempotency-key",
        CREATE_KEY,
    )
    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", crash)
    with pytest.raises(SimulatedCrash):
        _invoke(state_dir, adapter, *arguments)
    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", None)
    capsys.readouterr()
    assert _invoke(state_dir, adapter, *arguments) == 0
    assert [row["name"] for row in adapter.list_instances()] == ["daimon-x"]
    assert adapter.list_volumes() == ["daimon-x-home"]
    spec = load_spec_raw(state_dir / "instances", "daimon-x")
    assert spec["state"] == "provisioned-pending-activation"
    assert spec["identity_pubkey"].startswith("ssh-ed25519 ")
    tokens = list((state_dir / "confirmations").glob("*.json"))
    assert len(tokens) == 1
    token = json.loads(tokens[0].read_text())
    assert token["target"] == "daimon-x"
    assert token["used"] is False
    record = OperationJournal(state_dir).list_all(limit=10)[0]
    assert record["state"] == "completed"
    assert record["result"]["token"] == token["token"]
    events = [
        json.loads(line)
        for line in (state_dir / "audit.jsonl").read_text().splitlines()
    ]
    assert sum(event["event_id"] == record["audit_event_id"] for event in events) == 1


@pytest.mark.parametrize("operation", ["start", "stop", "restart"])
def test_registry_write_failure_resumes_exact_logical_transition(
    tmp_path, monkeypatch, capsys, operation
):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()
    spec = _created(state_dir, adapter)
    if operation in {"stop", "restart"}:
        assert (
            _invoke(
                state_dir,
                adapter,
                "start",
                "daimon-x",
                "--idempotency-key",
                START_KEY,
            )
            == 0
        )
    capsys.readouterr()
    original_save = embodiments.Registry._save
    failed = False

    def fail_once(self, value):
        nonlocal failed
        if not failed:
            failed = True
            raise embodiments.RegistryError("injected registry persistence failure")
        return original_save(self, value)

    monkeypatch.setattr(embodiments.Registry, "_save", fail_once)
    key = {"start": START_KEY, "stop": STOP_KEY, "restart": RESTART_KEY}[operation]
    if operation == "start":
        # The setup did not consume START_KEY in this parameter.
        pass
    assert (
        _invoke(
            state_dir,
            adapter,
            operation,
            "daimon-x",
            "--idempotency-key",
            key,
        )
        == 10
    )
    pending = OperationJournal(state_dir).open_for_target("daimon-x")
    assert pending is not None and pending["state"] == "runtime-applied"
    intended = pending["intended_transition"]["incarnation_id"]
    capsys.readouterr()
    assert (
        _invoke(
            state_dir,
            adapter,
            operation,
            "daimon-x",
            "--idempotency-key",
            key,
        )
        == 0
    )
    registry = embodiments.Registry(state_dir).status(spec["embodiment_id"])
    if operation == "stop":
        assert registry["status"] == "stopped"
        assert registry["current_incarnation_id"] is None
    else:
        assert registry["status"] == "running"
        assert registry["current_incarnation_id"] == intended
        assert sum(
            row["incarnation_id"] == intended for row in registry["incarnations"]
        ) == 1


def test_restart_failure_between_registry_stop_and_start_reuses_intended_id(
    tmp_path, monkeypatch, capsys
):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()
    spec = _created(state_dir, adapter)
    assert (
        _invoke(
            state_dir,
            adapter,
            "start",
            "daimon-x",
            "--idempotency-key",
            START_KEY,
        )
        == 0
    )
    original_save = embodiments.Registry._save
    calls = 0

    def fail_second(self, value):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise embodiments.RegistryError("injected between stop and start")
        return original_save(self, value)

    monkeypatch.setattr(embodiments.Registry, "_save", fail_second)
    capsys.readouterr()
    assert (
        _invoke(
            state_dir,
            adapter,
            "restart",
            "daimon-x",
            "--idempotency-key",
            RESTART_KEY,
        )
        == 10
    )
    pending = OperationJournal(state_dir).open_for_target("daimon-x")
    assert pending is not None
    intended = pending["intended_transition"]["incarnation_id"]
    capsys.readouterr()
    assert (
        _invoke(
            state_dir,
            adapter,
            "restart",
            "daimon-x",
            "--idempotency-key",
            RESTART_KEY,
        )
        == 0
    )
    registry = embodiments.Registry(state_dir).status(spec["embodiment_id"])
    assert registry["current_incarnation_id"] == intended
    assert sum(row["incarnation_id"] == intended for row in registry["incarnations"]) == 1


def test_spec_idempotency_and_audit_failures_resume_without_second_runtime_effect(
    tmp_path, monkeypatch, capsys
):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()
    _created(state_dir, adapter)
    original_update = lifecycle.update_spec
    failed = False

    def fail_spec_once(*args, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("injected spec failure")
        return original_update(*args, **kwargs)

    monkeypatch.setattr(lifecycle, "update_spec", fail_spec_once)
    capsys.readouterr()
    assert (
        _invoke(
            state_dir,
            adapter,
            "start",
            "daimon-x",
            "--idempotency-key",
            START_KEY,
        )
        == 10
    )
    adapter.mutation_log.clear()
    assert (
        _invoke(
            state_dir,
            adapter,
            "start",
            "daimon-x",
            "--idempotency-key",
            START_KEY,
        )
        == 0
    )
    assert adapter.mutation_log == []

    assert (
        _invoke(
            state_dir,
            adapter,
            "stop",
            "daimon-x",
            "--idempotency-key",
            STOP_KEY,
        )
        == 0
    )
    # A second operation exercises failures after logical truth. Each retry
    # must only finish persistence, never repeat the already-observed stop.
    assert adapter.mutation_log[-1] == ("stop", "daimon-x")

    # Re-start under a new id to stage the persistence-boundary injections.
    start_again_key = "55555555-5555-4555-8555-555555555555"
    original_save_store = idempotency.save_store
    save_failed = False

    def fail_idempotency_once(*args, **kwargs):
        nonlocal save_failed
        if not save_failed:
            save_failed = True
            raise OSError("injected idempotency failure")
        return original_save_store(*args, **kwargs)

    monkeypatch.setattr(idempotency, "save_store", fail_idempotency_once)
    capsys.readouterr()
    assert (
        _invoke(
            state_dir,
            adapter,
            "start",
            "daimon-x",
            "--idempotency-key",
            start_again_key,
        )
        == 10
    )
    mutation_count = len(adapter.mutation_log)
    assert (
        _invoke(
            state_dir,
            adapter,
            "start",
            "daimon-x",
            "--idempotency-key",
            start_again_key,
        )
        == 0
    )
    assert len(adapter.mutation_log) == mutation_count

    # Stop again and fail the deterministic audit append once.
    stop_again_key = "66666666-6666-4666-8666-666666666666"
    original_append = audit.append_event
    audit_failed = False

    def fail_audit_once(*args, **kwargs):
        nonlocal audit_failed
        if not audit_failed and kwargs.get("action") == "stop":
            audit_failed = True
            raise OSError("injected audit failure")
        return original_append(*args, **kwargs)

    monkeypatch.setattr(audit, "append_event", fail_audit_once)
    capsys.readouterr()
    assert (
        _invoke(
            state_dir,
            adapter,
            "stop",
            "daimon-x",
            "--idempotency-key",
            stop_again_key,
        )
        == 10
    )
    mutation_count = len(adapter.mutation_log)
    assert (
        _invoke(
            state_dir,
            adapter,
            "stop",
            "daimon-x",
            "--idempotency-key",
            stop_again_key,
        )
        == 0
    )
    assert len(adapter.mutation_log) == mutation_count


def test_pending_exact_bytes_resume_and_competing_bytes_conflict(
    tmp_path, monkeypatch, capsys
):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()
    _created(state_dir, adapter)

    def crash(boundary, _record):
        if boundary == "after-plan":
            raise SimulatedCrash

    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", crash)
    with pytest.raises(SimulatedCrash):
        _invoke(
            state_dir,
            adapter,
            "stop",
            "daimon-x",
            "--timeout",
            "10",
            "--idempotency-key",
            STOP_KEY,
        )
    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", None)
    capsys.readouterr()
    assert (
        _invoke(
            state_dir,
            adapter,
            "stop",
            "daimon-x",
            "--timeout",
            "20",
            "--idempotency-key",
            STOP_KEY,
        )
        == 6
    )
    assert OperationJournal(state_dir).open_for_target("daimon-x") is not None


def test_degraded_target_blocks_unsafe_follow_on(tmp_path, capsys):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()
    _created(state_dir, adapter)
    journal = OperationJournal(state_dir)
    record = journal.plan(
        operation="start",
        target="daimon-x",
        idempotency_key=START_KEY,
        intent={"operation": "start", "target": "daimon-x", "runtime_call": {}},
        expected_precondition={},
        intended_transition={},
        audit_identity={},
    )
    journal.advance(record["operation_id"], "degraded", last_error="ambiguous")
    with pytest.raises(JournalConflict, match="explicit repair"):
        journal.plan(
            operation="start",
            target="daimon-x",
            idempotency_key=START_KEY,
            intent={
                "operation": "start",
                "target": "daimon-x",
                "runtime_call": {},
            },
            expected_precondition={},
            intended_transition={},
            audit_identity={},
        )
    capsys.readouterr()
    assert (
        _invoke(
            state_dir,
            adapter,
            "stop",
            "daimon-x",
            "--idempotency-key",
            STOP_KEY,
        )
        == 6
    )


def test_journal_rejects_same_identity_for_different_bytes(tmp_path):
    journal = OperationJournal(tmp_path)
    journal.plan(
        operation="stop",
        target="daimon-x",
        idempotency_key=STOP_KEY,
        intent={"runtime_call": {"method": "stop", "timeout": 10}},
        expected_precondition={},
        intended_transition={},
        audit_identity={},
    )
    with pytest.raises(JournalConflict, match="different operation bytes"):
        journal.plan(
            operation="stop",
            target="daimon-x",
            idempotency_key=STOP_KEY,
            intent={"runtime_call": {"method": "stop", "timeout": 20}},
            expected_precondition={},
            intended_transition={},
            audit_identity={},
        )


def test_terminal_identity_requires_explicit_effect_truth_successor(tmp_path):
    journal = OperationJournal(tmp_path)
    record = journal.plan(
        operation="stop",
        target="daimon-x",
        idempotency_key=STOP_KEY,
        intent={"runtime_call": {"method": "stop", "timeout": 10}},
        expected_precondition={},
        intended_transition={},
        audit_identity={},
    )
    journal.advance(record["operation_id"], "compensated")
    with pytest.raises(JournalConflict, match="terminal idempotency"):
        journal.plan(
            operation="stop",
            target="daimon-x",
            idempotency_key=STOP_KEY,
            intent={"runtime_call": {"method": "stop", "timeout": 10}},
            expected_precondition={},
            intended_transition={},
            audit_identity={},
        )
    successor = journal.plan(
        operation="stop",
        target="daimon-x",
        idempotency_key=STOP_KEY,
        intent={"runtime_call": {"method": "stop", "timeout": 10}},
        expected_precondition={},
        intended_transition={},
        audit_identity={},
        allow_terminal_successor=True,
    )
    assert successor["operation_id"] != record["operation_id"]


def test_bounded_repair_resumes_degraded_power_intent(tmp_path, monkeypatch, capsys):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()
    spec = _created(state_dir, adapter)

    def crash(boundary, _record):
        if boundary == "after-plan":
            raise SimulatedCrash

    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", crash)
    with pytest.raises(SimulatedCrash):
        _invoke(
            state_dir,
            adapter,
            "start",
            "daimon-x",
            "--idempotency-key",
            START_KEY,
        )
    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", None)
    journal = OperationJournal(state_dir)
    pending = journal.open_for_target("daimon-x")
    assert pending is not None
    journal.advance(pending["operation_id"], "degraded", last_error="ambiguous")
    capsys.readouterr()
    assert (
        run(
            [
                "--state-dir",
                str(state_dir),
                "repair",
                "--operation-id",
                pending["operation_id"],
                "--json",
            ],
            adapter=adapter,
        )
        == 0
    )
    final = journal.get(pending["operation_id"])
    assert final is not None and final["state"] == "completed"
    registry = embodiments.Registry(state_dir).status(spec["embodiment_id"])
    assert registry["current_incarnation_id"] == final["result"]["incarnation_id"]
    events = [
        json.loads(line)
        for line in (state_dir / "audit.jsonl").read_text().splitlines()
    ]
    assert any(event["action"] == "lifecycle-repair" for event in events)


def test_restart_repair_forces_an_observable_stopped_boundary(
    tmp_path, monkeypatch, capsys
):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()
    _created(state_dir, adapter)
    assert (
        _invoke(
            state_dir,
            adapter,
            "start",
            "daimon-x",
            "--idempotency-key",
            START_KEY,
        )
        == 0
    )

    def crash(boundary, _record):
        if boundary == "after-plan":
            raise SimulatedCrash

    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", crash)
    with pytest.raises(SimulatedCrash):
        _invoke(
            state_dir,
            adapter,
            "restart",
            "daimon-x",
            "--idempotency-key",
            RESTART_KEY,
        )
    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", None)
    journal = OperationJournal(state_dir)
    pending = journal.open_for_target("daimon-x")
    assert pending is not None
    journal.advance(pending["operation_id"], "degraded", last_error="ambiguous")
    adapter.mutation_log.clear()
    capsys.readouterr()
    assert (
        run(
            [
                "--state-dir",
                str(state_dir),
                "repair",
                "--operation-id",
                pending["operation_id"],
                "--json",
            ],
            adapter=adapter,
        )
        == 0
    )
    assert adapter.mutation_log == [
        ("stop", "daimon-x"),
        ("start", "daimon-x"),
    ]


def test_repair_audit_failure_does_not_release_degraded_target(
    tmp_path, monkeypatch, capsys
):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()
    _created(state_dir, adapter)
    journal = OperationJournal(state_dir)
    record = journal.plan(
        operation="start",
        target="daimon-x",
        idempotency_key=START_KEY,
        intent={
            "operation": "start",
            "target": "daimon-x",
            "runtime_call": {"method": "start", "name": "daimon-x", "timeout": None},
        },
        expected_precondition={},
        intended_transition={"runtime_state": "running"},
        audit_identity={},
    )
    journal.advance(record["operation_id"], "degraded", last_error="ambiguous")
    original_append = audit.append_event

    def fail_repair_audit(*args, **kwargs):
        if kwargs.get("action") == "lifecycle-repair":
            raise OSError("injected repair audit failure")
        return original_append(*args, **kwargs)

    monkeypatch.setattr(audit, "append_event", fail_repair_audit)
    capsys.readouterr()
    assert (
        run(
            [
                "--state-dir",
                str(state_dir),
                "repair",
                "--operation-id",
                record["operation_id"],
                "--json",
            ],
            adapter=adapter,
        )
        == 10
    )
    assert journal.get(record["operation_id"])["state"] == "degraded"


def test_reconcile_reports_pending_and_degraded_operations(tmp_path, capsys):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()
    _created(state_dir, adapter)
    journal = OperationJournal(state_dir)
    first = journal.plan(
        operation="start",
        target="daimon-x",
        idempotency_key=START_KEY,
        intent={"runtime_call": {"method": "start", "name": "daimon-x"}},
        expected_precondition={},
        intended_transition={},
        audit_identity={},
    )
    journal.advance(first["operation_id"], "degraded", last_error="ambiguous")
    capsys.readouterr()
    assert (
        run(
            ["--state-dir", str(state_dir), "reconcile", "--json"],
            adapter=adapter,
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["open_operations"] == 1
    finding = next(
        row for row in report["findings"] if row["kind"] == "degraded_operation"
    )
    assert finding["severity"] == "error"
    assert first["operation_id"] in finding["message"]


def test_read_only_existing_probe_does_not_create_database(tmp_path):
    assert OperationJournal.existing(tmp_path) is None
    assert not (tmp_path / "operation-journal.sqlite3").exists()
    assert _operation_journal_state(str(tmp_path)) == {
        "state": "clean",
        "open": 0,
        "degraded": 0,
    }


def test_corrupt_journal_row_degrades_health_and_reconcile(tmp_path, capsys):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()
    _created(state_dir, adapter)
    journal = OperationJournal(state_dir)
    record = journal.plan(
        operation="start",
        target="daimon-x",
        idempotency_key=START_KEY,
        intent={"runtime_call": {"method": "start", "name": "daimon-x"}},
        expected_precondition={},
        intended_transition={},
        audit_identity={},
    )
    journal.advance(record["operation_id"], "compensated")
    connection = sqlite3.connect(journal.path)
    try:
        connection.execute(
            "UPDATE operations SET intent_json='{' WHERE operation_id=?",
            (record["operation_id"],),
        )
        connection.commit()
    finally:
        connection.close()
    assert _operation_journal_state(str(state_dir)) == {
        "state": "unavailable",
        "open": 0,
        "degraded": 0,
    }
    capsys.readouterr()
    assert (
        run(
            ["--state-dir", str(state_dir), "reconcile", "--json"],
            adapter=adapter,
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["operation_journal"] == "unavailable"
    finding = next(
        item
        for item in report["findings"]
        if item["kind"] == "operation_journal_unavailable"
    )
    assert finding["severity"] == "error"


def test_health_degrades_while_operation_requires_attention(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    journal = OperationJournal(state_dir)
    pending = journal.plan(
        operation="start",
        target="daimon-x",
        idempotency_key=START_KEY,
        intent={"runtime_call": {"method": "start", "name": "daimon-x"}},
        expected_precondition={},
        intended_transition={},
        audit_identity={},
    )
    monkeypatch.setattr(handlers, "_audit_chain_ok", lambda _state_dir: True)
    monkeypatch.setattr(handlers, "_mirror_state", lambda _state_dir: "not-configured")
    deps = handlers.Deps(
        config_path="configs/clusterctl.yaml",
        state_dir=str(state_dir),
        adapter_factory=FakeAdapter,
    )
    response = handlers.health(
        deps,
        handlers.RequestContext(
            request_id="health-test",
            actor="health",
            scope_token=None,
        ),
    )
    assert response.status == 200
    assert isinstance(response.body, dict)
    assert response.body["status"] == "degraded"
    assert response.body["operation_journal"] == {
        "state": "attention-required",
        "open": 1,
        "degraded": 0,
    }

    journal.advance(pending["operation_id"], "degraded", last_error="ambiguous")
    response = handlers.health(
        deps,
        handlers.RequestContext(
            request_id="health-test-degraded",
            actor="health",
            scope_token=None,
        ),
    )
    assert isinstance(response.body, dict)
    assert response.body["operation_journal"]["degraded"] == 1


def test_audit_retry_reuses_closed_stale_lock_context(tmp_path, monkeypatch, capsys):
    state_dir = tmp_path / "state"
    adapter = FakeAdapter()
    _created(state_dir, adapter)
    capsys.readouterr()
    lock_dir = state_dir / "locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    (lock_dir / "daimon-x.lock").write_text(
        json.dumps({"operation": "old-start", "pid": 999999, "ts_ms": 0}),
        encoding="utf-8",
    )

    def crash(boundary, _record):
        if boundary == "after-audit":
            raise SimulatedCrash

    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", crash)
    with pytest.raises(SimulatedCrash):
        _invoke(
            state_dir,
            adapter,
            "start",
            "daimon-x",
            "--idempotency-key",
            START_KEY,
        )
    monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", None)
    capsys.readouterr()
    assert (
        _invoke(
            state_dir,
            adapter,
            "start",
            "daimon-x",
            "--idempotency-key",
            START_KEY,
        )
        == 0
    )
    events = [
        event
        for event in audit.read_events(state_dir)
        if event["action"] == "start" and event["result"] == "ok"
    ]
    assert len(events) == 1
    assert events[0]["detail"]["stale_lock_broken"] is True
    assert events[0]["detail"]["previous_holder"]["operation"] == "old-start"
