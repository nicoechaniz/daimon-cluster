"""Lifecycle mutation tests (issue #11) — fake adapter only, no incus needed."""
import json
import time
from pathlib import Path

import pytest

from clusterctl.adapters import FakeAdapter
from clusterctl.cli import run
from clusterctl.lifecycle import REDACTED, redact_line

UUID1 = "11111111-1111-1111-1111-111111111111"
UUID2 = "22222222-2222-2222-2222-222222222222"


@pytest.fixture()
def state_dir(tmp_path):
    return tmp_path / "state"


def _run(state_dir, *argv, adapter=None):
    ad = adapter if adapter is not None else FakeAdapter()
    code = run(["--state-dir", str(state_dir), *argv], adapter=ad)
    return code, ad


def test_create_happy_path(state_dir, capsys):
    code, ad = _run(state_dir, "create", "daimon-x", "--species", "test",
                    "--idempotency-key", UUID1, "--json")
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == "ok"
    assert (state_dir / "instances" / "daimon-x.yaml").exists()
    capsys.readouterr()
    code, _ = _run(state_dir, "status", "daimon-x", "--json", adapter=ad)
    assert code == 0
    rec = json.loads(capsys.readouterr().out)
    assert rec["state"] == "stopped"


def test_create_duplicate_name_conflict(state_dir, capsys):
    _run(state_dir, "create", "daimon-x", "--species", "t", "--idempotency-key", UUID1)
    capsys.readouterr()
    code, _ = _run(state_dir, "create", "daimon-x", "--species", "t",
                   "--idempotency-key", UUID2)
    assert code == 6


def test_idempotent_replay(state_dir, capsys):
    code, ad = _run(state_dir, "create", "daimon-x", "--species", "t",
                    "--idempotency-key", UUID1)
    assert code == 0
    capsys.readouterr()
    # same adapter: production incus is a shared substrate (R5 — the
    # replay is verified against OBSERVED state, so the test's fake
    # must model the same shared world)
    code, _ = _run(state_dir, "create", "daimon-x", "--species", "t",
                   "--idempotency-key", UUID1, "--json", adapter=ad)
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out.get("idempotent-replay") is True
    assert out.get("effect-truth") == "verified"


def test_idempotency_key_reuse_different_op_conflicts(state_dir, capsys):
    _run(state_dir, "create", "daimon-x", "--species", "t", "--idempotency-key", UUID1)
    capsys.readouterr()
    code, _ = _run(state_dir, "start", "daimon-x", "--idempotency-key", UUID1)
    assert code == 6


def test_lock_conflict_reports_holder(state_dir, capsys):
    ad = FakeAdapter()
    _run(state_dir, "create", "daimon-x", "--species", "t", "--idempotency-key", UUID1, adapter=ad)
    locks = state_dir / "locks"
    locks.mkdir(parents=True, exist_ok=True)
    (locks / "daimon-x.lock").write_text(json.dumps(
        {"operation": "stop", "pid": 424242, "ts_ms": int(time.time() * 1000)}))
    capsys.readouterr()
    code, _ = _run(state_dir, "start", "daimon-x", "--json", adapter=ad)
    assert code == 6
    captured = capsys.readouterr()
    assert "stop" in (captured.err + captured.out) or "424242" in (captured.err + captured.out)


def test_stale_lock_is_broken(state_dir, capsys):
    ad = FakeAdapter()
    _run(state_dir, "create", "daimon-x", "--species", "t", "--idempotency-key", UUID1, adapter=ad)
    locks = state_dir / "locks"
    locks.mkdir(parents=True, exist_ok=True)
    stale_ms = int((time.time() - 900) * 1000)  # 15 min ago
    (locks / "daimon-x.lock").write_text(json.dumps(
        {"operation": "stop", "pid": 424242, "ts_ms": stale_ms}))
    capsys.readouterr()
    code, _ = _run(state_dir, "start", "daimon-x", adapter=ad)
    assert code == 0
    assert not (locks / "daimon-x.lock").exists()


def test_logs_redaction(state_dir, capsys):
    ad = FakeAdapter(
        instances=[{"name": "daimon-x", "state": "running",
                    "image_version": "t", "budgets": {}, "uptime_s": 1,
                    "profiles": ["tribe-agent"], "config_show": ""}],
        log_lines={"daimon-x": ["ok line", "-----BEGIN PRIVATE KEY-----",
                                "Authorization: Bearer abc123", "clean"]},
    )
    (state_dir / "instances").mkdir(parents=True)
    (state_dir / "instances" / "daimon-x.yaml").write_text(
        "schema: instance-spec/v1\nname: daimon-x\nspecies: t\n"
        "image_version: t\nbudgets:\n  cpu: 1\n  memory_mib: 1536\n  disk_gib: 8\n"
        "created_ms: 1\ncreated_by: test\n")
    code, _ = _run(state_dir, "logs", "daimon-x", "--lines", "10", adapter=ad)
    assert code == 0
    out = capsys.readouterr().out
    assert "PRIVATE KEY" not in out and "abc123" not in out
    assert out.count(REDACTED) == 2
    assert redact_line("nothing secret here") == "nothing secret here"


def test_destroy_plan_content(state_dir, capsys):
    _run(state_dir, "create", "daimon-x", "--species", "t", "--idempotency-key", UUID1)
    capsys.readouterr()
    code, _ = _run(state_dir, "destroy-plan", "daimon-x")
    assert code == 0
    out = capsys.readouterr().out
    assert "archive" in out and "destroy" in out and "900" in out
    # plan only: the instance must still exist
    assert (state_dir / "instances" / "daimon-x.yaml").exists()


def test_creation_failure_reverses_cleanly(state_dir, capsys):
    ad = FakeAdapter(fail_create=True)
    code, _ = _run(state_dir, "create", "daimon-x", "--species", "t",
                   "--idempotency-key", UUID1, adapter=ad)
    assert code != 0
    # spec marked creation-failed (not silently declared), nothing running
    spec = (state_dir / "instances" / "daimon-x.yaml").read_text()
    assert "creation-failed" in spec
    assert ("create_instance", "daimon-x") in ad.mutation_log


def test_audit_on_success_and_denial(state_dir, capsys):
    ad = FakeAdapter()
    _run(state_dir, "create", "daimon-x", "--species", "t", "--idempotency-key", UUID1, adapter=ad)
    capsys.readouterr()
    _run(state_dir, "start", "daimon-x", adapter=ad)
    code, _ = _run(state_dir, "start", "ghost", adapter=ad)  # unknown -> denial (exit 3)
    assert code == 3
    log = (state_dir / "audit.jsonl").read_text().strip().splitlines()
    events = [json.loads(l) for l in log]
    assert any(e["action"] == "start" and e["result"] == "ok" for e in events)
    assert any(e["result"] in ("denied", "error") for e in events)
    assert all(e["schema"] == "audit-event/v1" for e in events)


def test_status_shows_last_audit_event(state_dir, capsys):
    code, ad = _run(state_dir, "create", "daimon-x", "--species", "t",
                    "--idempotency-key", UUID1)
    _run(state_dir, "start", "daimon-x", adapter=ad)
    capsys.readouterr()
    code, _ = _run(state_dir, "status", "daimon-x", "--json", adapter=ad)
    assert code == 0
    rec = json.loads(capsys.readouterr().out)
    assert rec["last_audit_event"]["action"] == "start"
    assert rec["last_audit_event"]["result"] == "ok"


def test_unknown_instance_exit_3(state_dir, capsys):
    code, _ = _run(state_dir, "stop", "ghost")
    assert code == 3
