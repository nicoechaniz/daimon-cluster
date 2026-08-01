"""Audit hash-chain + reconcile tests (issue #19)."""
import json

import pytest
import yaml

from clusterctl import audit
from clusterctl.adapters import FakeAdapter
from clusterctl.config import Config
from clusterctl.reconcile import run_reconcile


def _cfg(state_dir):
    return Config(host_id="test", incus_project="default",
                  managed_prefix="", profile="tribe-agent",
                  state_dir=str(state_dir))


def _append(sd, action, result="ok", actor="tester", target="daimon-x"):
    audit.append_event(str(sd), actor=actor, action=action, target=target,
                       result=result, detail={})


def _lines(sd):
    return (sd / "audit.jsonl").read_text().strip().splitlines()


@pytest.fixture()
def state_dir(tmp_path):
    sd = tmp_path / "state"
    sd.mkdir()
    return sd


def test_chain_links_and_monotonic_seq(state_dir):
    for i in range(3):
        _append(state_dir, f"op{i}")
    events = [json.loads(l) for l in _lines(state_dir)]
    assert [e["seq"] for e in events] == [0, 1, 2]
    assert events[0]["prev_sha256"] == "0" * 64
    for e in events:
        assert len(e["event_sha256"]) == 64
    assert audit.verify_chain(str(state_dir))["ok"]


def test_tamper_detected_with_first_bad_seq(state_dir):
    for i in range(3):
        _append(state_dir, f"op{i}")
    lines = _lines(state_dir)
    e = json.loads(lines[1])
    e["actor"] = "mallory"
    lines[1] = json.dumps(e)
    (state_dir / "audit.jsonl").write_text("\n".join(lines) + "\n")
    r = audit.verify_chain(str(state_dir))
    assert not r["ok"] and r["first_bad_seq"] == 1


def test_truncation_detected_via_hwm(state_dir):
    for i in range(4):
        _append(state_dir, f"op{i}")
    lines = _lines(state_dir)
    (state_dir / "audit.jsonl").write_text("\n".join(lines[:-2]) + "\n")
    r = audit.verify_chain(str(state_dir))
    assert not r["ok"] and r["error"] == "truncation"


def test_gap_detected(state_dir):
    for i in range(3):
        _append(state_dir, f"op{i}")
    lines = _lines(state_dir)
    e = json.loads(lines[2])
    e["seq"] = 7
    # recompute the event hash so only the GAP is wrong, not the hash
    e["event_sha256"] = audit.event_hash(e)
    lines[2] = json.dumps(e)
    (state_dir / "audit.jsonl").write_text("\n".join(lines) + "\n")
    r = audit.verify_chain(str(state_dir))
    assert not r["ok"] and "gap" in (r["error"] or "")


def test_prechain_migration_anchoring(state_dir):
    # legacy event without seq
    (state_dir / "audit.jsonl").write_text(json.dumps({
        "schema": "audit-event/v1", "ts_ms": 1, "actor": "legacy",
        "action": "create", "target": "x", "result": "ok",
        "detail": {}}) + "\n")
    _append(state_dir, "chained-op")
    events = [json.loads(l) for l in _lines(state_dir)]
    assert "seq" not in events[0] and events[1]["seq"] == 1
    assert events[1]["prev_sha256"] != "0" * 64  # anchored on legacy tail
    assert audit.verify_chain(str(state_dir))["ok"]


def _adapter(with_volumes=None):
    return FakeAdapter(instances=[{"name": "iso-x", "state": "running",
                                   "image_version": "v1", "budgets": {},
                                   "uptime_s": 1}],
                       volumes=with_volumes or [])

def _spec(state_dir, name="iso-x"):
    inst = state_dir / "instances"
    inst.mkdir(exist_ok=True)
    (inst / f"{name}.yaml").write_text(yaml.safe_dump({
        "schema": "instance-spec/v1", "name": name, "image_version": "v1"}))


def test_reconcile_clean(state_dir):
    _spec(state_dir)
    _append(state_dir, "create", target="iso-x")
    r = run_reconcile(_cfg(state_dir), _adapter())
    assert r["schema"] == "clusterctl-reconcile-report/v1"
    assert r["findings"] == []


def test_reconcile_untracked_container(state_dir):
    # incus has iso-x but audit never created it
    r = run_reconcile(_cfg(state_dir), _adapter())
    kinds = [f["kind"] for f in r["findings"]]
    assert "untracked_container" in kinds


def test_reconcile_untracked_volume(state_dir):
    _spec(state_dir)
    _append(state_dir, "create", target="iso-x")
    ad = _adapter(with_volumes=["mystery-vol"])
    r = run_reconcile(_cfg(state_dir), ad)
    kinds = [f["kind"] for f in r["findings"]]
    assert "untracked_volume" in kinds


def test_reconcile_impossible_transition(state_dir):
    _append(state_dir, "stop", target="ghost")  # stop without prior create
    r = run_reconcile(_cfg(state_dir), _adapter())
    kinds = [f["kind"] for f in r["findings"]]
    assert "impossible_transition" in kinds
