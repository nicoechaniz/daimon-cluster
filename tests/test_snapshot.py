"""Quiesced snapshot create tests (issue #14) — fake adapter only."""
import json

import pytest
import yaml

from clusterctl.adapters import FakeAdapter
from clusterctl.cli import run

UUID1 = "11111111-1111-1111-1111-111111111111"
UUID2 = "22222222-2222-2222-2222-222222222222"
UUID3 = "33333333-3333-3333-3333-333333333333"

NAME = "daimon-x"


@pytest.fixture()
def state_dir(tmp_path):
    return tmp_path / "state"


def _declare(state_dir, name=NAME, image_version="tribe-base/2026-08-01.1"):
    inst_dir = state_dir / "instances"
    inst_dir.mkdir(parents=True, exist_ok=True)
    (inst_dir / f"{name}.yaml").write_text(yaml.safe_dump({
        "schema": "instance-spec/v1",
        "name": name,
        "image_version": image_version,
    }), encoding="utf-8")


def _adapter(**kwargs):
    instances = kwargs.pop("instances", None)
    if instances is None:
        instances = [{"name": NAME, "state": "running", "image_version": "v1",
                      "budgets": {}, "uptime_s": 5}]
    return FakeAdapter(instances=instances, **kwargs)


def _run(state_dir, *argv, adapter=None):
    ad = adapter if adapter is not None else _adapter()
    code = run(["--state-dir", str(state_dir), *argv], adapter=ad)
    return code, ad


def _snap(state_dir, key=UUID1, adapter=None, name=NAME):
    return _run(state_dir, "snapshot", "create", name,
                "--idempotency-key", key, "--json", adapter=adapter)


def _manifests(state_dir, name=NAME):
    mdir = state_dir / "backups" / name
    if not mdir.exists():
        return []
    return sorted(mdir.glob("*.json"))


def _log_names(ad):
    return [entry[0] for entry in ad.mutation_log]


# --------------------------------------------------------------------------
# happy path + ordering
# --------------------------------------------------------------------------

def test_snapshot_create_happy_path_order(state_dir, capsys):
    _declare(state_dir)
    ad = _adapter()
    code, _ = _snap(state_dir, adapter=ad)
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == "ok"
    assert out["snap_name"].startswith("snap-")

    calls = _log_names(ad)
    # park before quiesce-verify before capture
    assert calls.index("exec_quiesce_park") < calls.index("exec_quiesce_verify")
    assert calls.index("exec_quiesce_verify") < calls.index("incus_snapshot_create")
    # unpark ALWAYS after capture and before manifest write
    assert calls.index("incus_snapshot_create") < calls.index("exec_unpark")
    assert calls.index("exec_unpark") < calls.index("manifest_write")
    # snapshot verify before manifest write
    assert calls.index("incus_snapshot_verify") < calls.index("manifest_write")

    # snapshot exists on the instance
    assert ad._instances[0]["snapshots"] == [out["snap_name"]]

    # audit ok carries snap name + quiesce summary + manifest path
    events = [
        json.loads(line)
        for line in (state_dir / "audit.jsonl").read_text().splitlines()
    ]
    ok = [e for e in events if e["action"] == "snapshot-create" and e["result"] == "ok"]
    assert ok
    det = ok[-1]["detail"]
    assert det["snap_name"] == out["snap_name"]
    assert det["quiesce"]["parked"] is True
    assert det["quiesce"]["sqlite_ok"] is True
    assert det["manifest"].endswith(".json")


def test_manifest_schema_shape(state_dir, capsys):
    _declare(state_dir, image_version="tribe-base/2026-08-01.1")
    code, ad = _snap(state_dir)
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    manifests = _manifests(state_dir)
    assert len(manifests) == 1
    m = json.loads(manifests[0].read_text())
    assert m["schema"] == "cluster-backup-manifest/v1"
    assert m["name"] == NAME
    assert m["snap_name"] == out["snap_name"]
    assert isinstance(m["created_ms"], int)
    assert m["image_version"] == "tribe-base/2026-08-01.1"
    assert m["quiesce"]["parked"] is True
    assert m["quiesce"]["sqlite_ok"] is True
    assert m["quiesce"]["checkpoint_files"] == [
        "/home/agent/.hermes/agent-memory/library.db"
    ]
    assert m["verified_readable"] is True
    assert m["retention_class"] == "local-quiesced"
    assert m["rpo_class"] == "pre-mutation"


# --------------------------------------------------------------------------
# fail-closed paths
# --------------------------------------------------------------------------

def test_park_failure_fails_closed(state_dir, capsys):
    _declare(state_dir)
    ad = _adapter(fail_quiesce=True)
    code, _ = _snap(state_dir, adapter=ad)
    assert code == 10
    calls = _log_names(ad)
    # unpark attempted even though park failed; no capture, no manifest
    assert "exec_unpark" in calls
    assert "incus_snapshot_create" not in calls
    assert "manifest_write" not in calls
    assert _manifests(state_dir) == []
    assert ad._instances[0].get("snapshots", []) == []
    err = [
        json.loads(line)
        for line in (state_dir / "audit.jsonl").read_text().splitlines()
        if '"error"' in line or True
    ]
    ev = [e for e in err if e["action"] == "snapshot-create"]
    assert ev[-1]["result"] == "error"


def test_sqlite_integrity_failure_fails_closed(state_dir, capsys):
    _declare(state_dir)
    ad = _adapter(fail_verify=True)
    code, _ = _snap(state_dir, adapter=ad)
    assert code == 10
    calls = _log_names(ad)
    assert "exec_unpark" in calls
    assert "incus_snapshot_create" not in calls
    assert "manifest_write" not in calls
    assert _manifests(state_dir) == []


def test_capture_failure_unparks_and_writes_no_manifest(state_dir, capsys):
    _declare(state_dir)
    ad = _adapter(fail_capture=True)
    code, _ = _snap(state_dir, adapter=ad)
    assert code == 10
    calls = _log_names(ad)
    assert calls.index("incus_snapshot_create") < calls.index("exec_unpark")
    assert "manifest_write" not in calls
    assert _manifests(state_dir) == []
    assert ad._instances[0].get("snapshots", []) == []


def test_undeclared_instance_exits_3(state_dir, capsys):
    ad = _adapter()
    code, _ = _snap(state_dir, adapter=ad)
    assert code == 3
    assert _manifests(state_dir) == []


# --------------------------------------------------------------------------
# retention (design §6)
# --------------------------------------------------------------------------

def test_retention_prunes_beyond_3_newest_keeps_newest(state_dir, capsys):
    _declare(state_dir)
    ad = _adapter(instances=[{
        "name": NAME, "state": "running", "image_version": "v1",
        "budgets": {}, "uptime_s": 5,
        "snapshots": ["snap-100", "snap-200", "snap-300", "other-snap"],
    }])
    code, _ = _snap(state_dir, adapter=ad)
    assert code == 0
    snaps = sorted(ad._instances[0]["snapshots"])
    # 4 pre-existing snap-* would exceed 3 -> oldest pruned; newest kept.
    assert "snap-100" not in snaps
    assert "snap-200" in snaps and "snap-300" in snaps
    # newest verified (the one just created) is always kept
    out = json.loads(capsys.readouterr().out)
    assert out["snap_name"] in snaps
    # non-snap-* snapshots are never touched
    assert "other-snap" in snaps
    assert len([s for s in snaps if s.startswith("snap-")]) == 3


def test_retention_noop_when_fewer_than_3(state_dir, capsys):
    _declare(state_dir)
    ad = _adapter(instances=[{
        "name": NAME, "state": "running", "image_version": "v1",
        "budgets": {}, "uptime_s": 5, "snapshots": ["snap-100"],
    }])
    code, _ = _snap(state_dir, adapter=ad)
    assert code == 0
    assert "snap-100" in ad._instances[0]["snapshots"]
    assert "incus_snapshot_delete" not in _log_names(ad)


# --------------------------------------------------------------------------
# idempotency
# --------------------------------------------------------------------------

def test_idempotent_replay(state_dir, capsys):
    _declare(state_dir)
    ad = _adapter()
    code1, _ = _snap(state_dir, key=UUID1, adapter=ad)
    assert code1 == 0
    capsys.readouterr()
    code2, _ = _snap(state_dir, key=UUID1, adapter=ad)
    assert code2 == 0
    out2 = json.loads(capsys.readouterr().out)
    assert out2.get("idempotent-replay") is True
    # exactly one capture happened
    assert _log_names(ad).count("incus_snapshot_create") == 1
    assert len(_manifests(state_dir)) == 1
    assert len(ad._instances[0]["snapshots"]) == 1
