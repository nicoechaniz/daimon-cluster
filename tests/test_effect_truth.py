"""Effect-truth idempotency reconciled from compaii's M10-R5 line."""

import contextlib
import io
import json
from pathlib import Path

import pytest

from clusterctl import audit
from clusterctl.adapters import FakeAdapter
from clusterctl.cli import run

UUID1 = "11111111-1111-1111-1111-111111111111"
UUID2 = "22222222-2222-2222-2222-222222222222"


@pytest.fixture()
def state_dir(tmp_path):
    return tmp_path / "state"


@pytest.fixture()
def adapter():
    return FakeAdapter(instances=[], exec_handler=lambda name, argv: "")


def _run(state_dir, *argv, adapter):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = run([
            "--state-dir", str(state_dir), "--actor", "effect-truth-test",
            *argv,
        ], adapter=adapter)
    return code, out.getvalue(), err.getvalue()


def _create_running(state_dir, adapter):
    code, _, _ = _run(
        state_dir, "create", "daimon-x", "--species", "test",
        "--idempotency-key", UUID1, adapter=adapter,
    )
    assert code == 0
    adapter.start("daimon-x")


def test_false_stop_record_is_not_replayed(state_dir, adapter):
    _create_running(state_dir, adapter)
    code, _, _ = _run(
        state_dir, "stop", "daimon-x", "--idempotency-key", UUID2,
        "--json", adapter=adapter,
    )
    assert code == 0
    adapter.start("daimon-x")  # reality contradicts the recorded effect

    code, out, _ = _run(
        state_dir, "stop", "daimon-x", "--idempotency-key", UUID2,
        "--json", adapter=adapter,
    )
    assert code == 0
    assert json.loads(out).get("idempotent-replay") is not True
    assert adapter._find("daimon-x")["state"] == "stopped"
    discrepancies = [
        event for event in audit.read_events(state_dir)
        if event["result"] == "error"
        and (event.get("detail") or {}).get("kind")
        == "effect-truth-discrepancy"
    ]
    assert len(discrepancies) == 1
    assert discrepancies[0]["detail"]["observed"]["state"] == "running"
    assert discrepancies[0]["detail"]["recorded_effect"]["state"] == "stopped"
    assert audit.verify_chain(state_dir)["ok"] is True


def test_verified_replay_remains_a_noop(state_dir, adapter):
    _create_running(state_dir, adapter)
    code, _, _ = _run(
        state_dir, "stop", "daimon-x", "--idempotency-key", UUID2,
        "--json", adapter=adapter,
    )
    assert code == 0
    code, out, _ = _run(
        state_dir, "stop", "daimon-x", "--idempotency-key", UUID2,
        "--json", adapter=adapter,
    )
    assert code == 0
    payload = json.loads(out)
    assert payload["idempotent-replay"] is True
    assert payload["effect-truth"] == "verified"
    assert [call for call in adapter.mutation_log if call == ("stop", "daimon-x")] == [
        ("stop", "daimon-x")
    ]


def test_start_replay_against_stopped_body_reexecutes(state_dir, adapter):
    _create_running(state_dir, adapter)
    code, _, _ = _run(
        state_dir, "start", "daimon-x", "--idempotency-key", UUID2,
        "--json", adapter=adapter,
    )
    assert code == 0
    adapter.stop("daimon-x")

    code, out, _ = _run(
        state_dir, "start", "daimon-x", "--idempotency-key", UUID2,
        "--json", adapter=adapter,
    )
    assert code == 0
    assert json.loads(out).get("idempotent-replay") is not True
    assert adapter._find("daimon-x")["state"] == "running"


def test_snapshot_replay_is_verified_by_snapshot_presence(state_dir, adapter):
    _create_running(state_dir, adapter)
    code, out, _ = _run(
        state_dir, "snapshot", "create", "daimon-x",
        "--idempotency-key", UUID2, "--json", adapter=adapter,
    )
    assert code == 0
    snap_name = json.loads(out)["snap_name"]

    code, out, _ = _run(
        state_dir, "snapshot", "create", "daimon-x",
        "--idempotency-key", UUID2, "--json", adapter=adapter,
    )
    assert code == 0
    assert json.loads(out)["idempotent-replay"] is True
    assert adapter.incus_snapshot_list("daimon-x").count(snap_name) == 1

    adapter.incus_snapshot_delete("daimon-x", snap_name)
    code, out, _ = _run(
        state_dir, "snapshot", "create", "daimon-x",
        "--idempotency-key", UUID2, "--json", adapter=adapter,
    )
    assert code == 0
    assert json.loads(out).get("idempotent-replay") is not True
    assert adapter.incus_snapshot_list("daimon-x")


def test_snapshot_replay_requires_its_durable_manifest(state_dir, adapter):
    _create_running(state_dir, adapter)
    code, out, _ = _run(
        state_dir, "snapshot", "create", "daimon-x",
        "--idempotency-key", UUID2, "--json", adapter=adapter,
    )
    assert code == 0
    first = json.loads(out)
    before = set(adapter.incus_snapshot_list("daimon-x"))
    Path(first["manifest"]).unlink()

    code, out, _ = _run(
        state_dir, "snapshot", "create", "daimon-x",
        "--idempotency-key", UUID2, "--json", adapter=adapter,
    )
    assert code == 0
    assert json.loads(out).get("idempotent-replay") is not True
    assert set(adapter.incus_snapshot_list("daimon-x")) > before


def test_snapshot_unverifiable_refuses_instead_of_duplicating(
    state_dir, adapter, monkeypatch,
):
    _create_running(state_dir, adapter)
    code, out, _ = _run(
        state_dir, "snapshot", "create", "daimon-x",
        "--idempotency-key", UUID2, "--json", adapter=adapter,
    )
    assert code == 0
    before = list(adapter.incus_snapshot_list("daimon-x"))

    def unreachable(name, snap_name):
        raise RuntimeError("incus unavailable")

    monkeypatch.setattr(adapter, "incus_snapshot_verify", unreachable)
    code, _, err = _run(
        state_dir, "snapshot", "create", "daimon-x",
        "--idempotency-key", UUID2, "--json", adapter=adapter,
    )
    assert code == 10
    assert "cannot be verified" in err
    assert adapter.incus_snapshot_list("daimon-x") == before


def test_plain_park_reexecutes_when_quiescence_cannot_be_observed(
    state_dir, adapter,
):
    _create_running(state_dir, adapter)
    code, _, _ = _run(
        state_dir, "park", "daimon-x", "--idempotency-key", UUID2,
        "--json", adapter=adapter,
    )
    assert code == 0
    code, out, _ = _run(
        state_dir, "park", "daimon-x", "--idempotency-key", UUID2,
        "--json", adapter=adapter,
    )
    assert code == 0
    assert json.loads(out).get("idempotent-replay") is not True
    parks = [call for call in adapter.mutation_log if call[0] == "exec_quiesce_park"]
    assert len(parks) == 2


def test_provision_prepare_does_not_replay_a_consumed_confirmation(
    state_dir,
):
    adapter = FakeAdapter(instances=[])
    code, out, _ = _run(
        state_dir, "provision", "prepare", "daimon-x", "--species", "test",
        "--requested-by", "alice", "--sponsor", "bob",
        "--idempotency-key", UUID1, "--json", adapter=adapter,
    )
    assert code == 0
    result = json.loads(out)
    token_path = state_dir / "confirmations" / f"{result['token']}.json"
    confirmation = json.loads(token_path.read_text(encoding="utf-8"))
    confirmation["used"] = True
    token_path.write_text(
        json.dumps(confirmation, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    code, out, _ = _run(
        state_dir, "provision", "prepare", "daimon-x", "--species", "test",
        "--requested-by", "alice", "--sponsor", "bob",
        "--idempotency-key", UUID1, "--json", adapter=adapter,
    )
    assert code == 10
    assert "idempotent-replay" not in out
