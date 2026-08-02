"""Effect-truth idempotency tests (M10-R5).

The drill #26 bug class, root-fixed: the idempotency store recorded
"stop ok" while the body never actually stopped — a retry replayed the
recorded result against a contradictory reality. After R5, a replay is
served ONLY when the observed state matches the recorded effect; a
contradiction is audited as an effect-truth discrepancy and the
operation executes FRESH (operations are state-convergent — replaying
a lie is not).

The human_turn keying (UX double-click dedupe) is untouched: a
verified replay still no-ops exactly once.
"""

import json

import pytest

from clusterctl import audit
from clusterctl.adapters import FakeAdapter
from clusterctl.cli import run

UUID1 = "11111111-1111-1111-1111-111111111111"
UUID2 = "22222222-2222-2222-2222-222222222222"


@pytest.fixture()
def state_dir(tmp_path):
    return tmp_path / "state"


def _run(state_dir, *argv, adapter):
    import contextlib
    import io
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = run(["--config", "configs/clusterctl.yaml",
                    "--state-dir", str(state_dir),
                    "--actor", "test", *argv], adapter=adapter)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture()
def adapter():
    # empty world — every test creates daimon-x through the CLI so the
    # idempotency records and the fake substrate stay in the same world
    return FakeAdapter(instances=[], exec_handler=lambda name, argv: "")


def _create(state_dir, adapter):
    code, _, _ = _run(state_dir, "create", "daimon-x", "--species", "t",
                      "--idempotency-key", UUID1, adapter=adapter)
    assert code == 0
    adapter.start("daimon-x")


# ---------------------------------------------------------------------------
# the drill #26 class: recorded "stopped", body actually running
# ---------------------------------------------------------------------------

def test_false_record_is_not_replayed(state_dir, adapter, capsys):
    _create(state_dir, adapter)

    # a stop executes and records its effect
    code, _, _ = _run(state_dir, "stop", "daimon-x",
                      "--idempotency-key", UUID2, "--json", adapter=adapter)
    assert code == 0
    capsys.readouterr()
    assert adapter._find("daimon-x")["state"] == "stopped"

    # THE LIE: reality moves on without the store (a crash, a manual
    # incus start, another actor) — the record now says "stopped" but
    # the body is running
    adapter.start("daimon-x")

    # a retry with the same key must NOT replay the false record: it
    # re-executes (converging the body back to stopped) and audits the
    # discrepancy
    code, out, _ = _run(state_dir, "stop", "daimon-x",
                        "--idempotency-key", UUID2, "--json", adapter=adapter)
    assert code == 0
    payload = json.loads(out)
    assert payload.get("idempotent-replay") is not True
    assert adapter._find("daimon-x")["state"] == "stopped"

    events = audit.read_events(state_dir)
    discrepancies = [e for e in events
                     if e["result"] == "error"
                     and (e.get("detail") or {}).get("kind")
                     == "effect-truth-discrepancy"]
    assert len(discrepancies) == 1
    detail = discrepancies[0]["detail"]
    assert detail["observed"]["state"] == "running"
    assert detail["recorded_effect"]["state"] == "stopped"
    # the tamper-evident chain holds through the discrepancy events
    assert audit.verify_chain(state_dir)["ok"] is True


def test_verified_replay_still_noops(state_dir, adapter, capsys):
    """The UX dedupe (double-click protection) is untouched: when the
    observed state DOES match the record, the replay no-ops."""
    _create(state_dir, adapter)
    code, _, _ = _run(state_dir, "stop", "daimon-x",
                      "--idempotency-key", UUID2, "--json", adapter=adapter)
    assert code == 0
    capsys.readouterr()

    code, out, _ = _run(state_dir, "stop", "daimon-x",
                        "--idempotency-key", UUID2, "--json", adapter=adapter)
    assert code == 0
    payload = json.loads(out)
    assert payload["idempotent-replay"] is True
    assert payload["effect-truth"] == "verified"
    # exactly one stop reached the substrate
    stops = [c for c in adapter.mutation_log
             if c[0] == "stop" and c[1] == "daimon-x"]
    assert len(stops) == 1


def test_start_replay_against_stopped_body_reexecutes(state_dir, adapter,
                                                      capsys):
    """Mirror image: recorded "active", body actually stopped → fresh
    execution starts it."""
    _create(state_dir, adapter)
    code, _, _ = _run(state_dir, "start", "daimon-x",
                      "--idempotency-key", UUID2, "--json", adapter=adapter)
    assert code == 0
    capsys.readouterr()
    adapter.stop("daimon-x", 30)  # reality contradicts the record

    code, out, _ = _run(state_dir, "start", "daimon-x",
                        "--idempotency-key", UUID2, "--json", adapter=adapter)
    assert code == 0
    assert json.loads(out).get("idempotent-replay") is not True
    assert adapter._find("daimon-x")["state"] == "running"


def test_snapshot_replay_verified_by_snapshot_presence(state_dir, adapter,
                                                       capsys):
    """snapshot-create verifies via incus_snapshot_verify: replay only
    while the recorded snapshot actually exists."""
    _create(state_dir, adapter)
    code, out, _ = _run(state_dir, "snapshot", "create", "daimon-x",
                        "--idempotency-key", UUID2, "--json",
                        adapter=adapter)
    assert code == 0
    snap = json.loads(out)["snap_name"]
    capsys.readouterr()

    # snapshot present → verified replay, no second snapshot
    code, out, _ = _run(state_dir, "snapshot", "create", "daimon-x",
                        "--idempotency-key", UUID2, "--json",
                        adapter=adapter)
    assert code == 0
    assert json.loads(out)["idempotent-replay"] is True
    assert adapter.incus_snapshot_list("daimon-x").count(snap) == 1

    # snapshot deleted in reality → contradiction → fresh execution
    adapter.incus_snapshot_delete("daimon-x", snap)
    code, out, _ = _run(state_dir, "snapshot", "create", "daimon-x",
                        "--idempotency-key", UUID2, "--json",
                        adapter=adapter)
    assert code == 0
    payload = json.loads(out)
    assert payload.get("idempotent-replay") is not True
    assert adapter.incus_snapshot_list("daimon-x")  # a new one exists
