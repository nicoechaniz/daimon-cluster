"""Handoff failure-injection gap tests (issue #30, M10-R2).

Scenarios NOT already covered by test_park.py / test_transfer.py /
test_registry.py. Under the M10 ontology (docs/design/ontology.md) the
two-holders race no longer exists as a concept — the registry is a
census, never an exclusion mechanism. What remains testable here:

- network partition during transfer — adapter.exec raising mid
  restore-files → TransferError → rollback: target destroyed, source
  parked, and the census records the rollback as a NEW appended record
  (cursor never goes down; the failed attempt stays in history).
- failure during checkpoint (hmk) — park refuses and rolls the spec
  back; the census is untouched.
- audit chain — after a failed park + a failed transfer,
  clusterctl.audit.verify_chain still verifies and the failures are
  recorded as audit events.

Retired scenarios (kept here as documentation of the purge):
- clock skew / expired lease → the registry has no TTL or clock
  semantics; liveness is observed from the fleet, not the census.
- two-holders race / stale fence → plurality is normal; the equivalent
  protection is checkpoint freshness (covered by
  test_transfer.py::test_wake_stale_checkpoint_refused).
- pre-renew lease restore → rollback never restores; it APPENDS
  (covered by test_transfer.py::test_transfer_start_failure_rolls_back
  and test_registry.py::test_rollback_appends_never_restores).

Every test asserts the CONVERGENT STATE explicitly. All against
FakeAdapter — no incus.
"""

import json

import pytest

from clusterctl import audit, park, registry, transfer
from clusterctl.adapters import FakeAdapter
from clusterctl.config import Config
from clusterctl.inventory import load_spec_raw

from test_park import (  # shared fixtures/helpers from the park suite
    DAIMON_ID, NAME, _cli, _exec_handler, _write_spec)
from test_transfer import BEING, NEW, _parked, _reg


@pytest.fixture()
def state_dir(tmp_path):
    return tmp_path / "state"


@pytest.fixture()
def cfg(state_dir):
    return Config(host_id="test-host", incus_project="default",
                  managed_prefix="", profile="tribe-agent",
                  state_dir=str(state_dir))


@pytest.fixture()
def adapter():
    return FakeAdapter(
        instances=[{"name": NAME, "state": "running",
                    "image_version": "tribe-base/test", "budgets": {},
                    "uptime_s": 5}],
        exec_handler=_exec_handler)


@pytest.fixture()
def registered(state_dir):
    return _reg(state_dir).register(BEING, DAIMON_ID, NAME, "awake",
                                    actor="test")


# ---------------------------------------------------------------------------
# network partition during transfer (restore-files exec unreachable)
# ---------------------------------------------------------------------------

def test_transfer_network_partition_during_restore_rolls_back(
        state_dir, cfg, adapter):
    """adapter.exec raising mid restore-files (network partition) →
    TransferError → rollback: target destroyed, source parked, and the
    census appends a rolled-back record (the attempt stays in history;
    the cursor never goes down)."""
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)

    def partition(name, argv):
        if argv[:2] == ["sh", "-c"]:
            raise RuntimeError("network partition: exec unreachable")
        return _exec_handler(name, argv)

    adapter.exec_handler = partition
    with pytest.raises(transfer.TransferError):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")

    log = adapter.mutation_log
    assert ("create_instance", NEW) in log   # the target existed...
    assert ("start", NEW) in log             # ...was started after the
                                             # census transition...
    assert ("delete", NEW) in log            # ...and rollback destroyed it
    assert log.index(("start", NEW)) < log.index(("delete", NEW))
    assert load_spec_raw(cfg.instances_dir, NEW) is None  # spec deleted
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"

    # the census: relocation attempt (3) + rolled-back (4) — BOTH kept
    row = _reg(state_dir).get(BEING, DAIMON_ID)
    assert row["state"] == "rolled-back"
    assert row["cursor"] == 4
    states = [e["state"] for e in _reg(state_dir).history(BEING)]
    assert states == ["awake", "parked", "awake", "rolled-back",
                      "rollback-note"]

    state = json.loads(
        transfer._transfer_state_path(cfg, NAME, NEW).read_text())
    assert state["rollback"]["target_destroyed"] is True
    assert "wake --handoff" in state["rollback"]["resume_hint"]

    # CONVERGENT STATE: both parked — nothing awake; the operator
    # resumes with `wake --handoff` on the source.


# ---------------------------------------------------------------------------
# failure DURING checkpoint (hmk) — park rolls back to source awake
# ---------------------------------------------------------------------------

def test_hmk_checkpoint_failure_rolls_back_to_active(
        state_dir, cfg, adapter, registered):
    """The hmk checkpoint step failing (exec_quiesce_verify raising)
    refuses the park and rolls the spec back — the source stays awake
    and the census is never touched."""
    _write_spec(state_dir)

    def boom(name):
        raise RuntimeError("wal checkpoint failed")

    adapter.exec_quiesce_verify = boom
    with pytest.raises(park.ParkError):
        park.run_park(NAME, cfg, adapter, actor="test")

    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "active"
    assert adapter._find(NAME)["state"] == "running"
    assert not any(c[0] == "stop" for c in adapter.mutation_log)
    # the census is untouched by a failed park — still the awake row
    row = _reg(state_dir).get(BEING, DAIMON_ID)
    assert row["state"] == "awake"
    assert row["cursor"] == 1

    # CONVERGENT STATE: source awake (pre-park state restored).


# ---------------------------------------------------------------------------
# audit chain after failures
# ---------------------------------------------------------------------------

def test_audit_chain_intact_after_failed_park_and_transfer(
        state_dir, cfg, adapter, capsys):
    """A failed park (unregistered) + a failed transfer (start failure)
    are both recorded as audit events and the hash chain still
    verifies."""
    _write_spec(state_dir)

    # failed park — unregistered embodiment → verification failure (10)
    code, _ = _cli(state_dir, "park", "--handoff", NAME, adapter=adapter)
    assert code == 10
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "active"

    # park for real, then make the transfer fail at target start
    _reg(state_dir).register(BEING, DAIMON_ID, NAME, "awake", actor="test")
    code, adapter = _cli(state_dir, "park", "--handoff", NAME,
                         adapter=adapter)
    assert code == 0

    real_start = adapter.start
    def boom(name):
        if name == NEW:
            raise RuntimeError("simulated target start failure")
        return real_start(name)
    adapter.start = boom
    code, _ = _cli(state_dir, "transfer", NAME, "--to", NEW,
                   adapter=adapter)
    assert code == 10
    capsys.readouterr()

    # failures recorded as audit events...
    events = audit.read_events(state_dir)
    assert any(e["action"] == "park" and e["result"] == "error"
               for e in events)
    assert any(e["action"] == "transfer" and e["result"] == "error"
               for e in events)
    assert any(e["action"] == "park" and e["result"] == "ok"
               for e in events)

    # ...and the tamper-evident chain still verifies
    chain = audit.verify_chain(state_dir)
    assert chain["ok"] is True
    assert chain["error"] is None

    # CONVERGENT STATE: both parked — the failed transfer rolled back
    # (target destroyed, source parked); nothing is left half-awake.
    assert load_spec_raw(cfg.instances_dir, NEW) is None
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"
