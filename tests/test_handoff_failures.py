"""Handoff failure-injection gap tests (issue #30).

Scenarios NOT already covered by test_park.py / test_transfer.py:

- clock skew — a lease with ttl_s=1 and created_ms far in the past:
  status() reports expired; the expired lease does NOT block re-acquire
  (a new holder acquires; the old holder's renew is refused).
- stale holder traffic — the two-holders race: holder A parks (epoch 0),
  holder B re-acquires after expiry (epoch 0, NEW acquisition), holder A
  attempts wake with its old manifest → TransferRefused (stale fence).
  Epochs reset on re-acquire, so this binds the manifest to the lease
  acquisition timestamp (lease_acquired_ms / acquired_ms).
- network partition during transfer — adapter.exec raising mid
  restore-files → TransferError → rollback leaves the target destroyed
  and the source parked.
- failure after CAS but before start (transfer) — adapter.start raising
  → rollback restores the pre-renew lease EXACTLY (epoch back to 0 via
  store.restore).
- hmk checkpoint failure during park (during-checkpoint injection).
- audit chain — after a failed park + a failed transfer,
  clusterctl.audit.verify_chain still verifies and the failures are
  recorded as audit events.

(Broker restart / non-empty bridge outbox is covered by
test_park.py::test_outbox_nonempty_refused_unless_forced — referenced
from the matrix, not duplicated here.)

Every test asserts the CONVERGENT STATE explicitly — exactly one of the
three documented states: source awake | both parked | target awake.

All tests run against FakeAdapter — no incus.
"""

import json

import pytest

from clusterctl import audit, leases, park, transfer
from clusterctl.adapters import FakeAdapter
from clusterctl.config import Config
from clusterctl.inventory import load_spec_raw

from test_park import (  # shared fixtures/helpers from the park suite
    DAIMON_ID, FINGERPRINT, NAME, PUBKEY, _cli, _exec_handler, _write_spec)
from test_transfer import NEW, _parked


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
def lease(state_dir):
    store = leases.LeaseStore(state_dir)
    return store.acquire(DAIMON_ID, PUBKEY, FINGERPRINT)


def _lease_path(state_dir, daimon_id=DAIMON_ID):
    return state_dir / "leases" / f"{daimon_id}.json"


def _expire_lease_file(state_dir, daimon_id=DAIMON_ID):
    """Clock-skew the lease on disk: created_ms far in the past, ttl 1s.

    The file is re-signed so it stays a valid lease/v1 record — only its
    TIMING is wrong, simulating a holder whose clock (or whose lease
    file) is stale.
    """
    path = _lease_path(state_dir, daimon_id)
    lease = json.loads(path.read_text())
    lease["ttl_s"] = 1
    lease["created_ms"] = leases.now_ms() - 10_000
    signer = leases.FakeSigner()
    lease["signature"] = signer.sign(leases._canonical(lease))
    path.write_text(json.dumps(lease, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")


# ---------------------------------------------------------------------------
# clock skew — expired lease reporting + re-acquire
# ---------------------------------------------------------------------------

def test_clock_skew_expired_lease_status_and_reacquire(state_dir, lease):
    """A lease with ttl_s=1 read with created_ms far in the past is
    expired; it does not block re-acquire and the old holder cannot
    renew."""
    store = leases.LeaseStore(state_dir)
    _expire_lease_file(state_dir)

    # status() reports expired
    st = store.status(DAIMON_ID)
    assert st["present"] is True
    assert st["expired"] is True
    assert st["expires_in_ms"] == 0

    # the OLD holder's renew is refused (CAS fencing on expiry)
    assert store.renew(DAIMON_ID, "") is None

    # the expired lease does NOT block re-acquire — a new holder takes
    # the identity with a fresh fence (epoch 0, NEW acquisition)
    new = store.acquire(DAIMON_ID, PUBKEY, FINGERPRINT)
    assert new["epoch"] == 0
    st = store.status(DAIMON_ID)
    assert st["expired"] is False
    assert st["last_epoch"] == 0

    # CONVERGENT STATE: exactly one valid holder — the new acquisition
    # (source awake under the new holder; no stale fence accepted).
    all_active = [s for s in store.list_all() if not s["expired"]]
    assert len(all_active) == 1
    assert all_active[0]["acquired_ms"] == new["acquired_ms"]


# ---------------------------------------------------------------------------
# stale holder traffic — the two-holders race
# ---------------------------------------------------------------------------

def test_stale_holder_wake_with_old_manifest_refused(
        state_dir, cfg, adapter):
    """Holder A parks (epoch 0). Holder B re-acquires after expiry
    (epoch 0, NEW acquisition). Holder A's wake with the OLD manifest
    is refused as a stale fence — B's fence is the only valid holder."""
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)  # A parks: manifest bound to A's lease

    # A's lease lapses (clock skew); B acquires a NEW fence at epoch 0.
    _expire_lease_file(state_dir)
    store = leases.LeaseStore(state_dir)
    b_lease = store.acquire(DAIMON_ID, PUBKEY, FINGERPRINT)
    assert b_lease["epoch"] == 0  # epoch resets — the race window

    # A attempts wake with its old manifest → stale fence refusal.
    with pytest.raises(transfer.TransferRefused):
        transfer.run_wake(NAME, cfg, adapter, actor="test")

    # A never started the container; the spec stays parked.
    assert not any(c[0] == "start" for c in adapter.mutation_log)
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"

    # B's fence is untouched and is the ONLY valid holder.
    st = store.status(DAIMON_ID)
    assert st["last_epoch"] == 0
    assert st["expired"] is False
    assert st["acquired_ms"] == b_lease["acquired_ms"]

    # CONVERGENT STATE: both parked — nothing was woken by the stale
    # holder; the identity stays with B (no two valid holders, no
    # accepted work from a stale fence).


def test_stale_holder_transfer_with_old_manifest_refused(
        state_dir, cfg, adapter):
    """Same race on the transfer entry point: the provenance gate
    refuses before any target is created."""
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)
    _expire_lease_file(state_dir)
    store = leases.LeaseStore(state_dir)
    store.acquire(DAIMON_ID, PUBKEY, FINGERPRINT)  # B's new fence

    with pytest.raises(transfer.TransferRefused):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")

    # nothing was created — refusal happened at the provenance gate
    assert not any(c[0] == "create_instance" for c in adapter.mutation_log)
    assert load_spec_raw(cfg.instances_dir, NEW) is None
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"

    # CONVERGENT STATE: both parked (source parked, target never
    # created; B remains the only valid holder).


# ---------------------------------------------------------------------------
# network partition during transfer (restore-files exec unreachable)
# ---------------------------------------------------------------------------

def test_transfer_network_partition_during_restore_rolls_back(
        state_dir, cfg, adapter):
    """adapter.exec raising mid restore-files (network partition) →
    TransferError → rollback: target destroyed, source parked, lease
    intact."""
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
                                             # fence (live-drill order)...
    assert ("delete", NEW) in log            # ...and rollback destroyed it
    assert log.index(("start", NEW)) < log.index(("delete", NEW))
    assert load_spec_raw(cfg.instances_dir, NEW) is None  # spec deleted
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"

    # the fence WAS taken (epoch 1) before the partition — rollback must
    # restore the pre-renew lease EXACTLY (epoch back to 0)
    st = leases.LeaseStore(state_dir).status(DAIMON_ID)
    assert st["last_epoch"] == 0
    assert st["expired"] is False

    state = json.loads(
        transfer._transfer_state_path(cfg, NAME, NEW).read_text())
    assert state["rollback"]["target_destroyed"] is True
    assert "wake --handoff" in state["rollback"]["resume_hint"]

    # CONVERGENT STATE: both parked — nothing awake; the operator
    # resumes with `wake --handoff` on the source.


# ---------------------------------------------------------------------------
# failure after CAS but before start — fence restored EXACTLY
# ---------------------------------------------------------------------------

def test_transfer_start_failure_restores_pre_renew_lease(
        state_dir, cfg, adapter):
    """adapter.start raising AFTER the fence CAS → rollback restores the
    pre-renew lease EXACTLY (epoch back to 0 via store.restore)."""
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)
    pre_renew = leases.LeaseStore(state_dir).get(DAIMON_ID)
    assert pre_renew["epoch"] == 0

    def boom(name):
        raise RuntimeError("simulated target start failure")

    adapter.start = boom
    with pytest.raises(transfer.TransferError):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")

    # the lease is back EXACTLY at its pre-renew state: epoch 0, same
    # acquisition, still valid
    restored = leases.LeaseStore(state_dir).get(DAIMON_ID)
    assert restored is not None
    assert restored["epoch"] == 0
    assert restored["acquired_ms"] == pre_renew["acquired_ms"]
    assert restored["created_ms"] == pre_renew["created_ms"]
    st = leases.LeaseStore(state_dir).status(DAIMON_ID)
    assert st["expired"] is False
    assert st["last_epoch"] == 0

    # target destroyed, source parked; rollback recorded fence_restored
    log = adapter.mutation_log
    assert ("delete", NEW) in log
    assert load_spec_raw(cfg.instances_dir, NEW) is None
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"
    state = json.loads(
        transfer._transfer_state_path(cfg, NAME, NEW).read_text())
    assert state["rollback"]["fence_restored"] is True
    assert state["rollback"]["target_destroyed"] is True

    # CONVERGENT STATE: both parked — no valid second holder was left
    # behind; the source resumes with `wake --handoff` from epoch 0.


# ---------------------------------------------------------------------------
# failure DURING checkpoint (hmk) — park rolls back to source awake
# ---------------------------------------------------------------------------

def test_hmk_checkpoint_failure_rolls_back_to_active(
        state_dir, cfg, adapter, lease):
    """The hmk checkpoint step failing (exec_quiesce_verify raising)
    refuses the park and rolls the spec back — the source stays awake."""
    _write_spec(state_dir)

    def boom(name):
        raise RuntimeError("wal checkpoint failed")

    adapter.exec_quiesce_verify = boom
    with pytest.raises(park.ParkError):
        park.run_park(NAME, cfg, adapter, actor="test")

    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "active"
    assert adapter._find(NAME)["state"] == "running"
    assert not any(c[0] == "stop" for c in adapter.mutation_log)
    # the lease is never touched by a failed park
    st = leases.LeaseStore(state_dir).status(DAIMON_ID)
    assert st["present"] and not st["expired"]

    # CONVERGENT STATE: source awake (pre-park state restored).


# ---------------------------------------------------------------------------
# audit chain after failures
# ---------------------------------------------------------------------------

def test_audit_chain_intact_after_failed_park_and_transfer(
        state_dir, cfg, adapter, capsys):
    """A failed park (no lease) + a failed transfer (lease vanished at
    the CAS step) are both recorded as audit events and the hash chain
    still verifies."""
    _write_spec(state_dir)

    # failed park — no lease held → verification failure (exit 10)
    code, _ = _cli(state_dir, "park", "--handoff", NAME, adapter=adapter)
    assert code == 10
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "active"

    # park for real, then make the transfer fail at the fence CAS
    leases.LeaseStore(state_dir).acquire(DAIMON_ID, PUBKEY, FINGERPRINT)
    code, adapter = _cli(state_dir, "park", "--handoff", NAME,
                         adapter=adapter)
    assert code == 0
    for f in (state_dir / "leases").glob("*.json"):
        f.unlink()  # identity lease vanishes before the CAS
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
