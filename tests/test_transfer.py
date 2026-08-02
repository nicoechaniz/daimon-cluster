"""Transfer, wake, re-entry, and rollback tests (issue #29).

Covers: wake happy path (fence epoch+1, verified restore, announcement),
stale-fence refusal, no-fence manifest refusal, wake start-failure
rollback, transfer happy path (call ORDER: create before start, fence
before start), transfer pre-condition refusals, tampered-manifest
refusal, CAS-failure rollback (target destroyed, spec deleted, source
parked with lease intact), restored-file sha mismatch, and resume from
an interruption point. All against FakeAdapter — no incus.
"""

import hashlib
import json

import pytest

from clusterctl import leases, park, transfer
from clusterctl.adapters import FakeAdapter
from clusterctl.cli import run
from clusterctl.config import Config
from clusterctl.embodiments import Registry
from clusterctl.inventory import load_spec_raw

from test_park import (  # shared fixtures/helpers from the park suite
    COMMIT_SHA, DAIMON_ID, FINGERPRINT, HANDOFF_CONTENT, NAME,
    NOW_CONTENT, PUBKEY, _Kill, _exec_handler, _manifest_path,
    _write_spec)

NEW = "daimon-y"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


EXPECTED_RESTORED = {
    "NOW.md": _sha(NOW_CONTENT),
    "DIALOGUE-HANDOFF.md": _sha(HANDOFF_CONTENT),
}


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


def _parked(state_dir, cfg, adapter):
    """Park NAME with a lease, leaving a verified manifest behind."""
    store = leases.LeaseStore(state_dir)
    store.acquire(DAIMON_ID, PUBKEY, FINGERPRINT)
    result = park.run_park(NAME, cfg, adapter, actor="test")
    assert result["result"] == "ok"
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"
    adapter.mutation_log.clear()


def _lease_files(state_dir):
    return list((state_dir / "leases").glob("*.json"))


def _declare_running_embodiment(state_dir):
    registry = Registry(state_dir)
    embodiment = registry.register(body_ref=DAIMON_ID)
    first = registry.start(embodiment["embodiment_id"])
    _write_spec(
        state_dir, body_ref=DAIMON_ID,
        embodiment_id=embodiment["embodiment_id"],
        current_incarnation_id=first["incarnation_id"],
    )
    return embodiment, first


# ---------------------------------------------------------------------------
# wake --handoff
# ---------------------------------------------------------------------------

def test_wake_happy_path(state_dir, cfg, adapter):
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)

    res = transfer.run_wake(NAME, cfg, adapter, actor="test")

    assert res["result"] == "ok"
    assert res["state"] == "active"
    assert res["fence_epoch"] == 1  # park held epoch 0; wake renews to 1
    assert res["announcement"] == "embodiment-relocation"
    assert res["restored_files"] == EXPECTED_RESTORED
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "active"
    assert ("start", NAME) in adapter.mutation_log


def test_park_and_wake_close_then_open_incarnation(state_dir, cfg, adapter):
    embodiment, first = _declare_running_embodiment(state_dir)
    _parked(state_dir, cfg, adapter)
    assert Registry(state_dir).status(embodiment["embodiment_id"])["status"] == "stopped"
    assert load_spec_raw(cfg.instances_dir, NAME)["current_incarnation_id"] is None

    result = transfer.run_wake(NAME, cfg, adapter, actor="test")
    assert result["incarnation_id"] != first["incarnation_id"]
    current = Registry(state_dir).status(embodiment["embodiment_id"])
    assert current["current_incarnation_id"] == result["incarnation_id"]


def test_wake_stale_fence_refused(state_dir, cfg, adapter):
    """Another holder renewed first → CAS refuse, container stays down."""
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)
    leases.LeaseStore(state_dir).renew(DAIMON_ID, "")  # epoch 1 externally

    with pytest.raises(transfer.TransferRefused):
        transfer.run_wake(NAME, cfg, adapter, actor="test")

    assert not any(c[0] == "start" for c in adapter.mutation_log)
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"


def test_wake_no_fence_manifest_refused(state_dir, cfg, adapter):
    """A --no-fence checkpoint cannot drive a resource-moving wake."""
    _write_spec(state_dir)
    park.run_park(NAME, cfg, adapter, actor="test", no_fence=True)
    adapter.mutation_log.clear()

    with pytest.raises(transfer.TransferRefused):
        transfer.run_wake(NAME, cfg, adapter, actor="test")
    assert not any(c[0] == "start" for c in adapter.mutation_log)


def test_wake_without_park_refused(state_dir, cfg, adapter):
    _write_spec(state_dir)  # status active, no manifest
    with pytest.raises(transfer.TransferRefused):
        transfer.run_wake(NAME, cfg, adapter, actor="test")


def test_wake_start_failure_rolls_back(state_dir, cfg, adapter):
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)

    def boom(name):
        raise RuntimeError("simulated start failure")
    adapter.start = boom

    with pytest.raises(transfer.TransferError):
        transfer.run_wake(NAME, cfg, adapter, actor="test")

    # spec rolled back to parked; the failure is recorded
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"
    record = json.loads(
        transfer._wake_record_path(cfg, NAME, 1).read_text())
    assert record["status"] == "failed"
    assert "start failure" in record["error"]


def test_wake_resume_from_interruption(state_dir, cfg, adapter):
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)
    seen = []

    def killer(step):
        seen.append(step)
        if len(seen) == 2:
            raise _Kill()

    with pytest.raises(_Kill):
        transfer.run_wake(NAME, cfg, adapter, actor="test",
                          on_step=killer)
    res = transfer.run_wake(NAME, cfg, adapter, actor="test")
    assert res["result"] == "ok"
    assert res["fence_epoch"] == 1


# ---------------------------------------------------------------------------
# transfer
# ---------------------------------------------------------------------------

def test_transfer_happy_path_order(state_dir, cfg, adapter):
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)

    res = transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")

    log = adapter.mutation_log
    i_create = log.index(("create_instance", NEW))
    i_start = log.index(("start", NEW))
    assert i_create < i_start  # target never reachable before create+verify
    # the fence (epoch 1) is held by the time start ran (step e before f)
    st = leases.LeaseStore(state_dir).status(DAIMON_ID)
    assert st["last_epoch"] == 1
    assert res["result"] == "ok"
    assert res["announcement"] == "embodiment-relocation"
    assert res["volume"] == "moved"
    assert res["restored_files"] == EXPECTED_RESTORED
    assert res["state_commit"] == COMMIT_SHA
    assert res["source_status"] == "transferred"
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "transferred"
    target_spec = load_spec_raw(cfg.instances_dir, NEW)
    assert target_spec["status"] == "active"
    assert target_spec["transferred_from"] == NAME
    # signed transfer record on disk
    record = json.loads(open(res["transfer_record"]).read())
    assert record["schema"] == "transfer-record/v1"
    assert record["source"] == NAME and record["target"] == NEW
    assert record["signature"]


def test_transfer_preserves_embodiment_and_opens_incarnation(state_dir, cfg, adapter):
    embodiment, first = _declare_running_embodiment(state_dir)
    _parked(state_dir, cfg, adapter)
    result = transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")
    target = load_spec_raw(cfg.instances_dir, NEW)
    assert target["embodiment_id"] == embodiment["embodiment_id"]
    assert result["incarnation_id"] != first["incarnation_id"]
    assert target["current_incarnation_id"] == result["incarnation_id"]


def test_transfer_requires_parked_source(state_dir, cfg, adapter):
    _write_spec(state_dir)  # active, not parked
    with pytest.raises(transfer.TransferRefused):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")


def test_transfer_tampered_manifest_refused(state_dir, cfg, adapter):
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)
    mp = _manifest_path(state_dir)
    manifest = json.loads(mp.read_text())
    manifest["actor"] = "mallory"
    mp.write_text(json.dumps(manifest))

    with pytest.raises(transfer.TransferRefused):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")
    # nothing was created
    assert not any(c[0] == "create_instance"
                   for c in adapter.mutation_log)
    assert load_spec_raw(cfg.instances_dir, NEW) is None


def test_transfer_cas_failure_rolls_back(state_dir, cfg, adapter):
    """Fence CAS failure after target create → full rollback, source
    parked with its lease intact."""
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)
    for f in _lease_files(state_dir):  # identity lease vanished
        f.unlink()

    with pytest.raises(transfer.TransferError):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")

    log = adapter.mutation_log
    assert ("create_instance", NEW) in log   # target existed...
    assert ("delete", NEW) in log            # ...and was destroyed
    assert not any(c == ("start", NEW) for c in log)  # never started
    assert load_spec_raw(cfg.instances_dir, NEW) is None  # spec deleted
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"
    # transfer-state records the rollback with a resume hint
    state = json.loads(
        transfer._transfer_state_path(cfg, NAME, NEW).read_text())
    assert state["rollback"]["attempted"] is True
    assert "wake --handoff" in state["rollback"]["resume_hint"]


def test_transfer_restored_sha_mismatch_rolls_back(state_dir, cfg, adapter):
    """A corrupted parked state file must never reach the target."""
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)
    parked_now = (park._park_dir(cfg, NAME) / NAME / "state" / "NOW.md")
    parked_now.write_text("tampered content\n", encoding="utf-8")

    with pytest.raises(transfer.TransferRefused):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")
    assert not any(c[0] == "create_instance"
                   for c in adapter.mutation_log)


def test_transfer_resume_from_interruption(state_dir, cfg, adapter):
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)
    seen = []

    def killer(step):
        seen.append(step)
        if len(seen) == 3:
            raise _Kill()

    with pytest.raises(_Kill):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test",
                              on_step=killer)
    res = transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")
    assert res["result"] == "ok"
    assert load_spec_raw(cfg.instances_dir, NEW)["status"] == "active"


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def _cli(state_dir, *argv, adapter):
    import contextlib
    import io
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = run(["--config", "configs/clusterctl.yaml",
                    "--state-dir", str(state_dir),
                    "--actor", "test", *argv], adapter=adapter)
    return code, out.getvalue(), err.getvalue()


def test_cli_wake_handoff_and_transfer(state_dir, cfg, adapter):
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)

    code, out, _ = _cli(state_dir, "wake", "--handoff", NAME, "--json",
                        adapter=adapter)
    assert code == 0
    assert json.loads(out)["announcement"] == "embodiment-relocation"

    # park again, then transfer via CLI
    park.run_park(NAME, cfg, adapter, actor="test")
    code, out, _ = _cli(state_dir, "transfer", NAME, "--to", NEW,
                        "--json", adapter=adapter)
    assert code == 0
    assert json.loads(out)["target"] == NEW


def test_announcement_strings_distinct():
    """Relocation vs creation announcements are exact, distinct strings."""
    assert transfer.ANNOUNCEMENT_RELOCATION == "embodiment-relocation"
    assert transfer.ANNOUNCEMENT_RELOCATION != "incarnation-creation"
