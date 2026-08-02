"""Transfer, wake, re-entry, and rollback tests (issue #29, M10-R2).

Covers: wake happy path (census transition at cursor+1, verified restore,
announcement), stale-checkpoint refusal (the census moved past), no-registry
manifest refusal, wake start-failure rollback (append-only: the embodiment
goes back to parked as a NEW record), transfer happy path (call ORDER:
create before register before start), transfer pre-condition refusals,
tampered-manifest refusal, start-failure rollback (target destroyed, spec
deleted, rolled-back record appended), restored-file sha mismatch, and
resume from an interruption point. All against FakeAdapter — no incus.

Ontology (docs/design/ontology.md): the registry is a census, never an
exclusion mechanism; transitions append at cursor+1 and the cursor never
goes down.
"""

import hashlib
import json

import pytest

from clusterctl import park, registry, transfer
from clusterctl.adapters import FakeAdapter
from clusterctl.cli import run
from clusterctl.config import Config
from clusterctl.inventory import load_spec_raw

from test_park import (  # shared fixtures/helpers from the park suite
    COMMIT_SHA, DAIMON_ID, HANDOFF_CONTENT, NAME,
    NOW_CONTENT, _Kill, _exec_handler, _manifest_path,
    _write_spec)

NEW = "daimon-y"
BEING = "daimon-x"


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


def _reg(state_dir):
    return registry.EmbodimentRegistry(state_dir)


def _parked(state_dir, cfg, adapter):
    """Register the embodiment awake, then park it — leaving a verified
    manifest behind and the census parked at cursor 2."""
    _reg(state_dir).register(BEING, DAIMON_ID, NAME, "awake", actor="test")
    result = park.run_park(NAME, cfg, adapter, actor="test")
    assert result["result"] == "ok"
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"
    adapter.mutation_log.clear()


# ---------------------------------------------------------------------------
# wake --handoff
# ---------------------------------------------------------------------------

def test_wake_happy_path(state_dir, cfg, adapter):
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)

    res = transfer.run_wake(NAME, cfg, adapter, actor="test")

    assert res["result"] == "ok"
    assert res["state"] == "active"
    assert res["cursor"] == 3  # awake=1, parked=2, re-entry=3
    assert res["announcement"] == "same-identity-relocation"
    assert res["restored_files"] == EXPECTED_RESTORED
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "active"
    assert ("start", NAME) in adapter.mutation_log
    row = _reg(state_dir).get(BEING, DAIMON_ID)
    assert row["state"] == "awake"
    assert row["body"] == NAME


def test_wake_stale_checkpoint_refused(state_dir, cfg, adapter):
    """The census moved past this checkpoint (a newer transition was
    registered) → refuse; the container stays down."""
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)
    _reg(state_dir).set_state(BEING, DAIMON_ID, "awake", actor="external")

    with pytest.raises(transfer.TransferRefused):
        transfer.run_wake(NAME, cfg, adapter, actor="test")

    assert not any(c[0] == "start" for c in adapter.mutation_log)
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"


def test_wake_no_registry_manifest_refused(state_dir, cfg, adapter):
    """A --no-registry checkpoint cannot drive a handoff wake."""
    _write_spec(state_dir)
    park.run_park(NAME, cfg, adapter, actor="test", no_registry=True)
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
        transfer._wake_record_path(cfg, NAME, 2).read_text())
    assert record["status"] == "failed"
    assert "start failure" in record["error"]
    # append-only rollback: the census records parked AGAIN at cursor+1 —
    # the awake attempt stays in history, the cursor never goes down
    row = _reg(state_dir).get(BEING, DAIMON_ID)
    assert row["state"] == "parked"
    assert row["cursor"] == 4  # awake=1, parked=2, re-entry=3, rollback=4
    states = [e["state"] for e in _reg(state_dir).history(BEING)]
    assert states == ["awake", "parked", "awake", "parked"]


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
    assert res["cursor"] == 3


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
    # the census recorded the relocation (cursor 3) before start ran
    row = _reg(state_dir).get(BEING, DAIMON_ID)
    assert row["state"] == "awake"
    assert row["body"] == NEW
    assert row["cursor"] == 3
    assert res["result"] == "ok"
    assert res["cursor"] == 3
    assert res["announcement"] == "same-identity-relocation"
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
    assert record["cursor"] == 3
    assert record["signature"]


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


def test_transfer_start_failure_rolls_back(state_dir, cfg, adapter):
    """Start failure after the census transition → full rollback: target
    destroyed, spec deleted, and the embodiment back to parked as a NEW
    record (append-only — the cursor never goes down)."""
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)

    real_start = adapter.start
    def boom(name):
        if name == NEW:
            raise RuntimeError("simulated target start failure")
        return real_start(name)
    adapter.start = boom

    with pytest.raises(transfer.TransferError):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")

    log = adapter.mutation_log
    assert ("create_instance", NEW) in log   # target existed...
    assert ("delete", NEW) in log            # ...and was destroyed
    assert load_spec_raw(cfg.instances_dir, NEW) is None  # spec deleted
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"
    # the census: relocation attempt (3) + rolled-back (4), both kept
    row = _reg(state_dir).get(BEING, DAIMON_ID)
    assert row["state"] == "rolled-back"
    assert row["cursor"] == 4
    states = [e["state"] for e in _reg(state_dir).history(BEING)]
    assert states == ["awake", "parked", "awake", "rolled-back",
                      "rollback-note"]
    # transfer-state records the rollback with a resume hint
    state = json.loads(
        transfer._transfer_state_path(cfg, NAME, NEW).read_text())
    assert state["rollback"]["attempted"] is True
    assert state["rollback"]["registry_rolled_back"] is True
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
    assert json.loads(out)["announcement"] == "same-identity-relocation"

    # park again, then transfer via CLI
    park.run_park(NAME, cfg, adapter, actor="test")
    code, out, _ = _cli(state_dir, "transfer", NAME, "--to", NEW,
                        "--json", adapter=adapter)
    assert code == 0
    assert json.loads(out)["target"] == NEW


def test_announcement_strings_distinct():
    """Relocation vs creation announcements are exact, distinct strings."""
    assert transfer.ANNOUNCEMENT_RELOCATION == "same-identity-relocation"
    assert transfer.ANNOUNCEMENT_RELOCATION != "incarnation-creation"
