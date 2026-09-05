"""Park with verified checkpoint manifest tests (issue #28).

Covers: happy path (all 8 steps), resume from every interruption point,
verification failure rollback, secret-refusal (fail-closed), unsigned /
tampered manifest rejection, --abandon-critical actor recording, the
explicit --no-fence path, and CLI wiring.

All tests run against FakeAdapter with a scripted exec_handler — no incus.
"""

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from clusterctl import leases, park
from clusterctl.adapters import FakeAdapter
from clusterctl.cli import run
from clusterctl.config import Config
from clusterctl.inventory import load_spec_raw

NAME = "daimon-x"
DAIMON_ID = "daimon-x@daimonmatrix"
PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGfakekey12345"
FINGERPRINT = "SHA256:abc123def456"
COMMIT_SHA = "c0ffee11" * 6

NOW_CONTENT = "# NOW\nworking on issue 28\n"
HANDOFF_CONTENT = "# DIALOGUE-HANDOFF\nresume hint: park tests\n"


class _Kill(Exception):
    """Simulates a kill between steps (raised inside the on_step hook)."""


class _OuterCrash(BaseException):
    """Simulates process loss at an outer operation-journal boundary."""


def _spec_dict(**overrides):
    spec = {
        "schema": "instance-spec/v1",
        "name": NAME,
        "species": "test",
        "image_version": "daimon-base/test",
        "budgets": {"cpu": 1, "memory_mib": 1536, "disk_gib": 8},
        "created_ms": 1,
        "created_by": "test",
        "daimon_id": DAIMON_ID,
        "hmk_path": "/home/agent/.hermes/agent-memory/library.db",
        "state_files": True,
        "state_repo": True,
    }
    spec.update(overrides)
    return spec


def _write_spec(state_dir, **overrides):
    inst = state_dir / "instances"
    inst.mkdir(parents=True, exist_ok=True)
    (inst / f"{NAME}.yaml").write_text(
        yaml.safe_dump(_spec_dict(**overrides), sort_keys=False),
        encoding="utf-8")


def _exec_handler(name, argv):
    if argv[:1] == ["cat"]:
        if argv[1].endswith("NOW.md"):
            return NOW_CONTENT
        if argv[1].endswith("DIALOGUE-HANDOFF.md"):
            return HANDOFF_CONTENT
        return None
    if argv[:1] == ["git"]:
        if "diff" in argv:
            return ""
        if "rev-parse" in argv:
            return COMMIT_SHA + "\n"
        return ""
    return None


@pytest.fixture()
def state_dir(tmp_path):
    return tmp_path / "state"


@pytest.fixture()
def cfg(state_dir):
    return Config(host_id="test-host", incus_project="default",
                  managed_prefix="", profile="daimon-agent",
                  state_dir=str(state_dir))


@pytest.fixture()
def adapter():
    return FakeAdapter(
        instances=[{"name": NAME, "state": "running",
                    "image_version": "daimon-base/test", "budgets": {},
                    "uptime_s": 5}],
        exec_handler=_exec_handler)


@pytest.fixture()
def lease(state_dir):
    store = leases.LeaseStore(state_dir)
    return store.acquire(DAIMON_ID, PUBKEY, FINGERPRINT)


def _cli(state_dir, *argv, adapter=None):
    ad = adapter if adapter is not None else FakeAdapter(
        instances=[{"name": NAME, "state": "running",
                    "image_version": "daimon-base/test", "budgets": {},
                    "uptime_s": 5}],
        exec_handler=_exec_handler)
    code = run(["--state-dir", str(state_dir), *argv], adapter=ad)
    return code, ad


def _manifest_path(state_dir, fence_epoch=0):
    suffix = fence_epoch if fence_epoch is not None else "nofence"
    return state_dir / "park" / NAME / f"manifest-{suffix}.json"


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------


def test_happy_path_all_steps(state_dir, cfg, adapter, lease, capsys):
    _write_spec(state_dir)
    out = park.run_park(NAME, cfg, adapter, actor="test")
    ad = adapter
    assert out["result"] == "ok"
    assert out["state"] == "parked"

    # spec transitioned to parked via the spec-store API
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"
    # container stopped only after manifest verified
    assert ad._find(NAME)["state"] == "stopped"

    mpath = _manifest_path(state_dir, lease["epoch"])
    assert mpath.is_file()
    manifest = park.load_manifest(mpath, leases.FakeSigner())
    assert manifest["schema"] == "checkpoint-manifest/v1"
    assert manifest["name"] == NAME
    assert manifest["fence_epoch"] == lease["epoch"]
    assert manifest["actor"] == "test"
    assert manifest["critical_jobs"] == "refused"
    assert manifest["hmk_integrity"] == "ok"
    assert manifest["state_commit"] == COMMIT_SHA
    assert manifest["backup_ids"] == "not-configured"
    assert manifest["resource_fence"] == "authority-current"
    assert manifest["resource_fence_epoch"] == lease["epoch"]
    assert [s["name"] for s in manifest["steps"]] == [
        "spec-parking", "critical-jobs", "hmk-checkpoint",
        "state-files", "state-repo", "verify"]

    # state files copied with recorded sha256
    dest = state_dir / "park" / NAME / "state"
    assert manifest["state_files"]["NOW.md"] == hashlib.sha256(
        NOW_CONTENT.encode()).hexdigest()
    assert (dest / "NOW.md").read_text() == NOW_CONTENT
    assert (dest / "DIALOGUE-HANDOFF.md").read_text() == HANDOFF_CONTENT

    # in-container execution happened in order: checkpoint before commit
    calls = [c[0] for c in ad.mutation_log]
    assert "exec_quiesce_verify" in calls
    assert calls.index("exec_quiesce_verify") < calls.index("stop")

    # park-state converged
    ps = json.loads((state_dir / "park" / f"{NAME}.json").read_text())
    assert ps["schema"] == "park-state/v1"
    assert ps["completed"] == list(park.STEPS)
    assert ps["failed_step"] is None


def test_handoff_park_replay_requires_current_terminal_effect(
    state_dir, adapter, lease, capsys,
):
    _write_spec(state_dir)
    before = (state_dir / "instances" / f"{NAME}.yaml").read_bytes()
    code, _ = _cli(
        state_dir, "park", "--handoff", NAME,
        "--idempotency-key", "33333333-3333-3333-3333-333333333333",
        "--json", adapter=adapter,
    )
    assert code == 6
    assert adapter.mutation_log == []
    assert (state_dir / "instances" / f"{NAME}.yaml").read_bytes() == before


@pytest.mark.parametrize(
    "boundary",
    [
        "after-plan",
        "after-runtime-dispatch-persist",
        "after-runtime-observation",
        "after-logical-commit",
        "after-idempotency",
        "after-audit",
        "after-completed",
    ],
)
def test_handoff_park_outer_journal_resumes_every_boundary(
    state_dir, adapter, lease, monkeypatch, capsys, boundary
):
    _write_spec(state_dir)
    code, _ = _cli(
        state_dir,
        "park",
        "--handoff",
        NAME,
        "--idempotency-key",
        "55555555-5555-4555-8555-555555555555",
        "--json",
        adapter=adapter,
    )
    assert code == 6
    assert adapter.mutation_log == []
    assert not (state_dir / "operation-journal.json").exists()


# ---------------------------------------------------------------------------
# resume from every interruption point
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kill_after", park.STEPS)
def test_resume_from_interruption(state_dir, cfg, adapter, lease, kill_after):
    _write_spec(state_dir)

    def hook(step):
        if step == kill_after:
            raise _Kill(step)

    with pytest.raises(_Kill):
        park.run_park(NAME, cfg, adapter, actor="test", on_step=hook)

    # state file records progress up to the kill point
    ps = json.loads((state_dir / "park" / f"{NAME}.json").read_text())
    assert kill_after in ps["completed"]

    # re-run converges
    result = park.run_park(NAME, cfg, adapter, actor="test")
    assert result["result"] == "ok"
    manifest = park.load_manifest(result["manifest"], leases.FakeSigner())
    assert manifest["fence_epoch"] == lease["epoch"]
    assert adapter._find(NAME)["state"] == "stopped"
    ps = json.loads((state_dir / "park" / f"{NAME}.json").read_text())
    assert ps["completed"] == list(park.STEPS)


# ---------------------------------------------------------------------------
# failed verification → rollback to active, lease untouched
# ---------------------------------------------------------------------------


def test_failed_verification_rolls_back(state_dir, cfg, adapter, lease):
    _write_spec(state_dir)
    calls = {"rev_parse": 0}

    def flaky(name, argv):
        if argv[:1] == ["git"] and "rev-parse" in argv:
            calls["rev_parse"] += 1
            # first call (record) vs second call (verify) disagree
            return ("aaa111" if calls["rev_parse"] == 1 else "bbb222") + "\n"
        return _exec_handler(name, argv)

    adapter.exec_handler = flaky
    with pytest.raises(park.ParkError):
        park.run_park(NAME, cfg, adapter, actor="test")

    # spec rolled back to its pre-park value, container NOT stopped
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "active"
    assert adapter._find(NAME)["state"] == "running"
    assert not any(c[0] == "stop" for c in adapter.mutation_log)
    # no manifest written
    assert not _manifest_path(state_dir).exists()
    # lease stays held by the daimon
    st = leases.LeaseStore(state_dir).status(DAIMON_ID)
    assert st["present"] and not st["expired"]
    # failure recorded in park-state
    ps = json.loads((state_dir / "park" / f"{NAME}.json").read_text())
    assert ps["failed_step"] == "verify"
    assert ps["error"]

    # and a fixed re-run converges from the failure point
    adapter.exec_handler = _exec_handler
    result = park.run_park(NAME, cfg, adapter, actor="test")
    assert result["result"] == "ok"
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "parked"


# ---------------------------------------------------------------------------
# secrets — fail closed, never in the manifest
# ---------------------------------------------------------------------------


def test_secret_in_staged_changes_refused(state_dir, cfg, adapter, lease, capsys):
    _write_spec(state_dir)

    def leaky(name, argv):
        if argv[:1] == ["git"] and "diff" in argv:
            return "+OPENAI_API_KEY=sk-fakesecret123\n+token=abc\n"
        return _exec_handler(name, argv)

    adapter.exec_handler = leaky
    with pytest.raises(park.ParkRefused):
        park.run_park(NAME, cfg, adapter, actor="test")
    ad = adapter
    # no commit was made, spec rolled back, no manifest
    git_calls = [c[2] for c in ad.mutation_log if c[0] == "exec"]
    assert not any("commit" in argv for argv in git_calls)
    assert load_spec_raw(cfg.instances_dir, NAME)["status"] == "active"
    assert not _manifest_path(state_dir).exists()
    # the refusal message never leaks the secret value
    err = capsys.readouterr().err
    assert "sk-fakesecret123" not in err


def test_happy_manifest_contains_no_secret_values(
        state_dir, cfg, adapter, lease):
    _write_spec(state_dir)
    result = park.run_park(NAME, cfg, adapter, actor="test")
    raw = json.dumps(result["checkpoint"]).lower()
    for pattern in ("private key", "api_key", "token=", "bearer ", "sk-"):
        assert pattern not in raw


# ---------------------------------------------------------------------------
# manifest signature
# ---------------------------------------------------------------------------


def test_unsigned_or_tampered_manifest_rejected(
        state_dir, cfg, adapter, lease):
    _write_spec(state_dir)
    result = park.run_park(NAME, cfg, adapter, actor="test")
    manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
    signer = leases.FakeSigner()
    assert park.verify_manifest(manifest, signer) is True

    tampered = dict(manifest, actor="mallory")
    assert park.verify_manifest(tampered, signer) is False
    park.load_manifest(result["manifest"], signer)  # control: ok (no raise)
    # write the tampered copy back and confirm it is rejected
    with open(result["manifest"], "w") as fh:
        json.dump(tampered, fh)
    with pytest.raises(leases.InvalidSignature):
        park.load_manifest(result["manifest"], signer)

    unsigned = dict(manifest)
    del unsigned["signature"]
    assert park.verify_manifest(unsigned, signer) is False


# ---------------------------------------------------------------------------
# --abandon-critical records the human actor
# ---------------------------------------------------------------------------


def test_abandon_critical_records_human_actor(
        state_dir, cfg, adapter, lease, capsys):
    _write_spec(state_dir)
    result = park.run_park(
        NAME, cfg, adapter, actor="mariano", abandon_critical=True
    )
    manifest = result["checkpoint"]
    assert manifest["critical_jobs"] == "human-abandoned"
    assert manifest["critical_jobs_actor"] == "mariano"


# ---------------------------------------------------------------------------
# resource-fence requirement / --no-fence
# ---------------------------------------------------------------------------


def test_no_fence_option_is_removed(state_dir, cfg, adapter, capsys):
    _write_spec(state_dir)
    # Missing authority fails before mutation; the bypass flag is not parsed.
    code, _ = _cli(state_dir, "park", "--handoff", NAME, "--json", adapter=adapter)
    assert code == 6
    before = (state_dir / "instances" / f"{NAME}.yaml").read_bytes()
    capsys.readouterr()
    with pytest.raises(SystemExit):
        _cli(state_dir, "park", "--handoff", NAME, "--no-fence", adapter=adapter)
    assert (state_dir / "instances" / f"{NAME}.yaml").read_bytes() == before
    assert adapter.mutation_log == []


# ---------------------------------------------------------------------------
# optional spec capabilities absent
# ---------------------------------------------------------------------------


def test_minimal_spec_records_absent_capabilities(state_dir, cfg, adapter, lease):
    _write_spec(state_dir, hmk_path=None, state_files=False, state_repo=False)
    result = park.run_park(NAME, cfg, adapter, actor="test")
    manifest = result["checkpoint"]
    assert manifest["hmk_integrity"] == "absent"
    assert manifest["state_files"] == "not-configured"
    assert manifest["state_commit"] is None
    assert not any(c[0] == "exec_quiesce_verify"
                   for c in adapter.mutation_log)


# ---------------------------------------------------------------------------
# admission
# ---------------------------------------------------------------------------


def test_undeclared_instance_exit_3(state_dir, capsys):
    code, _ = _cli(state_dir, "park", "--handoff", "ghost")
    assert code == 3


def test_backup_ids_listed_when_configured(state_dir, cfg, adapter, lease):
    _write_spec(state_dir)
    bdir = state_dir / "backups" / NAME
    bdir.mkdir(parents=True)
    (bdir / "1-snap-1.json").write_text(json.dumps(
        {"schema": "cluster-backup-manifest/v1", "name": NAME,
         "snap_name": "snap-1"}))
    result = park.run_park(NAME, cfg, adapter, actor="test")
    assert result["checkpoint"]["backup_ids"] == ["snap-1"]
