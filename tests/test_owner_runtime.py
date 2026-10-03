"""Real disposable Linux processes, native enrollment and history preservation."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from clusterctl.embodiments import Registry, RegistryError
from clusterctl.owner_body_reader import PROCESS_PROFILE_SCHEMA
from clusterctl.owner_runtime import ProcessPresence, PresenceError, enroll, validate_process

pytestmark = pytest.mark.skipif(not hasattr(os, "pidfd_open"), reason="Linux pidfd admission")

ORIGIN = {
    "body_ref": "codex:fixture:existing",
    "embodiment_id": "embodiment:33333333-3333-4333-8333-333333333333",
    "incarnation_id": "incarnation:44444444-4444-4444-8444-444444444444",
}


def process_binding(pid):
    return {
        "uid": os.geteuid(), "pid": pid,
        "start_ticks": int((Path("/proc") / str(pid) / "stat").read_text().rpartition(")")[2].split()[19]),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }


@pytest.fixture
def process():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        yield child, process_binding(child.pid)
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=3)


def profile(root, binding):
    return {
        "schema": PROCESS_PROFILE_SCHEMA, "socket_path": str(root / "reader.sock"),
        "socket_mode": "0600", "caller_uid": os.geteuid(),
        "origin": dict(ORIGIN), "process": dict(binding),
    }


def test_live_process_and_exit_are_real_kernel_observations(process):
    child, binding = process
    with ProcessPresence(binding) as presence:
        assert not os.get_inheritable(presence.descriptor)
        presence.verify()
        child.terminate()
        child.wait(timeout=3)
        with pytest.raises(PresenceError):
            presence.verify()
    assert presence.descriptor == -1
    with pytest.raises(PresenceError):
        ProcessPresence(binding)


@pytest.mark.parametrize("change", [
    {"uid": True}, {"uid": -1}, {"uid": 2**32}, {"pid": False},
    {"pid": 0}, {"start_ticks": 0}, {"start_ticks": True},
    {"boot_id": "not-a-boot"}, {"extra": "refused"},
])
def test_closed_process_descriptor_refuses(process, change):
    _, binding = process
    with pytest.raises(PresenceError):
        validate_process(dict(binding, **change))


@pytest.mark.parametrize("field", ["uid", "start_ticks", "boot_id"])
def test_wrong_owner_start_or_host_refuses_before_enrollment(tmp_path, process, field):
    _, binding = process
    wrong = dict(binding)
    wrong[field] = "00000000-0000-4000-8000-000000000000" if field == "boot_id" else binding[field] + 1
    with pytest.raises(PresenceError):
        enroll(tmp_path, profile(tmp_path, wrong))
    assert not (tmp_path / "embodiments.json").exists()
    assert not (tmp_path / "embodiments.lock").exists()


def test_atomic_enrollment_and_exact_replay_preserve_fleet(tmp_path, process):
    _, binding = process
    registry = Registry(tmp_path)
    sibling = registry.register(body_ref="other-body")
    registry.start(sibling["embodiment_id"])
    sibling_before = registry.status(sibling["embodiment_id"])
    value = profile(tmp_path, binding)
    result = enroll(tmp_path, value)
    assert result["current_incarnation_id"] == ORIGIN["incarnation_id"]
    assert registry.status(sibling["embodiment_id"]) == sibling_before
    before = registry.path.read_bytes()
    assert enroll(tmp_path, value) == result
    assert registry.path.read_bytes() == before
    registry.stop(ORIGIN["embodiment_id"])
    ended = registry.path.read_bytes()
    with pytest.raises(RegistryError):
        enroll(tmp_path, value)
    assert registry.path.read_bytes() == ended


@pytest.mark.parametrize("change", [
    {"body_ref": "another-body"}, {"embodiment_id": "embodiment:another"},
    {"incarnation_id": "incarnation:another"},
])
def test_conflicting_origin_preserves_history(tmp_path, process, change):
    _, binding = process
    value = profile(tmp_path, binding)
    enroll(tmp_path, value)
    before = Registry(tmp_path).path.read_bytes()
    substituted = copy.deepcopy(value)
    substituted["origin"].update(change)
    with pytest.raises(RegistryError):
        enroll(tmp_path, substituted)
    assert Registry(tmp_path).path.read_bytes() == before


def test_ack_loss_keeps_accepted_history_and_exact_retry(tmp_path, process, monkeypatch):
    _, binding = process
    value = profile(tmp_path, binding)
    original = ProcessPresence.verify
    calls = []

    def unavailable_after_commit(self):
        calls.append(True)
        if len(calls) == 2:
            raise PresenceError("synthetic response loss")
        return original(self)

    monkeypatch.setattr(ProcessPresence, "verify", unavailable_after_commit)
    with pytest.raises(PresenceError):
        enroll(tmp_path, value)
    before = Registry(tmp_path).path.read_bytes()
    monkeypatch.setattr(ProcessPresence, "verify", original)
    result = enroll(tmp_path, value)
    assert len(result["incarnations"]) == 1
    assert Registry(tmp_path).path.read_bytes() == before


def test_genuine_cli_exact_profile_and_rejected_drift(tmp_path, process):
    _, binding = process
    path = tmp_path / "profile.json"
    value = profile(tmp_path, binding)
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    command = [sys.executable, "-m", "clusterctl.owner_runtime", "--state-root", str(tmp_path / "state"), "--profile", str(path)]
    first = subprocess.run(command, capture_output=True, text=True, timeout=5)
    assert first.returncode == 0, first.stdout
    assert json.loads(first.stdout) == {"schema": "dm.cluster-owner-enrollment-result/v1", "status": "accepted"}
    registry = Registry(tmp_path / "state")
    before = registry.path.read_bytes()
    assert subprocess.run(command, capture_output=True, timeout=5).returncode == 0
    assert registry.path.read_bytes() == before
    value["process"]["start_ticks"] += 1
    path.write_text(json.dumps(value))
    refused = subprocess.run(command, capture_output=True, text=True, timeout=5)
    assert refused.returncode == 1
    assert json.loads(refused.stdout) == {"schema": "dm.cluster-owner-enrollment-result/v1", "status": "refused"}
    assert registry.path.read_bytes() == before


def test_saved_profile_is_copied_before_observation(tmp_path, process):
    from clusterctl.owner_body_reader import validate_profile
    _, binding = process
    value = profile(tmp_path, binding)
    admitted = validate_profile(value)
    value["process"]["pid"] += 1
    assert admitted["process"]["pid"] == binding["pid"]


def test_enrollment_cannot_relabel_an_existing_managed_body(tmp_path, process):
    _, binding = process
    registry = Registry(tmp_path)
    registry.register(body_ref=ORIGIN["body_ref"], embodiment_id=ORIGIN["embodiment_id"])
    registry.start(ORIGIN["embodiment_id"], incarnation_id=ORIGIN["incarnation_id"])
    before = registry.path.read_bytes()
    with pytest.raises(RegistryError):
        enroll(tmp_path, profile(tmp_path, binding))
    assert registry.path.read_bytes() == before
