"""Native receiving identity survives interrupted runtime publication/retries."""
import hashlib

import pytest

from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_custody import document
from clusterctl.onboarding_target import Target
from tests.test_onboarding_custody import fixture


def receiving(tmp_path):
    ceremony, plan, _ = fixture(tmp_path)
    ceremony.prepare(plan, identity_mode="first")
    host = ceremony.root / digest(plan)
    home = tmp_path / "guest"
    home.mkdir(mode=0o700)
    return ceremony, plan, Target(home, plan, document(host / "genesis.json"))


def files(root):
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


def test_receiving_target_runtime_retries_keep_keys_origin_and_receiving_writes(tmp_path):
    ceremony, plan, target = receiving(tmp_path)
    assert target.observe() == dict(phase="absent", request=None, receipt=None)
    request = target.prepare()
    assert target.observe()["phase"] == "prepared"
    preserved = files(target.preparation)
    assert target.prepare() == request and files(target.preparation) == preserved
    activation = ceremony.authorize_target(plan, request)
    complete = target.activate(activation)
    assert complete["phase"] == "v7" and complete["receipt"]["root_seeds_in_target"] is False
    own = target.package / "runtime/own-later-state"
    own.write_bytes(b"Receiving writes after activation")
    original = files(target.package)
    assert target.activate(activation) == complete
    assert files(target.package) == original and files(target.preparation) == preserved
    assert not list(target.home.rglob("holder.json"))
    assert not list(target.home.rglob("root.unlock"))


def test_interrupted_ack_after_native_runtime_publication_does_not_recreate_package(tmp_path, monkeypatch):
    from daimon_matrix import operator_first_embodiment as first
    ceremony, plan, target = receiving(tmp_path)
    request = target.prepare()
    activation = ceremony.authorize_target(plan, request)
    actual = first.activate_runtime
    def interrupted(*args, **kwargs):
        actual(*args, **kwargs)
        raise RuntimeError("process disappeared after atomic runtime publication")
    monkeypatch.setattr(first, "activate_runtime", interrupted)
    with pytest.raises(RuntimeError):
        target.activate(activation)
    published = files(target.package)
    observed = target.observe()
    assert observed["receipt"]["origin"] == request["body"]["origin"]
    assert target.activate(activation) == observed
    assert files(target.package) == published


def test_missing_unlock_or_changed_plan_cannot_replace_existing_identity(tmp_path):
    _, plan, target = receiving(tmp_path)
    target.prepare()
    original = files(target.preparation)
    (target.root / "body.unlock").unlink()
    with pytest.raises(OnboardingError, match="existing_onboarding_target_preserved"):
        target.prepare()
    assert files(target.preparation) == original
    other = Target(target.home, {**plan, "release_digest": "b" * 64}, target.genesis)
    with pytest.raises(OnboardingError, match="onboarding_target_binding_conflict"):
        other.prepare()
    assert files(target.preparation) == original


def test_receiving_credential_upgrade_keeps_origin_memory_and_runtime_reload(tmp_path):
    from clusterctl.onboarding_target import document
    ceremony, plan, target = receiving(tmp_path)
    request = target.prepare()
    before = target.activate(ceremony.authorize_target(plan, request))
    memory = target.home / "preserved-memory.db"
    memory.write_bytes(b"Own memory is outside native authority publication")
    prepared = files(target.preparation)
    native_keys = (target.package / "runtime/custody.json").read_bytes()
    proposal = target.credential_request()
    assert target.credential_request() == proposal
    response = ceremony.authorize_credential(plan, proposal)
    complete = target.apply_credential(response)
    assert complete["phase"] == "v8"
    assert complete["receipt"]["origin"] == before["receipt"]["origin"]
    assert target.apply_credential(response) == complete
    assert target.activate(ceremony.authorize_target(plan, request)) == complete
    assert files(target.preparation) == prepared
    assert (target.package / "runtime/custody.json").read_bytes() == native_keys
    assert memory.read_bytes() == b"Own memory is outside native authority publication"
    from daimon_matrix.runtime import load_runtime
    import time
    hosted = load_runtime(target.package / "runtime", "runtime.json", target._reader,
                          clock=lambda: time.time_ns() // 1_000_000)
    assert hosted.service.ledger.local_origin == before["receipt"]["origin"]
    assert document(target.package / "runtime/runtime.json")["authority_history"]


@pytest.mark.parametrize("phase", ["response", "candidate", "runtime", "receipt"])
def test_native_credential_publication_recovers_each_lost_ack_without_new_identity(tmp_path, monkeypatch, phase):
    from daimon_matrix import keystore
    ceremony, plan, target = receiving(tmp_path)
    original = target.activate(ceremony.authorize_target(plan, target.prepare()))
    proposed = target.credential_request()
    response = ceremony.authorize_credential(plan, proposed)
    interrupted_path = target.package / "runtime/runtime.json" if phase == "runtime" else target.credential / (phase + ".json")
    actual = keystore._atomic_write
    failures = []
    def interrupted(path, value):
        actual(path, value)
        if path == interrupted_path and not failures:
            failures.append(path)
            raise RuntimeError("acknowledgement lost after durable publication")
    monkeypatch.setattr(keystore, "_atomic_write", interrupted)
    with pytest.raises(RuntimeError, match="acknowledgement lost"):
        target.apply_credential(response)
    observed = target.observe()
    assert observed["phase"] in {"v7", "v8-published", "v8"}
    assert target.credential_request() == proposed
    assert ceremony.authorize_credential(plan, proposed) == response
    completed = target.apply_credential(response)
    assert completed["phase"] == "v8"
    assert completed["receipt"]["origin"] == original["receipt"]["origin"]
    assert len(failures) == 1


def test_credential_publication_refuses_running_writer_and_preserves_changed_runtime(tmp_path):
    import os
    from daimon_matrix import daemon, keystore, canonical
    ceremony, plan, target = receiving(tmp_path)
    target.activate(ceremony.authorize_target(plan, target.prepare()))
    proposed = target.credential_request()
    response = ceremony.authorize_credential(plan, proposed)
    descriptor = daemon.acquire_lock(target.package / "runtime")
    try:
        with pytest.raises(BlockingIOError):
            target.apply_credential(response)
        assert not (target.credential / "response.json").exists()
    finally:
        os.close(descriptor)
    target.apply_credential(response)
    from clusterctl.onboarding_target import document
    path = target.package / "runtime/runtime.json"
    changed = {**document(path), "runtime_label": "own-changed-runtime"}
    raw = canonical.canonical_bytes(changed)
    keystore._atomic_write(path, raw)
    with pytest.raises(OnboardingError, match="existing_onboarding_target_preserved"):
        target.apply_credential(response)
    assert path.read_bytes() == raw
