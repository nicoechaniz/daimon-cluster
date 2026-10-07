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
