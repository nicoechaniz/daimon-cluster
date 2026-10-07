"""Native public enrollment under separate Root and target custody."""
import json
import time
from types import SimpleNamespace

import pytest

from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_custody import FirstCustody, document
from tests.test_onboarding_custody import fixture


def target(root, genesis, body_ref):
    from daimon_matrix import operator_first_embodiment as first
    profile = dict(schema="dm.operator.rebirth-target-profile/v1", label="qualified-target",
                   body_ref=body_ref, principal_id="principal:qualified-target",
                   listen_host="127.0.0.1", listen_port=9218,
                   advertised_endpoint="http://127.0.0.1:9218/dm-peer/v1", targets=[])
    def reader():
        return bytearray(b"Synthetic-target-unlock-only")
    first.prepare_target(root, genesis, profile, reader, created_at_ms=time.time_ns() // 1_000_000)
    return document(root / "request.json"), reader


def test_lost_native_activation_ack_preserves_origin_and_target_runtime(tmp_path):
    from daimon_matrix import operator_first_embodiment as first
    ceremony, plan, _ = fixture(tmp_path)
    ceremony.prepare(plan, identity_mode="first")
    host = ceremony.root / digest(plan)
    guest = tmp_path / "guest-target"
    request, reader = target(guest, document(host / "genesis.json"), "codex:daimon-cluster:" + plan["name"])
    failed, commands = [], []
    def uncertain(argv, password):
        FirstCustody._run(argv, password)
        commands.append((argv, password))
        if argv[:2] == ["first-embodiment", "aggregate"] and not failed:
            failed.append(True)
            raise RuntimeError("ack lost after activation publication")
    ceremony.run = uncertain
    with pytest.raises(RuntimeError):
        ceremony.authorize_target(plan, request)
    published = document(host / "target-activation.json")
    activation = ceremony.authorize_target(plan, request)
    assert activation == published and activation["body"]["origin"] == request["body"]["origin"]
    assert len(commands) == 2  # reconciliation adds no holder call
    assert commands[0][1] == host / "root.unlock" and commands[1][1] is None
    assert str(guest) not in json.dumps([item[0] for item in commands])
    runtime = tmp_path / "guest-runtime"
    receipt = first.activate_runtime(runtime, document(host / "genesis.json"), guest,
        document(guest / "preparation.json"), request, activation, reader)
    assert receipt["origin"] == request["body"]["origin"] and receipt["root_seeds_in_target"] is False
    assert not list(runtime.rglob("root.unlock")) and not list(runtime.rglob("holder.json"))
    assert receipt["runtime_schema"] == "dm.runtime.bundle/v7"  # not V8/admission acceptance


def test_foreign_body_and_second_target_are_not_signed(tmp_path):
    ceremony, plan, _ = fixture(tmp_path)
    ceremony.prepare(plan, identity_mode="first")
    host = ceremony.root / digest(plan)
    genesis = document(host / "genesis.json")
    wrong, _ = target(tmp_path / "wrong", genesis, "codex:another-host:another-being")
    with pytest.raises(OnboardingError, match="onboarding_target_binding_conflict"):
        ceremony.authorize_target(plan, wrong)
    assert not (host / "target-request.json").exists()
    one, _ = target(tmp_path / "one", genesis, "codex:daimon-cluster:" + plan["name"])
    ceremony.authorize_target(plan, one)
    two, _ = target(tmp_path / "two", genesis, "codex:daimon-cluster:" + plan["name"])
    with pytest.raises(OnboardingError, match="existing_onboarding_target_preserved"):
        ceremony.authorize_target(plan, two)
    assert document(host / "target-request.json") == one


def test_incomplete_native_public_output_is_not_published(tmp_path, monkeypatch):
    from pathlib import Path
    import clusterctl.onboarding_custody as custody
    final = tmp_path / "intent.json"
    def partial(argv, **kwargs):
        path = Path(argv[argv.index("--output") + 1])
        path.write_bytes(b'{"incomplete')
        path.chmod(0o600)
        return SimpleNamespace(returncode=1)
    monkeypatch.setattr(custody.subprocess, "run", partial)
    with pytest.raises(OnboardingError, match="native_onboarding_custody_refused"):
        FirstCustody._run(["create-intent", "--output", str(final)], None)
    assert not final.exists() and not list(tmp_path.glob(".native-public-*"))
