"""Separated native credential signing matches the maintained constructors."""
from __future__ import annotations

import copy
import time

import pytest
from daimon_matrix import authority_epochs, identity, operator_rebirth
from daimon_matrix.canonical import canonical_bytes, unb64url
from daimon_matrix.keystore import EncryptedKeystore

from clusterctl import onboarding_credential as upgrade
from clusterctl.onboarding import OnboardingError, digest
from tests.test_onboarding_target import receiving


def material(tmp_path):
    ceremony, plan, target = receiving(tmp_path)
    request = target.prepare()
    target.activate(ceremony.authorize_target(plan, request))
    from clusterctl.onboarding_custody import document
    bundle = document(target.package / "runtime/runtime.json")
    previous = operator_rebirth.authority_from_runtime_bundle(bundle)
    body = EncryptedKeystore(target.package / "runtime/custody.json").open(target._reader)
    signing = body.secrets[bundle["keystore"]["signing_slot"]]
    root = ceremony.root / digest(plan)
    holder = EncryptedKeystore(root / "root/holder.json").open(lambda: bytearray((root / "root.unlock").read_bytes()))
    return plan, bundle, previous, signing, holder.secrets["genesis.root.v1:holder"]


def test_separated_native_credential_and_succession_equal_native_full_constructors(tmp_path):
    plan, bundle, previous, signing, root = material(tmp_path)
    now_ms = time.time_ns() // 1_000_000
    request = upgrade.receiving_request(previous, bundle["local_origin"], plan, signing, issued_at_ms=now_ms)
    assert all(seed not in canonical_bytes(request) for seed in (signing, root))
    response = upgrade.root_response(previous, plan, request, root, observed_at_ms=now_ms)
    successor = upgrade.verify_response(previous, plan, request, response)
    origin = bundle["local_origin"]
    member = previous.manifest.member(origin["embodiment_id"], origin["incarnation_id"])
    old = previous.credentials[member["embodiment_credential_id"]]["body"]
    native = identity.create_embodiment_credential_v2(previous.state, [root], signing,
        unb64url(old["encryption_key"]["public"], length=32), embodiment_id=old["embodiment_id"],
        body_ref=old["body_ref"], purposes=old["purposes"],
        validity={"mode": "until-revoked", "not_before_ms": old["valid_from_ms"]},
        revocation_generation=old["revocation_generation"], transport_principals=old["transport_principals"])
    assert response["credential"] == native
    native_transition = authority_epochs.create_credential_succession(previous, successor,
        embodiment_id=origin["embodiment_id"], incarnation_id=origin["incarnation_id"],
        migration_id=digest(plan) + ":credential-v2", issued_at_ms=now_ms,
        root_seeds=[root], signing_seed=signing)
    assert response["succession"] == native_transition
    # Keyless replay uses the original authorized instant and same identity.
    assert upgrade.verify_response(previous, plan, request, response).manifest == successor.manifest
    assert all(seed not in canonical_bytes(response) for seed in (signing, root))


@pytest.mark.parametrize("change", ["plan", "body", "validity", "origin", "time", "acceptance", "incarnation", "extra"])
def test_invalid_public_request_is_refused_before_root_signature(tmp_path, monkeypatch, change):
    plan, bundle, previous, signing, root = material(tmp_path)
    now_ms = time.time_ns() // 1_000_000
    request = upgrade.receiving_request(previous, bundle["local_origin"], plan, signing, issued_at_ms=now_ms)
    changed = copy.deepcopy(request)
    if change == "plan":
        changed["plan_digest"] = "a" * 64
    elif change == "body":
        changed["credential"]["body"]["body_ref"] = "codex:another:being"
    elif change == "validity":
        changed["credential"]["body"]["validity"]["not_before_ms"] = 0
    elif change == "origin":
        changed["origin"]["principal_id"] = "another-principal"
    elif change == "time":
        changed["issued_at_ms"] = True
    elif change == "acceptance":
        changed["acceptance"]["value"] = "a" * 86
    elif change == "incarnation":
        changed["authorization"]["body"]["incarnation_sequence"] += 1
    else:
        changed["extra"] = "not-authority"
    signatures = []
    monkeypatch.setattr(identity, "_signature", lambda *args: signatures.append(args))
    with pytest.raises(OnboardingError, match="onboarding_credential_request_rejected"):
        upgrade.root_response(previous, plan, changed, root, observed_at_ms=now_ms)
    assert signatures == []


def test_response_cannot_change_history_or_credential_and_expired_request_cannot_get_fresh_root_signature(tmp_path):
    plan, bundle, previous, signing, root = material(tmp_path)
    now_ms = time.time_ns() // 1_000_000
    request = upgrade.receiving_request(previous, bundle["local_origin"], plan, signing, issued_at_ms=now_ms)
    response = upgrade.root_response(previous, plan, request, root, observed_at_ms=now_ms)
    altered = copy.deepcopy(response)
    altered["manifest"]["revision"] += 1
    with pytest.raises(OnboardingError, match="onboarding_credential_response_rejected"):
        upgrade.verify_response(previous, plan, request, altered)
    with pytest.raises(OnboardingError, match="onboarding_credential_request_rejected"):
        upgrade.root_response(previous, plan, request, root,
            observed_at_ms=next(iter(previous.credentials.values()))["body"]["valid_until_ms"] + 1)
    # The completed native authorization remains reconcilable without Root custody.
    upgrade.verify_response(previous, plan, request, response)


def test_root_only_subprocess_reconciles_lost_ack_and_refuses_replacement_or_revocation(tmp_path):
    from clusterctl import being_seed
    from clusterctl.onboarding_custody import FirstCustody, document

    ceremony, plan, target = receiving(tmp_path)
    target.activate(ceremony.authorize_target(plan, target.prepare()))
    bundle = document(target.package / "runtime/runtime.json")
    previous = operator_rebirth.authority_from_runtime_bundle(bundle)
    body = EncryptedKeystore(target.package / "runtime/custody.json").open(target._reader)
    signing = body.secrets[bundle["keystore"]["signing_slot"]]
    request = upgrade.receiving_request(previous, bundle["local_origin"], plan, signing,
                                       issued_at_ms=time.time_ns() // 1_000_000)
    commands = []
    def interrupted(arguments, password):
        FirstCustody._run(arguments, password)
        commands.append((arguments, password))
        raise RuntimeError("lost response after atomic public publication")
    ceremony.run = interrupted
    with pytest.raises(RuntimeError, match="lost response"):
        ceremony.authorize_credential(plan, request)
    response = document(ceremony.root / digest(plan) / "credential-response.json")
    upgrade.verify_response(previous, plan, request, response)
    assert ceremony.authorize_credential(plan, request) == response
    assert len(commands) == 1
    arguments, password = commands[0]
    assert password.name == "root.unlock"
    assert "--holder" in arguments and str(ceremony.root / digest(plan) / "root") in arguments
    assert str(target.package) not in arguments and str(target.root) not in arguments
    assert str(ceremony.root / digest(plan) / "recovery") not in arguments
    changed = {**request, "issued_at_ms": request["issued_at_ms"] + 1}
    with pytest.raises(OnboardingError, match="existing_onboarding_credential_preserved"):
        ceremony.authorize_credential(plan, changed)
    grant = document(ceremony.grants / (plan["name"] + ".json"))
    being_seed._write(ceremony.grants / (plan["name"] + ".json"), {**grant, "revoked": True})
    with pytest.raises(OnboardingError, match="identity_authorization_required"):
        ceremony.authorize_credential(plan, request)
    assert len(commands) == 1
