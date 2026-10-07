"""Actual native V8 authority in a disposable, explicitly synthetic ceremony."""
from __future__ import annotations

import copy
import json
import time
import uuid

from daimon_matrix import authority_epochs, identity, operator_rebirth
from daimon_matrix.canonical import canonical_bytes, unb64url
from daimon_matrix.keystore import EncryptedKeystore, _atomic_write
from daimon_matrix.weave import BeingManifest, RootAuthority

from clusterctl.matrix_host import create_portable_snapshot, _public_bundle
from clusterctl.onboarding import digest
from tests.test_onboarding_target import receiving
from tests.test_rebirth import _provision_visibility


def test_native_v8_runtime_and_snapshot_keep_history_and_exclude_client_secrets(tmp_path):
    # These are test-generated holders, never Source or participant custody.
    ceremony, plan, target = receiving(tmp_path)
    request = target.prepare()
    target.activate(ceremony.authorize_target(plan, request))
    root = target.package / "runtime"
    original = json.loads((root / "runtime.json").read_bytes())
    previous = operator_rebirth.authority_from_runtime_bundle(original)
    origin = original["local_origin"]
    member = previous.manifest.member(origin["embodiment_id"], origin["incarnation_id"])
    old = previous.credentials[member["embodiment_credential_id"]]["body"]
    custody = EncryptedKeystore(root / "custody.json").open(target._reader)
    signing = custody.secrets[original["keystore"]["signing_slot"]]
    holder_root = ceremony.root / digest(plan)
    holder = EncryptedKeystore(holder_root / "root/holder.json").open(
        lambda: bytearray((holder_root / "root.unlock").read_bytes())
    )
    roots = [holder.secrets["genesis.root.v1:holder"]]
    credential = identity.create_embodiment_credential_v2(
        previous.state, roots, signing, unb64url(old["encryption_key"]["public"], length=32),
        embodiment_id=old["embodiment_id"], body_ref=old["body_ref"],
        purposes=old["purposes"], revocation_generation=old["revocation_generation"],
        transport_principals=old["transport_principals"],
        validity={"mode": "until-revoked", "not_before_ms": old["valid_from_ms"]},
    )
    prior = previous.incarnations[member["incarnation_authorization_id"]]["body"]
    incarnation = identity.create_incarnation_authorization(
        credential, signing, incarnation_id=origin["incarnation_id"],
        incarnation_sequence=prior["incarnation_sequence"], started_at_ms=prior["started_at_ms"],
    )
    manifest = copy.deepcopy(dict(previous.manifest.value))
    manifest["revision"] += 1
    assert len(manifest["embodiments"]) == 1
    manifest["embodiments"][0].update(
        embodiment_credential_id=credential["artifact_id"],
        incarnation_authorization_id=incarnation["artifact_id"],
    )
    successor = RootAuthority(
        BeingManifest.from_value(manifest), previous.state,
        {**previous.credentials, credential["artifact_id"]: credential},
        {**previous.incarnations, incarnation["artifact_id"]: incarnation},
    )
    transition = authority_epochs.create_credential_succession(
        previous, successor, embodiment_id=origin["embodiment_id"],
        incarnation_id=origin["incarnation_id"], migration_id=str(uuid.uuid4()),
        issued_at_ms=time.time_ns() // 1_000_000, root_seeds=roots, signing_seed=signing,
    )
    bundle = {**original, "schema": "dm.runtime.bundle/v8", "manifest": manifest,
              "credentials": list(successor.credentials.values()),
              "incarnations": list(successor.incarnations.values()),
              "authority_history": [{"manifest": previous.manifest.value, "successor": transition}]}
    _atomic_write(root / "runtime.json", canonical_bytes(bundle))
    _provision_visibility(root, bytes(target._reader()), time.time_ns() // 1_000_000)
    assert _public_bundle(root, "runtime.json") == bundle
    verified = operator_rebirth.authority_from_runtime_bundle(bundle)
    assert verified.manifest.digest == successor.manifest.digest
    assert bundle["local_origin"] == original["local_origin"]
    secrets = [path.read_bytes() for path in root.rglob("*")
               if path.is_file() and path.name in {"client.key", "capability.key"}]
    assert len(secrets) == 12
    snapshot = tmp_path / "snapshot"
    receipt = create_portable_snapshot(root, snapshot)
    names = {row["name"] for row in receipt["files"]}
    assert names.isdisjoint({"client.key", "client.json", "operator-clients", "host-clients"})
    content = b"".join(path.read_bytes() for path in snapshot.rglob("*") if path.is_file())
    assert all(secret not in content for secret in [*secrets, *roots])
    assert json.loads((snapshot / "payload/runtime.json").read_bytes())["authority_history"] == bundle["authority_history"]
