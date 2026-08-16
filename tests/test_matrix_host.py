import hashlib
import json
import os
import socket
import stat
import uuid
from types import SimpleNamespace

import pytest

pytest.importorskip("daimon_matrix")

from daimon_matrix.cluster import (
    resource_fence_position,
    verify_resource_fence_evidence,
)
from daimon_matrix.curator import (
    CuratorCoordinator,
    CuratorError,
    create_curator_item,
)
from daimon_matrix.ledger import Ledger
from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.operator_bootstrap import PROFILE_SCHEMA, _create

from clusterctl import matrix_host as matrix_host_module
from clusterctl.embodiments import Registry
from clusterctl.fences import SyntheticResourceFenceStore
from clusterctl.matrix_host import (
    EffectObserverRoute,
    EffectObserverRouter,
    MATRIX_CONTRACT_COMMIT,
    MatrixHostAdapter,
    MatrixHostError,
    create_portable_snapshot,
    matrix_root,
    restore_portable_snapshot,
)

BODY = "cluster:legion:compaii"
EMBODIMENT = "embodiment:11111111-1111-4111-8111-111111111111"
INCARNATION = "incarnation:22222222-2222-4222-8222-222222222222"
RESOURCE = "volume:compaii-state"


def _running(state_dir):
    registry = Registry(state_dir)
    registry.register(body_ref=BODY, embodiment_id=EMBODIMENT)
    registry.start(EMBODIMENT, incarnation_id=INCARNATION, started_at_ms=1)
    return registry


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def _password_descriptor(password: bytes) -> int:
    reader, writer = os.pipe()
    os.write(writer, password)
    os.close(writer)
    return reader


def _signed_snapshot_root(root, *, ledger_name="ledger.sqlite"):
    runtime_label = "snapshot-fixture"
    port = _available_port()
    peer_port = _available_port()
    profile = root / "snapshot-profile.json"
    profile.write_bytes(
        canonical_bytes(
            {
                "schema": PROFILE_SCHEMA,
                "embodiments": [
                    {
                        "label": runtime_label,
                        "body_ref": BODY,
                        "principal_id": "compaii@legion",
                        "listen_host": "127.0.0.1",
                        "listen_port": port,
                        "advertised_endpoint": f"http://127.0.0.1:{port}/dm-peer/v1",
                    },
                    {
                        "label": "snapshot-peer",
                        "body_ref": "cluster:snapshot-peer:compaii",
                        "principal_id": "compaii@snapshot-peer",
                        "listen_host": "127.0.0.1",
                        "listen_port": peer_port,
                        "advertised_endpoint": (
                            f"http://127.0.0.1:{peer_port}/dm-peer/v1"
                        ),
                    },
                ],
            }
        )
    )
    profile.chmod(0o600)
    root_password = _password_descriptor(b"snapshot-root-password-distinct")
    runtime_password = _password_descriptor(b"snapshot-runtime-password-distinct")
    peer_password = _password_descriptor(b"snapshot-peer-password-distinct")
    ceremony = root / "snapshot-ceremony"
    _create(
        ceremony,
        profile,
        root_password,
        [
            f"{runtime_label}={runtime_password}",
            f"snapshot-peer={peer_password}",
        ],
    )
    runtime = ceremony / "runtimes" / runtime_label
    bundle_path = runtime / "runtime.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["ledger"] = ledger_name
    bundle_path.write_bytes(canonical_bytes(bundle))
    bundle_path.chmod(0o600)
    ledger = runtime / ledger_name
    ledger.write_text("canonical-ledger", encoding="utf-8")
    ledger.chmod(0o600)
    for filename in (
        bundle["peer_transport"]["exchange_filename"],
        bundle["peer_transport"]["outbox_filename"],
        bundle["relationships"]["store_filename"],
        bundle["sources"]["cas_filename"],
    ):
        path = runtime / filename
        path.write_bytes(b"")
        path.chmod(0o600)
    return runtime


def test_body_snapshot_is_exact_registry_bound_and_filters_fences(tmp_path):
    _running(tmp_path)
    fences = SyntheticResourceFenceStore(tmp_path)
    fences.acquire(
        RESOURCE,
        "test-key",
        "SHA256:test",
        holder_embodiment_id=EMBODIMENT,
    )
    fences.acquire(
        "volume:other",
        "other-key",
        "SHA256:other",
        holder_embodiment_id="embodiment:other",
    )
    now = fences.get(RESOURCE)["created_ms"]
    adapter = MatrixHostAdapter(
        tmp_path, EMBODIMENT, fence_store=fences, clock=lambda: now
    )

    assert adapter.body_snapshot(BODY, EMBODIMENT, INCARNATION) == {
        "schema": "dm.cluster-body-snapshot/v1",
        "body_ref": BODY,
        "embodiment_id": EMBODIMENT,
        "incarnation_id": INCARNATION,
        "observed_at_ms": now,
        "state": "running",
        "resource_fences": [{"resource_ref": RESOURCE, "epoch": 0}],
    }
    coordinated = adapter.body_snapshot(
        BODY, EMBODIMENT, INCARNATION, evaluated_at_ms=now - 10
    )
    assert coordinated["observed_at_ms"] == now - 10
    assert coordinated["resource_fences"] == []
    with pytest.raises(MatrixHostError, match="matrix_evaluation_time_rejected"):
        adapter.body_snapshot(BODY, EMBODIMENT, INCARNATION, evaluated_at_ms=-1)
    with pytest.raises(MatrixHostError, match="matrix_origin_registry_mismatch"):
        adapter.body_snapshot(BODY, EMBODIMENT, "incarnation:substituted")


def test_fence_evidence_checks_live_high_water_and_effect_truth(tmp_path):
    _running(tmp_path)
    fences = SyntheticResourceFenceStore(tmp_path)
    first = fences.acquire(
        RESOURCE,
        "test-key",
        "SHA256:test",
        holder_embodiment_id=EMBODIMENT,
    )
    adapter = MatrixHostAdapter(
        tmp_path,
        EMBODIMENT,
        fence_store=fences,
        clock=lambda: first["created_ms"] + 1,
    )
    evidence = adapter.fence_evidence(RESOURCE)
    assert evidence is not None
    assert (
        verify_resource_fence_evidence(
            evidence,
            at_ms=first["created_ms"] + 1,
            verifier=adapter.verify_fence,
            body_ref=BODY,
            holder_embodiment_id=EMBODIMENT,
            holder_incarnation_id=INCARNATION,
            resource_ref=RESOURCE,
        )
        == evidence
    )

    intent = {"operation": "start", "target": "body:compaii"}
    receipt = adapter.create_effect_receipt(
        effect_id=str(uuid.UUID(int=1)),
        target_event_id=str(uuid.UUID(int=2)),
        decision_event_id=str(uuid.UUID(int=3)),
        adapter="clusterctl.lifecycle/v1",
        preview_hash="a" * 64,
        intent_hash=hashlib.sha256(
            json.dumps(intent, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        actor="compaii",
        authority="daimon",
        resource_fence=resource_fence_position(evidence),
        result="applied",
        observed_postcondition={"state": "running"},
        started_at_ms=first["created_ms"],
        completed_at_ms=first["created_ms"] + 1,
    )
    assert (
        adapter.reconcile_effect(
            receipt,
            intent=intent,
            observed_postcondition={"state": "running"},
            at_ms=first["created_ms"] + 1,
        )["status"]
        == "verified"
    )

    renewed = fences.renew(RESOURCE, "unused")
    assert renewed is not None and renewed["epoch"] == 1
    adapter.clock = lambda: renewed["created_ms"] + 1
    assert adapter.verify_fence(evidence, renewed["created_ms"] + 1)["current"] is False
    assert (
        adapter.reconcile_effect(
            receipt,
            intent=intent,
            observed_postcondition={"state": "running"},
            at_ms=renewed["created_ms"] + 1,
        )["status"]
        == "effect-truth-discrepancy"
    )


def test_allowlisted_curator_effect_completes_and_replay_rechecks_truth(tmp_path):
    _running(tmp_path)
    fences = SyntheticResourceFenceStore(tmp_path)
    held = fences.acquire(
        RESOURCE,
        "test-key",
        "SHA256:test",
        holder_embodiment_id=EMBODIMENT,
    )
    now = [held["created_ms"] + 1]
    intent = {"operation": "publish", "value": "synthetic"}
    postcondition = {"generation": 7, "state": "present"}

    adapter = None

    def observe(item, receipt, at_ms):
        assert item["work_kind"] == "publication"
        assert receipt["adapter"] == "synthetic-wiki/v1"
        assert at_ms == now[0]
        assert adapter is not None
        return {
            "intent": dict(intent),
            "observed_postcondition": dict(postcondition),
            "current_fence_evidence": adapter.fence_evidence(RESOURCE),
        }

    adapter = MatrixHostAdapter(
        tmp_path,
        EMBODIMENT,
        fence_store=fences,
        effect_observer_routes=[
            EffectObserverRoute(
                adapter="synthetic-wiki/v1",
                work_kind="publication",
                resource_namespace="volume",
                observer=observe,
            )
        ],
        clock=lambda: now[0],
    )
    origin = {
        "body_ref": BODY,
        "embodiment_id": EMBODIMENT,
        "incarnation_id": INCARNATION,
        "principal_id": "compaii@legion",
    }
    ledger = Ledger(
        tmp_path / "matrix-ledger.sqlite",
        authority=SimpleNamespace(
            manifest=SimpleNamespace(
                being_ref="me:synthetic",
                digest="d" * 64,
                trust_mode="provisional",
            )
        ),
        local_origin=origin,
        clock=lambda: now[0],
    )
    coordinator = CuratorCoordinator(
        ledger,
        clock=lambda: now[0],
        fence_verifier=adapter.verify_fence,
        effect_observer=adapter.effect_observer,
    )
    item = create_curator_item(
        subject_me_id="me:synthetic",
        resource_ref=RESOURCE,
        work_kind="publication",
        input_ref="proposal:synthetic",
        input_hash="a" * 64,
        coordination_mode="resource-fence",
        required_authority="daimon",
        effect_intent_hash=hashlib.sha256(
            json.dumps(intent, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        queued_at_ms=now[0],
    )
    coordinator.enqueue(
        item,
        client_id="client:effect-worker",
        request_id="34000000-0000-4000-8000-000000000001",
    )
    evidence = adapter.fence_evidence(RESOURCE)
    claim = coordinator.claim(
        item_id=item["item_id"],
        claim_id="34000000-0000-4000-8000-000000000002",
        expected_generation=0,
        lease_until_ms=now[0] + 1_000,
        fence_evidence=evidence,
        client_id="client:effect-worker",
        request_id="34000000-0000-4000-8000-000000000003",
    )
    receipt = adapter.create_effect_receipt(
        effect_id="34000000-0000-4000-8000-000000000004",
        target_event_id="34000000-0000-4000-8000-000000000005",
        decision_event_id="34000000-0000-4000-8000-000000000006",
        adapter="synthetic-wiki/v1",
        preview_hash="b" * 64,
        intent_hash=item["effect_intent_hash"],
        actor=origin["principal_id"],
        authority="daimon",
        resource_fence=resource_fence_position(evidence),
        result="applied",
        observed_postcondition=postcondition,
        started_at_ms=now[0] - 1,
        completed_at_ms=now[0],
    )
    result = coordinator.complete(
        claim_id=claim["claim_id"],
        expected_generation=1,
        outcome="completed",
        output_refs=["publication:synthetic"],
        effect_receipt=receipt,
        client_id="client:effect-worker",
        request_id="34000000-0000-4000-8000-000000000007",
    )
    assert result["effect_receipt"] == receipt

    postcondition["generation"] = 8
    with pytest.raises(CuratorError, match="effect-truth-discrepancy"):
        coordinator.complete(
            claim_id=claim["claim_id"],
            expected_generation=1,
            outcome="completed",
            output_refs=["publication:synthetic"],
            effect_receipt=receipt,
            client_id="client:effect-worker",
            request_id="34000000-0000-4000-8000-000000000007",
        )
    assert coordinator.inspect(item["item_id"])["result"] == result


def test_effect_observer_router_fails_closed_for_every_non_exact_route():
    item = {"work_kind": "publication", "resource_ref": "wiki:page:home"}
    receipt = {"adapter": "synthetic-wiki/v1"}
    exact = EffectObserverRouter(
        [
            EffectObserverRoute(
                "synthetic-wiki/v1",
                "publication",
                "wiki",
                lambda *_: {
                    "intent": {},
                    "observed_postcondition": {},
                    "current_fence_evidence": None,
                },
            )
        ]
    )
    for changed_item, changed_receipt in (
        (item, {"adapter": "unknown/v1"}),
        ({**item, "work_kind": "memory-projection"}, receipt),
        ({**item, "resource_ref": "volume:page:home"}, receipt),
    ):
        with pytest.raises(MatrixHostError, match="effect_truth_unverifiable"):
            exact(changed_item, changed_receipt, 1)
    with pytest.raises(MatrixHostError, match="effect_truth_unverifiable"):
        EffectObserverRouter()(item, receipt, 1)
    with pytest.raises(MatrixHostError, match="effect_observer_route_ambiguous"):
        EffectObserverRouter(
            [
                EffectObserverRoute(
                    "synthetic-wiki/v1", "publication", "wiki", lambda *_: {}
                ),
                EffectObserverRoute(
                    "synthetic-wiki/v1", "publication", "wiki", lambda *_: {}
                ),
            ]
        )
    unavailable = EffectObserverRouter(
        [EffectObserverRoute("synthetic-wiki/v1", "publication", "wiki", None)]
    )
    with pytest.raises(MatrixHostError, match="effect_truth_unverifiable"):
        unavailable(item, receipt, 1)

    def broken(*_args):
        raise RuntimeError("private observer detail")

    throwing = EffectObserverRouter(
        [EffectObserverRoute("synthetic-wiki/v1", "publication", "wiki", broken)]
    )
    with pytest.raises(MatrixHostError, match="^effect_truth_unverifiable$"):
        throwing(item, receipt, 1)


def test_high_water_rollback_fails_closed(tmp_path):
    _running(tmp_path)
    fences = SyntheticResourceFenceStore(tmp_path)
    first = fences.acquire(
        RESOURCE,
        "test-key",
        "SHA256:test",
        holder_embodiment_id=EMBODIMENT,
    )
    renewed = fences.renew(RESOURCE, "unused")
    assert renewed is not None
    fences._write_lease(RESOURCE, first)
    with pytest.raises(MatrixHostError, match="resource_fence_registry_unavailable"):
        MatrixHostAdapter(tmp_path, EMBODIMENT, fence_store=fences).fence_evidence(
            RESOURCE
        )


def test_registry_and_matrix_roots_are_owner_only_and_opaque(tmp_path):
    _running(tmp_path)
    registry_mode = stat.S_IMODE((tmp_path / "embodiments.json").stat().st_mode)
    assert registry_mode == 0o600
    root = matrix_root(tmp_path, EMBODIMENT)
    assert EMBODIMENT not in str(root)


@pytest.mark.parametrize(
    "schema",
    [
        "dm.runtime.bundle/v1",
        "dm.runtime.bundle/v2",
        "dm.runtime.bundle/v3",
        "dm.runtime.bundle/v4",
        "dm.runtime.bundle/v5",
        "dm.runtime.bundle/v6",
    ],
)
def test_public_bundle_rejects_undeployed_legacy_schemas(tmp_path, schema):
    root = tmp_path / "runtime"
    root.mkdir(mode=0o700)
    bundle = root / "runtime.json"
    bundle.write_text(json.dumps({"schema": schema}), encoding="utf-8")
    bundle.chmod(0o600)

    with pytest.raises(MatrixHostError, match="matrix_bundle_rejected"):
        matrix_host_module._public_bundle(root, "runtime.json")


def test_public_bundle_rejects_an_unpinned_successor_schema(tmp_path):
    root = tmp_path / "runtime"
    root.mkdir(mode=0o700)
    bundle = root / "runtime.json"
    bundle.write_text(json.dumps({"schema": "dm.runtime.bundle/v8"}), encoding="utf-8")
    bundle.chmod(0o600)

    with pytest.raises(MatrixHostError, match="matrix_bundle_rejected"):
        matrix_host_module._public_bundle(root, "runtime.json")


def test_quiesced_snapshot_restore_excludes_host_locals_and_detects_tamper(
    tmp_path, monkeypatch
):
    source = _signed_snapshot_root(tmp_path)
    (source / "matrix.sock").write_text("host-local", encoding="utf-8")
    (source / "matrix.sock").chmod(0o600)

    original_copy = matrix_host_module._copy_owner_file

    def interrupted_copy(*_args, **_kwargs):
        raise OSError("synthetic snapshot interruption")

    monkeypatch.setattr(
        matrix_host_module,
        "_copy_owner_file",
        interrupted_copy,
    )
    failed = tmp_path / "failed-snapshot"
    with pytest.raises(OSError, match="synthetic snapshot interruption"):
        create_portable_snapshot(source, failed)
    assert not failed.exists()
    assert not list(tmp_path.glob(".failed-snapshot.snapshot-*"))
    monkeypatch.setattr(matrix_host_module, "_copy_owner_file", original_copy)

    snapshot = tmp_path / "snapshot"
    manifest = create_portable_snapshot(source, snapshot)
    assert manifest["matrix_contract_commit"] == MATRIX_CONTRACT_COMMIT
    assert "matrix.sock" not in {row["name"] for row in manifest["files"]}
    assert ".daimon-matrixd.lock" not in {row["name"] for row in manifest["files"]}

    restored = tmp_path / "restored"
    assert restore_portable_snapshot(snapshot, restored) == manifest
    assert (restored / "ledger.sqlite").read_text() == "canonical-ledger"
    assert not (restored / "matrix.sock").exists()
    assert not (restored / ".daimon-matrixd.lock").exists()
    assert stat.S_IMODE(restored.stat().st_mode) == 0o700
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600 for path in restored.iterdir()
    )

    (snapshot / "payload" / "ledger.sqlite").write_text("tampered", encoding="utf-8")
    with pytest.raises(MatrixHostError, match="matrix_snapshot_payload_rejected"):
        restore_portable_snapshot(snapshot, tmp_path / "rejected")


def test_snapshot_restore_rejects_replacement_after_verification(tmp_path, monkeypatch):
    source = _signed_snapshot_root(tmp_path)
    (source / "ledger.sqlite").write_text("verified-ledger")
    snapshot = tmp_path / "snapshot"
    create_portable_snapshot(source, snapshot)
    real_verify = matrix_host_module.verify_portable_snapshot

    def replace_after_verify(path, **kwargs):
        result = real_verify(path, **kwargs)
        ledger = snapshot / "payload/ledger.sqlite"
        replacement = snapshot / "payload/replacement"
        replacement.write_text("attacker-bytes")
        replacement.chmod(0o600)
        os.replace(replacement, ledger)
        return result

    monkeypatch.setattr(
        matrix_host_module, "verify_portable_snapshot", replace_after_verify
    )
    with pytest.raises(MatrixHostError, match="matrix_snapshot_payload_replaced"):
        restore_portable_snapshot(snapshot, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


def test_snapshot_rejects_invalid_binding_before_creating_destination(tmp_path):
    source = _signed_snapshot_root(tmp_path)
    bundle_path = source / "runtime.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["operator_capability_binding"]["signature"]["value"] = "A" * 86
    bundle_path.write_bytes(canonical_bytes(bundle))
    destination = tmp_path / "rejected-snapshot"

    with pytest.raises(MatrixHostError, match="matrix_snapshot_source_unsafe"):
        create_portable_snapshot(source, destination)

    assert not destination.exists()


def test_snapshot_includes_ledger_even_when_its_name_ends_like_a_sidecar(tmp_path):
    source = _signed_snapshot_root(tmp_path, ledger_name="canonical-wal")
    destination = tmp_path / "snapshot"

    manifest = create_portable_snapshot(source, destination)

    assert "canonical-wal" in {row["name"] for row in manifest["files"]}
    assert (destination / "payload" / "canonical-wal").read_text() == (
        "canonical-ledger"
    )


def test_snapshot_includes_required_custody_even_when_its_name_looks_temporary(
    tmp_path,
):
    source = _signed_snapshot_root(tmp_path)
    bundle_path = source / "runtime.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    custody_name = bundle["keystore"]["filename"]
    (source / custody_name).rename(source / "custody.tmp")
    bundle["keystore"]["filename"] = "custody.tmp"
    bundle_path.write_bytes(canonical_bytes(bundle))
    destination = tmp_path / "snapshot"

    manifest = create_portable_snapshot(source, destination)

    assert "custody.tmp" in {row["name"] for row in manifest["files"]}
    assert (destination / "payload" / "custody.tmp").is_file()


def test_snapshot_rejects_a_missing_bundle_named_runtime_ledger(tmp_path):
    source = _signed_snapshot_root(tmp_path)
    bundle = json.loads((source / "runtime.json").read_text(encoding="utf-8"))
    (source / bundle["ledger"]).unlink()
    destination = tmp_path / "snapshot"

    with pytest.raises(MatrixHostError, match="matrix_snapshot_source_unsafe"):
        create_portable_snapshot(source, destination)

    assert not destination.exists()


def test_snapshot_create_and_restore_reject_linked_destination_parent(tmp_path):
    source = _signed_snapshot_root(tmp_path)
    victim = tmp_path / "victim"
    victim.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(victim, target_is_directory=True)

    with pytest.raises(MatrixHostError, match="snapshot_destination_exists"):
        create_portable_snapshot(source, linked / "snapshot")
    assert not (victim / "snapshot").exists()

    snapshot = tmp_path / "snapshot"
    create_portable_snapshot(source, snapshot)
    with pytest.raises(MatrixHostError, match="restore_destination_exists"):
        restore_portable_snapshot(snapshot, linked / "restored")
    assert not (victim / "restored").exists()


def test_snapshot_create_and_restore_reject_linked_source_parent(tmp_path):
    real_parent = tmp_path / "real"
    real_parent.mkdir(mode=0o700)
    source = _signed_snapshot_root(real_parent)
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    linked_source = linked_parent / source.relative_to(real_parent)

    with pytest.raises(MatrixHostError, match="matrix_root_not_owner_only"):
        create_portable_snapshot(linked_source, tmp_path / "rejected")
    assert not (tmp_path / "rejected").exists()

    snapshot = real_parent / "snapshot"
    create_portable_snapshot(source, snapshot)
    with pytest.raises(MatrixHostError, match="matrix_root_not_owner_only"):
        restore_portable_snapshot(linked_parent / "snapshot", tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


def test_snapshot_publication_never_replaces_a_concurrent_target(
    tmp_path, monkeypatch
):
    source = _signed_snapshot_root(tmp_path)
    destination = tmp_path / "snapshot"
    original_publish = matrix_host_module._publish_directory_noreplace
    contender_inode = None

    def publish_with_contender(parent_descriptor, temporary_name, target_name, **kwargs):
        nonlocal contender_inode
        os.mkdir(target_name, mode=0o700, dir_fd=parent_descriptor)
        contender_inode = os.stat(
            target_name, dir_fd=parent_descriptor, follow_symlinks=False
        ).st_ino
        return original_publish(
            parent_descriptor, temporary_name, target_name, **kwargs
        )

    monkeypatch.setattr(
        matrix_host_module, "_publish_directory_noreplace", publish_with_contender
    )
    with pytest.raises(MatrixHostError, match="snapshot_destination_exists"):
        create_portable_snapshot(source, destination)

    assert destination.stat().st_ino == contender_inode
    assert list(destination.iterdir()) == []


def test_snapshot_restore_never_replaces_a_concurrent_target(
    tmp_path, monkeypatch
):
    source = _signed_snapshot_root(tmp_path)
    snapshot = tmp_path / "snapshot"
    create_portable_snapshot(source, snapshot)
    destination = tmp_path / "restored"
    original_publish = matrix_host_module._publish_directory_noreplace
    contender_inode = None

    def publish_with_contender(parent_descriptor, temporary_name, target_name, **kwargs):
        nonlocal contender_inode
        os.mkdir(target_name, mode=0o700, dir_fd=parent_descriptor)
        contender_inode = os.stat(
            target_name, dir_fd=parent_descriptor, follow_symlinks=False
        ).st_ino
        return original_publish(
            parent_descriptor, temporary_name, target_name, **kwargs
        )

    monkeypatch.setattr(
        matrix_host_module, "_publish_directory_noreplace", publish_with_contender
    )
    with pytest.raises(MatrixHostError, match="restore_destination_exists"):
        restore_portable_snapshot(snapshot, destination)

    assert destination.stat().st_ino == contender_inode
    assert list(destination.iterdir()) == []


def test_support_status_marks_explicit_synthetic_fixture_nonproduction(tmp_path):
    _running(tmp_path)
    value = MatrixHostAdapter(
        tmp_path,
        EMBODIMENT,
        fence_store=SyntheticResourceFenceStore(tmp_path),
    ).support_status()
    assert value == {
        "schema": "dm.cluster-matrix-status/v1",
        "matrix_contract_commit": MATRIX_CONTRACT_COMMIT,
        "embodiment_id": EMBODIMENT,
        "resource_fences": {
            "schema": "resource-fence-support/v1",
            "mode": "synthetic-fake-signer",
            "production_ready": False,
            "interprocess_cas": False,
        },
    }
