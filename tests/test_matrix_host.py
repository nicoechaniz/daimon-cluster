import hashlib
import json
import stat
import uuid

import pytest

pytest.importorskip("daimon_matrix")

from daimon_matrix.cluster import (
    resource_fence_position,
    verify_resource_fence_evidence,
)

from clusterctl import matrix_host as matrix_host_module
from clusterctl.embodiments import Registry
from clusterctl.fences import ResourceFenceStore
from clusterctl.matrix_host import (
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


def test_body_snapshot_is_exact_registry_bound_and_filters_fences(tmp_path):
    _running(tmp_path)
    fences = ResourceFenceStore(tmp_path)
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
    fences = ResourceFenceStore(tmp_path)
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


def test_high_water_rollback_fails_closed(tmp_path):
    _running(tmp_path)
    fences = ResourceFenceStore(tmp_path)
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
    ],
)
def test_public_bundle_accepts_the_pinned_additive_line(tmp_path, schema):
    root = tmp_path / "runtime"
    root.mkdir(mode=0o700)
    bundle = root / "runtime.json"
    bundle.write_text(json.dumps({"schema": schema}), encoding="utf-8")
    bundle.chmod(0o600)

    assert matrix_host_module._public_bundle(root, "runtime.json") == {
        "schema": schema
    }


def test_public_bundle_rejects_an_unpinned_successor_schema(tmp_path):
    root = tmp_path / "runtime"
    root.mkdir(mode=0o700)
    bundle = root / "runtime.json"
    bundle.write_text(
        json.dumps({"schema": "dm.runtime.bundle/v6"}), encoding="utf-8"
    )
    bundle.chmod(0o600)

    with pytest.raises(MatrixHostError, match="matrix_bundle_rejected"):
        matrix_host_module._public_bundle(root, "runtime.json")


def test_quiesced_snapshot_restore_excludes_host_locals_and_detects_tamper(
    tmp_path, monkeypatch
):
    source = tmp_path / "runtime"
    source.mkdir(mode=0o700)
    origin = {
        "body_ref": BODY,
        "embodiment_id": EMBODIMENT,
        "incarnation_id": INCARNATION,
        "principal_id": "compaii@legion",
    }
    bundle = {
        "schema": "dm.runtime.bundle/v1",
        "local_origin": origin,
        "socket": "matrix.sock",
    }
    for name, content in {
        "runtime.json": json.dumps(bundle),
        "custody.json": "encrypted",
        "ledger.sqlite": "canonical-ledger",
    }.items():
        path = source / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
    (source / "matrix.sock").write_text("host-local", encoding="utf-8")
    (source / "matrix.sock").chmod(0o600)

    original_copy = matrix_host_module.shutil.copyfile

    def interrupted_copy(*_args, **_kwargs):
        raise OSError("synthetic snapshot interruption")

    monkeypatch.setattr(
        matrix_host_module.shutil,
        "copyfile",
        interrupted_copy,
    )
    failed = tmp_path / "failed-snapshot"
    with pytest.raises(OSError, match="synthetic snapshot interruption"):
        create_portable_snapshot(source, failed)
    assert not failed.exists()
    assert not list(tmp_path.glob(".failed-snapshot.snapshot-*"))
    monkeypatch.setattr(matrix_host_module.shutil, "copyfile", original_copy)

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


def test_support_status_admits_nonproduction_fence_backend(tmp_path):
    _running(tmp_path)
    value = MatrixHostAdapter(tmp_path, EMBODIMENT).support_status()
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
