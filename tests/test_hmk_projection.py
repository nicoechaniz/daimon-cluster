from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("daimon_matrix")

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.cluster import resource_fence_position
from daimon_matrix.curator import create_curator_claim, create_curator_item

from clusterctl.embodiments import Registry
from clusterctl.fences import SyntheticResourceFenceStore
from clusterctl.hmk_projection import (
    DM034ExecutionJournal,
    DM034ExecutorError,
    DM034ProjectionExecutor,
    DM034_EXECUTOR_ADAPTER,
    DM034_RESOURCE_NAMESPACE,
    DM034_WORK_KIND,
    create_dm034_intent,
    dm034_executor_root,
    profile_hash,
    restore_hmk_database,
    snapshot_hmk_database,
)
from clusterctl.matrix_host import (
    EffectObserverRouter,
    MatrixHostAdapter,
    MatrixHostError,
)

BODY = "cluster:legion:compaii"
EMBODIMENT = "embodiment:11111111-1111-4111-8111-111111111111"
INCARNATION = "incarnation:22222222-2222-4222-8222-222222222222"
ACTOR = "compaii@legion"
RESOURCE = "hmk:personal-memory:peer-a"
FIXTURE = Path(__file__).parent / "fixtures" / "dm034-vector-v1.json"


class VectorAdapter:
    def __init__(self, vectors: dict[str, Any]) -> None:
        self.profile = copy.deepcopy(vectors["profile"])
        self.project_receipt = copy.deepcopy(vectors["project_receipt"])
        self.rebuild_plan_value = copy.deepcopy(vectors["rebuild_plan"])
        self.rebuild_receipt = copy.deepcopy(vectors["rebuild_receipt"])
        self.project_calls = 0
        self.rebuild_calls = 0
        self.statement_override: str | None = None
        self.observer_unavailable = False

    def project(self, *, event_id: str, idempotency_key: str) -> dict[str, Any]:
        assert event_id == self.project_receipt["source_event"]["event_id"]
        self.project_calls += 1
        return copy.deepcopy(self.project_receipt)

    def inspect(self, *, memory_id: str) -> dict[str, Any]:
        assert memory_id == self.project_receipt["source_event"]["memory_id"]
        effect = copy.deepcopy(self.project_receipt["effect"])
        effect["memory_id"] = memory_id
        if self.statement_override is not None:
            effect["statement"]["sha256"] = self.statement_override
        return {"projection": effect}

    def reconcile(self, receipt: dict[str, Any]) -> dict[str, Any]:
        if self.observer_unavailable:
            raise ConnectionError("synthetic private diagnostic")
        return {
            "schema": "dm.memory-projection.reconciliation/v1",
            "receipt_id": receipt["receipt_id"],
            "status": "verified",
            "reason": "effect-truth-matches",
        }

    def rebuild_plan(self, *, request_id: str, idempotency_key: str) -> dict[str, Any]:
        assert request_id == self.rebuild_plan_value["hmk_plan"]["request_id"]
        return copy.deepcopy(self.rebuild_plan_value)

    def rebuild_apply(self, value: Any) -> dict[str, Any]:
        assert value == self.rebuild_plan_value
        self.rebuild_calls += 1
        return copy.deepcopy(self.rebuild_receipt)

    def verify(self) -> dict[str, Any]:
        return {
            "namespace_id": self.rebuild_receipt["namespace_id"],
            "generation": self.rebuild_receipt["generation"],
            "manifest_hash": self.rebuild_receipt["matrix_manifest_hash"],
        }


def _setup(tmp_path: Path) -> tuple[MatrixHostAdapter, SyntheticResourceFenceStore, list[int]]:
    Registry(tmp_path).register(body_ref=BODY, embodiment_id=EMBODIMENT)
    Registry(tmp_path).start(EMBODIMENT, incarnation_id=INCARNATION, started_at_ms=1)
    fences = SyntheticResourceFenceStore(tmp_path)
    held = fences.acquire(
        RESOURCE,
        "test-key",
        "SHA256:test",
        holder_embodiment_id=EMBODIMENT,
    )
    now = [held["created_ms"] + 1]
    host = MatrixHostAdapter(
        tmp_path, EMBODIMENT, fence_store=fences, clock=lambda: now[0]
    )
    return host, fences, now


def _artifacts(
    host: MatrixHostAdapter,
    vectors: dict[str, Any],
    intent: dict[str, Any],
    now: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    item = create_curator_item(
        subject_me_id=vectors["project_receipt"]["subject_me_id"],
        resource_ref=RESOURCE,
        work_kind=DM034_WORK_KIND,
        input_ref=(
            f"matrix-event:{intent['source_event_id']}"
            if intent["operation"] == "project"
            else f"matrix-rebuild:{intent['rebuild_request_id']}"
        ),
        input_hash=intent["preview_hash"],
        coordination_mode="resource-fence",
        required_authority=intent["authority"],
        effect_intent_hash=hashlib.sha256(canonical_bytes(intent)).hexdigest(),
        queued_at_ms=now,
    )
    evidence = host.fence_evidence(RESOURCE)
    assert evidence is not None
    claim = create_curator_claim(
        claim_id=str(uuid.uuid4()),
        item=item,
        generation=1,
        actor_origin={
            "body_ref": BODY,
            "embodiment_id": EMBODIMENT,
            "incarnation_id": INCARNATION,
            "principal_id": ACTOR,
        },
        issued_at_ms=now,
        lease_until_ms=now + 60_000,
        resource_fence=resource_fence_position(evidence),
    )
    return item, claim


def _project_intent(vectors: dict[str, Any]) -> dict[str, Any]:
    source = vectors["project_receipt"]["source_event"]
    return create_dm034_intent(
        operation="project",
        target_event_id=source["event_id"],
        decision_event_id="34000000-0000-4000-8000-000000000010",
        source_event_id=source["event_id"],
        source_event_hash=source["event_hash"],
        rebuild_request_id=None,
        idempotency_key="vector:project",
        resource_ref=RESOURCE,
        profile_hash_value=profile_hash(vectors["profile"]),
        plan_hash=None,
        actor=ACTOR,
        authority="daimon",
        source_review=None,
    )


def test_exact_apply_replay_observer_and_changed_truth_fail_closed(
    tmp_path: Path,
) -> None:
    vectors = json.loads(FIXTURE.read_text())
    host, fences, now = _setup(tmp_path)
    intent = [_project_intent(vectors)]
    adapter = VectorAdapter(vectors)
    executor = DM034ProjectionExecutor(
        host,
        resource_ref=RESOURCE,
        current_intent=lambda _item: copy.deepcopy(intent[0]),
        adapter_resolver=lambda _item, _intent: adapter,
        journal=DM034ExecutionJournal(tmp_path / "executor" / "journal.sqlite"),
        clock=lambda: now[0],
    )
    item, claim = _artifacts(host, vectors, intent[0], now[0])

    first = executor.execute(item, claim)
    second = executor.execute(item, claim)
    assert first == second
    assert first["adapter"] == DM034_EXECUTOR_ADAPTER
    assert first["observed_postcondition"]["kind"] == "projection"
    assert adapter.project_calls == 1
    public_boundary = json.dumps(
        {
            "item": item,
            "intent": intent[0],
            "receipt": first,
        },
        sort_keys=True,
    )
    assert str(tmp_path) not in public_boundary
    assert "The orchard gate opens at dawn." not in public_boundary
    assert "library.db" not in public_boundary
    assert executor.route.resource_namespace == DM034_RESOURCE_NAMESPACE
    assert (
        executor.observe(item, first, now[0])["observed_postcondition"]
        == first["observed_postcondition"]
    )
    assert (
        EffectObserverRouter([executor.route])(item, first, now[0])["intent"]
        == intent[0]
    )

    original_row = executor.journal.lookup(item["item_id"])
    intent[0] = create_dm034_intent(
        **{
            **{
                "operation": "project",
                "target_event_id": vectors["project_receipt"]["source_event"][
                    "event_id"
                ],
                "decision_event_id": "34000000-0000-4000-8000-000000000010",
                "source_event_id": vectors["project_receipt"]["source_event"][
                    "event_id"
                ],
                "source_event_hash": "0" * 64,
                "rebuild_request_id": None,
                "idempotency_key": "vector:project",
                "resource_ref": RESOURCE,
                "profile_hash_value": profile_hash(vectors["profile"]),
                "plan_hash": None,
                "actor": ACTOR,
                "authority": "daimon",
                "source_review": None,
            }
        }
    )
    with pytest.raises(DM034ExecutorError, match="dm034_current_intent_mismatch"):
        executor.execute(item, claim)
    assert executor.journal.lookup(item["item_id"]) == original_row

    intent[0] = _project_intent(vectors)
    preview = intent[0]["preview_hash"]
    intent[0] = create_dm034_intent(
        operation="project",
        target_event_id=vectors["project_receipt"]["source_event"]["event_id"],
        decision_event_id="34000000-0000-4000-8000-000000000010",
        source_event_id=vectors["project_receipt"]["source_event"]["event_id"],
        source_event_hash=vectors["project_receipt"]["source_event"]["event_hash"],
        rebuild_request_id=None,
        idempotency_key="vector:project",
        resource_ref=RESOURCE,
        profile_hash_value=profile_hash(vectors["profile"]),
        plan_hash=None,
        actor=ACTOR,
        authority="daimon",
        source_review={
            "schema": "dm.cluster.dm034-source-review/v1",
            "review_event_id": "34000000-0000-4000-8000-000000000011",
            "review_hash": "1" * 64,
            "reviewed_decision_event_id": "34000000-0000-4000-8000-000000000010",
            "status": "approved",
            "independent": True,
        },
    )
    assert intent[0]["preview_hash"] == preview
    with pytest.raises(DM034ExecutorError, match="dm034_current_intent_mismatch"):
        executor.execute(item, claim)

    intent[0] = _project_intent(vectors)
    adapter.statement_override = "0" * 64
    with pytest.raises(DM034ExecutorError, match="dm034_postcondition_changed"):
        executor.execute(item, claim)
    adapter.statement_override = None

    adapter.observer_unavailable = True
    with pytest.raises(DM034ExecutorError, match="dm034_effect_truth_unverifiable"):
        executor.execute(item, claim)
    with pytest.raises(MatrixHostError, match="effect_truth_unverifiable"):
        EffectObserverRouter([executor.route])(item, first, now[0])
    adapter.observer_unavailable = False

    renewed = fences.renew(RESOURCE, "unused")
    assert renewed is not None
    now[0] = renewed["created_ms"] + 1
    with pytest.raises(DM034ExecutorError, match="dm034_production_fence_changed"):
        executor.execute(item, claim)
    with pytest.raises(MatrixHostError, match="effect_truth_unverifiable"):
        EffectObserverRouter()(item, first, now[0])


@pytest.mark.parametrize("stage", ["after-inner-effect", "after-effect-stage"])
def test_crash_recovery_preserves_exact_outer_receipt(
    tmp_path: Path, stage: str
) -> None:
    vectors = json.loads(FIXTURE.read_text())
    host, _fences, now = _setup(tmp_path)
    intent = _project_intent(vectors)
    adapter = VectorAdapter(vectors)
    armed = [True]

    def fault(seen: str) -> None:
        if armed[0] and seen == stage:
            armed[0] = False
            raise RuntimeError("synthetic-crash")

    executor = DM034ProjectionExecutor(
        host,
        resource_ref=RESOURCE,
        current_intent=lambda _item: intent,
        adapter_resolver=lambda _item, _intent: adapter,
        journal=DM034ExecutionJournal(tmp_path / "executor" / "journal.sqlite"),
        clock=lambda: now[0],
        fault=fault,
    )
    item, claim = _artifacts(host, vectors, intent, now[0])
    with pytest.raises(RuntimeError, match="synthetic-crash"):
        executor.execute(item, claim)
    receipt = executor.execute(item, claim)
    assert executor.execute(item, claim) == receipt
    assert adapter.project_calls == (2 if stage == "after-inner-effect" else 1)


def test_rebuild_binds_exact_plan_and_fresh_namespace_postcondition(
    tmp_path: Path,
) -> None:
    vectors = json.loads(FIXTURE.read_text())
    host, _fences, now = _setup(tmp_path)
    adapter = VectorAdapter(vectors)
    plan_hash = hashlib.sha256(canonical_bytes(vectors["rebuild_plan"])).hexdigest()
    request_id = vectors["rebuild_plan"]["hmk_plan"]["request_id"]
    intent = create_dm034_intent(
        operation="rebuild",
        target_event_id="34000000-0000-4000-8000-000000000020",
        decision_event_id="34000000-0000-4000-8000-000000000021",
        source_event_id=None,
        source_event_hash=None,
        rebuild_request_id=request_id,
        idempotency_key="vector:rebuild",
        resource_ref=RESOURCE,
        profile_hash_value=profile_hash(vectors["profile"]),
        plan_hash=plan_hash,
        actor=ACTOR,
        authority="daimon",
        source_review=None,
    )
    executor = DM034ProjectionExecutor(
        host,
        resource_ref=RESOURCE,
        current_intent=lambda _item: intent,
        adapter_resolver=lambda _item, _intent: adapter,
        journal=DM034ExecutionJournal(tmp_path / "executor" / "journal.sqlite"),
        clock=lambda: now[0],
    )
    item, claim = _artifacts(host, vectors, intent, now[0])
    receipt = executor.execute(item, claim)
    assert receipt["observed_postcondition"] == {
        "schema": "dm.cluster.dm034-postcondition/v1",
        "kind": "namespace-rebuild",
        "namespace_id": vectors["rebuild_receipt"]["namespace_id"],
        "generation": 2,
        "manifest_hash": vectors["rebuild_receipt"]["matrix_manifest_hash"],
        "matrix_checkpoint_hash": vectors["rebuild_receipt"]["matrix_checkpoint"][
            "hash"
        ],
    }
    assert adapter.rebuild_calls == 1


def test_sqlite_snapshot_restore_is_payload_free_and_peer_roots_are_independent(
    tmp_path: Path,
) -> None:
    first = tmp_path / "peer-a"
    second = tmp_path / "peer-b"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    for base, marker in ((first, "a"), (second, "b")):
        database = sqlite3.connect(base / "library.db")
        database.execute("PRAGMA foreign_keys=ON")
        database.execute("CREATE TABLE marker(value TEXT NOT NULL)")
        database.execute("INSERT INTO marker VALUES (?)", (marker,))
        database.commit()
        database.close()
        (base / "library.db").chmod(0o600)

    snapshot = tmp_path / "peer-a.snapshot.sqlite"
    evidence = snapshot_hmk_database(first, snapshot)
    assert set(evidence) == {
        "schema",
        "byte_length",
        "sha256",
        "integrity_check",
        "foreign_key_violations",
    }
    restored = tmp_path / "restored-a"
    assert restore_hmk_database(snapshot, restored) == evidence
    connection = sqlite3.connect(restored / "library.db")
    assert connection.execute("SELECT value FROM marker").fetchone() == ("a",)
    connection.close()
    connection = sqlite3.connect(second / "library.db")
    assert connection.execute("SELECT value FROM marker").fetchone() == ("b",)
    connection.close()
    assert dm034_executor_root(tmp_path, EMBODIMENT) != dm034_executor_root(
        tmp_path, "embodiment:33333333-3333-4333-8333-333333333333"
    )
