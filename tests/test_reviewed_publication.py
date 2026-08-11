from __future__ import annotations

import copy
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("daimon_matrix")

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.cluster import resource_fence_position
from daimon_matrix.curator import create_curator_claim, create_curator_item

from clusterctl.embodiments import Registry
from clusterctl.fences import ResourceFenceStore
from clusterctl.matrix_host import (
    EffectObserverRouter,
    MatrixHostAdapter,
    MatrixHostError,
)
from clusterctl.reviewed_publication import (
    DM035ExecutorError,
    DM035PublicationExecutor,
    DM035_EXECUTOR_ADAPTER,
    DM035_RESOURCE_NAMESPACE,
    DM035_WORK_KIND,
    create_dm035_intent,
    dm035_publisher_root,
)

BODY = "cluster:vector:compaii"
EMBODIMENT = "embodiment:11111111-1111-4111-8111-111111111111"
INCARNATION = "incarnation:22222222-2222-4222-8222-222222222222"
ACTOR = "compaii@vector"
RESOURCE = "publication:daimon-matrix:peer-a"
EVENT_ID = "35000000-0000-4000-8000-000000000006"
EVENT_HASH = "e" * 64
FIXTURE = Path(__file__).parent / "fixtures" / "dm035-vector-v1.json"


class VectorCoordinator:
    def __init__(self, vectors: dict[str, Any]) -> None:
        self.profile = copy.deepcopy(vectors["profile"])
        self.policy = copy.deepcopy(vectors["policy"])
        self.acceptance = copy.deepcopy(vectors["acceptance"])
        self.calls = 0
        self.lose_once = False
        self.unavailable = False
        self.drift = False

    def execute(self, *, claim_id: str) -> dict[str, Any]:
        assert claim_id == self.acceptance["claim_id"]
        self.calls += 1
        if self.lose_once:
            self.lose_once = False
            raise ConnectionError("synthetic private response-loss detail")
        acceptance = copy.deepcopy(self.acceptance)
        if self.drift:
            acceptance["provider_receipt"]["artifact_sha256"] = "0" * 64
        return {
            "event": {"event_id": EVENT_ID, "content_hash": EVENT_HASH},
            "acceptance": acceptance,
        }

    def reconcile(self, acceptance_event_id: str) -> dict[str, Any]:
        if self.unavailable:
            raise ConnectionError("synthetic private observer detail")
        assert acceptance_event_id == EVENT_ID
        return {
            "schema": "dm.publication.reconciliation/v1",
            "acceptance_event_id": EVENT_ID,
            "status": "verified",
        }


def _setup(tmp_path: Path) -> tuple[MatrixHostAdapter, ResourceFenceStore, list[int]]:
    Registry(tmp_path).register(body_ref=BODY, embodiment_id=EMBODIMENT)
    Registry(tmp_path).start(EMBODIMENT, incarnation_id=INCARNATION, started_at_ms=1)
    fences = ResourceFenceStore(tmp_path)
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


def _intent(vectors: dict[str, Any]) -> dict[str, Any]:
    return create_dm035_intent(
        request_event_id=vectors["claim"]["request_event_id"],
        request_event_hash=vectors["claim"]["request_event_hash"],
        request=vectors["request"],
        publication_claim=vectors["claim"],
        profile=vectors["profile"],
        resource_ref=RESOURCE,
    )


def _artifacts(
    host: MatrixHostAdapter,
    vectors: dict[str, Any],
    intent: dict[str, Any],
    now: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    item = create_curator_item(
        subject_me_id=vectors["policy"]["subject_me_id"],
        resource_ref=RESOURCE,
        work_kind=DM035_WORK_KIND,
        input_ref=f"matrix-publication:{intent['request_event_id']}",
        input_hash=intent["preview_hash"],
        coordination_mode="resource-fence",
        required_authority="daimon",
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


def test_exact_reviewed_publish_replay_and_fresh_observer(tmp_path: Path) -> None:
    vectors = json.loads(FIXTURE.read_text())
    host, _fences, now = _setup(tmp_path)
    intent = [_intent(vectors)]
    coordinator = VectorCoordinator(vectors)
    executor = DM035PublicationExecutor(
        host,
        resource_ref=RESOURCE,
        current_intent=lambda _item: copy.deepcopy(intent[0]),
        coordinator_resolver=lambda _item, _intent: coordinator,
        clock=lambda: now[0],
    )
    item, claim = _artifacts(host, vectors, intent[0], now[0])

    first = executor.execute(item, claim)
    second = executor.execute(item, claim)
    assert first == second
    assert first["adapter"] == DM035_EXECUTOR_ADAPTER
    assert (
        first["preview_hash"]
        == vectors["request"]["proposal"]["rendered_ref"]["sha256"]
    )
    post = first["observed_postcondition"]
    assert post["before_target_sha256"] is None
    assert post["after_target_sha256"] == first["preview_hash"]
    assert post["acceptance_event_hash"] == EVENT_HASH
    assert executor.route.resource_namespace == DM035_RESOURCE_NAMESPACE
    assert executor.observe(item, first, now[0])["observed_postcondition"] == post
    assert (
        EffectObserverRouter([executor.route])(item, first, now[0])["intent"]
        == intent[0]
    )

    public_boundary = json.dumps(
        {"item": item, "intent": intent[0], "receipt": first}, sort_keys=True
    )
    assert str(tmp_path) not in public_boundary
    assert "Synthetic reviewed identity summary" not in public_boundary
    assert "project/daimon-matrix/compaii" not in public_boundary
    assert "matrix_publisher.py" not in public_boundary


def test_changed_review_intent_fence_and_postcondition_fail_closed(
    tmp_path: Path,
) -> None:
    vectors = json.loads(FIXTURE.read_text())
    host, fences, now = _setup(tmp_path)
    intent = [_intent(vectors)]
    coordinator = VectorCoordinator(vectors)
    executor = DM035PublicationExecutor(
        host,
        resource_ref=RESOURCE,
        current_intent=lambda _item: copy.deepcopy(intent[0]),
        coordinator_resolver=lambda _item, _intent: coordinator,
        clock=lambda: now[0],
    )
    item, claim = _artifacts(host, vectors, intent[0], now[0])
    receipt = executor.execute(item, claim)

    changed = copy.deepcopy(intent[0])
    changed["review"]["decision_hash"] = "0" * 64
    intent[0] = changed
    with pytest.raises(DM035ExecutorError, match="dm035_current_intent_mismatch"):
        executor.execute(item, claim)

    intent[0] = _intent(vectors)
    self_review = copy.deepcopy(intent[0])
    self_review["review"]["independent"] = False
    intent[0] = self_review
    with pytest.raises(DM035ExecutorError, match="dm035_review_rejected"):
        executor.execute(item, claim)

    intent[0] = _intent(vectors)
    coordinator.unavailable = True
    with pytest.raises(DM035ExecutorError, match="dm035_effect_truth_unverifiable"):
        executor.execute(item, claim)
    with pytest.raises(MatrixHostError, match="effect_truth_unverifiable"):
        EffectObserverRouter([executor.route])(item, receipt, now[0])
    coordinator.unavailable = False

    coordinator.drift = True
    with pytest.raises(DM035ExecutorError, match="dm035_effect_truth_unverifiable"):
        executor.execute(item, claim)
    coordinator.drift = False

    renewed = fences.renew(RESOURCE, "unused")
    assert renewed is not None
    now[0] = renewed["created_ms"] + 1
    with pytest.raises(DM035ExecutorError, match="dm035_production_fence_changed"):
        executor.execute(item, claim)
    with pytest.raises(MatrixHostError, match="effect_truth_unverifiable"):
        EffectObserverRouter()(item, receipt, now[0])


def test_inner_response_loss_retries_to_same_content_addressed_outer_receipt(
    tmp_path: Path,
) -> None:
    vectors = json.loads(FIXTURE.read_text())
    host, _fences, now = _setup(tmp_path)
    intent = _intent(vectors)
    coordinator = VectorCoordinator(vectors)
    coordinator.lose_once = True
    executor = DM035PublicationExecutor(
        host,
        resource_ref=RESOURCE,
        current_intent=lambda _item: intent,
        coordinator_resolver=lambda _item, _intent: coordinator,
        clock=lambda: now[0],
    )
    item, claim = _artifacts(host, vectors, intent, now[0])
    with pytest.raises(DM035ExecutorError, match="dm035_inner_effect_unverifiable"):
        executor.execute(item, claim)
    first = executor.execute(item, claim)
    assert executor.execute(item, claim) == first
    assert coordinator.calls == 3


def test_publisher_roots_are_per_embodiment(tmp_path: Path) -> None:
    assert dm035_publisher_root(tmp_path, EMBODIMENT) != dm035_publisher_root(
        tmp_path, "embodiment:33333333-3333-4333-8333-333333333333"
    )
