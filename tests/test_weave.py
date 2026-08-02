import copy
import json
import uuid
from pathlib import Path

import pytest

from weave.fanout import RequestHandler, request
from weave.ledger import Ledger, WeaveError
from weave.protocol import (
    BeingManifest,
    EventSigner,
    ProtocolError,
    canonical_json,
    validate_event,
)


def ref(prefix):
    return f"{prefix}:{uuid.uuid4()}"


@pytest.fixture()
def setup_weave(tmp_path):
    emb_a, emb_b = ref("embodiment"), ref("embodiment")
    manifest = BeingManifest.from_value(
        {
            "schema": "being-manifest/v1",
            "being_ref": ref("being"),
            "revision": 1,
            "embodiments": sorted(
                [
                    {"embodiment_id": emb_a, "principal_id": "compaii@legion", "body_ref": "cluster:legion:compaii", "status": "active"},
                    {"embodiment_id": emb_b, "principal_id": "compaii@daimonmatrix", "body_ref": "cluster:daimonmatrix:compaii", "status": "active"},
                ],
                key=lambda row: row["embodiment_id"],
            ),
        }
    )
    signer_a, signer_b = EventSigner.generate("legion/sig/1"), EventSigner.generate("daimonmatrix/sig/1")
    public_keys = {signer_a.kid: signer_a.public_key_text, signer_b.kid: signer_b.public_key_text}
    origin_a = {"embodiment_id": emb_a, "incarnation_id": ref("incarnation"), "principal_id": "compaii@legion", "body_ref": "cluster:legion:compaii"}
    origin_b = {"embodiment_id": emb_b, "incarnation_id": ref("incarnation"), "principal_id": "compaii@daimonmatrix", "body_ref": "cluster:daimonmatrix:compaii"}
    a = Ledger(tmp_path / "a.db", manifest=manifest, local_origin=origin_a, public_keys=public_keys)
    b = Ledger(tmp_path / "b.db", manifest=manifest, local_origin=origin_b, public_keys=public_keys)
    return manifest, signer_a, signer_b, origin_a, origin_b, a, b


def test_independent_ledgers_preview_pull_and_local_adoption(setup_weave):
    _, signer_a, signer_b, _, _, a, b = setup_weave
    experience = b.append_local(kind="experience.observed", subject="deployment", payload={"summary": "live drill passed"}, signer=signer_b)
    proposal = b.append_local(kind="configuration.proposed", subject="github.identity", payload={"email": "compaii@daimonmatrix", "secret_slot_ref": "github/daimonmatrix"}, signer=signer_b)

    page = b.delta({})
    assert a.preview(page)["missing"] == 2
    assert a.events() == []
    assert a.ingest(page, source="compaii@daimonmatrix")["missing"] == 2
    assert a.ingest(page, source="compaii@daimonmatrix")["missing"] == 0
    assert [item["state"] for item in a.diff()] == ["pending", "pending"]

    decision = a.append_local(
        kind="adoption.decided", subject="github.identity",
        payload={"target_event_id": proposal["event_id"], "decision": "adopt", "reason": "chosen locally"},
        supersedes=None, signer=signer_a,
    )
    states = {item["event_id"]: item["state"] for item in a.diff()}
    assert states[experience["event_id"]] == "pending"
    assert states[proposal["event_id"]] == "adopted"
    assert b.diff(subject="github.identity")[0]["state"] == "pending"

    a.append_local(
        kind="adoption.decided", subject="github.identity",
        payload={"target_event_id": proposal["event_id"], "decision": "revert", "reason": "changed mind"},
        supersedes=decision["event_id"], signer=signer_a,
    )
    assert a.diff(subject="github.identity")[0]["state"] == "reverted"
    assert a.novelty_summary() == {
        "total": 2,
        "by_kind": {"configuration.proposed": 1, "experience.observed": 1},
        "by_origin": {"compaii@daimonmatrix": 2},
        "by_state": {"pending": 1, "reverted": 1},
    }


def test_manifest_mismatch_and_secret_values_fail_closed(setup_weave):
    manifest, _, signer_b, _, origin_b, a, _ = setup_weave
    other = copy.deepcopy(manifest.value)
    other["revision"] = 2
    other_manifest = BeingManifest.from_value(other)
    foreign = Ledger(a.path.parent / "foreign.db", manifest=other_manifest, local_origin=origin_b, public_keys={signer_b.kid: signer_b.public_key_text})
    event = foreign.append_local(kind="preference.proposed", subject="voice", payload={"value": "quiet"}, signer=signer_b)
    with pytest.raises(ProtocolError, match="manifest_hash_mismatch"):
        a.preview([event])
    with pytest.raises(ProtocolError, match="secret_value_forbidden"):
        foreign.append_local(kind="configuration.proposed", subject="github", payload={"api_token": "do-not-sync"}, signer=signer_b)


def test_gap_equivocation_and_batch_atomicity(setup_weave):
    _, _, signer_b, _, _, a, b = setup_weave
    first = b.append_local(kind="experience.observed", subject="one", payload={"value": 1}, signer=signer_b)
    second = b.append_local(kind="experience.observed", subject="two", payload={"value": 2}, signer=signer_b)
    with pytest.raises(WeaveError, match="gap"):
        a.ingest([second], source="compaii@daimonmatrix")
    assert a.peer_sync_states()[0]["state"] == "gap"
    assert a.events() == []
    a.ingest([first, second], source="compaii@daimonmatrix")
    assert a.peer_sync_states()[0]["state"] == "coherent"
    assert a.peer_sync_states()[0]["error"] is None
    tampered = copy.deepcopy(first)
    tampered["payload"]["value"] = "tampered"
    with pytest.raises(ProtocolError, match="content_hash_mismatch"):
        a.ingest([tampered], source="compaii@daimonmatrix")
    assert a.peer_sync_states()[0]["state"] == "quarantined"
    a.ingest([first, second], source="compaii@daimonmatrix")
    assert a.peer_sync_states()[0]["state"] == "coherent"
    conflicting = copy.deepcopy(second)
    conflicting["event_id"] = str(uuid.uuid4())
    with pytest.raises((ProtocolError, WeaveError)):
        a.preview([conflicting])


def test_live_we_fanout_preserves_origin_and_deduplicates(setup_weave):
    manifest, _, _, origin_a, origin_b, _, _ = setup_weave
    value = request(manifest, origin_a, {"prompt": "what changed?"}, now_ms=1_000)
    handler = RequestHandler(manifest, origin_b)
    first = handler.handle(value, lambda content: {"answer": content["prompt"]}, now_ms=2_000)
    second = handler.handle(value, lambda _: pytest.fail("duplicate executed"), now_ms=2_100)
    assert first == second
    assert first["origin"] == origin_b
    assert first["request_id"] == value["request_id"]


def test_partitioned_embodiments_merge_without_losing_origin(setup_weave):
    _, signer_a, signer_b, origin_a, origin_b, a, b = setup_weave
    # Partition: both embodiments append independently.
    a.append_local(kind="experience.observed", subject="legion-only", payload={"summary": "saw rain"}, signer=signer_a)
    b.append_local(kind="experience.observed", subject="matrix-one", payload={"summary": "deployed"}, signer=signer_b)
    b.append_local(kind="skill.proposed", subject="matrix-two", payload={"summary": "learned recovery"}, signer=signer_b)

    # Interrupted heal: A receives only the first contiguous B event.
    first_page = b.delta({}, limit=1)
    a.ingest(first_page, source="compaii@daimonmatrix")
    a_head_map = {head["incarnation_id"]: head["max_sequence"] for head in a.heads()}
    a.ingest(b.delta(a_head_map), source="compaii@daimonmatrix")
    assert max(row["sequence"] for row in a.peer_cursors("compaii@daimonmatrix")) == 2

    # B receives A's complete branch; re-sync is idempotent.
    b_head_map = {head["incarnation_id"]: head["max_sequence"] for head in b.heads()}
    b.ingest(a.delta(b_head_map), source="compaii@legion")
    assert a.ingest(b.delta({}), source="resync")["missing"] == 0

    a_events = {event["event_id"]: event for event in a.events()}
    b_events = {event["event_id"]: event for event in b.events()}
    assert set(a_events) == set(b_events)
    assert {event["origin"]["embodiment_id"] for event in a_events.values()} == {
        origin_a["embodiment_id"], origin_b["embodiment_id"]
    }
    assert a.path != b.path
    assert signer_a.public_key_text != signer_b.public_key_text


def test_manifest_hash_is_canonical_and_members_are_sorted():
    first, second = ref("embodiment"), ref("embodiment")
    rows = [
        {"embodiment_id": first, "principal_id": "a", "body_ref": "one", "status": "active"},
        {"embodiment_id": second, "principal_id": "b", "body_ref": "two", "status": "active"},
    ]
    rows.sort(key=lambda row: row["embodiment_id"])
    value = {"schema": "being-manifest/v1", "being_ref": ref("being"), "revision": 1, "embodiments": rows}
    manifest = BeingManifest.from_value(json.loads(canonical_json(value)))
    assert len(manifest.digest) == 64
    with pytest.raises(ProtocolError, match="not_sorted"):
        BeingManifest.from_value({**value, "embodiments": list(reversed(rows))})


def test_accepts_daimon_matrix_golden_vector():
    root = Path(__file__).parent / "fixtures" / "matrix-weave-v1"
    index = json.loads((root / "index.json").read_text(encoding="utf-8"))
    manifest = BeingManifest.load(root / index["manifest"])
    assert manifest.digest == index["manifest_hash"]
    event = json.loads((root / index["valid_events"][0]).read_text(encoding="utf-8"))
    assert validate_event(event, manifest, index["public_keys"])["content_hash"] == event["content_hash"]
