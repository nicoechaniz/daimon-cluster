"""Partition + coherent-merge tests (M10-R6) — the re-imagined split-brain.

The old split-brain test asked: "two bodies claim one identity → the
stale one is rejected". Under the M10 ontology that question is a
misconception: plurality is normal and both branches of a partition
REALLY HAPPENED. The test of fire is: partitioned embodiments branch
their chains, and when the partition heals the branches CONVERGE —
nothing erased, nothing excluded, one woven chain on both sides.
"""

import json

import pytest

from clusterctl import registry, wesync
from clusterctl.signing import _canonical, _sha256_hex

from test_wesync import BEING, EMB_A, EMB_B, _seed_both


@pytest.fixture()
def host_a(tmp_path):
    return tmp_path / "host-a"


@pytest.fixture()
def host_b(tmp_path):
    return tmp_path / "host-b"


def _partition(a, b):
    """Both sides append chain transitions INDEPENDENTLY (the partition).
    A parks its embodiment; B parks its own; each adds a second
    transition. Same cursors, different content — two true branches."""
    a.registry.set_state(BEING, EMB_A, "parked", actor="a-partition")   # 3a
    a.registry.set_state(BEING, EMB_A, "awake", actor="a-partition")    # 4a
    b.registry.set_state(BEING, EMB_B, "parked", actor="b-partition")   # 3b
    b.registry.set_state(BEING, EMB_B, "awake", actor="b-partition")    # 4b
    a.record_experience(BEING, EMB_A, "observation", {"side": "a"})
    b.record_experience(BEING, EMB_B, "observation", {"side": "b"})


def test_partition_then_coherent_merge(host_a, host_b):
    a, b = _seed_both(host_a, host_b)
    _partition(a, b)

    # heal: full-chain bundles cross in both directions; import flags
    # the branch on both sides (never a silent winner)
    bundle_ab = a.export_bundle(BEING, EMB_A)   # full chain
    bundle_ba = b.export_bundle(BEING, EMB_B)
    rep_b = b.import_bundle(bundle_ab)
    rep_a = a.import_bundle(bundle_ba)
    assert rep_b["branch"] is True and rep_a["branch"] is True
    assert b.merge_state(BEING) is not None
    assert a.merge_state(BEING) is not None
    # experiences already converged on both sides during import
    assert len(a.experiences(BEING)) == len(b.experiences(BEING)) == 3

    # THE MERGE — both sides compute it independently
    merge_a = a.merge_branch(BEING, bundle_ba)
    merge_b = b.merge_branch(BEING, bundle_ab)

    # deterministic: same divergence, same base, same tip
    assert merge_a["divergence"] == merge_b["divergence"] == 3
    assert merge_a["base_sha"] == merge_b["base_sha"]
    assert merge_a["tip_cursor"] == merge_b["tip_cursor"]
    assert merge_a["base"] != merge_b["base"]  # perspective differs...
    # ...but the CHAINS are byte-identical
    chain_a = a.registry.history(BEING)
    chain_b = b.registry.history(BEING)
    assert [json.dumps(e, sort_keys=True) for e in chain_a] == \
           [json.dumps(e, sort_keys=True) for e in chain_b]

    # nothing was erased: all four partitioned transitions survive —
    # two as base entries, two as merged_entry payloads
    states = [e["state"] for e in chain_a]
    assert states[:2] == ["awake", "awake"]          # shared prefix
    base_states = [e["state"] for e in chain_a[2:4]]
    assert base_states == ["parked", "awake"]        # the winning branch
    merged = [e for e in chain_a if e["state"] == "merged"]
    assert len(merged) == 2                          # the losing branch
    merged_actors = {e["merged_entry"]["actor"] for e in merged}
    assert merged_actors == {"a-partition", "b-partition"} - {
        chain_a[2]["actor"], chain_a[3]["actor"]}
    assert chain_a[-1]["state"] == "merge-record"
    assert chain_a[-1]["base_sha"] == merge_a["base_sha"]

    # both chains verify; common root intact; flags cleared
    for host in (a, b):
        assert host.registry.verify_chain(BEING)["ok"] is True
        assert host.merge_state(BEING) is None
    assert registry.verify_common_root(chain_a, chain_b) is True

    # the census follows the base chain (merged records are history)
    row_a = a.registry.get(BEING, EMB_A)
    row_b = a.registry.get(BEING, EMB_B)
    assert row_a["state"] != "merged" and row_b["state"] != "merged"

    # post-merge sync is a clean no-op on chain, converged experiences
    bundle2 = a.export_bundle(BEING, EMB_A)
    rep = b.import_bundle(bundle2)
    assert rep["branch"] is False
    assert rep["chain_appended"] == 0


def test_merge_is_idempotent(host_a, host_b):
    a, b = _seed_both(host_a, host_b)
    _partition(a, b)
    bundle_ba = b.export_bundle(BEING, EMB_B)
    a.import_bundle(bundle_ba)
    first = a.merge_branch(BEING, bundle_ba)
    assert first["merged"] == 2
    tip_before = _sha256_hex(_canonical(a.registry.history(BEING)[-1]))
    # a second merge against the same bundle: no divergence remains
    second = a.merge_branch(BEING, bundle_ba)
    assert second["merged"] == 0
    tip_after = _sha256_hex(_canonical(a.registry.history(BEING)[-1]))
    assert tip_before == tip_after


def test_merge_requires_full_chain_when_local_loses(host_a, host_b):
    """A partial bundle cannot rebuild a losing local chain."""
    a, b = _seed_both(host_a, host_b)
    _partition(a, b)
    # partial bundle: only B's tail (cursors 3-4), not the full chain
    partial = b.export_bundle(BEING, EMB_B,
                              {"chain_cursor": 2, "experiences": {}})
    a.import_bundle(partial)
    # determine which side loses; if A loses, merge must refuse cleanly
    mine = a.registry.history(BEING)[2]
    remote = partial["chain_segment"][0]
    from clusterctl.wesync import _strip
    mine_sha = _sha256_hex(_canonical(_strip(mine)))
    remote_sha = _sha256_hex(_canonical(_strip(remote)))
    if mine_sha > remote_sha:  # local loses → needs the full chain
        with pytest.raises(wesync.WeSyncError, match="full-chain"):
            a.merge_branch(BEING, partial)
    else:  # local wins → partial is enough
        report = a.merge_branch(BEING, partial)
        assert report["merged"] == 2
