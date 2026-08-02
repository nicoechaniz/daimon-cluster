"""Chain of existence tests (M10-R3, docs/design/ontology.md).

The invariant made checkable: ONE INTERFERENCE PATTERN = common root
(genesis_sha) + unbroken path (prev links, increasing cursors) +
coherence by sync (segment export against a peer high-water mark).

Covers: genesis anchoring, unbroken-path verification, tamper detection
(link break, genesis_sha swap, cursor regression, wrong being_root),
segment export by cursor, cross-chain common-root verification, and an
end-to-end lifecycle chain built by park → wake → transfer (the R2
machinery — CAS conserved, repurposed as cursor/registry appends).
"""

import json

import pytest

from clusterctl import park, registry, transfer
from clusterctl.adapters import FakeAdapter
from clusterctl.config import Config
from clusterctl.signing import _canonical, _sha256_hex

from test_park import DAIMON_ID, NAME, _exec_handler, _write_spec
from test_transfer import BEING, NEW, _parked, _reg


@pytest.fixture()
def state_dir(tmp_path):
    return tmp_path / "state"


@pytest.fixture()
def cfg(state_dir):
    return Config(host_id="test-host", incus_project="default",
                  managed_prefix="", profile="tribe-agent",
                  state_dir=str(state_dir))


@pytest.fixture()
def adapter():
    return FakeAdapter(
        instances=[{"name": NAME, "state": "running",
                    "image_version": "tribe-base/test", "budgets": {},
                    "uptime_s": 5}],
        exec_handler=_exec_handler)


def _rewrite_history(state_dir, being, mutate):
    """Rewrite a history file applying ``mutate(entry, index)`` to each
    entry — simulating a tampered chain (no re-signing: signature checks
    happen in history(); these tests target the LINK layer, so mutate
    must keep signatures valid... it cannot. Use the helper only with
    a fresh FakeSigner re-sign)."""
    path = state_dir / "registry" / f"{being}.history.jsonl"
    entries = [json.loads(line) for line in path.read_text().splitlines()]
    signer = registry.FakeSigner()
    out = []
    for i, e in enumerate(entries):
        e = {k: v for k, v in e.items() if k != "signature"}
        e = mutate(e, i)
        e["signature"] = signer.sign(_canonical(e))
        out.append(json.dumps(e, separators=(",", ":")))
    path.write_text("\n".join(out) + "\n")


# ---------------------------------------------------------------------------
# genesis + unbroken path
# ---------------------------------------------------------------------------

def test_genesis_anchor_and_unbroken_path(state_dir):
    reg = _reg(state_dir)
    reg.register(BEING, DAIMON_ID, NAME, "awake")
    reg.register(BEING, DAIMON_ID, NAME, "parked")
    reg.register(BEING, DAIMON_ID, NAME, "awake")

    result = reg.verify_chain(BEING)
    assert result["ok"] is True
    assert result["length"] == 3
    assert result["cursor"] == 3
    assert result["genesis_sha"]

    entries = reg.history(BEING)
    assert entries[0]["prev_sha256"] is None
    for prev, entry in zip(entries, entries[1:]):
        assert entry["prev_sha256"] == _sha256_hex(_canonical(prev))
        assert entry["genesis_sha"] == result["genesis_sha"]


def test_genesis_anchor_is_reproducible(state_dir):
    """Any verifier can recompute the genesis self-anchor from the
    on-disk entry alone."""
    reg = _reg(state_dir)
    reg.register(BEING, DAIMON_ID, NAME, "awake")
    genesis = reg.history(BEING)[0]
    recomputed = _sha256_hex(_canonical(
        {k: v for k, v in genesis.items()
         if k not in ("signature", "genesis_sha")}))
    assert genesis["genesis_sha"] == recomputed


# ---------------------------------------------------------------------------
# tamper detection
# ---------------------------------------------------------------------------

def test_broken_prev_link_detected(state_dir):
    reg = _reg(state_dir)
    for state in ("awake", "parked", "awake"):
        reg.register(BEING, DAIMON_ID, NAME, state)

    def mutate(e, i):
        if i == 2:
            e["prev_sha256"] = "0" * 64  # forged link
        return e
    _rewrite_history(state_dir, BEING, mutate)

    result = _reg(state_dir).verify_chain(BEING)
    assert result["ok"] is False
    assert "broken prev link" in result["error"]


def test_genesis_sha_swap_detected(state_dir):
    reg = _reg(state_dir)
    reg.register(BEING, DAIMON_ID, NAME, "awake")
    reg.register(BEING, DAIMON_ID, NAME, "parked")

    def mutate(e, i):
        if i == 1:
            e["genesis_sha"] = "f" * 64  # claims a different root
        return e
    _rewrite_history(state_dir, BEING, mutate)

    result = _reg(state_dir).verify_chain(BEING)
    assert result["ok"] is False
    assert "genesis_sha changed" in result["error"]


def test_cursor_regression_detected(state_dir):
    reg = _reg(state_dir)
    reg.register(BEING, DAIMON_ID, NAME, "awake")
    reg.register(BEING, DAIMON_ID, NAME, "parked")

    def mutate(e, i):
        if i == 1:
            e["cursor"] = 1  # regression (also breaks nothing else)
        return e
    _rewrite_history(state_dir, BEING, mutate)

    result = _reg(state_dir).verify_chain(BEING)
    assert result["ok"] is False
    assert "cursor not increasing" in result["error"]


def test_wrong_being_root_detected(state_dir):
    reg = _reg(state_dir)
    reg.register(BEING, DAIMON_ID, NAME, "awake")
    # a chain file claiming root "mallory" whose genesis says "daimon-x"
    src = state_dir / "registry" / f"{BEING}.history.jsonl"
    dst = state_dir / "registry" / "mallory.history.jsonl"
    dst.write_text(src.read_text())
    result = reg.verify_chain("mallory")
    assert result["ok"] is False
    assert "different being_root" in result["error"]
    # and verifying a root with no chain at all refuses cleanly
    assert reg.verify_chain("nobody")["error"] == "empty chain"


def test_empty_chain_not_ok(state_dir):
    result = _reg(state_dir).verify_chain(BEING)
    assert result["ok"] is False
    assert result["error"] == "empty chain"


# ---------------------------------------------------------------------------
# segment export (the /we.sync primitive)
# ---------------------------------------------------------------------------

def test_segment_export_by_cursor(state_dir):
    reg = _reg(state_dir)
    reg.register(BEING, DAIMON_ID, NAME, "awake")          # 1
    reg.register(BEING, DAIMON_ID, NAME, "parked")         # 2
    reg.register(BEING, DAIMON_ID, NAME, "awake")          # 3

    assert [e["cursor"] for e in reg.segment(BEING, 0)] == [1, 2, 3]
    assert [e["cursor"] for e in reg.segment(BEING, 2)] == [3]
    assert reg.segment(BEING, 3) == []
    # a segment carries the chain context (genesis_sha on every entry)
    seg = reg.segment(BEING, 1)
    assert all(e["genesis_sha"] == reg.verify_chain(BEING)["genesis_sha"]
               for e in seg)


# ---------------------------------------------------------------------------
# common root across chains
# ---------------------------------------------------------------------------

def test_common_root_positive_and_negative(state_dir, tmp_path):
    reg_a = _reg(state_dir)
    reg_a.register(BEING, DAIMON_ID, NAME, "awake")
    reg_a.register(BEING, DAIMON_ID, NAME, "parked")

    # a second host's copy of the SAME being's chain (same genesis)
    other_dir = tmp_path / "other-state"
    reg_b = registry.EmbodimentRegistry(other_dir)
    chain = reg_a.history(BEING)
    hpath = other_dir / "registry" / f"{BEING}.history.jsonl"
    hpath.parent.mkdir(parents=True, exist_ok=True)
    hpath.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n"
                             for e in chain))
    reg_b.register(BEING, "compaii@legion", "legion-host", "awake")

    assert registry.verify_common_root(reg_a.history(BEING),
                                       reg_b.history(BEING)) is True
    # ...and the other host derives its snapshot from the received chain,
    # appends at the RIGHT next cursor, and the extended chain verifies
    row = reg_b.get(BEING, "compaii@legion")
    assert row["cursor"] == 3
    assert reg_b.verify_chain(BEING)["ok"] is True

    # a DIFFERENT being has a different genesis
    reg_a.register("eko", "eko@daimonmatrix", "iso-e", "awake")
    assert registry.verify_common_root(reg_a.history(BEING),
                                       reg_a.history("eko")) is False
    assert registry.verify_common_root([], reg_a.history(BEING)) is False


# ---------------------------------------------------------------------------
# end-to-end: the lifecycle writes the chain (R2 machinery, R3 semantics)
# ---------------------------------------------------------------------------

def test_lifecycle_writes_a_verifiable_chain(state_dir, cfg, adapter):
    """park → wake → transfer append to the being's chain; every
    transition is a cursor/registry append (the conserved CAS
    machinery); the whole chain verifies."""
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)                     # awake=1, parked=2
    transfer.run_wake(NAME, cfg, adapter, actor="test")  # awake=3
    park.run_park(NAME, cfg, adapter, actor="test")      # parked=4
    transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")  # awake=5

    reg = _reg(state_dir)
    result = reg.verify_chain(BEING)
    assert result["ok"] is True
    assert result["cursor"] == 5
    entries = reg.history(BEING)
    assert [(e["cursor"], e["state"]) for e in entries] == [
        (1, "awake"), (2, "parked"), (3, "awake"),
        (4, "parked"), (5, "awake")]
    # the relocation is one embodiment moving bodies — chain continuity,
    # not a new identity
    assert entries[4]["embodiment"] == DAIMON_ID
    assert entries[4]["body"] == NEW
    assert all(e["embodiment"] == DAIMON_ID for e in entries)
    # and the final row agrees with the chain tip
    row = reg.get(BEING, DAIMON_ID)
    assert row["state"] == "awake"
    assert row["body"] == NEW
    assert row["cursor"] == result["cursor"]
