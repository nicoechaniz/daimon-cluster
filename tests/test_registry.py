"""Embodiment registry tests (M10-R2, docs/design/ontology.md).

The registry is a census and sync directory — NEVER an exclusion
mechanism. These tests pin the ontology in code: plurality of awake
embodiments is normal, cursors order but never refuse, history is
append-only and signed, rollbacks append (the cursor never goes down).
"""

import json

import pytest

from clusterctl.registry import (
    EmbodimentRegistry, RegistryError, RegistryNotFound, REGISTRY_SCHEMA,
)
from clusterctl.signing import InvalidSignature

BEING = "compaii"
EMB_A = "compaii@daimonmatrix"
EMB_B = "compaii@legion"


@pytest.fixture()
def reg(tmp_path):
    return EmbodimentRegistry(tmp_path / "state")


def test_register_first_embodiment(reg):
    entry = reg.register(BEING, EMB_A, "iso-a", "awake", actor="test")
    assert entry["cursor"] == 1
    row = reg.get(BEING, EMB_A)
    assert row["state"] == "awake"
    assert row["body"] == "iso-a"
    assert row["being_root"] == BEING


def test_plurality_is_normal(reg):
    """Two awake embodiments of one being: not a conflict, not a warning —
    just the census doing its job."""
    reg.register(BEING, EMB_A, "iso-a", "awake")
    entry = reg.register(BEING, EMB_B, "iso-b", "awake")
    assert entry["cursor"] == 2
    rows = reg.list_all(BEING)
    awake = [r for r in rows if r["state"] == "awake"]
    assert len(awake) == 2
    assert {r["embodiment"] for r in awake} == {EMB_A, EMB_B}


def test_cursor_is_monotonic_per_being(reg):
    cursors = [
        reg.register(BEING, EMB_A, "iso-a", "awake")["cursor"],
        reg.register(BEING, EMB_A, "iso-a", "parked")["cursor"],
        reg.register(BEING, EMB_A, "iso-a", "awake")["cursor"],
    ]
    assert cursors == [1, 2, 3]
    assert reg.current_cursor(BEING) == 3


def test_cursors_are_independent_across_beings(reg):
    reg.register(BEING, EMB_A, "iso-a", "awake")
    other = reg.register("eko", "eko@daimonmatrix", "iso-e", "awake")
    assert other["cursor"] == 1


def test_set_state_preserves_body(reg):
    reg.register(BEING, EMB_A, "iso-a", "awake")
    entry = reg.set_state(BEING, EMB_A, "parked", manifest="/tmp/m.json")
    assert entry["body"] == "iso-a"
    assert entry["manifest"] == "/tmp/m.json"
    assert reg.get(BEING, EMB_A)["state"] == "parked"


def test_set_state_unknown_embodiment(reg):
    with pytest.raises(RegistryNotFound):
        reg.set_state(BEING, "ghost@nowhere", "parked")


def test_invalid_state_refused(reg):
    with pytest.raises(RegistryError):
        reg.register(BEING, EMB_A, "iso-a", "asleep")


def test_rollback_appends_never_restores(reg):
    """A rollback is a NEW record at cursor+1; history keeps the failed
    transition AND its rollback. The cursor never goes down."""
    reg.register(BEING, EMB_A, "iso-a", "parked")
    reg.register(BEING, EMB_A, "iso-b", "awake")  # transfer attempt
    entry = reg.rollback(BEING, EMB_A, "transfer failed")
    assert entry["state"] == "rolled-back"
    assert entry["cursor"] == 3
    states = [e["state"] for e in reg.history(BEING)
              if e.get("embodiment") == EMB_A]
    assert states == ["parked", "awake", "rolled-back", "rollback-note"]
    assert any("transfer failed" in (e.get("note") or "")
               for e in reg.history(BEING))


def test_history_is_append_only_and_signed(reg, tmp_path):
    reg.register(BEING, EMB_A, "iso-a", "awake")
    reg.register(BEING, EMB_A, "iso-a", "parked")
    hist = reg.history(BEING)
    assert [e["cursor"] for e in hist] == [1, 2]
    # tamper with one entry → verification fails closed
    hpath = tmp_path / "state" / "registry" / f"{BEING}.history.jsonl"
    lines = hpath.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["state"] = "awake-but-mallory"
    lines[0] = json.dumps(entry)
    hpath.write_text("\n".join(lines) + "\n")
    with pytest.raises(InvalidSignature):
        reg.history(BEING)


def test_snapshot_tamper_refused(reg, tmp_path):
    reg.register(BEING, EMB_A, "iso-a", "awake")
    spath = tmp_path / "state" / "registry" / f"{BEING}.json"
    snap = json.loads(spath.read_text())
    snap["embodiments"][EMB_A]["state"] = "parked"  # unsigned edit
    spath.write_text(json.dumps(snap))
    with pytest.raises(InvalidSignature):
        reg.list_all(BEING)


def test_find_across_beings(reg):
    reg.register(BEING, EMB_A, "iso-a", "awake")
    reg.register("eko", "eko@legion", "iso-e", "awake")
    assert reg.find("eko@legion")["being_root"] == "eko"
    assert reg.find("ghost@nowhere") is None


def test_empty_registry_is_empty(reg):
    assert reg.list_all() == []
    assert reg.beings() == []
    assert reg.history("nobody") == []
    assert reg.current_cursor("nobody") == 0


def test_snapshot_schema(reg, tmp_path):
    reg.register(BEING, EMB_A, "iso-a", "awake")
    snap = json.loads(
        (tmp_path / "state" / "registry" / f"{BEING}.json").read_text())
    assert snap["schema"] == REGISTRY_SCHEMA
    assert snap["being_root"] == BEING
    assert "signature" in snap
