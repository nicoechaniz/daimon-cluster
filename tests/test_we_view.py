"""/we dashboard view tests (M10-R7).

The dashboard's "/we — Beings" card is a THIN CLIENT: all semantics
live in clusterctl (the registry census + chain verification + wesync
merge state). GET /v1/registry returns one card per being: being root,
genesis anchor, chain tip cursor, sync state (coherente/mergeando),
experience count, and the embodiment rows with their cursors.

Plurality is normal: two awake embodiments of one being render as two
rows, never as an error.
"""

import json
import types

import pytest

from clusterctl.registry import EmbodimentRegistry
from clusterctl.wesync import WeSync
from clusterd import handlers

BEING = "compaii"


@pytest.fixture()
def state_dir(tmp_path):
    return tmp_path / "state"


def _deps(state_dir):
    return types.SimpleNamespace(state_dir=state_dir, config_path=None)


def _ctx():
    return types.SimpleNamespace(request_id="r1", actor="test",
                                 scope_token=None)


def _seed(state_dir):
    reg = EmbodimentRegistry(state_dir)
    reg.register(BEING, "compaii@daimonmatrix", "daimonmatrix", "awake",
                 actor="test")
    reg.register(BEING, "compaii@legion", "legion", "awake",
                 actor="test")
    WeSync(state_dir).record_experience(
        BEING, "compaii@daimonmatrix", "observation", {"n": 1})
    return reg


def test_empty_census_returns_empty_list(state_dir):
    resp = handlers.list_embodiments(_deps(state_dir), _ctx())
    assert resp.status == 200
    assert resp.body == []


def test_being_card_shape(state_dir):
    _seed(state_dir)
    resp = handlers.list_embodiments(_deps(state_dir), _ctx())
    assert resp.status == 200
    beings = resp.body
    assert len(beings) == 1
    card = beings[0]
    assert card["being_root"] == BEING
    assert card["chain_ok"] is True
    assert card["chain_cursor"] == 2
    assert card["genesis_sha"] and len(card["genesis_sha"]) == 12
    assert card["sync_state"] == "coherente"
    assert card["merge_state"] is None
    assert card["experiences"] == 1

    rows = {(e["embodiment"], e["state"], e["body"], e["cursor"])
            for e in card["embodiments"]}
    # plurality: BOTH awake embodiments listed, never an error
    assert rows == {("compaii@daimonmatrix", "awake", "daimonmatrix", 1),
                    ("compaii@legion", "awake", "legion", 2)}


def test_merge_flag_surfaces_as_mergeando(state_dir):
    _seed(state_dir)
    sync = WeSync(state_dir)
    sync._flag_merge(BEING, "legion", "test")
    resp = handlers.list_embodiments(_deps(state_dir), _ctx())
    card = resp.body[0]
    assert card["sync_state"] == "mergeando"
    assert card["merge_state"]["branch_with"] == "legion"
    # and when the merge completes the card heals
    sync._clear_merge(BEING)
    card = handlers.list_embodiments(_deps(state_dir), _ctx()).body[0]
    assert card["sync_state"] == "coherente"


def test_chain_verification_failure_surfaces(state_dir):
    _seed(state_dir)
    # corrupt one entry's signature
    hist = state_dir / "registry" / f"{BEING}.history.jsonl"
    lines = hist.read_text().splitlines()
    entry = json.loads(lines[-1])
    entry["signature"] = "0" * 64
    lines[-1] = json.dumps(entry)
    hist.write_text("\n".join(lines) + "\n")
    card = handlers.list_embodiments(_deps(state_dir), _ctx()).body[0]
    assert card["chain_ok"] is False


def test_dashboard_html_contains_we_card():
    resp = handlers.dashboard(types.SimpleNamespace(), _ctx())
    assert resp.status == 200
    html = resp.body if isinstance(resp.body, str) else resp.body.decode()
    assert 'id="we-card"' in html
    assert 'hx-get="/v1/registry"' in html
    assert "renderWe" in html
