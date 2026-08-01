"""Regression tests for drill #26 dashboard findings (2026-08-01).

Two live findings from Nico's first dashboard session:

1. Independent mutation intents collided on one Idempotency-Key
   (steward-<digest>): the steward's hours-old stop result replayed for
   nico's dashboard stop — the container never stopped while the audit
   recorded ok. Fix: the key now binds the human turn (per intent).
2. dashboard/prepare for destroy read the steward's token FILE from
   the host (it does not exist) → 502 'clusterd internal:
   FileNotFoundError'. Fix: the dashboard's own bearer token is used.
"""

from clusterd import handlers
from steward_tools import mutations


def _make_plan(op="stop", target="daimon-x", actor="nico"):
    return mutations.MutationPlan(
        operation=op, target=target, impact="stops the instance",
        destructive=False,
        action_digest=mutations.action_digest(op, target, actor, {}),
        created_ms=mutations._now_ms(), ttl_s=120, actor=actor)


class TestIdempotencyKeyPerIntent:
    """drill #26 finding 1: same action, different intents → different
    keys; same intent retried → same key."""

    def test_different_turns_produce_different_keys(self):
        plan = _make_plan()
        h1 = mutations._mutation_headers(plan, "turn-aaa")
        h2 = mutations._mutation_headers(plan, "turn-bbb")
        assert h1["Idempotency-Key"] != h2["Idempotency-Key"]

    def test_same_turn_retries_share_key(self):
        plan = _make_plan()
        h1 = mutations._mutation_headers(plan, "turn-aaa")
        h2 = mutations._mutation_headers(plan, "turn-aaa")
        assert h1["Idempotency-Key"] == h2["Idempotency-Key"]
        assert h1["Idempotency-Key"].startswith("steward-")

    def test_same_action_different_actors_differ(self):
        p_nico = _make_plan(actor="nico")
        p_stew = _make_plan(actor="steward@daimonmatrix")
        h1 = mutations._mutation_headers(p_nico, "t")
        h2 = mutations._mutation_headers(p_stew, "t")
        assert h1["Idempotency-Key"] != h2["Idempotency-Key"]


class TestDashboardPrepareDestroyUsesCallerToken:
    """drill #26 finding 2: destroy prepare must not touch the steward
    token file on the host — the handler must pass a client carrying
    the caller's bearer token."""

    def test_prepare_destroy_passes_scope_token_client(self, monkeypatch,
                                                       tmp_path):
        import types
        captured = {}

        def fake_propose(name, client=None):
            captured["name"] = name
            captured["client"] = client
            return _make_plan(op="destroy", target=name)

        monkeypatch.setattr(mutations, "propose_destroy", fake_propose)
        # any read of the steward token file must raise — the dashboard
        # client must carry the caller's token instead
        monkeypatch.setattr(mutations, "DEFAULT_MUTATE_TOKEN_PATH",
                            str(tmp_path / "no-such-token"))

        ctx = types.SimpleNamespace(scope_token="nico-token-xyz",
                                    request_id="r1", actor="nico")
        deps = types.SimpleNamespace()
        resp = handlers.dashboard_prepare(
            deps, ctx, _body={"operation": "destroy",
                              "target": "daimon-x", "actor": "nico"})
        assert resp.status == 200, resp.body
        client = captured["client"]
        assert isinstance(client, mutations.MutationClient)
        assert client._token() == "nico-token-xyz"  # no file read

    def test_client_without_override_reads_file(self, tmp_path,
                                                monkeypatch):
        """Control: a bare MutationClient DOES hit the token file (the
        original failure mode)."""
        monkeypatch.setattr(mutations, "DEFAULT_MUTATE_TOKEN_PATH",
                            str(tmp_path / "missing"))
        import pytest
        with pytest.raises(FileNotFoundError):
            mutations.MutationClient()._token()
