"""H4 acceptance: honest observations, bounded pages, and sync semantics."""

from __future__ import annotations

import json

import yaml

from clusterctl import audit
from clusterctl.adapters import FakeAdapter
from clusterctl.embodiments import Registry
from clusterctl.fences import ResourceFenceStore
from clusterctl.inventory import InstanceSpec, reconcile
from clusterd import handlers, paging

EMBODIMENT = "embodiment:11111111-1111-4111-8111-111111111111"
INCARNATION = "incarnation:22222222-2222-4222-8222-222222222222"


def _ctx(owner: str = "*") -> handlers.RequestContext:
    return handlers.RequestContext(
        request_id="request:h4",
        actor="reader",
        scope_token=None,
        token_record={"owner": owner},
    )


def _spec(state_dir, name: str, owner: str, embodiment_id: str | None = None):
    path = state_dir / "instances" / f"{name}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({
        "schema": "instance-spec/v1",
        "name": name,
        "species": "test",
        "image_version": "v1",
        "budgets": {},
        "created_by": owner,
        "embodiment_id": embodiment_id,
        "current_incarnation_id": INCARNATION if embodiment_id else None,
    }), encoding="utf-8")


def test_inventory_keeps_declared_runtime_and_identity_observations_separate():
    spec = InstanceSpec(
        name="daimon-a", species="test", image_version="v1",
        budgets={"cpu": 1, "memory_mib": None, "disk_gib": None},
        created_ms=1, created_by="alice", body_ref="body:a",
        embodiment_id=EMBODIMENT, current_incarnation_id=INCARNATION,
    )
    stopped = reconcile(
        {spec.name: spec},
        FakeAdapter(instances=[{
            "name": spec.name, "state": "stopped", "image_version": "v1",
            "budgets": {"cpu": 2}, "uptime_s": None,
        }]),
        "host-a",
    )[0]
    assert stopped["state"] == "drifted"
    assert stopped["observations"]["declared"]["state"] == "declared"
    assert stopped["observations"]["runtime"]["state"] == "stopped"
    assert stopped["observations"]["embodiment"]["state"] == "unavailable"
    assert stopped["observations"]["matrix_process"]["state"] == "unavailable"

    missing = reconcile({spec.name: spec}, FakeAdapter(), "host-a")[0]
    assert missing["state"] == "missing"
    assert missing["observations"]["runtime"] == {
        "state": "missing",
        "present": False,
        "observed_at_ms": missing["observed_at_ms"],
    }


def test_instance_pages_are_owner_scoped_and_cursor_is_scope_bound(tmp_path):
    _spec(tmp_path, "alice-one", "alice")
    _spec(tmp_path, "bob-one", "bob")
    adapter = FakeAdapter(instances=[
        {"name": "alice-one", "state": "running", "image_version": "v1",
         "budgets": {}, "uptime_s": 1},
        {"name": "bob-one", "state": "running", "image_version": "v1",
         "budgets": {}, "uptime_s": 1},
        {"name": "undeclared", "state": "running", "image_version": "v1",
         "budgets": {}, "uptime_s": 1},
    ])
    deps = handlers.Deps(
        config_path="configs/clusterctl.yaml", state_dir=str(tmp_path),
        adapter_factory=lambda: adapter,
    )
    response = handlers.list_instances(
        deps, _ctx("alice"), query={"limit": ["1"]}
    )
    assert response.status == 200
    assert [row["name"] for row in response.body["items"]] == ["alice-one"]
    assert response.body["page"]["has_more"] is False

    # A wildcard snapshot cannot be resumed under a narrower owner scope.
    wildcard = handlers.list_instances(
        deps, _ctx("*"), query={"limit": ["1"]}
    ).body
    denied = handlers.list_instances(
        deps,
        _ctx("alice"),
        query={"limit": ["1"], "cursor": [wildcard["page"]["next_cursor"]]},
    )
    assert denied.status == 400
    assert denied.body["error"] == "cursor-scope-mismatch"


def test_audit_snapshot_has_no_skips_or_duplicates_during_append(tmp_path):
    for index in range(4):
        audit.append_event(
            tmp_path, actor="reader", action="observe",
            target=f"daimon-{index}", result="ok",
        )
    deps = handlers.Deps(config_path="unused", state_dir=str(tmp_path))
    first = handlers.audit_tail(
        deps, _ctx(), query={"limit": ["2"]}
    ).body
    audit.append_event(
        tmp_path, actor="writer", action="append-after-snapshot",
        target="newer", result="ok",
    )
    second = handlers.audit_tail(
        deps,
        _ctx(),
        query={"limit": ["2"], "cursor": [first["page"]["next_cursor"]]},
    ).body
    ids = [row["event_id"] for row in first["items"] + second["items"]]
    assert len(ids) == len(set(ids)) == 4
    assert all(row["action"] != "append-after-snapshot"
               for row in first["items"] + second["items"])
    assert second["page"]["snapshot_id"] == first["page"]["snapshot_id"]


def test_invalid_and_expired_cursors_fail_closed():
    clock = [10.0]
    pager = paging.SnapshotPager(ttl_s=1, monotonic=lambda: clock[0])
    binding = pager.binding("test", "*")
    first = pager.first(
        [{"n": 1}, {"n": 2}], binding=binding, limit=1,
        observed_at_ms=1,
    )
    cursor = first["page"]["next_cursor"]
    try:
        pager.resume(cursor + "x", binding=binding, limit=1)
    except paging.CursorError as exc:
        assert exc.reason == "invalid-cursor"
        assert exc.stale is False
    else:  # pragma: no cover
        raise AssertionError("tampered cursor accepted")
    clock[0] = 12.0
    try:
        pager.resume(cursor, binding=binding, limit=1)
    except paging.CursorError as exc:
        assert exc.reason == "stale-cursor"
        assert exc.stale is True
    else:  # pragma: no cover
        raise AssertionError("expired cursor accepted")


def test_read_endpoint_maps_tampered_and_stale_cursors_to_safe_http_errors(tmp_path):
    clock = [10.0]
    pager = paging.SnapshotPager(ttl_s=1, monotonic=lambda: clock[0])
    deps = handlers.Deps(
        config_path="unused", state_dir=str(tmp_path), pager=pager
    )
    for index in range(2):
        audit.append_event(
            tmp_path, actor="reader", action="observe",
            target=f"daimon-{index}", result="ok",
        )
    first = handlers.audit_tail(
        deps, _ctx(), query={"limit": ["1"]}
    ).body
    cursor = first["page"]["next_cursor"]
    invalid = handlers.audit_tail(
        deps, _ctx(), query={"limit": ["1"], "cursor": [cursor + "x"]}
    )
    assert invalid.status == 400
    assert invalid.body["error"] == "invalid-cursor"
    clock[0] = 12.0
    stale = handlers.audit_tail(
        deps, _ctx(), query={"limit": ["1"], "cursor": [cursor]}
    )
    assert stale.status == 409
    assert stale.body["error"] == "stale-cursor"


class _MatrixClient:
    def __init__(
        self, *, integrity="ok", incomplete=0, pending=0,
        peer_availability="available", differences=0, partial=False,
    ):
        self.integrity = integrity
        self.incomplete = incomplete
        self.pending = pending
        self.peer_availability = peer_availability
        self.differences = differences
        self.partial = partial

    @staticmethod
    def _response(value):
        return {}, {"ok": True, "result": value}

    def runtime_status(self):
        return self._response({
            "schema": "dm.runtime.status/v1",
            "integrity": self.integrity,
            "ledger_schema_version": 3,
            "counts": {
                "known_events": 10,
                "incomplete_events": self.incomplete,
                "pending_rpc": self.pending,
            },
            "authority_epoch": {},
        })

    def scope_me(self):
        return self._response({
            "schema": "dm.scope.me/v1",
            "being_ref": "being:test",
            "manifest_hash": "a" * 64,
            "evaluated_at_ms": 1,
            "body": {"state": "running"},
            "heads": {},
            "effective": {"schema": "dm.we.projection/v1", "entries": []},
        })

    def scope_we(self):
        return self._response({
            "schema": "dm.scope.we/v1",
            "embodiments": [
                {"embodiment_id": EMBODIMENT, "availability": "local"},
                {"embodiment_id": "embodiment:peer",
                 "availability": self.peer_availability},
            ],
            "partial": self.partial,
        })

    def scope_diff(self):
        return self._response({
            "schema": "dm.scope.we-diff/v1",
            "entries": [
                {
                    "event_id": f"event:{index}", "state": "pending",
                    "kind": "claim", "subject": f"subject:{index}",
                    "payload": {"secret": index},
                }
                for index in range(self.differences)
            ],
            "origin_summaries": [],
        })

    def scope_sync_plan(self, params):
        return self._response({
            "schema": "dm.scope.sync-plan/v1",
            "plan_id": params["request_id"],
            "targets": [],
            "partial": self.partial,
        })


def _matrix_deps(tmp_path, client):
    registry = Registry(tmp_path)
    registry.register(body_ref="body:test", embodiment_id=EMBODIMENT)
    registry.start(EMBODIMENT, incarnation_id=INCARNATION)
    return handlers.Deps(
        config_path="unused", state_dir=str(tmp_path),
        matrix_client_factory=lambda _identifier: client,
    )


def _matrix_row(tmp_path, client):
    response = handlers.weave_status(_matrix_deps(tmp_path, client), _ctx())
    assert response.status == 200
    return response.body["embodiments"][0]


def test_matrix_local_corruption_peer_offline_peer_behind_and_caught_up_are_distinct(
    tmp_path,
):
    corrupt = _matrix_row(tmp_path / "corrupt", _MatrixClient(integrity="corrupt"))
    assert corrupt["owner_local"]["ledger_integrity"] == "corrupt"
    assert corrupt["peer_sync"]["caught_up"] == {
        "state": "unknown", "reason": "owner-local-ledger-not-ok",
    }
    assert corrupt["alerts"][0]["code"] == "owner-local-ledger-not-ok"

    offline = _matrix_row(
        tmp_path / "offline", _MatrixClient(peer_availability="offline")
    )
    assert offline["owner_local"]["queue"]["state"] == "clean"
    assert offline["peer_sync"]["reachability"]["state"] == "offline"
    assert offline["peer_sync"]["caught_up"]["state"] == "unknown"
    assert any(alert["code"] == "peer-offline" for alert in offline["alerts"])

    behind = _matrix_row(tmp_path / "behind", _MatrixClient(differences=1))
    assert behind["owner_local"]["queue"]["state"] == "clean"
    assert behind["peer_sync"]["reachability"]["state"] == "available"
    assert behind["peer_sync"]["known_difference_count"] == 1
    assert behind["peer_sync"]["caught_up"] == {
        "state": "no", "reason": "known-differences",
    }
    assert any(
        alert["code"] == "known-peer-differences" for alert in behind["alerts"]
    )

    caught_up = _matrix_row(tmp_path / "caught-up", _MatrixClient())
    assert caught_up["peer_sync"]["caught_up"] == {
        "state": "yes", "reason": "all-observed-peers-caught-up",
    }


def test_matrix_differences_are_redacted_bounded_and_stably_paginated(tmp_path):
    deps = _matrix_deps(tmp_path, _MatrixClient(differences=450))
    first = handlers.weave_differences(
        deps, _ctx(), query={
            "embodiment_id": [EMBODIMENT], "limit": ["200"],
        },
    )
    assert first.status == 200
    assert len(first.body["items"]) == 200
    assert "payload" not in json.dumps(first.body)
    second = handlers.weave_differences(
        deps, _ctx(), query={
            "embodiment_id": [EMBODIMENT], "limit": ["200"],
            "cursor": [first.body["page"]["next_cursor"]],
        },
    )
    third = handlers.weave_differences(
        deps, _ctx(), query={
            "embodiment_id": [EMBODIMENT], "limit": ["200"],
            "cursor": [second.body["page"]["next_cursor"]],
        },
    )
    ids = [
        row["event_id"]
        for page in (first.body, second.body, third.body)
        for row in page["items"]
    ]
    assert len(ids) == len(set(ids)) == 450
    assert third.body["page"]["has_more"] is False


def test_oversized_peer_views_are_summarized_with_a_hard_response_budget(tmp_path):
    class Oversized(_MatrixClient):
        def scope_we(self):
            return self._response({
                "schema": "dm.scope.we/v1",
                "embodiments": [
                    {
                        "embodiment_id": f"embodiment:peer-{index}",
                        "availability": "available",
                        "route": {"secret": "x" * 10_000},
                    }
                    for index in range(1_000)
                ],
                "partial": False,
            })

    response = handlers.weave_status(
        _matrix_deps(tmp_path, Oversized()), _ctx()
    )
    assert response.status == 200
    assert len(json.dumps(response.body).encode()) < 1_100_000
    row = response.body["embodiments"][0]
    assert row["peer_sync"]["topology_count"] == 1_000
    assert len(row["peer_sync"]["topology"]) == 100
    assert row["peer_sync"]["topology_truncated"] is True
    assert "secret" not in json.dumps(response.body)


def test_matrix_membership_and_difference_pages_are_owner_scoped(tmp_path):
    alice_id = EMBODIMENT
    bob_id = "embodiment:33333333-3333-4333-8333-333333333333"
    _spec(tmp_path, "alice-one", "alice", alice_id)
    _spec(tmp_path, "bob-one", "bob", bob_id)
    registry = Registry(tmp_path)
    registry.register(body_ref="body:alice", embodiment_id=alice_id)
    registry.start(alice_id, incarnation_id=INCARNATION)
    registry.register(body_ref="body:bob", embodiment_id=bob_id)
    registry.start(
        bob_id,
        incarnation_id="incarnation:44444444-4444-4444-8444-444444444444",
    )
    deps = handlers.Deps(
        config_path="unused", state_dir=str(tmp_path),
        matrix_client_factory=lambda _identifier: _MatrixClient(),
    )
    status = handlers.weave_status(deps, _ctx("alice"))
    assert [row["embodiment_id"] for row in status.body["embodiments"]] == [
        alice_id
    ]
    denied = handlers.weave_differences(
        deps, _ctx("alice"), query={"embodiment_id": [bob_id]}
    )
    assert denied.status == 404
    assert denied.body["error"] == "embodiment not found"


def test_dashboard_supporting_reads_are_owner_scoped(tmp_path):
    alice_id = EMBODIMENT
    bob_id = "embodiment:33333333-3333-4333-8333-333333333333"
    _spec(tmp_path, "alice-one", "alice", alice_id)
    _spec(tmp_path, "bob-one", "bob", bob_id)
    registry = Registry(tmp_path)
    registry.register(body_ref="body:alice", embodiment_id=alice_id)
    registry.register(body_ref="body:bob", embodiment_id=bob_id)
    fences = ResourceFenceStore(tmp_path)
    fences.acquire(
        "volume:alice", "alice-public-key", "SHA256:alice",
        holder_embodiment_id=alice_id,
    )
    fences.acquire(
        "volume:bob", "bob-public-key", "SHA256:bob",
        holder_embodiment_id=bob_id,
    )
    for name in ("alice-one", "bob-one"):
        path = tmp_path / "backups" / name / "snapshot.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"created_ms": 1}), encoding="utf-8")
    deps = handlers.Deps(config_path="unused", state_dir=str(tmp_path))
    assert [
        row["embodiment_id"]
        for row in handlers.list_embodiments(deps, _ctx("alice")).body
    ] == [alice_id]
    assert [
        row["resource_ref"]
        for row in handlers.list_resource_fences(deps, _ctx("alice")).body
    ] == ["volume:alice"]
    backups = handlers.list_backups(deps, _ctx("alice")).body
    assert [row["name"] for row in backups] == ["alice-one"]
    assert "manifest_path" not in backups[0]
