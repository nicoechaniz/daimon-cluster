"""clusterd tests (issue #17) — FakeAdapter-injected, CLI-equivalence.

Contract tests prove the HTTP API is a thin wrapper: the same operation
run via ``clusterctl.cli.run(argv, adapter=fake)`` and via HTTP against
the fake-backed server produces the same state transition and an
equivalent payload (name/state/result fields).
"""

import contextlib
import io
import json
import os
import threading
import urllib.error
import urllib.request

import pytest
import yaml

import clusterd
from clusterctl.adapters import FakeAdapter
from clusterctl.cli import run as cli_run
from clusterd import auth as clusterd_auth
from clusterd import handlers
from clusterd.server import make_server

UUID1 = "11111111-1111-1111-1111-111111111111"
UUID2 = "22222222-2222-2222-2222-222222222222"

NAME = "daimon-x"
CONFIG_PATH = "configs/clusterctl.yaml"


@pytest.fixture()
def state_dir(tmp_path):
    return tmp_path / "state"


def _declare(state_dir, name=NAME, image_version="tribe-base/2026-08-01.1"):
    inst_dir = state_dir / "instances"
    inst_dir.mkdir(parents=True, exist_ok=True)
    (inst_dir / f"{name}.yaml").write_text(yaml.safe_dump({
        "schema": "instance-spec/v1",
        "name": name,
        "image_version": image_version,
    }), encoding="utf-8")


def _adapter(instances=None):
    if instances is None:
        instances = [{"name": NAME, "state": "stopped", "image_version": "v1",
                      "budgets": {}, "uptime_s": None}]
    return FakeAdapter(instances=instances)


@pytest.fixture()
def server(state_dir):
    """FakeAdapter-backed clusterd on an ephemeral port (wildcard token)."""
    _declare(state_dir)
    ad = _adapter()
    _, raw_token = clusterd_auth.create_token(
        state_dir, actor="tester", scopes=["read", "mutate"], owner="*",
        ttl_days=1)
    deps = handlers.Deps(config_path=CONFIG_PATH, state_dir=str(state_dir),
                         adapter_factory=lambda: ad)
    srv = make_server(deps, "127.0.0.1", 0)
    srv.test_token = raw_token
    # Let MutationClients inside the dashboard flow find the correct port
    old_url = os.environ.get("CLUSTERD_URL")
    os.environ["CLUSTERD_URL"] = f"http://127.0.0.1:{srv.server_address[1]}"
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv, ad, state_dir
    if old_url is None:
        os.environ.pop("CLUSTERD_URL", None)
    else:
        os.environ["CLUSTERD_URL"] = old_url
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


def _req(server, method, path, headers=None, auth=True):
    url = f"http://127.0.0.1:{server.server_address[1]}{path}"
    headers = dict(headers or {})
    if auth and "Authorization" not in headers and \
            getattr(server, "test_token", None):
        headers["Authorization"] = f"Bearer {server.test_token}"
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8")


def _get(server, path, headers=None, auth=True):
    status, hdrs, body = _req(server, "GET", path, headers, auth=auth)
    return status, hdrs, json.loads(body)


def _post(server, path, headers=None, auth=True):
    status, hdrs, body = _req(server, "POST", path, headers, auth=auth)
    return status, hdrs, json.loads(body)


def _post_json(server, path, body_dict, headers=None, auth=True):
    """POST with JSON body to clusterd."""
    url = f"http://127.0.0.1:{server.server_address[1]}{path}"
    headers = dict(headers or {})
    headers.setdefault("Content-Type", "application/json")
    if auth and "Authorization" not in headers and \
            getattr(server, "test_token", None):
        headers["Authorization"] = f"Bearer {server.test_token}"
    data = json.dumps(body_dict).encode("utf-8")
    req = urllib.request.Request(url, method="POST", data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, dict(resp.headers), json.loads(body)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), json.loads(exc.read().decode("utf-8"))


def _cli(state_dir, *argv, adapter=None):
    """Run the same op via the CLI with captured JSON stdout/stderr."""
    ad = adapter if adapter is not None else _adapter()
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli_run(["--state-dir", str(state_dir), *argv], adapter=ad)
    return code, out.getvalue().strip(), err.getvalue().strip(), ad


# --------------------------------------------------------------------------
# health
# --------------------------------------------------------------------------

def test_health_ok(server):
    srv, _, _ = server
    status, hdrs, body = _get(srv, "/v1/health")
    assert status == 200
    assert body["schema"] == "clusterd-health/v1"
    assert body["status"] == "ok"
    assert body["version"] == clusterd.__version__
    assert body["clusterctl_reachable"] is True
    assert hdrs["X-Request-Id"]


def test_health_degraded_when_adapter_raises(state_dir):
    _declare(state_dir)

    class BoomAdapter(FakeAdapter):
        def list_instances(self):
            raise RuntimeError("incus unreachable")

    deps = handlers.Deps(config_path=CONFIG_PATH, state_dir=str(state_dir),
                         adapter_factory=BoomAdapter)
    srv = make_server(deps, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = _get(srv, "/v1/health")
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)
    assert status == 200
    assert body["status"] == "degraded"
    assert body["clusterctl_reachable"] is False


def test_health_degraded_when_adapter_factory_raises(state_dir):
    def factory():
        raise RuntimeError("cannot build adapter")

    deps = handlers.Deps(config_path=CONFIG_PATH, state_dir=str(state_dir),
                         adapter_factory=factory)
    srv = make_server(deps, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = _get(srv, "/v1/health")
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)
    assert status == 200
    assert body["clusterctl_reachable"] is False


# --------------------------------------------------------------------------
# CLI-equivalence: reads
# --------------------------------------------------------------------------

def test_list_matches_cli(server):
    srv, ad, state_dir = server
    code, out, _, _ = _cli(state_dir, "list", "--json", adapter=ad)
    assert code == 0
    cli_records = json.loads(out)

    status, _, http_records = _get(srv, "/v1/instances")
    assert status == 200
    assert isinstance(http_records, list)
    assert [(r["name"], r["state"]) for r in http_records] == \
           [(r["name"], r["state"]) for r in cli_records]


def test_get_instance_matches_cli(server):
    srv, ad, state_dir = server
    code, out, _, _ = _cli(state_dir, "status", NAME, "--json", adapter=ad)
    assert code == 0
    cli_rec = json.loads(out)

    status, _, http_rec = _get(srv, f"/v1/instances/{NAME}")
    assert status == 200
    for field in ("name", "state", "species"):
        assert http_rec[field] == cli_rec[field]


def test_get_instance_404_mirrors_exit_3(server):
    srv, ad, state_dir = server
    code, _, err, _ = _cli(state_dir, "status", "ghost", "--json", adapter=ad)
    assert code == 3

    status, _, body = _get(srv, "/v1/instances/ghost")
    assert status == 404
    assert body["error"] == f"clusterctl: instance 'ghost' not found" or \
        "ghost" in body["error"]
    assert "request_id" in body


# --------------------------------------------------------------------------
# CLI-equivalence: lifecycle mutations
# --------------------------------------------------------------------------

@pytest.mark.parametrize("operation,expected_state", [
    ("start", "running"),
    ("stop", "stopped"),
    ("restart", "running"),
])
def test_power_matches_cli(tmp_path, operation, expected_state):
    # Same operation via CLI (own state dir + adapter) and via HTTP
    # (own state dir + adapter) — equal state transition + payload.
    cli_dir = tmp_path / "cli-state"
    http_dir = tmp_path / "http-state"
    _declare(cli_dir)
    _declare(http_dir)
    # restart requires a running instance (FakeAdapter contract).
    seed_state = "running" if operation in ("stop", "restart") else "stopped"
    seed = [{"name": NAME, "state": seed_state, "image_version": "v1",
             "budgets": {}, "uptime_s": 0 if seed_state == "running" else None}]
    cli_ad = _adapter(instances=[dict(s) for s in seed])
    http_ad = _adapter(instances=[dict(s) for s in seed])

    code, out, _, cli_ad = _cli(
        cli_dir, operation, NAME, "--idempotency-key", UUID1, "--json",
        adapter=cli_ad)
    assert code == 0
    cli_result = json.loads(out)

    _, raw_token = clusterd_auth.create_token(
        http_dir, actor="tester", scopes=["read", "mutate"], owner="*",
        ttl_days=1)
    deps = handlers.Deps(config_path=CONFIG_PATH, state_dir=str(http_dir),
                         adapter_factory=lambda: http_ad)
    srv = make_server(deps, "127.0.0.1", 0)
    srv.test_token = raw_token
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, http_result = _post(
            srv, f"/v1/instances/{NAME}/{operation}",
            headers={"Idempotency-Key": UUID1})
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)

    assert status == 200
    for field in ("operation", "name", "result", "state"):
        assert http_result[field] == cli_result[field]
    assert http_result["state"] == expected_state
    # Equal state transition on the backing instances.
    assert cli_ad._instances[0]["state"] == expected_state
    assert http_ad._instances[0]["state"] == expected_state


def test_power_404_undeclared(server):
    srv, _, _ = server
    status, _, body = _post(srv, "/v1/instances/ghost/start",
                            headers={"Idempotency-Key": UUID1})
    assert status == 404
    assert body["action"] == "start"
    assert body["target"] == "ghost"
    assert "request_id" in body


def test_power_requires_idempotency_key(server):
    srv, ad, _ = server
    status, _, body = _post(srv, f"/v1/instances/{NAME}/start")
    assert status == 400
    assert "Idempotency-Key" in body["error"]
    assert body["request_id"]
    # No effect reached the adapter.
    assert ad.mutation_log == []


def test_idempotency_replay_via_http(server):
    srv, ad, _ = server
    status1, _, body1 = _post(srv, f"/v1/instances/{NAME}/start",
                              headers={"Idempotency-Key": UUID1})
    assert status1 == 200
    assert body1["result"] == "ok"

    status2, _, body2 = _post(srv, f"/v1/instances/{NAME}/start",
                              headers={"Idempotency-Key": UUID1})
    assert status2 == 200
    assert body2["idempotent-replay"] is True
    for field in ("operation", "name", "result", "state"):
        assert body2[field] == body1[field]
    # clusterctl's own store deduped: exactly one adapter mutation.
    assert [c[0] for c in ad.mutation_log] == ["start"]


def test_idempotency_conflict_mirrors_exit_6(server):
    srv, ad, _ = server
    status1, _, _ = _post(srv, f"/v1/instances/{NAME}/start",
                          headers={"Idempotency-Key": UUID2})
    assert status1 == 200
    # Same key, different operation -> CLI exit 6 -> HTTP 409.
    status2, _, body = _post(srv, f"/v1/instances/{NAME}/stop",
                             headers={"Idempotency-Key": UUID2})
    assert status2 == 409
    assert "idempotency_conflict" in body
    assert "request_id" in body


def test_token_actor_is_authoritative_for_audit(server):
    """With auth enforced (#18), the authenticated token actor — not the
    spoofable X-Actor header — flows to clusterctl audit events."""
    srv, _, state_dir = server
    status, _, _ = _post(srv, f"/v1/instances/{NAME}/start",
                         headers={"Idempotency-Key": UUID1,
                                  "X-Actor": "agent:spoofed"})
    assert status == 200
    events = [json.loads(l)
              for l in (state_dir / "audit.jsonl").read_text().splitlines()]
    assert any(e["actor"] == "tester" for e in events)
    assert not any(e["actor"] == "agent:spoofed" for e in events)


def test_request_id_echoed(server):
    srv, _, _ = server
    rid = "99999999-9999-9999-9999-999999999999"
    status, hdrs, body = _get(srv, "/v1/health", headers={"X-Request-Id": rid})
    assert status == 200
    assert hdrs["X-Request-Id"] == rid


# --------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------

def test_backups_returns_newest_manifest_per_daimon(server):
    srv, _, state_dir = server
    for name, entries in {
        "eko": [(100, "snap-100"), (200, "snap-200")],
        "oliva": [(150, "snap-150")],
    }.items():
        mdir = state_dir / "backups" / name
        mdir.mkdir(parents=True)
        for created_ms, snap in entries:
            (mdir / f"{created_ms}-{snap}.json").write_text(json.dumps({
                "schema": "cluster-backup-manifest/v1",
                "name": name,
                "snap_name": snap,
                "created_ms": created_ms,
                "verified_readable": True,
            }), encoding="utf-8")

    status, _, body = _get(srv, "/v1/backups")
    assert status == 200
    assert [e["name"] for e in body] == ["eko", "oliva"]
    eko = body[0]
    assert eko["schema"] == "clusterd-backup-summary/v1"
    # Newest manifest only.
    assert eko["manifest"]["snap_name"] == "snap-200"
    assert eko["manifest"]["created_ms"] == 200


def test_backups_empty(server):
    srv, _, _ = server
    status, _, body = _get(srv, "/v1/backups")
    assert status == 200
    assert body == []


def test_ontology_read_routes(server):
    from clusterctl.embodiments import Registry
    from clusterctl.fences import ResourceFenceStore

    srv, _, state_dir = server
    embodiment = Registry(state_dir).register(body_ref="cluster:test:compaii")
    Registry(state_dir).start(embodiment["embodiment_id"])
    ResourceFenceStore(state_dir).acquire(
        "volume:compaii-state", "test-public-key", "SHA256:test",
        holder_embodiment_id=embodiment["embodiment_id"],
    )

    status, _, embodiments = _get(srv, "/v1/embodiments")
    assert status == 200
    assert embodiments[0]["embodiment_id"] == embodiment["embodiment_id"]
    assert embodiments[0]["status"] == "running"

    status, _, fences = _get(srv, "/v1/resource-fences")
    assert status == 200
    assert fences[0]["resource_ref"] == "volume:compaii-state"
    assert fences[0]["holder_embodiment_id"] == embodiment["embodiment_id"]

    status, _, weave = _get(srv, "/v1/weave/status")
    assert status == 200
    assert weave == {
        "schema": "dm.cluster-matrix-status/v1",
        "configured": False,
        "implementation": "installed-daimon-matrix",
        "matrix_contract_commit": (
            "c7c6e236ff59596dd596e69fcd46efbe0446ea69"
        ),
        "embodiments": [],
    }


# --------------------------------------------------------------------------
# openapi
# --------------------------------------------------------------------------

def test_openapi_yaml_parses_and_contains_all_routes(server):
    from clusterd.routes import ROUTES
    srv, _, _ = server
    status, hdrs, body = _req(srv, "GET", "/v1/openapi.yaml")
    assert status == 200
    doc = yaml.safe_load(body)
    assert doc["openapi"].startswith("3.")
    assert doc["info"]["version"] == clusterd.__version__
    for route in ROUTES:
        assert route.path in doc["paths"], route.path
        op = doc["paths"][route.path][route.method.lower()]
        assert op["operationId"] == route.operation_id
    # Idempotency-Key documented as required on mutations.
    start_op = doc["paths"]["/v1/instances/{name}/start"]["post"]
    idem = [p for p in start_op["parameters"] if p["name"] == "Idempotency-Key"]
    assert idem and idem[0]["required"] is True
    # Bearer scheme documented (enforced since #18).
    assert "bearerAuth" in doc["components"]["securitySchemes"]


def test_dump_openapi(tmp_path):
    from clusterd.__main__ import main
    out = tmp_path / "openapi.yaml"
    assert main(["--dump-openapi", str(out)]) == 0
    doc = yaml.safe_load(out.read_text())
    assert doc["info"]["title"] == "clusterd"
    assert "/v1/instances" in doc["paths"]


# --------------------------------------------------------------------------
# envelope / routing hygiene
# --------------------------------------------------------------------------

def test_unknown_route_404(server):
    srv, _, _ = server
    status, _, body = _get(srv, "/v1/nope")
    assert status == 404
    assert body["error"]
    assert body["request_id"]


def test_method_not_allowed(server):
    srv, _, _ = server
    status, _, body = _post(srv, "/v1/instances",
                            headers={"Idempotency-Key": UUID1})
    assert status == 405
    assert body["request_id"]


def test_bearer_token_enforced(server):
    """Auth is #18 and now ENFORCED: default-deny without a token (401);
    the fixture wildcard token succeeds; health stays public."""
    srv, _, _ = server
    status_noauth, _, body = _get(srv, "/v1/instances", auth=False)
    assert status_noauth == 401
    assert body["error"] == "unauthorized"
    status_auth, _, _ = _get(srv, "/v1/instances")
    assert status_auth == 200
    status_health, _, _ = _get(srv, "/v1/health", auth=False)
    assert status_health == 200


# --------------------------------------------------------------------------
# multi-bind (issue #21)
# --------------------------------------------------------------------------

@pytest.fixture()
def two_bind_server(state_dir):
    """serve()-style: two ClusterdServers on ephemeral ports sharing ONE
    Deps, ONE token store and ONE rate limiter (make_servers, as serve())."""
    from clusterd.server import make_servers
    # Declared image matches the adapter's actual ("v1") so the power
    # state — not drift — is what the status record reports.
    _declare(state_dir, image_version="v1")
    ad = _adapter()
    _, raw_token = clusterd_auth.create_token(
        state_dir, actor="tester", scopes=["read", "mutate"], owner="*",
        ttl_days=1)
    deps = handlers.Deps(config_path=CONFIG_PATH, state_dir=str(state_dir),
                         adapter_factory=lambda: ad)
    srv_a, srv_b = make_servers(deps, [("127.0.0.1", 0), ("127.0.0.1", 0)])
    assert srv_a.server_address[1] != srv_b.server_address[1]
    # Shared service pieces — one state_dir, one store, one limiter.
    assert srv_a.deps is srv_b.deps
    assert srv_a.state_dir == srv_b.state_dir == str(state_dir)
    assert srv_a.token_store is srv_b.token_store
    assert srv_a.rate_limiter is srv_b.rate_limiter
    for srv in (srv_a, srv_b):
        srv.test_token = raw_token
    threads = [threading.Thread(target=s.serve_forever, daemon=True)
               for s in (srv_a, srv_b)]
    for t in threads:
        t.start()
    yield srv_a, srv_b, ad, state_dir
    for s in (srv_a, srv_b):
        s.shutdown()
        s.server_close()
    for t in threads:
        t.join(timeout=5)


def test_two_bind_health_on_both(two_bind_server):
    srv_a, srv_b, _, _ = two_bind_server
    for srv in (srv_a, srv_b):
        status, _, body = _get(srv, "/v1/health", auth=False)
        assert status == 200
        assert body["schema"] == "clusterd-health/v1"
        assert body["status"] == "ok"


def test_two_bind_equivalent_reads(two_bind_server):
    srv_a, srv_b, _, _ = two_bind_server
    status_a, _, body_a = _get(srv_a, "/v1/instances")
    status_b, _, body_b = _get(srv_b, "/v1/instances")
    assert status_a == status_b == 200
    assert [(r["name"], r["state"]) for r in body_a] == \
           [(r["name"], r["state"]) for r in body_b]


def test_two_bind_token_works_on_both(two_bind_server):
    srv_a, srv_b, _, _ = two_bind_server
    for srv in (srv_a, srv_b):
        status, _, body = _get(srv, "/v1/instances", auth=False)
        assert status == 401  # default-deny, same on both sockets
        status, _, body = _get(srv, f"/v1/instances/{NAME}")
        assert status == 200
        assert body["name"] == NAME


def test_two_bind_mutation_via_a_visible_via_b(two_bind_server):
    srv_a, srv_b, ad, _ = two_bind_server
    status, _, before = _get(srv_b, f"/v1/instances/{NAME}")
    assert status == 200
    assert before["state"] == "stopped"
    # Mutate via socket A...
    status, _, body = _post(srv_a, f"/v1/instances/{NAME}/start",
                            headers={"Idempotency-Key": UUID1})
    assert status == 200
    assert body["state"] == "running"
    # ...is visible via socket B (shared state): the record changed, and
    # both sockets report the SAME post-mutation record.
    status, _, body_b = _get(srv_b, f"/v1/instances/{NAME}")
    status, _, body_a = _get(srv_a, f"/v1/instances/{NAME}")
    assert status == 200
    assert body_b["state"] != "stopped"
    assert body_b["state"] == body_a["state"]
    assert ad._instances[0]["state"] == "running"
    # And the idempotency store is shared: replay on B dedupes — exactly
    # ONE adapter mutation reached the backing service.
    status, _, body = _post(srv_b, f"/v1/instances/{NAME}/start",
                            headers={"Idempotency-Key": UUID1})
    assert status == 200
    assert body["idempotent-replay"] is True
    assert [c[0] for c in ad.mutation_log] == ["start"]


# --------------------------------------------------------------------------
# audit route (issue #24)
# --------------------------------------------------------------------------

def test_audit_returns_json_list(server):
    """GET /v1/audit returns a JSON list of audit events."""
    srv, _, state_dir = server
    # Append a few audit events.
    from clusterctl.audit import append_event
    append_event(state_dir, actor="tester", action="start",
                 target="daimon-x", result="ok",
                 request_id="req-1")
    append_event(state_dir, actor="tester", action="stop",
                 target="daimon-x", result="ok",
                 request_id="req-2")

    status, _, body = _get(srv, "/v1/audit")
    assert status == 200
    assert isinstance(body, list)
    assert len(body) >= 2
    for event in body:
        assert event["schema"] == "audit-event/v1"
        assert "event_id" in event
        assert "ts_ms" in event
        assert "actor" in event
        assert "action" in event
        assert "target" in event
        assert "result" in event


def test_audit_filtered_by_params(server):
    """GET /v1/audit filters by actor, target, and action query params."""
    srv, _, state_dir = server
    from clusterctl.audit import append_event
    append_event(state_dir, actor="tester", action="start",
                 target="daimon-x", result="ok")
    append_event(state_dir, actor="other", action="stop",
                 target="daimon-x", result="ok")
    append_event(state_dir, actor="tester", action="restart",
                 target="daimon-y", result="ok")

    # Filter by actor.
    status, _, body = _get(srv, "/v1/audit?actor=tester")
    assert status == 200
    assert all(e["actor"] == "tester" for e in body)

    # Filter by action.
    status, _, body = _get(srv, "/v1/audit?action=stop")
    assert status == 200
    assert all(e["action"] == "stop" for e in body)

    # Filter by target.
    status, _, body = _get(srv, "/v1/audit?target=daimon-y")
    assert status == 200
    assert all(e.get("target") == "daimon-y" for e in body)

    # Combined filter.
    status, _, body = _get(srv, "/v1/audit?actor=tester&action=restart")
    assert status == 200
    assert all(e["actor"] == "tester" and e["action"] == "restart"
               for e in body)

    # Limit.
    status, _, body = _get(srv, "/v1/audit?limit=1")
    assert status == 200
    assert len(body) == 1


def test_audit_owner_scoped(server):
    """Owner-scoped tokens only see events about their own daimons."""
    srv, _, state_dir = server
    # Declare two instances with different owners.
    from clusterd import auth as clusterd_auth
    inst_dir = state_dir / "instances"
    inst_dir.mkdir(parents=True, exist_ok=True)
    (inst_dir / "alice-daimon.yaml").write_text(yaml.safe_dump({
        "schema": "instance-spec/v1",
        "name": "alice-daimon",
        "image_version": "v1",
        "created_by": "alice",
    }), encoding="utf-8")
    (inst_dir / "bob-daimon.yaml").write_text(yaml.safe_dump({
        "schema": "instance-spec/v1",
        "name": "bob-daimon",
        "image_version": "v1",
        "created_by": "bob",
    }), encoding="utf-8")

    from clusterctl.audit import append_event
    append_event(state_dir, actor="alice", action="start",
                 target="alice-daimon", result="ok")
    append_event(state_dir, actor="bob", action="start",
                 target="bob-daimon", result="ok")

    # Create an alice-scoped token and a fresh server with it.
    _, alice_token = clusterd_auth.create_token(
        state_dir, actor="alice", scopes=["read"], owner="alice",
        ttl_days=1)
    from clusterd.server import make_server
    from clusterd import handlers
    deps_alice = handlers.Deps(config_path=srv.deps.config_path,
                               state_dir=str(state_dir),
                               adapter_factory=srv.deps.adapter_factory)
    srv2 = make_server(deps_alice, "127.0.0.1", 0)
    srv2.test_token = alice_token
    import threading
    t2 = threading.Thread(target=srv2.serve_forever, daemon=True)
    t2.start()
    try:
        status, _, body = _get(srv2, "/v1/audit")
    finally:
        srv2.shutdown()
        srv2.server_close()
        t2.join(timeout=5)

    assert status == 200
    # Alice should only see her own daimon's events.
    assert len(body) >= 1
    for event in body:
        assert event["target"] == "alice-daimon", \
            f"alice must not see {event['target']}"


def test_audit_redaction(server):
    """Audit route redacts secret patterns in event fields."""
    srv, _, state_dir = server
    # Write a fake audit line with a secret directly into the log.
    audit_file = state_dir / "audit.jsonl"
    import json as _json, time as _time, uuid as _uuid
    event = {
        "schema": "audit-event/v1",
        "event_id": str(_uuid.uuid4()),
        "ts_ms": int(_time.time() * 1000),
        "actor": "tester",
        "action": "start",
        "target": "daimon-x",
        "result": "ok",
        "detail": {"note": "token=sk-abcd1234 PRIVATE KEY exposed"},
        "idempotency_key": None,
        "request_id": "req-1",
    }
    audit_file.write_text(_json.dumps(event) + "\n", encoding="utf-8")

    status, _, body = _get(srv, "/v1/audit")
    assert status == 200
    assert len(body) >= 1
    # The detail field must be redacted.
    found = [e for e in body if e.get("request_id") == "req-1"]
    assert found, "redaction test event not found"
    detail = found[0].get("detail", {})
    detail_str = _json.dumps(detail)
    assert "[REDACTED]" in detail_str, \
        f"detail should contain [REDACTED], got: {detail_str}"
    assert "PRIVATE KEY" not in detail_str, \
        f"'PRIVATE KEY' must not appear in response"


# --------------------------------------------------------------------------
# dashboard route (issue #24)
# --------------------------------------------------------------------------

def test_dashboard_returns_html_200(server):
    """GET /v1/dashboard serves the public app shell (no auth for the HTML;
    every DATA route stays auth-gated — the shell carries no data)."""
    srv, _, _ = server

    # Without token: 200 HTML shell (browser navigations send no
    # Authorization header; the JS token prompt happens client-side).
    status_noauth, hdrs_noauth, body_noauth = _req(
        srv, "GET", "/v1/dashboard", auth=False)
    assert status_noauth == 200
    assert "text/html" in hdrs_noauth.get("Content-Type", "")
    assert "htmx" in body_noauth
    assert "sessionStorage" in body_noauth
    # The shell must not embed any fleet data (names, states, audit rows).
    assert "daimon-x" not in body_noauth
    assert "\"instances\"" not in body_noauth

    # With read-scoped token: same 200 HTML.
    status, hdrs, body = _req(srv, "GET", "/v1/dashboard")
    assert status == 200
    assert "text/html" in hdrs.get("Content-Type", "")
    assert "<!DOCTYPE html>" in body


def test_dashboard_html_contains_required_elements(server):
    """Dashboard HTML sanity check: htmx CDN, token input, sessionStorage."""
    srv, _, _ = server
    status, _, body = _req(srv, "GET", "/v1/dashboard")
    assert status == 200
    # HTMX script tag.
    assert "htmx.org" in body
    # Token input field.
    assert "token-input" in body
    # Session storage usage.
    assert "sessionStorage" in body
    # Auth prompt div.
    assert "auth-prompt" in body
    # Dashboard sections.
    assert "health-content" in body
    assert "fleet-content" in body
    assert "weave-content" in body
    assert "embodiments-content" in body
    assert "fences-content" in body
    assert "backups-content" in body
    assert "activity-content" in body
    # Retry link pattern for degraded/no-data state.
    assert "retry-link" in body
    # CDN script source.
    assert "unpkg.com" in body



# --------------------------------------------------------------------------
# dashboard lifecycle + backup actions (issue #25)
# --------------------------------------------------------------------------

def test_dashboard_prepare_returns_plan_without_mutating(server):
    """prepare returns plan JSON without any adapter mutations."""
    srv, ad, _ = server
    ad.mutation_log.clear()

    status, _, body = _post_json(srv, "/v1/dashboard/prepare",
                                 {"operation": "start", "target": NAME})
    assert status == 200
    assert body["schema"] == "steward-mutation-plan/v1"
    assert body["operation"] == "start"
    assert body["target"] == NAME
    assert body["destructive"] is False
    assert body["action_digest"]
    assert body["created_ms"]
    assert body["ttl_s"]
    # PREPARE NEVER mutates.
    assert ad.mutation_log == []


def test_dashboard_prepare_restore_on_running_409(server):
    """restore proposal on a running instance → 409 pre-condition."""
    srv, ad, state_dir = server
    ad._instances = [{"name": NAME, "state": "running", "image_version": "tribe-base/2026-08-01.1",
                      "budgets": {}, "uptime_s": 600}]
    # Verify the adapter change took effect before the handler runs
    from clusterd.handlers import get_instance, Deps, RequestContext
    ctx = RequestContext(request_id="rid", actor=srv.test_token or "tester",
                         scope_token=srv.test_token)
    stat_resp = get_instance(srv.deps, ctx, NAME)
    assert stat_resp.body.get("state") == "running", \
        f"pre-check: expected running, got {stat_resp.body}"
    status, _, body = _post_json(srv, "/v1/dashboard/prepare",
                                 {"operation": "restore", "target": NAME})
    assert status == 409, f"expected 409, got {status}: {body}"
    assert "stopped before restore" in body.get("error", "")


def test_dashboard_prepare_restore_on_stopped_ok(server):
    """restore proposal on a stopped instance returns a valid plan."""
    srv, ad, _ = server
    status, _, body = _post_json(srv, "/v1/dashboard/prepare",
                                 {"operation": "restore", "target": NAME})
    assert status == 200
    assert body["operation"] == "restore"
    assert body["destructive"] is False


def test_dashboard_confirm_executes_and_idempotent_replay(server):
    """confirm executes the mutation; replay of same plan returns same result."""
    srv, ad, _ = server

    # Phase 1: prepare
    status, _, plan = _post_json(srv, "/v1/dashboard/prepare",
                                 {"operation": "start", "target": NAME})
    assert status == 200

    # Phase 2: confirm
    status, _, result = _post_json(srv, "/v1/dashboard/confirm", {
        "operation": "start",
        "target": NAME,
        "plan": plan,
        "human_turn_id": "turn-1",
    })
    assert status == 200
    assert result["ok"] is True
    assert result["operation"] == "start"
    assert [c[0] for c in ad.mutation_log] == ["start"]

    # Phase 3: replay — same plan JSON, different HTTP request, same
    # Idempotency-Key (digest-derived). clusterd's idempotency store
    # returns the original result; exactly ONE adapter mutation.
    status, _, result2 = _post_json(srv, "/v1/dashboard/confirm", {
        "operation": "start",
        "target": NAME,
        "plan": plan,
        "human_turn_id": "turn-1",
    })
    assert status == 200 and result2["ok"] is True
    assert [c[0] for c in ad.mutation_log] == ["start"]  # still just one


def test_dashboard_confirm_typed_name_rejection_on_destructive(server):
    """typed-name validation on destructive plans: missing / wrong case rejected."""
    srv, ad, _ = server
    ad.mutation_log.clear()
    # Synthetic destructive plan (destroy prepare needs clusterd challenge
    # roundtrip not available in this fake fixture — test the handler check directly)
    plan = {
        "schema": "steward-mutation-plan/v1", "operation": "destroy",
        "target": NAME, "impact": "destruction", "destructive": True,
        "action_digest": "a" * 64, "created_ms": 999999999999999999999,
        "ttl_s": 120, "challenge_token": None,
        "display_text": "...", "actor": "steward@daimonmatrix",
        "args": {}, "used": False,
    }
    # missing typed_name
    status, _, r = _post_json(srv, "/v1/dashboard/confirm",
        {"operation": "destroy", "target": NAME, "plan": plan,
         "human_turn_id": "turn-dn"})
    assert status == 400 and r.get("refused") == "typed-name-mismatch"
    # wrong case
    status, _, r = _post_json(srv, "/v1/dashboard/confirm",
        {"operation": "destroy", "target": NAME, "plan": plan,
         "human_turn_id": "turn-dn", "typed_name": "Daimon-X"})
    assert status == 400 and r.get("refused") == "typed-name-mismatch"
    assert ad.mutation_log == []  # never reached the adapter


def test_dashboard_confirm_double_click_one_execution(server):
    """double-click on confirm results in exactly ONE adapter mutation.

    The JS mints the human turn at PREPARE time and reuses it on every
    confirm click of that banner — so both clicks of one intent carry
    the SAME turn and clusterctl's idempotency store dedupes them.
    A NEW prepare is a NEW intent and executes again (drill #26:
    independent intents must never replay a cached result)."""
    srv, ad, _ = server
    ad.mutation_log.clear()

    status, _, plan = _post_json(srv, "/v1/dashboard/prepare",
                                 {"operation": "stop", "target": NAME})
    assert status == 200

    # Two clicks on the SAME banner → same turn (as the JS sends it)
    for _ in range(2):
        status, _, result = _post_json(srv, "/v1/dashboard/confirm", {
            "operation": "stop", "target": NAME,
            "plan": plan, "human_turn_id": "turn-banner-1",
        })
        assert status == 200
    stop_count = sum(1 for c in ad.mutation_log if c[0] == "stop")
    assert stop_count == 1

    # A NEW prepare + confirm is a NEW intent → executes again
    status, _, plan2 = _post_json(srv, "/v1/dashboard/prepare",
                                  {"operation": "stop", "target": NAME})
    assert status == 200
    status, _, result2 = _post_json(srv, "/v1/dashboard/confirm", {
        "operation": "stop", "target": NAME,
        "plan": plan2, "human_turn_id": "turn-banner-2",
    })
    assert status == 200
    assert result2["ok"] is True
    stop_count = sum(1 for c in ad.mutation_log if c[0] == "stop")
    assert stop_count == 2


def test_dashboard_prepare_invalid_operation(server):
    """prepare with unknown operation returns 400."""
    srv, _, _ = server
    status, _, body = _post_json(srv, "/v1/dashboard/prepare",
                                 {"operation": "fly", "target": NAME})
    assert status == 400
    assert "unknown operation" in body["error"]


def test_dashboard_prepare_missing_fields(server):
    """prepare without operation or target returns 400."""
    srv, _, _ = server

    status, _, body = _post_json(srv, "/v1/dashboard/prepare", {})
    assert status == 400
    assert "required" in body["error"]

    status, _, body = _post_json(srv, "/v1/dashboard/prepare",
                                 {"operation": "start"})
    assert status == 400
    assert "required" in body["error"]


def test_dashboard_confirm_no_plan(server):
    """confirm without plan field returns 400."""
    srv, _, _ = server
    status, _, body = _post_json(srv, "/v1/dashboard/confirm",
                                 {"operation": "start", "target": NAME})
    assert status == 400
    assert "plan" in body["error"]


def test_dashboard_prepare_requires_auth(server):
    """prepare route requires bearer auth (not public)."""
    srv, _, _ = server
    status, _, body = _post_json(srv, "/v1/dashboard/prepare",
                                 {"operation": "start", "target": NAME},
                                 auth=False)
    assert status == 401


def test_dashboard_confirm_requires_mutate_scope(server):
    """confirm route requires mutate scope."""
    srv, _, state_dir = server
    from clusterd import auth as clusterd_auth
    from clusterd.server import make_server
    from clusterd import handlers as _h

    # Create a read-only token.
    _, ro_token = clusterd_auth.create_token(
        state_dir, actor="reader", scopes=["read"], owner="*",
        ttl_days=1)

    plan_payload = {"operation": "start", "target": NAME}
    # Use the default server (mutate-scoped) for prepare.
    status, _, plan = _post_json(srv, "/v1/dashboard/prepare", plan_payload)
    assert status == 200

    # Spin up a read-only server.
    deps_ro = _h.Deps(config_path=srv.deps.config_path,
                       state_dir=str(state_dir),
                       adapter_factory=srv.deps.adapter_factory)
    srv_ro = make_server(deps_ro, "127.0.0.1", 0)
    srv_ro.test_token = ro_token
    import threading
    t_ro = threading.Thread(target=srv_ro.serve_forever, daemon=True)
    t_ro.start()
    try:
        status_ro, _, body = _post_json(srv_ro, "/v1/dashboard/confirm", {
            "operation": "start",
            "target": NAME,
            "plan": plan,
            "human_turn_id": "turn-scope",
        })
    finally:
        srv_ro.shutdown()
        srv_ro.server_close()
        t_ro.join(timeout=5)

    assert status_ro == 403
    assert "insufficient-scope" in body.get("error", "")


def test_restore_instance_route_returns_501(server):
    """POST /v1/instances/{name}/restore returns 501 placeholder."""
    srv, _, _ = server
    status, _, body = _post(srv, f"/v1/instances/{NAME}/restore")
    assert status == 501
    assert "later milestone" in body["error"]


def test_handlers_use_no_shell():
    """Guard: handlers delegate via clusterctl's Python API, never via
    a shell — raw user text must never reach subprocess/os.system."""
    import inspect
    src = inspect.getsource(handlers)
    for forbidden in ("subprocess", "os.system", "os.popen", "shell=True"):
        assert forbidden not in src, f"handlers.py must not use {forbidden}"
