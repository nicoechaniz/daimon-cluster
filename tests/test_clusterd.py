"""clusterd tests (issue #17) — FakeAdapter-injected, CLI-equivalence.

Contract tests prove the HTTP API is a thin wrapper: the same operation
run via ``clusterctl.cli.run(argv, adapter=fake)`` and via HTTP against
the fake-backed server produces the same state transition and an
equivalent payload (name/state/result fields).
"""

import contextlib
import io
import json
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


def _declare(state_dir, name=NAME):
    inst_dir = state_dir / "instances"
    inst_dir.mkdir(parents=True, exist_ok=True)
    (inst_dir / f"{name}.yaml").write_text(yaml.safe_dump({
        "schema": "instance-spec/v1",
        "name": name,
        "image_version": "tribe-base/2026-08-01.1",
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
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv, ad, state_dir
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


def test_handlers_use_no_shell():
    """Guard: handlers delegate via clusterctl's Python API, never via
    a shell — raw user text must never reach subprocess/os.system."""
    import inspect
    src = inspect.getsource(handlers)
    for forbidden in ("subprocess", "os.system", "os.popen", "shell=True"):
        assert forbidden not in src, f"handlers.py must not use {forbidden}"
