"""steward_tools tests (issue #22) — the safety invariants as tests.

Proves, against the FakeAdapter-backed clusterd (same fixture pattern
as test_clusterd.py):

- the package contains no shell constructs and no mutation-verb strings
  (source scan — the steward's window is read-only by construction);
- the client refuses cross-origin redirects (never follows a bounce to
  another host) but follows a same-origin one;
- cluster_logs input bounds: name regex rejects traversal/injection/
  overlong names; lines clamps to 200;
- an unreachable clusterd is an explicit ok=False/degraded result,
  never an exception;
- the new logs route redacts secrets end-to-end (a 'PRIVATE KEY' line
  comes back [REDACTED]);
- every tool result carries source_ts_ms from the clusterd envelope;
- backups staleness: newest manifest older than 26h -> stale=True.
"""

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

from clusterctl import audit
from clusterctl.adapters import FakeAdapter
from clusterd import auth as clusterd_auth
from clusterd import handlers
from clusterd.server import make_server
from steward_tools import client as steward_client
from steward_tools import tools

NAME = "daimon-x"
CONFIG_PATH = "configs/clusterctl.yaml"
PACKAGE_DIR = Path(steward_client.__file__).resolve().parent


# --------------------------------------------------------------------------
# fixtures (test_clusterd.py pattern: FakeAdapter + ephemeral server)
# --------------------------------------------------------------------------

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


def _write_manifest(state_dir, name, created_ms):
    mdir = state_dir / "backups" / name
    mdir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema": "cluster-backup-manifest/v1",
        "name": name,
        "snap_name": f"snap-{created_ms}",
        "created_ms": created_ms,
        "image_version": "tribe-base/2026-08-01.1",
        "quiesce": {"parked": True, "sqlite_ok": True,
                    "checkpoint_files": []},
        "verified_readable": True,
        "retention_class": "local-quiesced",
        "rpo_class": "pre-mutation",
    }
    (mdir / f"{created_ms}-snap-{created_ms}.json").write_text(
        json.dumps(manifest), encoding="utf-8")


def _adapter(log_lines=None):
    return FakeAdapter(
        instances=[{"name": NAME, "state": "running",
                    "image_version": "tribe-base/2026-08-01.1",
                    "budgets": {}, "uptime_s": 42}],
        log_lines=log_lines or {})


@pytest.fixture()
def server(state_dir, tmp_path, monkeypatch):
    """FakeAdapter-backed clusterd + a read-scoped steward token file.

    Also points CLUSTERD_URL at the ephemeral server so default-built
    clients (and tools that build their own) reach it.
    """
    _declare(state_dir)
    ad = _adapter(log_lines={NAME: [f"log line {i}" for i in range(250)]})
    _, raw_token = clusterd_auth.create_token(
        state_dir, actor="steward@daimonmatrix", scopes=["read"],
        owner="*", ttl_days=1)
    token_file = tmp_path / "read-token"
    token_file.write_text(raw_token, encoding="utf-8")
    deps = handlers.Deps(config_path=CONFIG_PATH, state_dir=str(state_dir),
                         adapter_factory=lambda: ad)
    srv = make_server(deps, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv(
        "CLUSTERD_URL", f"http://127.0.0.1:{srv.server_address[1]}")
    yield srv, ad, state_dir, token_file
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


@pytest.fixture()
def client(server):
    _srv, _ad, _sd, token_file = server
    return steward_client.ClusterdClient(token_path=str(token_file))


def _closed_port_url():
    import socket
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"http://127.0.0.1:{port}"


# --------------------------------------------------------------------------
# source-scan guard: the package is read-only by construction
# --------------------------------------------------------------------------

def test_package_has_no_shell_or_mutation_constructs():
    sources = list(PACKAGE_DIR.glob("*.py"))
    assert sources, "steward_tools package not found"
    for path in sources:
        src = path.read_text(encoding="utf-8")
        assert "subprocess" not in src, f"{path.name}: shell construct"
        assert "os.system" not in src, f"{path.name}: shell construct"
    # The READ path stays read-only by construction: client.py and
    # tools.py contain no mutation-verb method strings (GET only).
    # mutations.py (issue #23) legitimately issues mutation requests —
    # its gate is covered by tests/test_steward_mutations.py.
    for name in ("client.py", "tools.py", "__init__.py"):
        src = (PACKAGE_DIR / name).read_text(encoding="utf-8")
        assert not re.search(r"\b(POST|PUT|DELETE)\b", src), \
            f"{name}: mutation-verb method string (read path is GET only)"


# --------------------------------------------------------------------------
# redirect policy
# --------------------------------------------------------------------------

class _RedirectHandler(BaseHTTPRequestHandler):
    """302s everything to server.redirect_target except /ok (JSON 200)."""

    def do_GET(self):
        if self.path == "/ok":
            body = json.dumps({"schema": "clusterd-health/v1",
                               "status": "ok"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(302)
        self.send_header("Location", self.server.redirect_target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture()
def redirect_server(tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), _RedirectHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    token_file = tmp_path / "read-token"
    token_file.write_text("dummy", encoding="utf-8")
    yield srv, token_file
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


def test_redirect_to_other_origin_refused(redirect_server, monkeypatch):
    srv, token_file = redirect_server
    srv.redirect_target = "http://10.255.255.1:8785/v1/health"
    monkeypatch.setenv("CLUSTERD_URL",
                       f"http://127.0.0.1:{srv.server_address[1]}")
    c = steward_client.ClusterdClient(token_path=str(token_file))
    with pytest.raises(steward_client.CrossOriginRedirect):
        c.health()


def test_same_origin_redirect_followed(redirect_server, monkeypatch):
    srv, token_file = redirect_server
    port = srv.server_address[1]
    srv.redirect_target = f"http://127.0.0.1:{port}/ok"
    monkeypatch.setenv("CLUSTERD_URL", f"http://127.0.0.1:{port}")
    c = steward_client.ClusterdClient(token_path=str(token_file))
    status, payload, _headers = c.health()
    assert status == 200
    assert payload["status"] == "ok"


# --------------------------------------------------------------------------
# client construction rules
# --------------------------------------------------------------------------

def test_base_url_is_construction_time_constant(monkeypatch):
    monkeypatch.delenv("CLUSTERD_URL", raising=False)
    c = steward_client.ClusterdClient(token_path="/nonexistent")
    assert c.base_url == steward_client.DEFAULT_BASE_URL
    monkeypatch.setenv("CLUSTERD_URL", "http://127.0.0.1:9999/")
    c2 = steward_client.ClusterdClient(token_path="/nonexistent")
    assert c2.base_url == "http://127.0.0.1:9999"  # env honored, / stripped
    # ...and the first instance is NOT repointed by the later env change
    assert c.base_url == steward_client.DEFAULT_BASE_URL


# --------------------------------------------------------------------------
# cluster_logs input bounds
# --------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["../etc", "a;b", "a" * 40, "", "-x", "Abc",
                                 "x y", "x.y", ".."])
def test_cluster_logs_rejects_invalid_names(bad):
    with pytest.raises(ValueError):
        tools.cluster_logs(bad)


def test_cluster_logs_name_also_rejected_by_client(client):
    with pytest.raises(ValueError):
        client.logs("../etc", 50)


def test_cluster_logs_lines_clamped_to_200(server, client):
    res = tools.cluster_logs(NAME, lines=99999, client=client)
    assert res["ok"] is True
    # 250 fake log lines exist; the steward clamp binds the request to 200.
    assert res["data"]["line_count"] == 200
    assert len(res["data"]["lines"]) == 200


def test_cluster_logs_defaults_and_lower_clamp(server, client):
    res = tools.cluster_logs(NAME, client=client)  # default 50
    assert res["data"]["line_count"] == 50
    res = tools.cluster_logs(NAME, lines=0, client=client)  # clamps up to 1
    assert res["data"]["line_count"] == 1


def test_cluster_logs_404_becomes_degraded_not_exception(server, client):
    res = tools.cluster_logs("no-such-daimon", client=client)
    assert res["ok"] is False
    assert res["data"] is None
    assert res["degraded"] == ["clusterd-http-404"]


# --------------------------------------------------------------------------
# unreachable clusterd: explicit unknown state, never an exception
# --------------------------------------------------------------------------

@pytest.mark.parametrize("tool_call", [
    lambda c: tools.cluster_list(client=c),
    lambda c: tools.cluster_health(client=c),
    lambda c: tools.cluster_backups(client=c),
    lambda c: tools.cluster_logs(NAME, client=c),
])
def test_unreachable_clusterd_is_explicit_degraded(monkeypatch, tmp_path,
                                                   tool_call):
    monkeypatch.setenv("CLUSTERD_URL", _closed_port_url())
    token_file = tmp_path / "read-token"
    token_file.write_text("dummy", encoding="utf-8")
    c = steward_client.ClusterdClient(token_path=str(token_file))
    res = tool_call(c)  # must NOT raise
    assert res["schema"] == tools.SCHEMA
    assert res["ok"] is False
    assert res["data"] is None
    assert res["degraded"] == ["clusterd-unreachable"]


# --------------------------------------------------------------------------
# end-to-end against the fake-backed clusterd
# --------------------------------------------------------------------------

def test_cluster_list_projects_fleet(server, client):
    res = tools.cluster_list(client=client)
    assert res["ok"] is True
    assert res["stale"] is False
    assert res["degraded"] == []
    assert res["data"] == [{
        "name": NAME,
        "state": "running",
        "image_version": "tribe-base/2026-08-01.1",
        "uptime_s": 42,
    }]


def test_cluster_health_ok(server, client):
    res = tools.cluster_health(client=client)
    assert res["ok"] is True
    assert res["data"]["status"] == "ok"
    assert res["data"]["audit_chain_ok"] is True
    assert res["degraded"] == []


def test_cluster_health_degraded_names_subsystems(state_dir, tmp_path,
                                                  monkeypatch):
    class RaisingAdapter(FakeAdapter):
        def list_instances(self):
            raise RuntimeError("backend down")

    _declare(state_dir)
    _, raw_token = clusterd_auth.create_token(
        state_dir, actor="steward@daimonmatrix", scopes=["read"],
        owner="*", ttl_days=1)
    token_file = tmp_path / "read-token"
    token_file.write_text(raw_token, encoding="utf-8")
    deps = handlers.Deps(config_path=CONFIG_PATH, state_dir=str(state_dir),
                         adapter_factory=lambda: RaisingAdapter())
    srv = make_server(deps, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv(
            "CLUSTERD_URL", f"http://127.0.0.1:{srv.server_address[1]}")
        c = steward_client.ClusterdClient(token_path=str(token_file))
        res = tools.cluster_health(client=c)
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)
    assert res["ok"] is False
    assert res["data"]["status"] == "degraded"
    assert "clusterctl" in res["degraded"]


def test_cluster_backups_fresh(server, client, state_dir):
    _srv, _ad, sd, _tf = server
    _write_manifest(sd, NAME, audit.now_ms())
    res = tools.cluster_backups(client=client)
    assert res["ok"] is True
    assert res["stale"] is False
    entry = res["data"][0]
    assert entry["name"] == NAME
    assert entry["verified_readable"] is True
    assert 0 <= entry["age_ms"] < 60_000


def test_cluster_backups_stale_past_26h(server, client):
    _srv, _ad, sd, _tf = server
    old_ms = audit.now_ms() - 27 * 3600 * 1000
    _write_manifest(sd, NAME, old_ms)
    res = tools.cluster_backups(client=client)
    assert res["ok"] is True
    assert res["stale"] is True  # RPO 6h + margin = 26h
    assert res["data"][0]["age_ms"] >= 27 * 3600 * 1000


def test_cluster_backups_empty_is_stale(server, client):
    res = tools.cluster_backups(client=client)
    assert res["ok"] is True
    assert res["data"] == []
    assert res["stale"] is True
    assert "no-backup-manifests" in res["degraded"]


def test_logs_route_redaction_end_to_end(state_dir, tmp_path, monkeypatch):
    """A 'PRIVATE KEY' log line comes back [REDACTED] through the whole
    stack: steward tool -> clusterd logs route -> clusterctl redaction."""
    secret_lines = [
        "boot ok",
        "-----BEGIN PRIVATE KEY-----",
        "token=abc123",
        "bearer xyz",
        "done",
    ]
    _declare(state_dir)
    ad = _adapter(log_lines={NAME: secret_lines})
    _, raw_token = clusterd_auth.create_token(
        state_dir, actor="steward@daimonmatrix", scopes=["read"],
        owner="*", ttl_days=1)
    token_file = tmp_path / "read-token"
    token_file.write_text(raw_token, encoding="utf-8")
    deps = handlers.Deps(config_path=CONFIG_PATH, state_dir=str(state_dir),
                         adapter_factory=lambda: ad)
    srv = make_server(deps, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv(
            "CLUSTERD_URL", f"http://127.0.0.1:{srv.server_address[1]}")
        c = steward_client.ClusterdClient(token_path=str(token_file))
        res = tools.cluster_logs(NAME, lines=50, client=c)
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)
    assert res["ok"] is True
    lines = res["data"]["lines"]
    assert "PRIVATE KEY" not in "\n".join(lines)
    assert "abc123" not in "\n".join(lines)
    assert lines.count("[REDACTED]") >= 3
    assert res["data"]["redacted_count"] >= 3
    assert "boot ok" in lines  # non-secret lines survive untouched


def test_every_tool_result_carries_envelope_source_ts(server, client):
    _srv, _ad, sd, _tf = server
    _write_manifest(sd, NAME, audit.now_ms())
    results = [
        tools.cluster_list(client=client),
        tools.cluster_health(client=client),
        tools.cluster_backups(client=client),
        tools.cluster_logs(NAME, client=client),
    ]
    now_ms = int(time.time() * 1000)
    for res in results:
        assert res["schema"] == "steward-tool-result/v1"
        assert res["ok"] is True
        ts = res["source_ts_ms"]
        assert isinstance(ts, int)
        # From the clusterd HTTP Date envelope header: within a minute.
        assert abs(now_ms - ts) < 60_000
