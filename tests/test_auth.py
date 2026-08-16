"""clusterd auth tests (issue #18) — scoped bearer, confirmations, replay."""
import json
import threading
import urllib.error
import urllib.request

import pytest
import yaml

from clusterctl.adapters import FakeAdapter
from clusterd import auth as clusterd_auth
from clusterd import handlers
from clusterd.server import make_server

NAME = "daimon-x"
CONFIG_PATH = "configs/clusterctl.yaml"
IDEM = "dddddddd-1111-2222-3333-444444444444"


@pytest.fixture()
def state_dir(tmp_path):
    return tmp_path / "state"


def _declare(state_dir, name=NAME, created_by="tester"):
    inst_dir = state_dir / "instances"
    inst_dir.mkdir(parents=True, exist_ok=True)
    (inst_dir / f"{name}.yaml").write_text(yaml.safe_dump({
        "schema": "instance-spec/v1", "name": name,
        "instance_kind": "generic-instance", "image_version": "v1",
        "created_by": created_by,
    }), encoding="utf-8")


@pytest.fixture()
def server(state_dir):
    _declare(state_dir)
    ad = FakeAdapter(instances=[{"name": NAME, "state": "running",
                                 "image_version": "v1", "budgets": {},
                                 "uptime_s": 1}])
    deps = handlers.Deps(config_path=CONFIG_PATH, state_dir=str(state_dir),
                         adapter_factory=lambda: ad)
    srv = make_server(deps, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv, ad, state_dir
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


def _req(srv, method, path, token=None, headers=None):
    url = f"http://127.0.0.1:{srv.server_address[1]}{path}"
    h = dict(headers or {})
    if token:
        h["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        return exc.code, json.loads(body) if body else {}


def _token(state_dir, actor="tester", scopes=None, owner="*", ttl_days=1):
    scopes = tuple(clusterd_auth.VALID_SCOPES) if scopes is None else scopes
    _, raw = clusterd_auth.create_token(state_dir, actor=actor,
                                        scopes=list(scopes), owner=owner,
                                        ttl_days=ttl_days)
    return raw


def test_missing_and_unknown_token_401(server):
    srv, _, _ = server
    assert _req(srv, "GET", "/v1/instances")[0] == 401
    assert _req(srv, "GET", "/v1/instances", token="dcd_wrong")[0] == 401


def test_health_is_public(server):
    srv, _, _ = server
    status, body = _req(srv, "GET", "/v1/health")
    assert status == 200 and body["status"] == "ok"


def test_valid_token_reads(server):
    srv, _, state_dir = server
    tok = _token(state_dir)
    assert _req(srv, "GET", "/v1/instances", token=tok)[0] == 200


def test_read_scope_cannot_mutate(server):
    srv, _, state_dir = server
    tok = _token(state_dir, scopes=("fleet:read",))
    status, body = _req(srv, "POST", f"/v1/instances/{NAME}/stop", token=tok,
                        headers={"Idempotency-Key": IDEM})
    assert status == 403 and body["error"] == "insufficient-scope"


def test_revocation_without_restart(server):
    srv, _, state_dir = server
    tok = _token(state_dir, actor="revokee")
    assert _req(srv, "GET", "/v1/instances", token=tok)[0] == 200
    rec = clusterd_auth.TokenStore(state_dir).resolve(tok)
    clusterd_auth.revoke_token(state_dir, rec["token_id"])
    status, body = _req(srv, "GET", "/v1/instances", token=tok)
    assert status == 401 and body["error"] == "unauthorized"


def test_owner_cannot_touch_anothers_daimon(server):
    srv, _, state_dir = server  # spec created_by "tester"
    tok = _token(state_dir, actor="mallory", owner="mallory")
    assert _req(srv, "GET", f"/v1/instances/{NAME}", token=tok)[0] == 403


def test_unattended_steward_requires_cryptographic_approval(server):
    srv, _, state_dir = server
    tok = _token(
        state_dir,
        actor="steward@daimonmatrix",
        scopes=("lifecycle:write",),
    )
    status, body = _req(srv, "POST", f"/v1/instances/{NAME}/stop", token=tok,
                        headers={"Idempotency-Key": IDEM})
    assert status == 409 and body["error"] == "human-approval-required"
    status, body = _req(
        srv,
        "POST",
        f"/v1/instances/{NAME}/stop",
        token=tok,
        headers={"Idempotency-Key": IDEM, "X-Attended": "true"},
    )
    assert status == 409 and body["error"] == "human-approval-required"


def test_destroy_challenge_and_confirm_binding(server):
    srv, _, state_dir = server
    tok = _token(state_dir)
    status, ch = _req(srv, "POST", f"/v1/instances/{NAME}/destroy", token=tok,
                      headers={"Idempotency-Key": IDEM})
    assert status == 409 and ch["schema"] == "confirmation/v1"
    # wrong actor presenting the challenge -> rejected (401 or 409)
    tok2 = _token(state_dir, actor="mallory")
    status, _ = _req(srv, "POST", f"/v1/instances/{NAME}/destroy", token=tok2,
                     headers={"Idempotency-Key": IDEM,
                              "X-Confirm-Token": ch["token"]})
    assert status in (401, 409)
    # wrong target
    status, _ = _req(srv, "POST", "/v1/instances/other/destroy", token=tok,
                     headers={"Idempotency-Key": IDEM,
                              "X-Confirm-Token": ch["token"]})
    assert status in (404, 409)
    # correct confirm -> single-use consume (501 = execution later milestone)
    status, _ = _req(srv, "POST", f"/v1/instances/{NAME}/destroy", token=tok,
                     headers={"Idempotency-Key": IDEM,
                              "X-Confirm-Token": ch["token"]})
    assert status == 501
    # reuse -> rejected
    status, _ = _req(srv, "POST", f"/v1/instances/{NAME}/destroy", token=tok,
                     headers={"Idempotency-Key": IDEM,
                              "X-Confirm-Token": ch["token"]})
    assert status == 409


def test_audit_denials_without_token_material(server):
    srv, _, state_dir = server
    secret = _token(state_dir, actor="leakcheck")
    _req(srv, "GET", "/v1/instances", token="dcd_nonexistent")
    log = (state_dir / "audit.jsonl").read_text()
    assert "dcd_nonexistent" not in log and secret not in log
    events = [json.loads(l) for l in log.strip().splitlines()]
    denied = [e for e in events if e["result"] == "denied"]
    assert denied and all("request_id" in (e.get("detail") or {}) for e in denied)


def test_store_keeps_only_hashes(state_dir):
    _declare(state_dir)
    raw = _token(state_dir)
    data = json.loads((state_dir / "auth" / "tokens.json").read_text())
    assert raw not in json.dumps(data)
    rec = data["tokens"][-1] if "tokens" in data else data[-1]
    assert rec["sha256_of_token"] and "token" not in rec
