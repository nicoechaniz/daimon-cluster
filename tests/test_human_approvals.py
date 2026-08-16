"""Adversarial clusterd least-authority and human-approval tests."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from clusterctl.adapters import FakeAdapter
from clusterctl.fences import Ed25519Signer
from clusterd import approvals, auth, handlers
from clusterd.server import make_server

NAME = "daimon-x"
IDEM = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"


def _declare(state_dir: Path, *, owner: str | None = "alice") -> None:
    directory = state_dir / "instances"
    directory.mkdir(parents=True, exist_ok=True)
    value = {
        "schema": "instance-spec/v1",
        "name": NAME,
        "image_version": "v1",
    }
    if owner is not None:
        value["created_by"] = owner
    (directory / f"{NAME}.yaml").write_text(
        yaml.safe_dump(value), encoding="utf-8"
    )


def _signer(path: Path, key_id: str = "human:test") -> Ed25519Signer:
    private = Ed25519PrivateKey.generate()
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return Ed25519Signer(path, key_id)


@pytest.fixture()
def server(tmp_path):
    state_dir = tmp_path / "state"
    _declare(state_dir)
    adapter = FakeAdapter(
        instances=[
            {
                "name": NAME,
                "state": "running",
                "image_version": "v1",
                "budgets": {},
                "uptime_s": 1,
            }
        ]
    )
    deps = handlers.Deps(
        config_path="configs/clusterctl.yaml",
        state_dir=str(state_dir),
        adapter_factory=lambda: adapter,
    )
    srv = make_server(deps, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv, adapter, state_dir
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def _token(state_dir: Path, *, actor: str, scopes: list[str], owner: str = "*"):
    record, raw = auth.create_token(
        state_dir, actor=actor, scopes=scopes, owner=owner, ttl_days=1
    )
    return record, raw


def _request(srv, method: str, path: str, token: str, *, headers=None, body=None):
    request_headers = dict(headers or {})
    request_headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"http://127.0.0.1:{srv.server_address[1]}{path}",
        method=method,
        headers=request_headers,
        data=data,
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _approval_for(response: dict, signer: Ed25519Signer) -> str:
    intent = {
        key: value
        for key, value in response.items()
        if key not in {"error", "request_id"}
    }
    return approvals.encode_approval(approvals.sign_intent(signer, intent))


def test_attended_header_cannot_self_assert_human_presence(server, tmp_path):
    srv, adapter, state_dir = server
    _record, token = _token(
        state_dir, actor="steward@test", scopes=["lifecycle:write"]
    )
    status, body = _request(
        srv,
        "POST",
        f"/v1/instances/{NAME}/stop",
        token,
        headers={"Idempotency-Key": IDEM, "X-Attended": "true"},
        body={},
    )
    assert status == 409
    assert body["error"] == "human-approval-required"
    assert body["schema"] == approvals.INTENT_SCHEMA
    assert adapter.mutation_log == []


def test_separate_authority_approval_is_bound_single_use(server, tmp_path):
    srv, adapter, state_dir = server
    record, token = _token(
        state_dir, actor="steward@test", scopes=["lifecycle:write"]
    )
    signer = _signer(tmp_path / "human.pem")
    approvals.register_authority(
        state_dir, key_id=signer.key_id, public_key=signer.public_key
    )
    status, intent = _request(
        srv,
        "POST",
        f"/v1/instances/{NAME}/stop",
        token,
        headers={"Idempotency-Key": IDEM},
        body={},
    )
    assert status == 409 and intent["token_id"] == record["token_id"]
    encoded = _approval_for(intent, signer)
    headers = {"Idempotency-Key": IDEM, "X-Human-Approval": encoded}
    assert _request(
        srv, "POST", f"/v1/instances/{NAME}/stop", token, headers=headers, body={}
    )[0] == 200
    status, body = _request(
        srv, "POST", f"/v1/instances/{NAME}/stop", token, headers=headers, body={}
    )
    assert status == 403 and body["error"] == "human-approval-denied"
    assert adapter.mutation_log == [("stop", NAME)]


def test_approval_rejects_token_target_body_state_and_revocation(server, tmp_path):
    srv, adapter, state_dir = server
    _record, token = _token(
        state_dir, actor="steward@test", scopes=["lifecycle:write"]
    )
    _other_record, other_token = _token(
        state_dir, actor="steward@test", scopes=["lifecycle:write"]
    )
    signer = _signer(tmp_path / "human.pem")
    approvals.register_authority(
        state_dir, key_id=signer.key_id, public_key=signer.public_key
    )
    _, intent = _request(
        srv,
        "POST",
        f"/v1/instances/{NAME}/stop",
        token,
        headers={"Idempotency-Key": IDEM},
        body={},
    )
    encoded = _approval_for(intent, signer)
    headers = {"Idempotency-Key": IDEM, "X-Human-Approval": encoded}
    status, _ = _request(
        srv,
        "POST",
        f"/v1/instances/{NAME}/stop",
        other_token,
        headers=headers,
        body={},
    )
    assert status == 403
    # Changing current target bytes invalidates the unconsumed approval.
    _declare(state_dir, owner="changed-owner")
    status, _ = _request(
        srv,
        "POST",
        f"/v1/instances/{NAME}/stop",
        token,
        headers=headers,
        body={},
    )
    assert status == 403
    assert adapter.mutation_log == []


def test_exact_scopes_do_not_cross_operation_classes(server):
    srv, adapter, state_dir = server
    _record, token = _token(
        state_dir, actor="alice", scopes=["lifecycle:write"]
    )
    status, body = _request(
        srv,
        "POST",
        f"/v1/instances/{NAME}/snapshot",
        token,
        headers={"Idempotency-Key": IDEM},
        body={},
    )
    assert status == 403 and body["error"] == "insufficient-scope"
    assert adapter.mutation_log == []


def test_owner_scoped_token_rejects_missing_owner(server):
    srv, adapter, state_dir = server
    _declare(state_dir, owner=None)
    _record, token = _token(
        state_dir, actor="alice", scopes=["fleet:read"], owner="alice"
    )
    status, body = _request(
        srv, "GET", f"/v1/instances/{NAME}", token
    )
    assert status == 403 and body["error"] == "not your daimon"
    assert adapter.mutation_log == []


def _direct_intent(state_dir: Path, *, now_ms: int = 1_000) -> dict:
    return approvals.issue_intent(
        state_dir,
        token_id="token:test",
        actor="steward@test",
        operation="stopInstance",
        method="POST",
        path=f"/v1/instances/{NAME}/stop",
        target=NAME,
        args={},
        now_ms=now_ms,
    )


def _consume_direct(state_dir: Path, encoded: str, *, now_ms: int = 1_001):
    return approvals.consume_approval(
        state_dir,
        encoded,
        token_id="token:test",
        actor="steward@test",
        operation="stopInstance",
        method="POST",
        path=f"/v1/instances/{NAME}/stop",
        target=NAME,
        args={},
        now_ms=now_ms,
    )


def test_revoked_expired_and_tampered_approvals_fail_closed(tmp_path):
    state_dir = tmp_path / "state"
    _declare(state_dir)
    signer = _signer(tmp_path / "human.pem")
    approvals.register_authority(
        state_dir, key_id=signer.key_id, public_key=signer.public_key
    )
    intent = _direct_intent(state_dir)
    approval = approvals.sign_intent(signer, intent)
    tampered = json.loads(json.dumps(approval))
    tampered["intent"]["operation"] = "startInstance"
    with pytest.raises(approvals.ApprovalError):
        _consume_direct(state_dir, approvals.encode_approval(tampered))
    with pytest.raises(approvals.ApprovalError, match="expired"):
        _consume_direct(
            state_dir, approvals.encode_approval(approval), now_ms=400_001
        )
    approvals.revoke_authority(state_dir, signer.key_id)
    with pytest.raises(approvals.ApprovalError, match="authority-unknown"):
        _consume_direct(state_dir, approvals.encode_approval(approval))


def test_concurrent_replay_has_exactly_one_consumer(tmp_path):
    state_dir = tmp_path / "state"
    _declare(state_dir)
    signer = _signer(tmp_path / "human.pem")
    approvals.register_authority(
        state_dir, key_id=signer.key_id, public_key=signer.public_key
    )
    encoded = approvals.encode_approval(
        approvals.sign_intent(signer, _direct_intent(state_dir))
    )
    barrier = threading.Barrier(3)
    results: list[str] = []

    def contender() -> None:
        barrier.wait()
        try:
            _consume_direct(state_dir, encoded)
        except approvals.ApprovalError as exc:
            results.append(exc.reason)
        else:
            results.append("accepted")

    threads = [threading.Thread(target=contender) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)
    assert sorted(results) == ["accepted", "human-approval-replayed"]
