"""Test-owned HTTP helpers must release HTTPError even when decoding fails."""
import io
import json
from types import SimpleNamespace
from unittest.mock import Mock
import urllib.error
import urllib.request

import pytest

from steward_tools.client import ClusterdClient, ClusterdHTTPError, TIMEOUT_S
from steward_tools.mutations import MutationClient
from tests import test_auth, test_clusterd


@pytest.mark.parametrize("helper", ["auth", "request", "post_json"])
@pytest.mark.parametrize("payload", [b'{"error": "denied"}', b"\xff"])
def test_http_helpers_close_error(monkeypatch, helper, payload):
    response = io.BytesIO(payload)
    error = urllib.error.HTTPError(
        "http://127.0.0.1:1/denied", 403, "Forbidden", {"X-Test": "kept"}, response
    )
    close = Mock(wraps=error.close)
    monkeypatch.setattr(error, "close", close)
    monkeypatch.setattr(urllib.request, "urlopen", Mock(side_effect=error))
    server = SimpleNamespace(server_address=("127.0.0.1", 1))

    def invoke():
        if helper == "auth":
            return test_auth._req(server, "GET", "/denied")
        if helper == "request":
            return test_clusterd._req(server, "GET", "/denied")
        return test_clusterd._post_json(server, "/denied", {})

    try:
        if payload == b"\xff":
            with pytest.raises(UnicodeDecodeError):
                invoke()
        else:
            result = invoke()
            assert result[0] == 403
            if helper == "auth":
                assert result[1] == {"error": "denied"}
            else:
                assert result[1] == {"X-Test": "kept"}
                assert result[2] == (
                    payload.decode() if helper == "request" else json.loads(payload)
                )
        close.assert_called_once_with()
        assert response.closed
    finally:
        # Keep the regression's failing version clean: inspect before teardown.
        error.close()


@pytest.mark.parametrize("client_type", [ClusterdClient, MutationClient])
@pytest.mark.parametrize("payload", [b'{"error": "denied"}', b"not JSON", b"\xff"])
def test_product_clients_close_error(monkeypatch, tmp_path, client_type, payload):
    token_path = tmp_path / "token"
    token_path.write_text("synthetic-token\n")
    client = client_type(token_path=str(token_path), base_url="http://127.0.0.1:1")
    response = io.BytesIO(payload)
    error = urllib.error.HTTPError(
        "http://127.0.0.1:1/v1/instances", 403, "Forbidden", {}, response
    )
    close = Mock(wraps=error.close)
    monkeypatch.setattr(error, "close", close)
    open_response = Mock(side_effect=error)
    monkeypatch.setattr(client._opener, "open", open_response)
    try:
        with pytest.raises(ClusterdHTTPError) as caught:
            if client_type is ClusterdClient:
                client.instances()
            else:
                client._post("/v1/instances", {"X-Human-Turn": "synthetic-turn"})
        assert type(caught.value) is ClusterdHTTPError
        assert caught.value.status == 403
        assert caught.value.body == (
            {"error": "denied"} if payload.startswith(b"{") else None
        )
        assert str(caught.value) == "clusterd answered HTTP 403"
        assert caught.value.__cause__ is error
        open_response.assert_called_once()
        request = open_response.call_args.args[0]
        assert request.full_url == "http://127.0.0.1:1/v1/instances"
        assert request.get_header("Authorization") == "Bearer synthetic-token"
        assert open_response.call_args.kwargs == {"timeout": TIMEOUT_S}
        assert request.get_method() == (
            "GET" if client_type is ClusterdClient else "POST"
        )
        if client_type is MutationClient:
            assert request.data == b"{}"
            assert request.get_header("X-human-turn") == "synthetic-turn"
        close.assert_called_once_with()
        assert response.closed
    finally:
        # Teardown is after the ownership assertion, never a product finalizer.
        error.close()
