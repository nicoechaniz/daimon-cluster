"""Real signed Matrix runtime through the unchanged installed clusterd consumer.

All authority, keys, sockets and state are disposable synthetic fixtures.
No live Incus, Docker, remote host or production custody is used.
"""
import json
from pathlib import Path
import tempfile
import threading
import time

import pytest

from clusterctl.adapters import FakeAdapter
from clusterctl.matrix_host import MatrixHostAdapter, matrix_client_factory
from clusterctl.matrix_fencing.fences import FenceError
from clusterd.auth import create_token
from clusterd.handlers import Deps
from clusterd.server import make_server
import test_clusterd as http_fixture
import test_matrix_host_process as runtime_fixture


def test_missing_modern_authority_refuses_without_creating_placeholder(tmp_path):
    with pytest.raises(FenceError, match="production fence database is unavailable"):
        MatrixHostAdapter(tmp_path, "embodiment:missing")
    assert not (tmp_path / "resource-fences.sqlite3").exists()


def test_old_http_consumer_reads_real_five_method_client_and_enforces_old_auth():
    with tempfile.TemporaryDirectory(prefix="dmm-http-") as name:
        state = Path(name) / "state"
        now = time.time_ns() // 1_000_000
        authority = runtime_fixture._authority(now)
        origin = authority["origins"]["legion"]
        registry = runtime_fixture.Registry(state)
        registry.register(body_ref=origin["body_ref"], embodiment_id=origin["embodiment_id"])
        registry.start(origin["embodiment_id"], incarnation_id=origin["incarnation_id"], started_at_ms=now)
        root, bundle, _, host_capabilities = runtime_fixture._write_runtime(state, authority, "legion", now)
        runtime_fixture._write_client_config(
            state, host_capabilities["status"], origin,
            runtime_id=bundle["runtime_id"], runtime_label=bundle["runtime_label"],
        )
        process, _ = runtime_fixture._spawn(state, origin["embodiment_id"])
        server = None
        thread = None
        try:
            factory = matrix_client_factory(state)
            client = factory(origin["embodiment_id"])
            for call in (
                client.runtime_status, client.scope_me, client.scope_we, client.scope_diff,
                lambda: client.scope_sync_plan({"request_id": "40000000-0000-4000-8000-000000000001", "limit": 100}),
            ):
                response = call()
                assert isinstance(response, tuple) and len(response) == 2
                assert response[1]["ok"] is True, response
            adapter = FakeAdapter(instances=[])
            _, token = create_token(state, actor="synthetic-reader", scopes=["read"], owner="*", ttl_days=1)
            server = make_server(
                Deps(config_path="configs/clusterctl.yaml", state_dir=str(state),
                     adapter_factory=lambda: adapter, matrix_client_factory=factory),
                "127.0.0.1", 0,
            )
            server.test_token = token
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            status, _, denied = http_fixture._get(server, "/v1/weave/status", auth=False)
            assert status == 401
            assert "embodiments" not in denied
            status, _, body = http_fixture._get(server, "/v1/weave/status")
            assert status == 200, body
            assert body["configured"] is True
            assert body["matrix_contract_commit"] == "0a80cc5c38d3c7f5cad98d440153f0cf9706686b"
            row = body["embodiments"][0]
            assert row["me"]["body"]["state"] == "running"
            assert row["me"]["body"]["resource_fences"] == []
            assert row["runtime"]["integrity"] == "ok"
            encoded = json.dumps(body)
            for forbidden in (str(root), "client.key", "custody.json", '"endpoint"', '"payload"', runtime_fixture.PASSWORD.decode()):
                assert forbidden not in encoded
            status, _, _ = http_fixture._req(server, "POST", "/v1/instances/missing/start")
            assert status == 403
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if thread is not None:
                thread.join(timeout=5)
            runtime_fixture._stop(process)
