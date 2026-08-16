#!/usr/bin/env python3
"""Reproducible H4 read-model drill against an isolated clusterd server.

The drill uses a temporary state directory and FakeAdapter.  It starts a real
HTTP server on an ephemeral loopback port, authenticates owner-scoped tokens,
and destroys all scratch state on exit.  No token or private material is
printed.
"""

from __future__ import annotations

import argparse
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from clusterctl import audit
from clusterctl.adapters import FakeAdapter
from clusterctl.embodiments import Registry
from clusterd import auth, handlers, paging
from clusterd.server import make_server

ALICE_EMBODIMENT = "embodiment:11111111-1111-4111-8111-111111111111"
ALICE_INCARNATION = "incarnation:22222222-2222-4222-8222-222222222222"
BOB_EMBODIMENT = "embodiment:33333333-3333-4333-8333-333333333333"
BOB_INCARNATION = "incarnation:44444444-4444-4444-8444-444444444444"


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError(reason)


def _spec(
    state_dir: Path, name: str, owner: str, embodiment_id: str,
    incarnation_id: str,
) -> None:
    path = state_dir / "instances" / f"{name}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({
        "schema": "instance-spec/v1",
        "name": name,
        "species": "drill",
        "image_version": "v1",
        "budgets": {},
        "created_by": owner,
        "body_ref": f"body:{owner}",
        "embodiment_id": embodiment_id,
        "current_incarnation_id": incarnation_id,
    }), encoding="utf-8")


class _MatrixClient:
    @staticmethod
    def _response(result):
        return {}, {"ok": True, "result": result}

    def runtime_status(self):
        return self._response({
            "schema": "dm.runtime.status/v1",
            "integrity": "ok",
            "ledger_schema_version": 3,
            "counts": {
                "known_events": 10, "incomplete_events": 0,
                "pending_rpc": 0,
            },
            "authority_epoch": {},
        })

    def scope_me(self):
        return self._response({
            "schema": "dm.scope.me/v1",
            "being_ref": "being:drill",
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
                {"embodiment_id": ALICE_EMBODIMENT, "availability": "local"},
                {"embodiment_id": "embodiment:peer", "availability": "available",
                 "route": {"endpoint": "https://must-not-pass.invalid"}},
            ],
            "partial": False,
        })

    def scope_diff(self):
        return self._response({
            "schema": "dm.scope.we-diff/v1",
            "entries": [
                {
                    "event_id": f"event:{index}",
                    "state": "pending",
                    "kind": "claim",
                    "subject": f"subject:{index}",
                    "payload": {"secret": "must-not-pass"},
                }
                for index in range(450)
            ],
            "origin_summaries": [],
        })

    def scope_sync_plan(self, params):
        return self._response({
            "schema": "dm.scope.sync-plan/v1",
            "plan_id": params["request_id"],
            "targets": [],
            "partial": False,
        })


def _get(base: str, path: str, token: str) -> tuple[int, dict]:
    request = urllib.request.Request(
        base + path,
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def run() -> dict:
    with TemporaryDirectory(prefix="daimon-h4-read-model-") as temporary:
        state_dir = Path(temporary)
        _spec(
            state_dir, "alice-one", "alice", ALICE_EMBODIMENT,
            ALICE_INCARNATION,
        )
        _spec(
            state_dir, "bob-one", "bob", BOB_EMBODIMENT, BOB_INCARNATION,
        )
        registry = Registry(state_dir)
        registry.register(body_ref="body:alice", embodiment_id=ALICE_EMBODIMENT)
        registry.start(ALICE_EMBODIMENT, incarnation_id=ALICE_INCARNATION)
        registry.register(body_ref="body:bob", embodiment_id=BOB_EMBODIMENT)
        registry.start(BOB_EMBODIMENT, incarnation_id=BOB_INCARNATION)
        adapter = FakeAdapter(instances=[
            {
                "name": "alice-one", "state": "running",
                "image_version": "v1", "budgets": {}, "uptime_s": 1,
            },
            {
                "name": "bob-one", "state": "running",
                "image_version": "v1", "budgets": {}, "uptime_s": 1,
            },
            {
                "name": "undeclared", "state": "running",
                "image_version": "v1", "budgets": {}, "uptime_s": 1,
            },
        ])
        _, alice_token = auth.create_token(
            state_dir, actor="alice", scopes=["fleet:read"], owner="alice",
            ttl_days=1,
        )
        _, bob_token = auth.create_token(
            state_dir, actor="bob", scopes=["fleet:read"], owner="bob", ttl_days=1,
        )
        deps = handlers.Deps(
            config_path="configs/clusterctl.yaml",
            state_dir=str(state_dir),
            adapter_factory=lambda: adapter,
            matrix_client_factory=lambda _identifier: _MatrixClient(),
        )
        server = make_server(deps, "127.0.0.1", 0)
        server.RequestHandlerClass.log_message = lambda *_args: None
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            status, instances = _get(base, "/v1/instances?limit=1", alice_token)
            _require(status == 200, "instances-http")
            _require(instances.get("schema") == "clusterd-page/v1", "page-schema")
            _require(
                [row.get("name") for row in instances["items"]] == ["alice-one"],
                "instance-owner-scope",
            )
            observations = instances["items"][0]["observations"]
            _require(observations["runtime"]["state"] == "running", "runtime-state")
            _require(observations["embodiment"]["state"] == "running",
                     "embodiment-state")
            _require(observations["matrix_process"]["state"] == "available",
                     "matrix-process-state")

            for index in range(4):
                audit.append_event(
                    state_dir, actor="alice", action="before-snapshot",
                    target="alice-one", result="ok",
                    request_id=f"audit:{index}",
                )
            status, first = _get(base, "/v1/audit?limit=2", alice_token)
            _require(status == 200 and first["page"]["has_more"], "audit-first")
            audit.append_event(
                state_dir, actor="alice", action="after-snapshot",
                target="alice-one", result="ok",
            )
            cursor = first["page"]["next_cursor"]
            encoded_cursor = urllib.parse.quote(cursor, safe="")
            status, second = _get(
                base, f"/v1/audit?limit=2&cursor={encoded_cursor}", alice_token
            )
            _require(status == 200, "audit-resume")
            events = first["items"] + second["items"]
            _require(len({row["event_id"] for row in events}) == 4,
                     "audit-skip-or-duplicate")
            _require(all(row["action"] != "after-snapshot" for row in events),
                     "audit-snapshot-instability")
            status, mismatch = _get(
                base, f"/v1/audit?limit=2&cursor={encoded_cursor}", bob_token
            )
            _require(status == 400 and mismatch.get("error") == "cursor-scope-mismatch",
                     "cursor-owner-binding")
            status, tampered = _get(
                base, f"/v1/audit?limit=2&cursor={encoded_cursor}x", alice_token
            )
            _require(status == 400 and tampered.get("error") == "invalid-cursor",
                     "cursor-integrity")

            status, matrix = _get(base, "/v1/weave/status", alice_token)
            _require(status == 200 and len(matrix["embodiments"]) == 1,
                     "matrix-owner-scope")
            row = matrix["embodiments"][0]
            _require(row["owner_local"]["queue"]["state"] == "clean",
                     "owner-local-queue")
            _require(row["peer_sync"]["reachability"]["state"] == "available",
                     "peer-reachability")
            _require(row["peer_sync"]["known_difference_count"] == 450,
                     "known-difference-count")
            _require(row["peer_sync"]["caught_up"]["state"] == "no",
                     "caught-up-honesty")
            encoded_matrix = json.dumps(matrix)
            _require("must-not-pass" not in encoded_matrix,
                     "matrix-status-redaction")

            difference_path = (
                "/v1/weave/differences?embodiment_id="
                + urllib.parse.quote(ALICE_EMBODIMENT, safe="")
                + "&limit=200"
            )
            pages = []
            status, page = _get(base, difference_path, alice_token)
            while True:
                _require(status == 200, "difference-page-http")
                pages.append(page)
                if not page["page"]["has_more"]:
                    break
                next_cursor = urllib.parse.quote(
                    page["page"]["next_cursor"], safe=""
                )
                status, page = _get(
                    base, difference_path + "&cursor=" + next_cursor,
                    alice_token,
                )
            difference_items = [item for page in pages for item in page["items"]]
            _require(len(difference_items) == 450, "difference-page-count")
            _require(len({item["event_id"] for item in difference_items}) == 450,
                     "difference-skip-or-duplicate")
            _require("payload" not in json.dumps(pages), "difference-redaction")

            clock = [10.0]
            short_pager = paging.SnapshotPager(
                ttl_s=0.01, monotonic=lambda: clock[0]
            )
            binding = short_pager.binding("drill", "alice")
            page = short_pager.first(
                [{"n": 1}, {"n": 2}], binding=binding, limit=1,
                observed_at_ms=1,
            )
            clock[0] = 11.0
            try:
                short_pager.resume(
                    page["page"]["next_cursor"], binding=binding, limit=1
                )
            except paging.CursorError as exc:
                _require(exc.stale and exc.reason == "stale-cursor",
                         "stale-cursor-classification")
            else:
                raise RuntimeError("stale-cursor-accepted")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    return {
        "schema": "h4-read-model-drill/v1",
        "ok": True,
        "server": "ephemeral-loopback",
        "state": "temporary-removed",
        "instance_owner_scope": "verified",
        "audit_snapshot_append_boundary": "verified",
        "cursor_integrity_scope_expiry": "verified",
        "matrix_local_peer_separation": "verified",
        "difference_items": 450,
        "difference_pages": 3,
        "redaction": "verified",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    receipt = run()
    if args.json:
        print(json.dumps(receipt, sort_keys=True))
    else:
        for key, value in receipt.items():
            print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
