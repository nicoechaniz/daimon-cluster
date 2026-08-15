import json

from clusterctl.embodiments import Registry
from clusterd import __main__ as clusterd_main
from clusterd.handlers import Deps, RequestContext, weave_status

EMBODIMENT = "embodiment:11111111-1111-4111-8111-111111111111"
INCARNATION = "incarnation:22222222-2222-4222-8222-222222222222"
BODY = "cluster:test:compaii"
ORIGIN = {
    "body_ref": BODY,
    "embodiment_id": EMBODIMENT,
    "incarnation_id": INCARNATION,
    "principal_id": "compaii@test",
}
PROJECTION = {
    "schema": "dm.we.projection/v1",
    "being_ref": "being:test",
    "manifest_hash": "a" * 64,
    "local_embodiment_id": EMBODIMENT,
    "entries": [],
    "projection_hash": "b" * 64,
}


class MatrixClient:
    @staticmethod
    def _response(result):
        return {}, {"ok": True, "result": result}

    def runtime_status(self):
        return self._response(
            {
                "schema": "dm.runtime.status/v1",
                "being_ref": "being:test",
                "manifest_hash": "a" * 64,
                "local_origin": ORIGIN,
                "ledger_schema_version": 3,
                "integrity": "ok",
                "counts": {"known_events": 0, "private": "/secret/count"},
                "authority_epoch": {
                    "schema": "dm.we.authority-epoch-status/v1",
                    "active_manifest_hash": "a" * 64,
                    "accepted_manifest_hashes": ["a" * 64],
                    "epoch_count": 1,
                },
                "private_path": "/secret/runtime",
            }
        )

    def scope_me(self):
        return self._response(
            {
                "schema": "dm.scope.me/v1",
                "being_ref": "being:test",
                "manifest_hash": "a" * 64,
                "evaluated_at_ms": 1,
                "origin": ORIGIN,
                "credential_ref": "credential:test",
                "incarnation_authorization_ref": "incarnation-auth:test",
                "body_capabilities": ["incus.inspect/v1"],
                "body": {
                    "schema": "dm.cluster-body-snapshot/v1",
                    "body_ref": BODY,
                    "embodiment_id": EMBODIMENT,
                    "incarnation_id": INCARNATION,
                    "observed_at_ms": 1,
                    "state": "running",
                    "resource_fences": [],
                    "private_path": "/secret/body",
                },
                "heads": {},
                "effective": PROJECTION,
            }
        )

    def scope_we(self):
        return self._response(
            {
                "schema": "dm.scope.we/v1",
                "being_ref": "being:test",
                "manifest_hash": "a" * 64,
                "evaluated_at_ms": 1,
                "local_origin": ORIGIN,
                "embodiments": [
                    {
                        "body_ref": BODY,
                        "embodiment_id": EMBODIMENT,
                        "incarnation_id": INCARNATION,
                        "manifest_status": "active",
                        "transport_principals": [ORIGIN["principal_id"]],
                        "availability": "local",
                        "route": {"endpoint": "https://private.invalid"},
                        "evidence_ref": "evidence:test",
                    }
                ],
                "partial": False,
            }
        )

    def scope_diff(self):
        return self._response(
            {
                **PROJECTION,
                "schema": "dm.scope.we-diff/v1",
                "origin_summaries": [
                    {
                        "embodiment_id": EMBODIMENT,
                        "states": {"pending": 0},
                        "payload": "must-not-pass",
                    }
                ],
                "payload": {"secret": "must-not-pass"},
            }
        )

    def scope_sync_plan(self, params):
        return self._response(
            {
                "schema": "dm.scope.sync-plan/v1",
                "plan_id": params["request_id"],
                "targets": [
                    {
                        "embodiment_id": "embodiment:remote",
                        "incarnation_id": "incarnation:remote",
                        "availability": "available",
                        "evidence_ref": "evidence:remote",
                        "request": {
                            "payload": "private-request",
                            "endpoint": "https://private.invalid",
                        },
                    }
                ],
                "partial": False,
            }
        )


def _running(tmp_path):
    registry = Registry(tmp_path)
    registry.register(body_ref=BODY, embodiment_id=EMBODIMENT)
    registry.start(EMBODIMENT, incarnation_id=INCARNATION)


def _context():
    return RequestContext("request:test", "tester", None)


def test_status_uses_matrix_client_and_redacts_routes_payloads_and_paths(tmp_path):
    _running(tmp_path)
    response = weave_status(
        Deps(
            config_path="unused",
            state_dir=str(tmp_path),
            matrix_client_factory=lambda _embodiment_id: MatrixClient(),
        ),
        _context(),
    )
    assert response.status == 200
    assert response.body["schema"] == "dm.cluster-matrix-status/v1"
    assert response.body["implementation"] == "installed-daimon-matrix"
    row = response.body["embodiments"][0]
    assert row["identity_view"]["body"]["state"] == "running"
    assert row["matrix_process"]["state"] == "available"
    assert row["owner_local"]["ledger_integrity"] == "ok"
    assert row["owner_local"]["authority_epoch"] == {
        "schema": "dm.we.authority-epoch-status/v1",
        "active_manifest_hash": "a" * 64,
        "accepted_manifest_hashes": ["a" * 64],
        "epoch_count": 1,
    }
    encoded = json.dumps(response.body)
    for forbidden in (
        "private.invalid",
        "private-request",
        "must-not-pass",
        "/secret/runtime",
        "/secret/count",
        "/secret/body",
        '"endpoint"',
        '"payload"',
        '"private_path"',
    ):
        assert forbidden not in encoded


def test_status_failure_is_membership_safe(tmp_path):
    _running(tmp_path)

    def unavailable(_embodiment_id):
        raise RuntimeError("/private/socket and membership details")

    response = weave_status(
        Deps(
            config_path="unused",
            state_dir=str(tmp_path),
            matrix_client_factory=unavailable,
        ),
        _context(),
    )
    assert response.status == 200
    assert response.body["embodiments"][0]["matrix_process"]["state"] == "down"
    assert response.body["embodiments"][0]["owner_local"]["state"] == \
        "unavailable"
    assert "/private/socket" not in json.dumps(response.body)


def test_clusterd_entrypoint_wires_the_production_matrix_factory(tmp_path, monkeypatch):
    captured = {}

    def serve(deps, binds):
        captured["deps"] = deps
        captured["binds"] = binds

    monkeypatch.setattr(clusterd_main.server, "serve", serve)
    assert (
        clusterd_main.main(
            [
                "--bind",
                "127.0.0.1:18785",
                "--config",
                "unused.yaml",
                "--state-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    assert captured["binds"] == [("127.0.0.1", 18785)]
    assert captured["deps"].matrix_client_factory is not None
