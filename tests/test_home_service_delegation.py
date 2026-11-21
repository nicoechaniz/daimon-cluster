"""Delegated engines keep one central App and authenticate each package owner."""

from copy import deepcopy
import threading

import pytest

from clusterctl.homes.registry import version_digest
from clusterctl.homes.service_deploy import configuration
from tests import test_home_service_deploy as fixtures
from tests.test_home_service_deploy import app_fixture, ManagerFixture, envelope
from clusterctl.homes.service_runtime import key


base_setup = fixtures.setup


@pytest.fixture
def delegated(base_setup, tmp_path, monkeypatch):
    c, g, conf, raw, _, artifact, value = base_setup
    app, central = app_fixture(tmp_path, conf, raw, artifact)
    entry = dict(
        artifact_ref="b" * 32,
        kind="link",
        url="https://one.example/workshop/",
        application={"schema": "dm.application/v1", "mode": "shared"},
        title=value["app"]["title"],
        summary=value["app"]["summary"],
        **value["audience"],
    )
    entry["version_ref"] = version_digest(entry)
    central.state_value = {"schema": 1, "entries": [entry]}
    app.owner("one", "own-test-token", "sync", {})
    token = tmp_path / "delegate-token"
    token.write_text("delegate-test-token")
    token.chmod(0o600)
    app.homes["two"] = dict(
        app.homes["one"],
        owner_being_ref="owner-two",
        owner_token_file=str(token),
        public_url="https://two.example",
    )
    app.locks["two"] = threading.RLock()
    app.sessions.register_owner(
        home="two", actor="owner-two", revision="v1", token="delegate-test-token"
    )
    artifact["artifact_ref"] = "c" * 32
    artifact["version_ref"] = version_digest(artifact)
    value["package"].update(
        resource=artifact["artifact_ref"], version=artifact["version_ref"]
    )
    package_broker = type(central)()
    package_broker.state_value = {"schema": 1, "entries": [artifact]}
    app.backends["two"] = package_broker
    app.registry.register(
        home="two",
        owner="owner-two",
        state=package_broker.state(),
        expected_revision=0,
        known_actor=app.authority.actor,
        known_tribe=lambda _: True,
    )
    d = dict(
        home="two",
        owner="owner-two",
        revision="v1",
        target_home="one",
        service="workshop",
        resource=entry["artifact_ref"],
        version=entry["version_ref"],
    )
    app.service_deployments.config = configuration(dict(conf, delegations=[d]))
    worker = ManagerFixture(c)
    monkeypatch.setattr(
        app.service_deployments,
        "execute",
        lambda g, v, raw=None: worker.run(
            envelope(c, v, raw, "apply" if raw else "observe")
        ),
    )
    monkeypatch.setattr(
        app.service_deployments, "route", lambda *a: {"state": "complete"}
    )
    return app, central, package_broker, worker, value, d


def test_own_package_updates_only_central_app_and_receipt(delegated):
    app, central, packages, worker, value, d = delegated
    before = deepcopy(central.state_value)
    result = app.owner("two", "delegate-test-token", "service-deploy", value)
    assert result["state"] == "finalization-required"
    assert worker.restarts == 1
    result = app.owner(
        "two",
        "delegate-test-token",
        "service-finalize",
        dict(request=value, resource=d["resource"], version=d["version"]),
    )
    assert result["state"] == "complete"
    assert result["url"] == "https://one.example/workshop/"
    assert result["resource"] == d["resource"]
    assert central.state_value == before
    assert packages.state_value["entries"][0]["kind"] == "artifact"
    assert app.owner("two", "delegate-test-token", "service-deploy", value)["retained"]
    assert worker.restarts == 1
    service_key = "s-" + key(worker.config)
    assert app.service_deployments.access(app, "one", app.authority.actor("human-one"), service_key)
    assert not app.service_deployments.access(app, "one", app.authority.actor("human-two"), service_key)
    op = app.service_deployments.journal.latest_for_target(key(worker.config))
    assert op["intent"]["runtime_call"]["delegation"]


@pytest.mark.parametrize(
    "fault",
    [
        "token",
        "revision",
        "removed",
        "audience",
        "title",
        "central-app",
        "foreign-package",
        "target-owner",
    ],
)
def test_authority_and_app_fail_before_dispatch(delegated, fault):
    app, central, packages, worker, value, d = delegated
    token = "delegate-test-token"
    if fault == "token":
        token = "own-test-token"
    elif fault == "revision":
        d["revision"] = "obsolete"
    elif fault == "removed":
        app.service_deployments.config["delegations"] = []
    elif fault == "audience":
        value["audience"]["visibility"] = "public"
    elif fault == "title":
        value["app"]["title"] = "Other App"
    elif fault == "central-app":
        central.state_value["entries"][0]["version_ref"] = "f" * 64
    elif fault == "foreign-package":
        packages.state_value["entries"] = []
    elif fault == "target-owner":
        app.homes["one"]["owner_being_ref"] = "owner-two"
    with pytest.raises(ValueError):
        app.owner("two", token, "service-deploy", value)
    assert worker.restarts == 0


def test_revocation_between_apply_and_finalize_preserves_pending(delegated):
    app, _, _, worker, value, d = delegated
    app.owner("two", "delegate-test-token", "service-deploy", value)
    app.service_deployments.config["delegations"] = []
    with pytest.raises(ValueError):
        app.owner(
            "two",
            "delegate-test-token",
            "service-finalize",
            dict(request=value, resource=d["resource"], version=d["version"]),
        )
    assert worker.restarts == 1


def test_configuration_does_not_clone_receiver_or_implicitly_delegate(base_setup):
    conf = deepcopy(base_setup[2])
    d = dict(
        home="two",
        owner="owner-two",
        revision="v1",
        target_home="one",
        service="workshop",
        resource="b" * 32,
        version="c" * 64,
    )
    for invalid in [
        dict(d, target_home="absent"),
        dict(d, home="one"),
        dict(d, shell="/bin/sh"),
    ]:
        with pytest.raises(ValueError):
            configuration(dict(conf, delegations=[invalid]))
    with pytest.raises(ValueError):
        configuration(dict(conf, delegations=[d, d]))
    assert configuration(dict(conf, delegations=[d]))["grants"] == conf["grants"]


def test_inspect_is_read_only_and_does_not_claim_rollback(delegated):
    app, _, _, worker, value, d = delegated
    assert app.owner("two", "delegate-test-token", "service-inspect", value) == {
        "state": "unobserved"
    }
    assert worker.restarts == 0
    app.owner("two", "delegate-test-token", "service-deploy", value)
    app.owner(
        "two",
        "delegate-test-token",
        "service-finalize",
        dict(request=value, resource=d["resource"], version=d["version"]),
    )
    result = app.owner("two", "delegate-test-token", "service-inspect", value)
    assert result["state"] == "ready" and result["operation_state"] == "completed"
    assert result["rollback_verified"] is False
    assert result["digest"] == value["package"]["sha256"]
    assert worker.restarts == 1


def test_delegated_owner_command_does_not_publish_a_fork(delegated):
    from types import SimpleNamespace
    import urllib.request
    from clusterctl.homes.service_publish import publish
    from clusterctl.homes.service import handler
    from tests.test_home_gateway import serving

    app, _, _, worker, value, _ = delegated

    def forbidden(*args):
        raise AssertionError("Delegation must not mutate the package Home catalog")

    publisher = SimpleNamespace(
        owner_request=None,
        NoRedirect=urllib.request.HTTPRedirectHandler,
        private_token=lambda _: "delegate-test-token",
        publish=forbidden,
        submitted_state=forbidden,
    )
    with serving(handler(app, owner=True)) as url:
        binding = {
            "access": {
                "owner_url": url,
                "home_ref": "two",
                "owner_token_file": "fixture",
            }
        }
        assert publish(publisher, binding, value)["state"] == "complete"
        assert publish(publisher, binding, value, inspect=True)["state"] == "ready"
    assert worker.restarts == 1
