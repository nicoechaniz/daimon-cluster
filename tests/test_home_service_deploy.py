"""Own HTTP deployment: real file/registry/HTTP boundaries, simulated system manager."""

from copy import deepcopy
import io
import os
from pathlib import Path
import tarfile

import pytest

from clusterctl.homes.service_package import canonical, sha, unpack, request
from clusterctl.homes.service_runtime import Runtime, key, receiver, unit
from clusterctl.homes.service_deploy import configuration, ServiceRoutes
from clusterctl.homes.registry import version_digest
from clusterctl.homes.service import Application, handler
from clusterctl.homes.sessions import Sessions
from tests.test_home_gateway import Authority, serving


def archive(
    *, source=b'console.log("own service");', name="main.js", kind=tarfile.REGTYPE
):
    spec = dict(
        schema="dm.home-service-package/v1",
        service="workshop",
        runtime="node24-http",
        entry=name,
        state_schema="v1",
        health={"path": "/health", "sha256": sha(b"ok")},
        files=[{"path": name, "sha256": sha(source)}],
    )
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for n, data in [("service.json", canonical(spec)), (name, source)]:
            info = tarfile.TarInfo(n)
            info.size, info.mode = len(data), 0o644
            if n == name:
                info.type = kind
            tar.addfile(info, io.BytesIO(data))
    return stream.getvalue(), spec


def selected_entry(reference, **fields):
    row = dict(
        artifact_ref=reference,
        title="Package",
        summary="",
        kind="artifact",
        visibility="public",
        recipients=[],
        tribes=[],
        files=["package.tar"],
        **fields,
    )
    row["version_ref"] = version_digest(row)
    return row


@pytest.fixture
def setup(tmp_path):
    root, data, units = (tmp_path / n for n in ("runtime", "data", "units"))
    for p in (root, data, units):
        p.mkdir(mode=0o700)
    code = tmp_path / "code"
    code.mkdir(mode=0o750)
    c = dict(
        schema="dm.home-service-receiver/v1",
        home="one",
        owner="owner-one",
        service="workshop",
        placement="kvm",
        machine_sha256="a" * 64,
        profile_file=str(tmp_path / "profile.json"),
        profile_sha256="b" * 64,
        node="/usr/bin/node",
        node_sha256="c" * 64,
        root=str(root),
        code=str(code),
        data=str(data),
        unit_dir=str(units),
        uid=os.getuid() or 1000,
        gid=os.getgid() or 1000,
        port=4187,
        state_schema="v1",
        memory_mb=128,
        cpu_percent=25,
        tasks=48,
        state_bytes=64 * 1024**2,
        quota_probe=["/usr/local/bin/own-quota-observe"],
    )
    g = dict(
        receiver=c,
        prefix="/workshop/",
        upstream="127.0.0.1:4187",
        command=["/usr/local/libexec/own-service-receiver"],
        route_command=["/usr/local/libexec/own-service-route"],
        auth_backend="http://127.0.0.1:9180",
        routes={
            "config": str(tmp_path / "Caddyfile"),
            "state": str(tmp_path / "routes"),
            "anchor": "# HOME-SERVICE s-" + key(c),
        },
    )
    conf = dict(
        schema="dm.home-service-capabilities/v1",
        state=str(tmp_path / "deployments"),
        grants=[g],
    )
    raw, package = archive()
    artifact = selected_entry("a" * 32)
    value = dict(
        schema="dm.home-service-deploy/v1",
        service="workshop",
        request_id="original",
        package={
            "resource": artifact["artifact_ref"],
            "version": artifact["version_ref"],
            "file": "package.tar",
            "sha256": sha(raw),
        },
        previous=None,
        audience={"visibility": "human", "recipients": [], "tribes": []},
        app={
            "title": "Workshop",
            "summary": "Own workshop",
            "decision": "Selected for my human.",
        },
    )
    return c, g, conf, raw, package, artifact, value


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../main.js", tarfile.REGTYPE),
        ("/main.js", tarfile.REGTYPE),
        ("main.js", tarfile.SYMTYPE),
        ("main.js", tarfile.LNKTYPE),
        ("main.js", tarfile.CHRTYPE),
        ("main.js", tarfile.DIRTYPE),
    ],
)
def test_package_rejects_traversal_links_and_special_members(name, kind):
    raw, _ = archive(name=name, kind=kind)
    with pytest.raises(ValueError):
        unpack(raw, sha(raw))


def test_exact_digest_and_inventory(setup):
    _, _, _, raw, spec, _, _ = setup
    assert unpack(raw, sha(raw))[0] == spec
    with pytest.raises(ValueError, match="digest"):
        unpack(raw + b"x", sha(raw))
    altered = raw.replace(b"console.log", b"CONSOLE.LOG")
    with pytest.raises(ValueError, match="inventory"):
        unpack(altered, sha(altered))


@pytest.mark.parametrize(
    "field,bad",
    [
        ("uid", 0),
        ("placement", "retired"),
        ("port", 80),
        ("root", "/tmp/../unrelated"),
        ("memory_mb", True),
        ("node", "/bin/node\nExecStart=bad"),
    ],
)
def test_receiver_cannot_become_shell_or_wrong_profile(setup, field, bad):
    c = {**setup[0], field: bad}
    with pytest.raises(ValueError):
        receiver(c)


@pytest.mark.parametrize(
    "change", ["reserved", "collision", "upstream", "extra", "traversal"]
)
def test_gateway_operator_grant_validation(setup, change):
    _, _, conf, *_ = setup
    conf = deepcopy(conf)
    if change == "reserved":
        conf["grants"][0]["prefix"] = "/access/"
    if change == "collision":
        conf["grants"] *= 2
    if change == "upstream":
        conf["grants"][0]["upstream"] += "\nlog bad"
    if change == "extra":
        conf["grants"][0]["shell"] = "arbitrary"
    if change == "traversal":
        conf["state"] += "/../other"
    with pytest.raises(ValueError):
        configuration(conf)


@pytest.mark.parametrize("field", ["previous", "package", "app", "service"])
def test_typed_request_failures_are_closed(setup, field):
    value = deepcopy(setup[-1])
    value[field] = []
    with pytest.raises(ValueError):
        request(value)


class ManagerFixture(Runtime):
    """Simulates ONLY systemd; real package writes, CAS and recovery run unchanged."""

    def __init__(self, config):
        super().__init__(config)
        self.restarts, self.loaded, self.fail_after_restart = 0, False, False

    def preflight(self):
        pass

    def listener_precondition(self, current):
        pass

    def command(self, argv):
        if argv[1] == "restart":
            self.restarts += 1
            self.loaded = True
            if self.fail_after_restart:
                raise TimeoutError("lost reply after actual manager effect")
        return b""

    def health(self, record):
        expected = unit(
            self.config, self.code / ("release-" + record["digest"]), record["package"]
        )
        return self.loaded and self.unit_path.read_bytes() == expected


def envelope(c, value, raw=None, action="apply"):
    import base64

    return dict(
        schema="dm.home-service-executor/v1",
        action=action,
        capability=sha(canonical(c)),
        request_id=value["request_id"],
        digest=value["package"]["sha256"],
        previous=value["previous"],
        package=base64.b64encode(raw).decode() if raw is not None else None,
    )


def test_receiving_apply_recovery_and_compatible_rollback(setup):
    c, _, _, raw, spec, _, value = setup
    worker = ManagerFixture(c)
    (Path(c["data"]) / "valuable.db").write_bytes(b"private existing data")
    worker.fail_after_restart = True
    with pytest.raises(TimeoutError):
        worker.run(envelope(c, value, raw))
    assert worker.restarts == 1
    worker.fail_after_restart = False
    assert worker.run(envelope(c, value, action="observe"))["state"] == "ready"
    assert worker.run(envelope(c, value, raw))["state"] == "ready"
    assert worker.restarts == 1
    changed, _ = archive(source=b'console.log("successor");')
    successor = deepcopy(value)
    successor.update(request_id="successor", previous=sha(raw))
    successor["package"]["sha256"] = sha(changed)
    assert worker.run(envelope(c, successor, changed))["state"] == "ready"
    assert worker.run(envelope(c, value, action="observe"))["state"] == "superseded"
    rollback = deepcopy(value)
    rollback.update(request_id="rollback", previous=sha(changed))
    assert worker.run(envelope(c, rollback, raw))["state"] == "ready"
    assert worker.restarts == 3
    assert (Path(c["data"]) / "valuable.db").read_bytes() == b"private existing data"
    assert "NoNewPrivileges=true" in worker.unit_path.read_text()
    assert "ReadWritePaths=" + c["data"] in worker.unit_path.read_text()


def test_wrong_owner_predecessor_or_current_unit_never_restarts(setup):
    c, _, _, raw, _, _, value = setup
    worker = ManagerFixture(c)
    denied = envelope(c, value, raw)
    denied["capability"] = "f" * 64
    with pytest.raises(ValueError, match="capability"):
        worker.run(denied)
    worker.run(envelope(c, value, raw))
    next_value = deepcopy(value)
    next_value["request_id"] = "another"
    with pytest.raises(ValueError, match="predecessor"):
        worker.run(envelope(c, next_value, raw))
    next_value["previous"] = sha(raw)
    worker.unit_path.write_text("different current operator unit")
    with pytest.raises(ValueError, match="concurrent_unit"):
        worker.run(envelope(c, next_value, raw))
    assert worker.restarts == 1


def test_symlink_in_existing_release_is_never_served(setup):
    c, _, _, raw, _, _, value = setup
    worker = ManagerFixture(c)
    release = worker.code / ("release-" + sha(raw))
    release.mkdir()
    (release / "main.js").symlink_to("/etc/passwd")
    with pytest.raises(ValueError):
        worker.run(envelope(c, value, raw))
    assert worker.restarts == 0


def app_fixture(tmp_path, conf, raw, artifact):
    authority = Authority()
    token = tmp_path / "owner-token"
    token.write_text("own-test-token")
    token.chmod(0o600)

    class Broker:
        state_value = {"schema": 1, "entries": [artifact]}

        def state(self):
            return self.state_value

        def open(self, target, **kwargs):
            assert (
                artifact["artifact_ref"] in target and artifact["version_ref"] in target
            )
            stream = io.BytesIO(raw)
            stream.headers = {"X-Home-Version": artifact["version_ref"]}
            return stream

    broker = Broker()
    home = dict(
        owner_being_ref="owner-one",
        owner_revision="v1",
        owner_token_file=str(token),
        public_url="https://one.example",
        vpn_url="https://one.vpn",
    )
    app = Application(
        {
            "homes": {"one": home},
            "content_public_url": "https://content.example",
            "content_vpn_url": "https://content.vpn",
        },
        authority,
        Sessions(tmp_path / "sessions"),
        backends={"one": broker},
        service_deployments=conf,
    )
    app.registry.register(
        home="one",
        owner="owner-one",
        state=broker.state(),
        expected_revision=0,
        known_actor=authority.actor,
        known_tribe=lambda _: True,
    )
    return app, broker


def test_actual_owner_auth_registry_finalize_and_http_audience(
    setup, tmp_path, monkeypatch
):
    import urllib.request
    import urllib.error

    c, _, conf, raw, _, artifact, value = setup
    app, broker = app_fixture(tmp_path, conf, raw, artifact)
    worker = ManagerFixture(c)
    monkeypatch.setattr(
        app.service_deployments,
        "execute",
        lambda g, v, raw=None: worker.run(
            envelope(c, v, raw, "apply" if raw else "observe")
        ),
    )
    route_calls = []

    def route(*args, **kwargs):
        route_calls.append(1)
        return {"state": "complete"}

    monkeypatch.setattr(app.service_deployments, "route", route)
    with pytest.raises(ValueError, match="owner_denied"):
        app.owner("one", "another-token", "service-deploy", value)
    assert worker.restarts == 0
    result = app.owner("one", "own-test-token", "service-deploy", value)
    assert result["state"] == "publication-required" and worker.restarts == 1
    assert (
        app.owner("one", "own-test-token", "service-deploy", value)["state"]
        == "publication-required"
    )
    assert worker.restarts == 1
    changed = deepcopy(value)
    changed["app"]["summary"] = "different bytes, same request"
    with pytest.raises(ValueError, match="request_conflict"):
        app.owner("one", "own-test-token", "service-deploy", changed)
    entry = dict(
        artifact_ref="b" * 32,
        kind="link",
        url=result["url"],
        application={"schema": "dm.application/v1", "mode": "shared"},
        title="Workshop",
        summary="Own workshop",
        **value["audience"],
    )
    entry["version_ref"] = version_digest(entry)
    finalize = {
        "request": value,
        "resource": entry["artifact_ref"],
        "version": entry["version_ref"],
    }
    with pytest.raises(ValueError, match="exact_app"):
        app.owner("one", "own-test-token", "service-finalize", finalize)
    broker.state_value["entries"].append(entry)
    app.owner("one", "own-test-token", "sync", {})
    assert (
        app.owner("one", "own-test-token", "service-finalize", finalize)["state"]
        == "complete"
    )
    assert app.owner("one", "own-test-token", "service-deploy", value)["retained"]
    with serving(handler(app)) as url:

        def status(actor=None, **headers):
            req = urllib.request.Request(
                url + "/service-access/s-" + key(c),
                headers={"Host": "one.example", **headers},
            )
            if actor:
                token = app.sessions.issue(
                    home="one",
                    subject=app.authority.actor(actor),
                    origin="https://one.example",
                )
                req.add_header("Cookie", "__Host-home=" + token)
            try:
                with urllib.request.urlopen(req, timeout=3) as response:
                    return response.status
            except urllib.error.HTTPError as e:
                code = e.code
                e.close()
                return code

        assert status() == 401
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        req = urllib.request.Request(url + "/service-access/s-" + key(c), headers={
            "Host": "one.example", "Sec-Fetch-Dest": "document",
            "X-Forwarded-Uri": "/workshop/?tab=cases"})
        with pytest.raises(urllib.error.HTTPError) as redirect:
            urllib.request.build_opener(NoRedirect).open(req, timeout=3)
        with redirect.value as response:
            assert response.code == 302
            assert response.headers["Location"] == "/access/sso/start?return=%2Fworkshop%2F%3Ftab%3Dcases"
        assert app.service_deployments.login_return("one", "s-" + key(c), "//other.example/") == "/workshop/"
        assert app.service_deployments.login_return("one", "s-" + key(c), "/owner/") == "/workshop/"
        assert status("human-two") == 403
        assert status("human-one") == 204
        assert status(
            "human-one",
            **{"X-Forwarded-Method": "POST", "Origin": "https://other.example"},
        ) in (403, 404)
        assert (
            status(
                "human-one",
                **{"X-Forwarded-Method": "POST", "Origin": "https://one.example"},
            )
            == 204
        )
        app.service_deployments.config["grants"].clear()
        assert status("human-one") == 403


def test_route_scope_and_concurrent_replacement_preserved(setup):
    c, g, *_ = setup
    value = {
        "name": "s-" + key(c),
        "origin": "https://one.example",
        "prefix": "/workshop/",
    }
    block = ServiceRoutes.render(value, g, g["auth_backend"])
    assert b"forward_auth" in block and b"header_up -Authorization" in block
    assert b'Cache-Control "private, no-store"' in block and b"defer" in block
    assert b"path /workshop/*" in block
    before = (g["routes"]["anchor"] + "\n").encode()
    after = ServiceRoutes.compose(before, value, block, g["routes"]["anchor"])
    assert ServiceRoutes.compose(after, value, block, g["routes"]["anchor"]) == after
    with pytest.raises(ValueError, match="concurrent_route"):
        ServiceRoutes.compose(
            after.replace(b":4187", b":4188"), value, block, g["routes"]["anchor"]
        )
    with pytest.raises(ValueError):
        ServiceRoutes.compose(
            b"handle /workshop/* {}\n" + before, value, block, g["routes"]["anchor"]
        )


def test_no_capability_is_inherited_from_home_owner_token(tmp_path):
    raw, _ = archive()
    _, _, _, _, _, artifact, value = setup.__wrapped__(tmp_path)
    conf = {
        "schema": "dm.home-service-capabilities/v1",
        "state": str(tmp_path / "empty-grants"),
        "grants": [],
    }
    app, _ = app_fixture(tmp_path, conf, raw, artifact)
    with pytest.raises(ValueError, match="capability_denied"):
        app.owner("one", "own-test-token", "service-deploy", value)


def test_real_host_mismatch_refuses_before_manager_or_package_write(setup):
    worker = Runtime(setup[0])
    with pytest.raises(ValueError, match="host_profile_mismatch"):
        worker.run(envelope(setup[0], setup[-1], setup[3]))
    assert not list(worker.root.iterdir())


def test_actual_listening_socket_must_belong_to_selected_pid(setup):
    import socket

    c = deepcopy(setup[0])
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        c["port"] = server.getsockname()[1]
        worker = Runtime(c)
        assert worker.owns_listener(os.getpid())
        assert not worker.owns_listener(os.getppid())
        with pytest.raises(ValueError, match="existing_listener"):
            worker.listener_precondition(None)


def test_fixed_transport_sends_only_closed_capability_envelope(setup, tmp_path):
    import sys
    from clusterctl.homes.service_deploy import Deployments

    c, g, conf, raw, _, _, value = setup
    script = tmp_path / "receiver-fixture.py"
    script.write_text(
        "import sys,json\nv=json.load(sys.stdin)\n"
        'assert set(v)==set("schema action capability request_id digest previous package".split())\n'
        'print(json.dumps({"state":"ready","digest":v["digest"]}))\n'
    )
    conf = deepcopy(conf)
    conf["grants"][0]["command"] = [sys.executable, str(script)]
    deployer = Deployments(conf)
    assert deployer.execute(conf["grants"][0], value, raw) == {
        "state": "ready",
        "digest": sha(raw),
    }


def test_transport_timeout_is_not_an_apply_retry(setup, monkeypatch):
    import subprocess
    from clusterctl.homes.service_deploy import Deployments

    c, g, conf, raw, _, _, value = setup
    calls = []

    def lost(*args, **kwargs):
        calls.append(1)
        raise subprocess.TimeoutExpired(args[0], 100)

    monkeypatch.setattr(subprocess, "run", lost)
    result = Deployments(conf).execute(g, value, raw)
    assert result == {"state": "uncertain", "digest": sha(raw)}
    assert calls == [1]


def test_owner_revocation_after_package_fetch_prevents_apply(
    setup, tmp_path, monkeypatch
):
    _, _, conf, raw, _, artifact, value = setup
    app, broker = app_fixture(tmp_path, conf, raw, artifact)
    original = broker.open

    def revoke(*args, **kwargs):
        stream = original(*args, **kwargs)
        from dataclasses import replace

        app.authority.people["owner-one"] = replace(
            app.authority.people["owner-one"], enabled=False
        )
        return stream

    monkeypatch.setattr(broker, "open", revoke)
    monkeypatch.setattr(
        app.service_deployments,
        "execute",
        lambda *args: pytest.fail("revoked execution"),
    )
    with pytest.raises(ValueError, match="owner_revoked"):
        app.owner("one", "own-test-token", "service-deploy", value)


def test_one_command_uses_existing_link_sync_and_exact_completed_retry(
    setup, tmp_path, monkeypatch
):
    import urllib.request
    from types import SimpleNamespace
    from clusterctl.homes.service_publish import publish

    c, _, conf, raw, _, artifact, value = setup
    app, broker = app_fixture(tmp_path, conf, raw, artifact)
    worker = ManagerFixture(c)
    monkeypatch.setattr(
        app.service_deployments,
        "execute",
        lambda g, v, raw=None: worker.run(
            envelope(c, v, raw, "apply" if raw else "observe")
        ),
    )
    monkeypatch.setattr(
        app.service_deployments, "route", lambda *args, **kwargs: {"state": "complete"}
    )
    links = []

    def link(binding, args):
        links.append(args.url)
        row = dict(
            artifact_ref="b" * 32,
            id=args.id,
            kind="link",
            url=args.url,
            application={"schema": "dm.application/v1", "mode": "shared"},
            title=args.title,
            summary=args.summary,
            **value["audience"],
        )
        row["version_ref"] = version_digest(row)
        broker.state_value["entries"].append(row)
        publisher.owner_request(binding, "sync", {})

    publisher = SimpleNamespace(
        owner_request=None,
        NoRedirect=urllib.request.HTTPRedirectHandler,
        private_token=lambda _: "own-test-token",
        publish=link,
        submitted_state=lambda _: broker.state_value,
    )
    with serving(handler(app, owner=True)) as url:
        binding = {
            "access": {
                "owner_url": url,
                "home_ref": "one",
                "owner_token_file": "unused-fixture",
            }
        }
        result = publish(publisher, binding, value)
        assert result["state"] == "complete"
        assert publish(publisher, binding, value)["retained"]
    assert publisher.owner_request is None
    assert worker.restarts == 1 and len(links) == 1


def test_route_helper_accepts_only_operator_declaration_digest(setup, monkeypatch):
    from clusterctl.homes.service_routes import apply, declaration

    _, g, *_ = setup
    config = declaration(g, "https://one.example")
    monkeypatch.setattr(
        ServiceRoutes,
        "reconcile",
        lambda *args, **kwargs: {"state": "complete", "route_loaded": True},
    )
    call = {
        "schema": "dm.home-service-route-call/v1",
        "capability": sha(canonical(config)),
    }
    assert apply(config, call)["state"] == "complete"
    for bad in ({**call, "config": "/another/file"}, {**call, "capability": "0" * 64}):
        with pytest.raises(ValueError):
            apply(config, bad)


def test_rendered_route_adapts_with_actual_caddy_when_available(setup, tmp_path):
    import json
    import shutil
    import subprocess

    executable = shutil.which("caddy")
    if not executable:
        pytest.skip("Caddy binary is optional in this source-only test environment")
    c, g, *_ = setup
    request = {
        "name": "s-" + key(c),
        "origin": "https://one.example",
        "prefix": g["prefix"],
    }
    block = ServiceRoutes.render(request, g, g["auth_backend"])
    config = tmp_path / "service.Caddyfile"
    config.write_bytes(
        b"http://one.example {\n" + block + b' handle {\n  respond "fallback"\n }\n}\n'
    )
    result = subprocess.run(
        [executable, "adapt", "--config", str(config), "--adapter", "caddyfile"],
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr.decode()
    adapted = json.loads(result.stdout)
    wire = json.dumps(adapted)
    assert "/service-access/s-" + key(c) in wire
    assert "/workshop/*" in wire


def test_new_release_is_readable_under_private_operator_umask(setup):
    c, _, _, _, _, _, value = setup
    raw, _ = archive(name="src/main.js")
    value = deepcopy(value)
    value["package"]["sha256"] = sha(raw)
    worker = ManagerFixture(c)
    previous_umask = os.umask(0o077)
    try:
        assert worker.run(envelope(c, value, raw))["state"] == "ready"
    finally:
        os.umask(previous_umask)
    release = worker.code / ("release-" + sha(raw))
    assert release.stat().st_mode & 0o777 == 0o755
    assert (release / "src").stat().st_mode & 0o777 == 0o755
    assert (release / "src/main.js").stat().st_mode & 0o777 == 0o644


def test_verified_runtime_file_can_exceed_small_operator_record_limit(setup):
    c, _, _, _, _, _, value = setup
    code = b'/*' + b'vendored code ' * 6000 + b'*/'
    raw, _ = archive(source=code)
    value = deepcopy(value)
    value['package']['sha256'] = sha(raw)
    worker = ManagerFixture(c)
    assert worker.run(envelope(c, value, raw))['state'] == 'ready'
    assert (worker.code / ('release-' + sha(raw)) / 'main.js').read_bytes() == code


def test_same_healthy_code_can_be_reattested_without_restarting(setup):
    c, _, _, raw, _, _, value = setup
    worker = ManagerFixture(c)
    assert worker.run(envelope(c, value, raw))['state'] == 'ready'
    assert worker.restarts == 1
    selected = worker.read('current.json')
    state = Path(c['data']) / 'existing-state'
    state.write_bytes(b'keep this state')
    revised = deepcopy(value)
    revised.update(request_id='new-fixed-transport', previous=selected['digest'])
    assert worker.run(envelope(c, revised, raw))['state'] == 'ready'
    assert worker.restarts == 1 and state.read_bytes() == b'keep this state'
    assert worker.read('current.json')['pins']['request_id'] == 'new-fixed-transport'
