"""Host lifecycle contracts with injected Matrix boundaries; no live discovery."""

from __future__ import annotations

import builtins
import os
import sys
from dataclasses import dataclass, replace
from types import ModuleType, SimpleNamespace

import pytest

from clusterctl import matrix_host as host


@dataclass(frozen=True)
class Service:
    body_reader: object
    curator_fence_verifier: object
    curator_effect_observer: object
    messaging: object = None


@dataclass(frozen=True)
class Runtime:
    service: Service
    messaging_http: object = None


@pytest.fixture
def lifecycle(tmp_path, monkeypatch):
    events = []
    held = []
    runtimes = []
    adapter = SimpleNamespace(
        require_origin=lambda origin: events.append("origin"),
        body_snapshot=object(),
        verify_fence=object(),
        effect_observer=object(),
    )
    monkeypatch.setattr(host, "MatrixHostAdapter", lambda *a, **kw: adapter)
    monkeypatch.setattr(host, "_owner_directory", lambda path: tmp_path)
    monkeypatch.setattr(
        host,
        "_public_bundle",
        lambda *a: {
            "local_origin": {},
            "socket": "matrix.sock",
        },
    )
    monkeypatch.setattr(host, "_origin", lambda value: value)
    monkeypatch.setattr(host.signal, "signal", lambda *a: None)

    def lock(root):
        events.append("lock")
        fd = os.open(tmp_path / "lock", os.O_CREAT | os.O_RDWR, 0o600)
        held.append(fd)
        return fd

    def load(root, bundle, password, **hooks):
        events.append("load")
        assert password() == b"synthetic"
        runtime = Runtime(
            Service(
                **{
                    key: hooks[key]
                    for key in (
                        "body_reader",
                        "curator_fence_verifier",
                        "curator_effect_observer",
                    )
                }
            )
        )
        runtimes.append(runtime)
        return runtime

    def serve(runtime, **kwargs):
        events.append("serve")
        runtimes.append(runtime)
        assert runtime.service.body_reader is adapter.body_snapshot
        assert runtime.service.curator_fence_verifier is adapter.verify_fence
        assert runtime.service.curator_effect_observer is adapter.effect_observer
        if kwargs["ready_descriptor"] is not None:
            os.write(kwargs["ready_descriptor"], b"ready")

    api = {
        "runtime": SimpleNamespace(load_runtime=load),
        "daemon": SimpleNamespace(acquire_lock=lock, serve_forever=serve),
    }

    def checked_api():
        events.append("dependency")
        return api

    monkeypatch.setattr(host, "_matrix_api", checked_api)
    module = ModuleType("daimon_matrix.messaging_config")

    def compose(runtime, directory):
        events.append("compose")
        assert directory == tmp_path / "application"
        assert runtime.service.body_reader is adapter.body_snapshot
        assert runtime.service.curator_fence_verifier is adapter.verify_fence
        assert runtime.service.curator_effect_observer is adapter.effect_observer
        return replace(
            runtime,
            service=replace(runtime.service, messaging=True),
            messaging_http=True,
        )

    def pre_read(root, bundle, directory, *, at_ms):
        events.append("pre_read")
        return {}

    module.read_application_authorities = pre_read
    module.load_application = compose
    monkeypatch.setitem(sys.modules, "daimon_matrix.messaging_config", module)

    def invoke(*extra):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"synthetic")
        os.close(write_fd)
        try:
            return host.main(
                [
                    "--state-dir",
                    str(tmp_path),
                    "--embodiment-id",
                    "embodiment:00000000-0000-4000-8000-000000000001",
                    "--password-fd",
                    str(read_fd),
                    *extra,
                ]
            )
        finally:
            try:
                os.close(read_fd)
            except OSError:
                pass

    return SimpleNamespace(
        events=events,
        held=held,
        runtimes=runtimes,
        api=api,
        module=module,
        invoke=invoke,
        root=tmp_path,
    )


def test_incompatible_application_fails_closed_without_disclosure(lifecycle, capsys):
    def reject(*args):
        raise ValueError("private application path or configuration")

    lifecycle.module.load_application = reject
    assert (
        lifecycle.invoke("--messaging-application", str(lifecycle.root / "application"))
        == 1
    )
    assert lifecycle.events == ["dependency", "origin", "lock", "pre_read", "load"]
    assert '"code":"matrix_messaging_application_rejected"' in capsys.readouterr().err
    with pytest.raises(OSError):
        os.fstat(lifecycle.held[0])


@pytest.mark.parametrize("failure", [ImportError, FileNotFoundError, TypeError])
def test_configured_failure_never_signals_ready(
    lifecycle, capsys, monkeypatch, failure
):
    def reject(*args):
        raise failure("sensitive details")

    if failure is ImportError:
        monkeypatch.setitem(sys.modules, "daimon_matrix.messaging_config", None)
    else:
        lifecycle.module.load_application = reject
    read_fd, write_fd = os.pipe()
    try:
        assert (
            lifecycle.invoke(
                "--messaging-application",
                str(lifecycle.root / "application"),
                "--ready-fd",
                str(write_fd),
            )
            == 1
        )
        os.close(write_fd)
        write_fd = None
        assert os.read(read_fd, 64) == b""
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
    assert lifecycle.events == (
        ["dependency", "origin", "lock"]
        if failure is ImportError
        else ["dependency", "origin", "lock", "pre_read", "load"]
    )
    diagnostic = capsys.readouterr().err
    assert "sensitive details" not in diagnostic
    assert '"code":"matrix_messaging_application_rejected"' in diagnostic
    with pytest.raises(OSError):
        os.fstat(lifecycle.held[0])


def test_opt_out_does_not_import_messaging(lifecycle, monkeypatch):
    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name == "daimon_matrix.messaging_config":
            pytest.fail("opt-out imported messaging")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    original_load = lifecycle.api["runtime"].load_runtime

    # Deliberately has the old pinned signature: no new keywords permitted.
    def old_load(
        root,
        bundle,
        password,
        *,
        clock,
        body_reader,
        curator_fence_verifier,
        curator_effect_observer,
    ):
        return original_load(
            root,
            bundle,
            password,
            clock=clock,
            body_reader=body_reader,
            curator_fence_verifier=curator_fence_verifier,
            curator_effect_observer=curator_effect_observer,
        )

    lifecycle.api["runtime"].load_runtime = old_load
    assert lifecycle.invoke() == 0
    assert lifecycle.events == ["dependency", "origin", "lock", "load", "serve"]
    assert lifecycle.runtimes[-1] is lifecycle.runtimes[0]


def test_dependency_rejection_precedes_composition(lifecycle, monkeypatch):
    def reject():
        raise host.MatrixHostError("daimon_matrix_contract_mismatch")

    monkeypatch.setattr(host, "_matrix_api", reject)
    assert (
        lifecycle.invoke("--messaging-application", str(lifecycle.root / "application"))
        == 1
    )
    assert lifecycle.events == []


def test_runtime_rejection_precedes_composition(lifecycle, capsys):
    def reject(*args, **kwargs):
        raise host.MatrixHostError("invalid_runtime_bundle")

    lifecycle.api["runtime"].load_runtime = reject
    assert (
        lifecycle.invoke("--messaging-application", str(lifecycle.root / "application"))
        == 1
    )
    assert lifecycle.events == ["dependency", "origin", "lock", "pre_read"]
    assert '"code":"invalid_runtime_bundle"' in capsys.readouterr().err
    with pytest.raises(OSError):
        os.fstat(lifecycle.held[0])


def test_serve_failure_releases_lock_and_stops(lifecycle):
    observed = []

    def reject(runtime, **kwargs):
        assert runtime.messaging_http is True
        observed.append(kwargs["stop"])
        raise OSError("synthetic bind failure")

    lifecycle.api["daemon"].serve_forever = reject
    assert (
        lifecycle.invoke("--messaging-application", str(lifecycle.root / "application"))
        == 1
    )
    assert observed[0].is_set()
    with pytest.raises(OSError):
        os.fstat(lifecycle.held[0])


def test_application_startup_failure_releases_real_runtime_lock(monkeypatch):
    # The installed-line composition has no modern rebirth/admission launcher.
    # Exercise the actual supported host with root-signed process fixtures.
    import tempfile
    import time
    from pathlib import Path
    import test_matrix_host_process as fixtures

    with tempfile.TemporaryDirectory(prefix="dmm-") as name:
        state = Path(name) / "state"
        now = time.time_ns() // 1_000_000
        authority = fixtures._authority(now)
        origin = authority["origins"]["legion"]
        registry = fixtures.Registry(state)
        registry.register(body_ref=origin["body_ref"], embodiment_id=origin["embodiment_id"])
        registry.start(origin["embodiment_id"], incarnation_id=origin["incarnation_id"], started_at_ms=now)
        fixtures._write_runtime(state, authority, "legion", now)
        real_popen = fixtures.subprocess.Popen

        def configured_child(argv, **kwargs):
            return real_popen([*argv, "--messaging-application", str(Path(name) / "missing")], **kwargs)

        with monkeypatch.context() as scoped:
            scoped.setattr(fixtures.subprocess, "Popen", configured_child)
            with pytest.raises(AssertionError, match="matrix_messaging_application_rejected"):
                fixtures._spawn(state, origin["embodiment_id"])
        process, _ = fixtures._spawn(state, origin["embodiment_id"])
        fixtures._stop(process)


def test_programmatic_run_accepts_explicit_application(lifecycle):
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"synthetic")
    os.close(write_fd)
    try:
        assert (
            host.run(
                lifecycle.root,
                "embodiment:00000000-0000-4000-8000-000000000001",
                password_fd=read_fd,
                messaging_application=lifecycle.root / "application",
            )
            == 0
        )
    finally:
        try:
            os.close(read_fd)
        except OSError:
            pass
    assert lifecycle.events[-2:] == ["compose", "serve"]


@pytest.mark.parametrize("failure", [ValueError, FileNotFoundError, TypeError])
def test_preread_rejection_is_safe_before_password_or_runtime(
    lifecycle, monkeypatch, capsys, failure
):
    def reject(*args, **kwargs):
        lifecycle.events.append("pre_read")
        os.fstat(lifecycle.held[0])
        raise failure("sensitive authority or database path")

    def forbidden_reader(*args):
        pytest.fail("pre-read failure created a password reader")

    lifecycle.module.read_application_authorities = reject
    monkeypatch.setattr(host, "_password_reader", forbidden_reader)
    read_fd, password_fd = os.pipe()
    ready_read, ready_write = os.pipe()
    os.write(password_fd, b"unconsumed")
    os.close(password_fd)
    try:
        assert (
            host.run(
                lifecycle.root,
                "embodiment:00000000-0000-4000-8000-000000000001",
                password_fd=read_fd,
                ready_fd=ready_write,
                messaging_application=lifecycle.root / "application",
            )
            == 1
        )
        assert os.read(read_fd, 64) == b"unconsumed"
        os.close(ready_write)
        ready_write = None
        assert os.read(ready_read, 64) == b""
    finally:
        os.close(read_fd)
        os.close(ready_read)
        if ready_write is not None:
            os.close(ready_write)
    assert lifecycle.events == ["dependency", "origin", "lock", "pre_read"]
    assert not lifecycle.runtimes
    assert capsys.readouterr().err == (
        '{"code":"matrix_messaging_application_rejected",'
        '"schema":"dm.cluster-matrix-host-diagnostic/v1"}\n'
    )
    with pytest.raises(OSError):
        os.fstat(lifecycle.held[0])


def test_shared_authorities_preloaded_under_lock_before_runtime(lifecycle, monkeypatch):
    public = {"foreign-being": object()}
    observed = []
    clock_reads = []

    def now():
        clock_reads.append(True)
        return 123_000_000

    monkeypatch.setattr(host.time, "time_ns", now)

    def pre_read(root, bundle, directory, *, at_ms):
        assert lifecycle.events == ["dependency", "origin", "lock"]
        os.fstat(lifecycle.held[0])
        assert root == lifecycle.root
        assert bundle == "selected-runtime.json"
        assert directory == lifecycle.root / "application"
        assert at_ms == 123
        assert len(clock_reads) == 1
        lifecycle.events.append("pre_read")
        return public

    original_load = lifecycle.api["runtime"].load_runtime

    def load(*args, **kwargs):
        assert lifecycle.events[-1] == "pre_read"
        assert kwargs["relationship_authorities"] is public
        # The base runtime receives the same time source used by preflight.
        assert kwargs["clock"]() == 123
        assert len(clock_reads) == 2
        observed.append(kwargs["clock"])
        return original_load(*args, **kwargs)

    lifecycle.module.read_application_authorities = pre_read
    lifecycle.api["runtime"].load_runtime = load
    assert (
        lifecycle.invoke(
            "--bundle",
            "selected-runtime.json",
            "--messaging-application",
            str(lifecycle.root / "application"),
        )
        == 0
    )
    assert observed
    assert lifecycle.events == [
        "dependency",
        "origin",
        "lock",
        "pre_read",
        "load",
        "compose",
        "serve",
    ]


def test_cli_opt_in_composes_after_hooks_before_serving(lifecycle):
    result = lifecycle.invoke(
        "--messaging-application", str(lifecycle.root / "application")
    )
    assert result == 0
    assert lifecycle.events == [
        "dependency",
        "origin",
        "lock",
        "pre_read",
        "load",
        "compose",
        "serve",
    ]
    assert lifecycle.runtimes[-1].service.messaging is True
    assert lifecycle.runtimes[-1].messaging_http is True
    with pytest.raises(OSError):
        os.fstat(lifecycle.held[0])
