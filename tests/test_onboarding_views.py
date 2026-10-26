"""Readiness cleanup preserves real native serving failures for diagnostics."""
import os
import threading
from types import SimpleNamespace

import pytest
from daimon_matrix import daemon

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_views import serve_views


def view():
    return SimpleNamespace(messaging_http=None, peer_dispatcher=None, socket_path='matrix.sock',
        peer_context=None, service=SimpleNamespace(router=None, messaging=None),
        egress=SimpleNamespace(validate_registry=lambda paths: None))


def test_pre_ready_worker_refusal_survives_readiness_cleanup(monkeypatch):
    original = OSError('private startup detail must remain out of public diagnostics')

    def fail(*args, **kwargs):
        raise original

    monkeypatch.setattr(daemon, 'serve_forever', fail)
    with pytest.raises(OnboardingError, match='onboarding_runtime_view_failed') as raised:
        serve_views([view()], threading.Event())
    assert raised.value.__cause__ is original


def test_readiness_eof_without_worker_exception_remains_not_ready(monkeypatch):
    monkeypatch.setattr(daemon, 'serve_forever', lambda *args, **kwargs: None)
    with pytest.raises(OnboardingError, match='onboarding_runtime_not_ready') as raised:
        serve_views([view()], threading.Event())
    assert raised.value.__cause__ is None


def test_successful_view_preserves_actual_ready_handshake(monkeypatch):
    stop = threading.Event()
    reader, writer = os.pipe()

    def ready(runtime, *, stop, ready_descriptor):
        os.write(ready_descriptor, b'READY\n')
        os.close(ready_descriptor)
        stop.wait()

    monkeypatch.setattr(daemon, 'serve_forever', ready)
    errors = []

    def run():
        try:
            serve_views([view()], stop, ready_descriptor=writer)
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=run)
    worker.start()
    try:
        import select
        assert select.select([reader], [], [], 2)[0]
        assert os.read(reader, 16) == b'READY\n'
    finally:
        stop.set()
        worker.join(timeout=2)
        os.close(reader)
    assert not worker.is_alive()
    assert not errors
