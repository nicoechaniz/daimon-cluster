"""Readiness cleanup preserves real native serving failures for diagnostics."""
import os
import threading
import time
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


def test_slow_view_uses_the_shared_startup_deadline_not_a_five_second_subwindow(monkeypatch):
    import select
    stop = threading.Event()
    release = threading.Event()
    reader, writer = os.pipe()
    now = [time.monotonic_ns()]
    deadline = now[0] + 60_000_000_000
    original_select = select.select
    calls = []
    observed = []

    def ready(runtime, *, stop, ready_descriptor, startup_deadline_ns):
        observed.append(startup_deadline_ns)
        release.wait(2)
        os.write(ready_descriptor, b'READY\n')
        os.close(ready_descriptor)
        stop.wait()

    def delayed_select(*args):
        calls.append(True)
        if len(calls) == 1:
            now[0] += 6_000_000_000
            release.set()
            return [], [], []
        return original_select(*args)

    monkeypatch.setattr(daemon, 'serve_forever', ready)
    monkeypatch.setattr(time, 'monotonic_ns', lambda: now[0])
    monkeypatch.setattr(time, 'monotonic', lambda: now[0] / 1_000_000_000)
    monkeypatch.setattr(select, 'select', delayed_select)
    errors = []

    def run():
        try:
            serve_views([view()], stop, ready_descriptor=writer, startup_deadline_ns=deadline)
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert original_select([reader], [], [], 2)[0]
        assert os.read(reader, 16) == b'READY\n'
    finally:
        stop.set()
        release.set()
        worker.join(timeout=2)
        os.close(reader)
    assert not worker.is_alive() and not errors
    assert observed == [deadline]


@pytest.mark.parametrize('code,exposed', [('reader_journal_deadline_expired', True),
    ('private arbitrary diagnostic content', False)])
def test_native_recovery_diagnostic_keeps_only_closed_values(capsys, code, exposed):
    import json
    from clusterctl.onboarding_runtime import report_child_refusal
    error = OnboardingError('private exception message')
    error.recovery_failure = {'stage': 'append', 'code': code}
    report_child_refusal(error)
    result = json.loads(capsys.readouterr().err)
    detail = result['exceptions'][0]
    assert ('reader_recovery_failure' in detail) is exposed
    assert 'private' not in json.dumps(result)
