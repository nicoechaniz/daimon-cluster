"""Visibility maintenance resumes real effects rather than redoing onboarding."""
import contextlib
import hashlib
import json
from types import SimpleNamespace

import pytest

from tools import tribe_visibility as tool


def request():
    docs = {'compaii': {'destination': 'conversation'}}
    return dict(intent=dict(operation_id='operation', canonical_disclosures=docs),
        owners={name: {'directory': name} for name in ('compaii', 'eko')},
        publications={'compaii': {'predecessor_sha256': 'a'*64}}, max_seconds=30)


def test_one_invocation_reuses_signatures_and_finishes_publication():
    value = request()
    calls, observations, saved = [], [], []

    def dispatch(name, payload, seconds):
        assert 0 < seconds <= 30
        calls.append((name, payload['mode']))
        if payload['mode'] == 'publish':
            assert len(payload['publication']['bindings']) == 2
            return dict(receipt={'published': True}, retained=False, lifecycle=1)
        return dict(receipt=dict(operation_id='operation', name=name,
            bindings=[dict(name='compaii', disclosure=value['intent']['canonical_disclosures']['compaii'],
                binding={'signer': name})]), retained=name=='compaii', lifecycle=int(name!='compaii'))

    result = tool.apply(value, dispatch=dispatch, observe=lambda name, _: observations.append(name),
        save=lambda v: saved.append(json.loads(json.dumps(v))),
        finish=lambda *_: {'receiving_readiness': 'qualified-local-projection'})
    assert result['complete'] is True
    assert calls == [('compaii', 'sign'), ('eko', 'sign'), ('compaii', 'publish')]
    assert observations == ['eko', 'compaii']
    assert saved[-1]['models'] == 0


def test_changed_disclosure_stops_before_any_publication():
    calls = []

    def dispatch(name, payload, _):
        calls.append(payload['mode'])
        return dict(receipt=dict(operation_id='operation', name=name,
            bindings=[dict(name='compaii', disclosure={'destination': 'changed'}, binding={})]),
            retained=True, lifecycle=0)

    with pytest.raises(ValueError, match='disclosure_changed'):
        tool.apply(request(), dispatch=dispatch, observe=lambda *_: pytest.fail('unexpected observation'),
            save=lambda _: None,finish=lambda *_: pytest.fail('unexpected completion'))
    assert calls == ['sign']


def worker_namespace():
    # Define the fixed transmitted program without executing its stdin entry.
    namespace = {}
    exec(compile(tool.WORKER.split('\npayload=json.load(open', 1)[0], 'worker', 'exec'), namespace)
    return namespace


def test_owner_failure_restores_matrix_and_ignores_dynamic_execstart_fields(tmp_path, monkeypatch):
    from clusterctl import onboarding_service
    namespace = worker_namespace()
    monkeypatch.setattr(namespace['os'], 'geteuid', lambda: 0)
    monkeypatch.setattr(onboarding_service, 'selection_lock', lambda _: contextlib.nullcontext())
    runtime = tmp_path/'runtime'
    runtime.mkdir()
    (runtime/'runtime.json').write_bytes(b'unchanged')
    owner = tmp_path/'owner'
    owner.mkdir()
    config = dict(code=str(tmp_path), runtime=str(runtime), sdk=str(tmp_path/'sdk'),
        stable_command_sha256=hashlib.sha256(b'fixed-argv').hexdigest(),
        service_command_sha256='obsolete presentation hash',
        runtime_sha256=hashlib.sha256(b'unchanged').hexdigest())
    launch = dict(name='eko', operation_id='operation', user='root', owner=str(owner),
        unit='daimon-onboarding-matrix.service', protected_units=['core.service'], owner_config=config)
    (tmp_path/'launch.json').write_text(json.dumps(launch))
    calls = []

    def system(*args):
        calls.append(args)
        if 'ExecStart' in args:
            return 'fixed-argv ; start_time=new-time ; pid=900'
        if args[:2] == ('show', 'core.service'):
            return 'MainPID=11\nInvocationID=unchanged'
        if 'MainPID' in args:
            return '0'
        return ''

    namespace['system'] = system
    monkeypatch.setattr(namespace['subprocess'], 'run',
        lambda *_, **__: SimpleNamespace(returncode=1, stderr='owner refused', stdout=''))
    with pytest.raises(RuntimeError, match='owner refused'):
        namespace['maintain'](dict(directory=str(tmp_path), mode='sign',
            intent={'operation_id': 'operation'}, worker=tool.WORKER))
    assert ('stop', 'daimon-onboarding-matrix.service') in calls
    assert ('start', 'daimon-onboarding-matrix.service') in calls
    state = json.loads((tmp_path/'apply-sign.json').read_text())
    assert state['complete'] is False and state['phase'] == 'restored'
    assert state['protected_processes_preserved'] is True


def test_late_selector_change_wins_over_watchdog_restoration(tmp_path, monkeypatch):
    from clusterctl import onboarding_service
    namespace = worker_namespace()
    monkeypatch.setattr(onboarding_service, 'selection_lock', lambda _: contextlib.nullcontext())
    runtime = tmp_path/'runtime'
    runtime.mkdir()
    (runtime/'runtime.json').write_bytes(b'original')
    (tmp_path/'launch.json').write_text(json.dumps(dict(unit='daimon-onboarding-matrix.service',
        owner_config=dict(code=str(tmp_path), runtime=str(runtime),
            stable_command_sha256=hashlib.sha256(b'old').hexdigest(),
            runtime_sha256=hashlib.sha256(b'original').hexdigest()))))
    (tmp_path/'apply-sign.json').write_text(json.dumps({'phase': 'owner-requested'}))
    calls = []
    namespace['system'] = lambda *args: calls.append(args) or 'later-selection'
    namespace['restore'](dict(directory=str(tmp_path), mode='sign'))
    assert not any(args[0] == 'start' for args in calls)
    assert json.loads((tmp_path/'apply-sign.json').read_text())['phase'] == 'later_selection_preserved'
