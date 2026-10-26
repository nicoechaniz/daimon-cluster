"""Native placement, cross-kernel deadlines and retained transport outcomes."""
import hashlib
import io
import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from clusterctl import being_seed, native_body
from clusterctl.onboarding import OnboardingError, digest
from tests.test_onboarding_host import configured


def placement(tmp_path, plan):
    key = tmp_path / 'operator.key'
    hosts = tmp_path / 'known_hosts'
    key.write_text('fixture key reference only')
    key.chmod(0o600)
    hosts.write_text('fixture pinned host reference only')
    locator = tmp_path / 'native.json'
    value = dict(schema='cluster-native-body-placement/v1', plan_digest=digest(plan),
        host='fixture.invalid', port=2222, ssh_user='operator', identity_file=str(key),
        identity_uid=os.geteuid(),
        known_hosts=str(hosts), machine_id_sha256=hashlib.sha256(b'fixture machine').hexdigest(),
        bootstrap_python='/opt/qualified-python/bin/python3', home='/home/agent')
    being_seed._write(locator, value)
    return locator, value


def test_native_placement_requires_original_plan_and_protected_references(tmp_path):
    plan = {'name': 'eko'}
    locator, value = placement(tmp_path, plan)
    assert native_body.NativeBody.load(locator, plan).python == Path(value['bootstrap_python'])
    with pytest.raises(OnboardingError, match='placement_required'):
        native_body.NativeBody.load(locator, {'name': 'oliva'})
    Path(value['identity_file']).chmod(0o644)
    with pytest.raises(OnboardingError, match='placement_required'):
        native_body.NativeBody.load(locator, plan)


@pytest.mark.parametrize('field,value', [('host', '-oProxyCommand=invalid'), ('ssh_user', 'user;command'),
    ('port', True), ('bootstrap_python', '/opt/../private/python')])
def test_native_placement_rejects_shell_and_option_injection(tmp_path, field, value):
    plan = {'name': 'eko'}
    locator, binding = placement(tmp_path, plan)
    binding[field] = value
    being_seed._write(locator, binding)
    with pytest.raises(OnboardingError, match='placement_required'):
        native_body.NativeBody.load(locator, plan)


def test_native_transport_preserves_stdin_and_quotes_each_remote_argument(tmp_path, monkeypatch):
    plan = {'name': 'eko'}
    locator, _ = placement(tmp_path, plan)
    body = native_body.NativeBody.load(locator, plan)
    payload = '{"operation_id":"same-retained-operation"}'
    speech = 'literal $(do-not-execute); `also literal`'
    def run(argv, **kwargs):
        assert argv[:3] == ['ssh', '-F', '/dev/null']
        assert 'StrictHostKeyChecking=yes' in argv
        remote = shlex.split(argv[-1])
        assert remote[:4] == [str(body.python), '-B', '-I', '-c']
        request = json.loads(remote[-1])
        assert request['argv'] == ['qualified-owner', speech]
        assert request['uid'] == 1000 and request['gid'] == 1000
        assert 0 < request['remaining_seconds'] <= 2
        assert kwargs['input'] == payload and 0 < kwargs['timeout'] <= 2
        return SimpleNamespace(returncode=0, stdout='{"retained":true}', stderr='')
    monkeypatch.setattr(native_body.subprocess, 'run', run)
    assert body.execute(['qualified-owner', speech], input_data=payload,
        deadline_ns=time.monotonic_ns()+2_000_000_000) == '{"retained":true}'


def test_native_timeout_retains_uncertainty_without_relaunch(tmp_path, monkeypatch):
    locator, _ = placement(tmp_path, {'name': 'eko'})
    body = native_body.NativeBody.load(locator, {'name': 'eko'})
    calls = []
    def timeout(*args, **kwargs):
        calls.append(args)
        raise subprocess.TimeoutExpired('private argv', 1, stderr='private detail')
    monkeypatch.setattr(native_body.subprocess, 'run', timeout)
    with pytest.raises(OnboardingError, match='^receiving_host_deadline_expired$'):
        body.execute(['qualified-owner'])
    assert len(calls) == 1


@pytest.mark.parametrize('wall,expected_deadline', [(1000, 51_000_000_000), (1004, 47_000_000_000)])
def test_real_remote_launcher_rebases_owner_clock_and_namespace(monkeypatch, wall, expected_deadline):
    request = dict(machine_id_sha256=hashlib.sha256(b'fixture machine').hexdigest(),
        argv=['owner', '--deadline-ns', '999999999999999', '--time-namespace', 'sender-kernel'],
        owner_clock=True, remaining_seconds=5, expires_at_ms=1_005_000,
        uid=1000, gid=1000, home='/home/agent', env={'HOME': '/home/agent'})
    calls = []
    class ExecObserved(Exception):
        pass
    monkeypatch.setattr(sys, 'argv', ['bootstrap', json.dumps(request)])
    monkeypatch.setattr(time, 'time', lambda: wall)
    monkeypatch.setattr(time, 'monotonic_ns', lambda: 46_000_000_000)
    monkeypatch.setattr(os, 'readlink', lambda path: 'receiver-kernel')
    monkeypatch.setattr(os, 'setgroups', lambda groups: calls.append(('groups', groups)))
    monkeypatch.setattr(os, 'setgid', lambda gid: calls.append(('gid', gid)))
    monkeypatch.setattr(os, 'setuid', lambda uid: calls.append(('uid', uid)))
    monkeypatch.setattr(os, 'chdir', lambda path: None)
    def observe(binary, argv, env):
        assert argv == ['owner', '--deadline-ns', str(expected_deadline), '--time-namespace', 'receiver-kernel']
        assert env['HOME'] == '/home/agent'
        assert env['PATH'] == '/usr/local/bin:' + os.defpath
        assert '/home/agent/.local/bin' not in env['PATH']
        raise ExecObserved()
    monkeypatch.setattr(os, 'execvpe', observe)
    with pytest.raises(ExecObserved):
        exec(native_body.REMOTE_LAUNCH, {'open': lambda *args: io.BytesIO(b'fixture machine')})
    assert calls == [('groups', []), ('gid', 1000), ('uid', 1000)]


def test_remote_expiry_refuses_before_changing_identity(monkeypatch):
    request = dict(machine_id_sha256=hashlib.sha256(b'fixture machine').hexdigest(),
                   remaining_seconds=5, expires_at_ms=1_000_000)
    monkeypatch.setattr(sys, 'argv', ['bootstrap', json.dumps(request)])
    monkeypatch.setattr(time, 'time', lambda: 1001)
    monkeypatch.setattr(os, 'setgroups', lambda groups: pytest.fail('expired effect'))
    with pytest.raises(SystemExit, match='receiving_host_deadline_expired'):
        exec(native_body.REMOTE_LAUNCH, {'open': lambda *args: io.BytesIO(b'fixture machine')})


def test_native_plan_executes_on_native_host_and_never_enters_old_incus(tmp_path, monkeypatch):
    config, plan, incus, backend = configured(tmp_path)
    locator, binding = placement(tmp_path, plan)
    backend.config = replace(config, native_by_name={plan['name']: (locator, digest(binding))})
    received = []
    def execute(body, argv, **kwargs):
        received.append((argv, kwargs))
        return '{"native":true}'
    monkeypatch.setattr(native_body.NativeBody, 'execute', execute)
    assert backend.execute_body(plan, ['qualified-owner'], home=True) == '{"native":true}'
    assert received[0][1]['env'] == {'HOME': '/home/agent'}
    with pytest.raises(OnboardingError, match='native_receiving_incus_unsupported'):
        backend._dispatch(plan, ['start', backend.instance(plan)])
    with pytest.raises(OnboardingError, match='native_receiving_initial_enrollment_unsupported'):
        backend._environment(plan)
    assert not incus.calls
    being_seed._write(locator, {**binding, 'host': 'different.invalid'})
    with pytest.raises(OnboardingError, match='native_receiving_placement_changed'):
        backend.execute_body(plan, ['qualified-owner'])
    being_seed._write(locator, binding)
    being_seed._write(config.grants / 'eko.json', dict(schema='cluster-onboarding-host-grant/v1', plan=plan, revoked=True))
    with pytest.raises(OnboardingError, match='host_authorization_required'):
        backend.execute_body(plan, ['qualified-owner'])
    assert len(received) == 1


def test_inc_state_executor_retains_existing_typed_execution(tmp_path):
    _, plan, incus, backend = configured(tmp_path)
    backend.run = lambda argv, **kwargs: json.dumps({'argv': argv, 'kwargs': kwargs})
    result = json.loads(backend.execute_body(plan, ['qualified-owner'], home=True, timeout_seconds=2))
    assert result['argv'] == ['exec', 'dm-eko', '--user', '1000', '--group', '1000',
                             '--env', 'HOME=/home/agent', '--', 'qualified-owner']
    assert result['kwargs']['timeout_seconds'] == 2


def test_public_code_transfer_resumes_retained_stage_after_timeout(tmp_path, monkeypatch):
    locator, _ = placement(tmp_path, {'name': 'eko'})
    body = native_body.NativeBody.load(locator, {'name': 'eko'})
    monkeypatch.setattr(native_body.onboarding_release, 'verify', lambda *args, **kwargs: {})
    transfers, commands = [], []
    published = []
    def available(self, code, checksum, **kwargs):
        return code.name.startswith('.partial-') or bool(published)
    def execute(self, argv, **kwargs):
        commands.append(argv)
        if 'renameat2' in argv[4]:
            published.append(True)
        return ''
    def transfer(argv, **kwargs):
        transfers.append(argv)
        if len(transfers) == 1:
            raise subprocess.TimeoutExpired('public artifact transfer', 1)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(native_body.NativeBody, 'code_available', available)
    monkeypatch.setattr(native_body.NativeBody, 'execute', execute)
    monkeypatch.setattr(native_body.subprocess, 'run', transfer)
    with pytest.raises(OnboardingError, match='receiving_host_deadline_expired'):
        body.prepare_code(tmp_path / 'qualified-public-code', 'a' * 64)
    progress = next((tmp_path / 'native.json.preparations').glob('*.json'))
    retained = progress.read_bytes()
    assert body.prepare_code(tmp_path / 'qualified-public-code', 'a' * 64) == Path('/opt/daimon-onboarding-runtime') / ('a' * 64)
    assert progress.read_bytes() == retained
    assert transfers[0][-1] == transfers[1][-1]
    assert '--checksum' in transfers[1] and '--delete' not in transfers[1]
    assert published and not any('private-home' in str(arg) for command in commands for arg in command)


def test_relocated_complete_job_does_not_reconcile_old_home_or_monitor(tmp_path):
    from clusterctl.onboarding_worker import Worker
    old = SimpleNamespace(names=lambda: ['eko'])
    retained = {'state': 'complete', 'name': 'eko', 'historical_plan': 'preserved'}
    class OldHome:
        def reconcile_committed(self, name):
            pytest.fail('old source home reconciled')
        def __call__(self, value):
            pytest.fail('old source home installation attempted')
    worker = Worker(old, lambda: pytest.fail('old backend entered'), homes=OldHome(),
        runtime_health=lambda result: pytest.fail('old container observation recreated'),
        relocated=lambda name: retained)
    assert worker.once() == [retained]
