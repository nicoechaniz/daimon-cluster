import json
import sys

import pytest

from clusterctl.homes import service_remote as remote
from clusterctl.onboarding_conversation_maintenance import BOOTSTRAP


@pytest.mark.parametrize('original', ['id', 'runtime-web;id', 'runtime-web extra',
                                    'maintenance-web "print(123)"', ''])
def test_forced_key_never_runs_arbitrary_ssh_command(monkeypatch, original):
    monkeypatch.setenv('SSH_ORIGINAL_COMMAND', original)
    monkeypatch.setattr(remote.os, 'execv', lambda *_: pytest.fail('Unexpected execution'))
    with pytest.raises(ValueError):
        remote.forward()


def test_runtime_forward_selects_only_fixed_sudo_dispatcher(monkeypatch):
    monkeypatch.setenv('SSH_ORIGINAL_COMMAND', 'runtime-web')
    calls = []
    monkeypatch.setattr(remote.os, 'execv', lambda *args: calls.append(args))
    remote.forward()
    assert calls == [('/usr/bin/sudo', ['sudo', '-n', remote.ROOT_WRAPPER, 'runtime-web'])]


def test_remote_root_dispatch_cannot_select_an_unconfigured_service():
    value = {'schema':'dm.home-service-remote/v1', 'operations':{
        'runtime-web':{'kind':'runtime', 'config':'/operator/web.json'}}}
    with pytest.raises(ValueError, match='service_remote_operation_denied'):
        remote.dispatch(value, 'runtime-foreign')


def test_remote_config_rejects_injected_argv():
    value = {'schema':'dm.home-service-remote/v1', 'operations':{
        'runtime-web':{'kind':'runtime', 'config':'/operator/web.json', 'argv':['sh']}}}
    with pytest.raises(ValueError):
        remote.configuration(value)


def test_remote_maintenance_selects_exact_installed_protocol(monkeypatch):
    import shlex
    monkeypatch.setenv('SSH_ORIGINAL_COMMAND', 'maintenance-web ' + shlex.quote(BOOTSTRAP))
    calls = []
    monkeypatch.setattr(remote.os, 'execv', lambda *args: calls.append(args))
    remote.forward()
    assert calls[0][1][-1] == 'maintenance-web'


def test_maintenance_rejects_a_changed_target_before_dropping_privilege(monkeypatch):
    import io
    selected = dict(python='/usr/bin/python3', script='/operator/scripts/interaction_web_maintenance.py',
                    script_sha256='a'*64, config='/operator/config.json', owner_uid=1000,
                    health_url='http://127.0.0.1:8800/health')
    raw = json.dumps(dict(selected, config='/foreign/config.json', nonce='a'*32)).encode()+b'\n'
    monkeypatch.setattr(sys, 'stdin', io.TextIOWrapper(io.BytesIO(raw)))
    monkeypatch.setattr(remote.os, 'setuid', lambda *_: pytest.fail('Unexpected privilege transition'))
    with pytest.raises(ValueError, match='service_remote_maintenance_denied'):
        remote.maintenance(selected)


def test_selected_maintenance_drops_to_actual_application_group_before_exec(monkeypatch):
    import hashlib
    import io
    from types import SimpleNamespace
    source = b'fixed installed public maintenance source'
    selected = dict(python='/usr/bin/python3', script='/operator/scripts/interaction_web_maintenance.py',
                    script_sha256=hashlib.sha256(source).hexdigest(), config='/operator/config.json',
                    owner_uid=1000, health_url='http://127.0.0.1:8800/health')
    raw = json.dumps(dict(selected, nonce='a'*32)).encode()+b'\n'
    monkeypatch.setattr(sys, 'stdin', io.TextIOWrapper(io.BytesIO(raw)))
    monkeypatch.setattr(remote, 'read_code', lambda *a, **kw: source)
    monkeypatch.setattr(remote.pwd, 'getpwuid', lambda _: SimpleNamespace(pw_gid=2000))
    calls = []
    for name in ('setgroups', 'setgid', 'setuid', 'execv'):
        monkeypatch.setattr(remote.os, name, lambda *args, name=name: calls.append((name,args)))
    remote.maintenance(selected)
    assert calls[:3] == [('setgroups', ([],)), ('setgid', (2000,)), ('setuid', (1000,))]
    assert calls[3][0] == 'execv' and calls[3][1][0] == selected['python']
    assert 'value=json.loads(sys.stdin.buffer.readline(16385))' not in calls[3][1][1][-1]
