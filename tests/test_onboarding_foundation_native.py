"""Extend the existing native writer without replacing the chat profile."""
import json
import subprocess
import sys
import tomllib

import pytest

from clusterctl import onboarding_chat_native as native


BEFORE = '''model = "preserved-model"
[mcp_servers.matrix]
command = "existing-chat"
args = ["mcp"]
startup_timeout_sec = 60
[mcp_servers.memory]
command = "existing-memory"
'''


def test_foundation_registration_preserves_chat_and_reconciles_exact_retry(tmp_path, monkeypatch):
    home = tmp_path/'codex'
    home.mkdir(mode=0o700)
    config = home/'config.toml'
    config.write_text(BEFORE)
    config.chmod(0o600)
    monkeypatch.setenv('CODEX_HOME', str(home))
    monkeypatch.setattr(native.shutil, 'which', lambda _: '/fixture/codex')
    writes = []
    def writer(binary, candidate, command, **options):
        assert options['role_name'] == 'matrix_foundation'
        writes.append(command)
        (candidate/'config.toml').write_text(BEFORE + '\n[mcp_servers.matrix_foundation]\n'
            'command = '+json.dumps(command[0])+'\nargs = '+json.dumps(command[1:])+
            '\nstartup_timeout_sec = 60\n')
    monkeypatch.setattr(native, '_write_codex_role', writer)
    attachment = tmp_path/'attachment'
    command = ['/qualified/python', '-B', 'foundation']
    result = native.register_codex_mcp(attachment, command, role_name='matrix_foundation', operation_id='d4de2b07-1a51-4e23-99f4-bf87da50c7f8')
    assert result['status'] == 'configured'
    history = tmp_path/'attachment/codex-mcp-history/d4de2b07-1a51-4e23-99f4-bf87da50c7f8'
    assert (history/'config.before.toml').read_text() == BEFORE
    assert (history/'config.candidate.toml').exists()
    assert not (history/'candidate-home').exists()
    after = config.read_bytes()
    value = tomllib.loads(after.decode())
    assert value['model'] == 'preserved-model'
    for name, role in tomllib.loads(BEFORE)['mcp_servers'].items():
        assert value['mcp_servers'][name] == role
    assert value['mcp_servers']['matrix_foundation']['command'] == command[0]
    assert native.register_codex_mcp(attachment, command, role_name='matrix_foundation', operation_id='d4de2b07-1a51-4e23-99f4-bf87da50c7f8')['status'] == 'configured'
    assert config.read_bytes() == after and writes == [command]
    with pytest.raises(ValueError, match='mcp_conflict'):
        native.register_codex_mcp(attachment, ['/other/selection'], role_name='matrix_foundation', operation_id='d4de2b07-1a51-4e23-99f4-bf87da50c7f8')
    assert config.read_bytes() == after


def test_unknown_native_role_refuses_before_creating_home(tmp_path, monkeypatch):
    home = tmp_path/'absent'
    monkeypatch.setenv('CODEX_HOME', str(home))
    with pytest.raises(ValueError, match='role_rejected'):
        native.register_codex_mcp(tmp_path/'attachment', ['/selected'], role_name='arbitrary')
    assert not home.exists()


def test_native_versioned_writer_selects_only_the_foundation_role(tmp_path):
    home = tmp_path/'candidate'
    home.mkdir(mode=0o700)
    (home/'config.toml').write_text(BEFORE)
    capture = tmp_path/'captured.json'
    program = tmp_path/'codex'
    program.write_text('#!'+sys.executable+'\n'+'''import json,os,sys
from pathlib import Path
for line in sys.stdin:
 request=json.loads(line)
 if 'id' not in request:continue
 method=request['method']
 if method=='config/read':result={'layers':[{'name':{'type':'user','file':str(Path(os.environ['CODEX_HOME'])/'config.toml')},'version':'fixture-v1'}]}
 elif method=='config/batchWrite':
  Path(CAPTURE).write_text(json.dumps(request['params']));result={}
 else:result={}
 print(json.dumps({'id':request['id'],'result':result}),flush=True)
'''.replace('CAPTURE', repr(str(capture))))
    program.chmod(0o700)
    native._write_codex_role(str(program), home, ['/selected', 'mcp'],
        role_name='matrix_foundation', startup_timeout_seconds=60)
    payload = json.loads(capture.read_text())
    assert payload['expectedVersion'] == 'fixture-v1'
    assert {edit['keyPath'] for edit in payload['edits']} == {
        'mcp_servers.matrix_foundation.command', 'mcp_servers.matrix_foundation.args',
        'mcp_servers.matrix_foundation.startup_timeout_sec'}
    assert (home/'config.toml').read_text() == BEFORE, 'the wire fixture does not claim native publication'


def test_foundation_command_qualifies_before_loading_owner_client(tmp_path, monkeypatch):
    from clusterctl import onboarding_foundation_native as foundation
    code, venv = tmp_path/'code', tmp_path/'sdk/venv'
    command = foundation.foundation_command(venv, venv.parent/'runtime-imports', code,
        code_digest='a'*64, runtime_root=tmp_path/'existing', request_dir=tmp_path/'requests')
    assert command[:5] == [str(venv/'bin/python'), '-B', '-I', '-S', '-c']
    assert command[9] == 'clusterctl.onboarding_foundation_native'
    calls = []
    monkeypatch.setattr(foundation.onboarding_code_successor, 'sdk_parameters',
        lambda *a, **k: dict(matrix_commit='b'*40, matrix_wheel_sha256='c'*64))
    def refuse(*args, **kwargs):
        calls.append('qualification')
        raise ValueError('private diagnostic must not be exposed')
    monkeypatch.setattr(foundation.onboarding_sdk, 'qualified_startup', refuse)
    def forbidden(*args):
        pytest.fail('unqualified source reached client files')
    monkeypatch.setattr(foundation, 'foundation_bridge', forbidden)
    assert foundation.main(command[10:]) == 2
    assert calls == ['qualification']


def test_foundation_legacy_sdk_refuses_before_owner_files(tmp_path, monkeypatch):
    from clusterctl.onboarding_foundation_native import foundation_bridge
    import daimon_matrix.mcp_server as mcp
    class Legacy:
        def __init__(self, client, request_dir):
            pytest.fail('unsupported constructor must not be invoked')
    monkeypatch.setattr(mcp, 'DaimonMcp', Legacy)
    with pytest.raises(ValueError, match='qualified_foundation_sdk_required'):
        foundation_bridge(tmp_path/'absent', tmp_path/'requests')
    assert not (tmp_path/'requests').exists()


def test_foundation_history_capacity_refuses_before_native_preparation(tmp_path, monkeypatch):
    home = tmp_path/'codex'
    home.mkdir(mode=0o700)
    config = home/'config.toml'
    config.write_text(BEFORE)
    config.chmod(0o600)
    monkeypatch.setenv('CODEX_HOME', str(home))
    attachment = tmp_path/'attachment'
    history = attachment/'codex-mcp-history'
    history.mkdir(parents=True, mode=0o700)
    for index in range(32):
        (history/str(index)).mkdir(mode=0o700)
    def forbidden(*args, **kwargs):
        pytest.fail('history capacity must refuse before native preparation')
    monkeypatch.setattr(native, '_codex_candidate', forbidden)
    with pytest.raises(ValueError, match='foundation_native_history_capacity'):
        native.register_codex_mcp(attachment, ['/selected'], role_name='matrix_foundation',
            operation_id='d4de2b07-1a51-4e23-99f4-bf87da50c7f8')
    assert config.read_text() == BEFORE
    assert len(list(history.iterdir())) == 32


def test_resumed_foundation_candidate_keeps_an_existing_writer_home(tmp_path, monkeypatch):
    home = tmp_path/'codex'
    home.mkdir(mode=0o700)
    config = home/'config.toml'
    config.write_text(BEFORE)
    config.chmod(0o600)
    monkeypatch.setenv('CODEX_HOME', str(home))
    operation = 'd4de2b07-1a51-4e23-99f4-bf87da50c7f8'
    attachment = tmp_path/'attachment'
    candidate = attachment/'codex-mcp-history'/operation/'candidate-home'
    for directory in (attachment, attachment/'codex-mcp-history', candidate.parent, candidate):
        directory.mkdir(mode=0o700)
    expected = BEFORE+'\n[mcp_servers.matrix_foundation]\ncommand = "/selected"\nargs = []\nstartup_timeout_sec = 60\n'
    (candidate/'config.toml').write_text(expected)
    (candidate/'config.toml').chmod(0o600)
    child = subprocess.Popen([sys.executable, '-c',
        'import sys; f=open("config.toml"); print("ready", flush=True); sys.stdin.read()'],
        cwd=candidate, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'ready'
        def forbidden(*args, **kwargs):
            pytest.fail('completed candidate must resume without launching another writer')
        monkeypatch.setattr(native, '_write_codex_role', forbidden)
        result = native.register_codex_mcp(attachment, ['/selected'],
            role_name='matrix_foundation', operation_id=operation)
        assert result['status'] == 'configured'
        assert child.poll() is None and candidate.is_dir()
        assert config.read_text() == expected
    finally:
        child.stdin.close()
        child.wait(timeout=5)
        child.stdout.close()
