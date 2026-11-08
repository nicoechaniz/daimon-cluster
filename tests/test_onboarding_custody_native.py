"""Qualified holder startup, closed child imports and unchanged FD publication."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl import being_seed
from clusterctl.onboarding_custody import _native_run
from clusterctl import onboarding_custody_native as native


def test_native_child_excludes_site_hooks_and_keeps_exact_arguments(tmp_path):
    venv = tmp_path / 'venv'
    subprocess.run([sys.executable, '-I', '-S', '-m', 'venv', '--without-pip', str(venv)],
                   check=True, timeout=15, capture_output=True)
    code, imports = tmp_path / 'code', tmp_path / 'runtime-imports'
    package = code / 'daimon_matrix'
    package.mkdir(parents=True)
    imports.mkdir()
    marker = tmp_path / 'unwanted-hook'
    (code / 'sitecustomize.py').write_text(f'open({str(marker)!r},"w").write("ran")')
    (package / '__init__.py').write_text('')
    (package / 'operator_genesis.py').write_text(
        'import json,sys;print(json.dumps(dict(no_site=sys.flags.no_site,'
        'isolated=sys.flags.isolated,argv=sys.argv[1:],paths=sys.path[:2])))')
    argv = native.native_command(venv, imports, code, 'daimon_matrix.operator_genesis',
                                 ['fixture', 'argument with spaces'])
    result = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=10)
    observed = json.loads(result.stdout)
    assert observed == dict(no_site=1, isolated=1, argv=['fixture', 'argument with spaces'],
                            paths=[str(code), str(imports)])
    assert not marker.exists()
    with pytest.raises(OnboardingError, match='qualified_native_custody_required'):
        native.native_command(venv, imports, code, 'os', ['--help'])


def test_startup_refusal_never_dispatches_or_opens_password(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(native.onboarding_code_successor, 'sdk_parameters',
                        lambda p: {'matrix_commit': 'a'*40, 'matrix_wheel_sha256': 'b'*64})
    # Real artifact verification fails before a holder/password operation.
    monkeypatch.setattr(native, '_native_run', lambda *a, **k: calls.append((a, k)))
    with pytest.raises((OnboardingError, FileNotFoundError)):
        native.main(['--venv', str(tmp_path/'venv'), '--code', str(tmp_path/'missing'),
                     '--code-digest', 'c'*64, '--password-file', str(tmp_path/'not-opened'),
                     '--', 'create-holder'])
    assert calls == [] and not (tmp_path/'not-opened').exists()


def test_native_failure_does_not_publish_partial_public_output(tmp_path):
    output = tmp_path / 'public.json'
    script = ('import json,os,sys; from pathlib import Path; '
              'p=Path(sys.argv[sys.argv.index("--output")+1]); '
              'p.write_text(json.dumps({"fixture":True}));p.chmod(0o600);sys.exit(2)')
    tmp_path.chmod(0o700)
    with pytest.raises(OnboardingError, match='native_onboarding_custody_refused'):
        _native_run(['create-intent', '--output', str(output)], None,
                    command_builder=lambda module, args: [sys.executable, '-I', '-c', script, *args])
    assert not output.exists() and not list(tmp_path.glob('.native-public-*'))


def test_password_uses_private_fd_and_rejects_symlinks(tmp_path):
    password = tmp_path/'password'
    password.write_bytes(b'fixture-secret-'.ljust(64, b'x'))
    password.chmod(0o600)
    output = tmp_path/'observed.json'
    script = ('import json,os,sys;from pathlib import Path;'
              'fd=int(sys.argv[sys.argv.index("--password-fd")+1]);'
              'secret=os.read(fd,65);'
              'Path(sys.argv[sys.argv.index("--output")+1]).write_text(json.dumps('
              '{"length":len(secret),"not_in_argv":secret.decode() not in str(sys.argv)}))')
    builder = lambda module, args: [sys.executable, '-I', '-c', script, *args]
    _native_run(['create-holder', '--output', str(output)], password, command_builder=builder)
    assert json.loads(output.read_text()) == {'length':64,'not_in_argv':True}
    linked = tmp_path/'linked';linked.symlink_to(password)
    with pytest.raises(being_seed.SeedError, match='seed_symlink_path_refused'):
        _native_run(['create-holder', '--output', str(output)], linked, command_builder=builder)


def test_backup_child_requires_its_own_qualified_startup_selection(tmp_path):
    venv=tmp_path/'venv';imports=tmp_path/'runtime-imports';code=tmp_path/'code'
    with pytest.raises(OnboardingError, match='qualified_native_custody_required'):
        native.native_command(venv,imports,code,'clusterctl.onboarding_holder_backup',[])
    command=native.native_command(venv,imports,code,'clusterctl.onboarding_holder_backup',
        ['--role','root'],code_digest='a'*64)
    assert command[command.index('--qualified-venv')+1]==str(venv)
    assert command[command.index('--qualified-code')+1]==str(code)
    assert command[command.index('--qualified-code-digest')+1]=='a'*64


def test_qualified_backup_does_not_import_legacy_git_adapter_before_proof(tmp_path,monkeypatch):
    from clusterctl import onboarding_holder_backup,onboarding_sdk,onboarding_code_successor
    calls=[]
    monkeypatch.setitem(sys.modules,'clusterctl.matrix_host',None)
    monkeypatch.setattr(onboarding_code_successor,'sdk_parameters',lambda p:
        dict(matrix_commit='a'*40,matrix_wheel_sha256='b'*64))
    def refuse(*args,**kwargs):
        calls.append('proof-before-password')
        raise OnboardingError('qualified_runtime_context_required')
    monkeypatch.setattr(onboarding_sdk,'qualified_startup',refuse)
    result=onboarding_holder_backup.main(['--ceremony-root',str(tmp_path),'--role','root',
        '--password-fd','-1','--qualified-venv',str(tmp_path/'venv'),
        '--qualified-code',str(tmp_path/'code'),'--qualified-code-digest','c'*64])
    assert result==1 and calls==['proof-before-password']
