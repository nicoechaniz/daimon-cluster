import importlib.util
import json
import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('login_refresh',
    Path(__file__).resolve().parents[1]/'tools/refresh_hosted_codex_login.py')
login = importlib.util.module_from_spec(spec)
spec.loader.exec_module(login)


def auth(account, token):
    return json.dumps({'auth_mode':'chatgpt','tokens':{
        'account_id':account,'access_token':token}}).encode()


def test_valid_newer_receiving_login_is_not_overwritten_or_revalidated_at_source():
    source, receiving = auth('selected','older'), auth('selected','newer')
    calls = []
    selection, raw = login.select_login(source, receiving,
        hashlib.sha256(b'selected').hexdigest(),
        validate=lambda value: calls.append(value) or True)
    assert selection == 'retained_valid_receiving_login'
    assert raw == receiving and calls == [receiving]


def test_invalid_receiving_login_selects_only_a_valid_same_account_source():
    source, receiving = auth('selected','fresh'), auth('selected','revoked')
    selection, raw = login.select_login(source, receiving,
        hashlib.sha256(b'selected').hexdigest(), validate=lambda value:value==source)
    assert selection == 'selected_valid_source_login' and raw == source


def test_other_account_and_changed_source_selection_are_preserved():
    source = auth('selected','fresh')
    for receiving, expected in ((auth('other','valid'),b'selected'),
                                (source,b'another-selection')):
        with pytest.raises(login.LoginError, match='receiving_account_preserved'):
            login.select_login(source,receiving,hashlib.sha256(expected).hexdigest(),
                               validate=lambda _:pytest.fail('no provider check before account match'))


def test_revoked_source_requires_device_login_without_installing():
    with pytest.raises(login.LoginError,match='source_device_login_required'):
        login.select_login(auth('selected','revoked-source'),auth('selected','revoked-target'),
                           hashlib.sha256(b'selected').hexdigest(),validate=lambda _:False)


def test_private_files_and_symlinks_are_not_interchangeable(tmp_path):
    path=tmp_path/'auth.json';path.write_bytes(auth('selected','private'));path.chmod(0o600)
    assert login.private_file(path)==path.read_bytes()
    path.chmod(0o644)
    with pytest.raises(login.LoginError):login.private_file(path)
    path.chmod(0o600)
    link=tmp_path/'link';link.symlink_to(path)
    with pytest.raises(OSError):login.private_file(link)


def test_real_installer_retains_preimage_and_restores_it_on_rejected_source(tmp_path):
    home=tmp_path/'home';root=home/'.codex';root.mkdir(mode=0o700,parents=True)
    destination=root/'auth.json';before=auth('selected','old')
    destination.write_bytes(before);destination.chmod(0o600)
    def apply(source):
        return subprocess.run([sys.executable,'-I','-c',login.INSTALL,
            str(Path(__file__).resolve().parents[1]),str(home),
            str(os.geteuid()),str(os.getegid())],input=json.dumps({
                'before_sha256':hashlib.sha256(before).hexdigest(),
                'source':source.decode()}),text=True,capture_output=True)
    rejected=json.loads(auth('selected','new'));rejected['auth_mode']='invalid'
    result=apply(json.dumps(rejected).encode())
    assert result.returncode!=0 and destination.read_bytes()==before
    backup=root/'provider-login-history'/hashlib.sha256(before).hexdigest()/'auth.json'
    destination.write_bytes(b'later-native-refresh')
    assert backup.read_bytes()==before
    destination.write_bytes(before)
    after=auth('selected','new')
    result=apply(after)
    assert result.returncode==0,result.stderr
    assert destination.read_bytes()==after
    assert backup.read_bytes()==before
    assert destination.stat().st_mode&0o777==0o600
    assert result.stdout.strip()=='{"installed": true, "same_account": true, "preimage_retained": true}'


def test_real_installer_refuses_drift_or_other_account_before_touching_destination(tmp_path):
    home=tmp_path/'home';root=home/'.codex';root.mkdir(mode=0o700,parents=True)
    destination=root/'auth.json';before=auth('selected','old')
    destination.write_bytes(before);destination.chmod(0o600)
    for expected,source in [('0'*64,auth('selected','new')),
                            (hashlib.sha256(before).hexdigest(),auth('other','new'))]:
        result=subprocess.run([sys.executable,'-I','-c',login.INSTALL,
            str(Path(__file__).resolve().parents[1]),str(home),str(os.geteuid()),str(os.getegid())],
            input=json.dumps({'before_sha256':expected,'source':source.decode()}),
            text=True,capture_output=True)
        assert result.returncode!=0 and destination.read_bytes()==before
    assert not (root/'provider-login-history').exists()


def test_partial_service_stop_failure_restores_previously_active_units(tmp_path, monkeypatch):
    source, current=auth('selected','fresh'),auth('selected','expired')
    receiver={'instance':'selected','home':'/home/selected',
              'account_sha256':hashlib.sha256(b'selected').hexdigest(),
              'units':['native.service','listener.service']}
    def pull(command, **kwargs):
        Path(command[-1]).write_bytes(current)
        Path(command[-1]).chmod(0o600)
        return subprocess.CompletedProcess(command,0)
    monkeypatch.setattr(login.subprocess,'run',pull)
    monkeypatch.setattr(login,'select_login',lambda *args:('selected_valid_source_login',source))
    calls=[]
    def operation(receiver,args,**kwargs):
        calls.append(args)
        if args[1]=='show':return 'active\n'
        if args[1]=='stop':raise login.LoginError('receiving_operation_failed')
        return ''
    monkeypatch.setattr(login,'incus',operation)
    with pytest.raises(login.LoginError,match='receiving_operation_failed'):
        login.refresh(source,receiver)
    assert calls[-1]==['systemctl','start','native.service','listener.service']


@pytest.mark.parametrize('expected,ok',[('selected',True),('other',False)])
def test_native_proof_checks_loaded_account_before_quota_or_refresh(tmp_path,expected,ok):
    helper=tmp_path/'native.py'
    helper.write_text('''import queue
class Native:
 def __init__(self,binary):self.messages=queue.Queue()
 def send(self,request):
  assert not request['params'].get('refreshToken')
  result={'account':{'type':'chatgpt'},'workspaceRouting':{'chatgptAccountId':'selected'}} if request['method']=='account/read' else {}
  self.messages.put({'id':request['id'],'result':result})
 def close(self):pass
''')
    result=subprocess.run([sys.executable,'-I','-c',login.RELOAD,'codex',str(helper),
        hashlib.sha256(expected.encode()).hexdigest()],text=True,capture_output=True)
    assert (result.returncode==0)==ok
    assert json.loads(result.stdout)['ok']==ok
    assert 'selected' not in result.stdout
