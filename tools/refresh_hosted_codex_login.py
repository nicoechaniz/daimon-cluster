#!/usr/bin/env python3
"""Refresh explicitly selected hosted Codex logins without inference or input replay.

The owner-private config selects receivers. A different account is never replaced.
Valid receiving credentials are retained; a fresh source repairs an invalid file.
Native account/read performs Codex's guarded in-memory reload.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request


class LoginError(ValueError):
    pass


def private_file(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077 or meta.st_size > 65536:
            raise LoginError('private_login_or_config_required')
        return stream.read(65537)


def account(raw: bytes) -> str:
    try:
        value = json.loads(raw)
        ident = value['tokens']['account_id']
        if value['auth_mode'] != 'chatgpt' or not isinstance(ident, str) or not ident:
            raise ValueError()
        return ident
    except (KeyError, TypeError, ValueError):
        raise LoginError('chatgpt_login_required') from None


def access_valid(raw: bytes) -> bool:
    ident = account(raw)
    token = json.loads(raw)['tokens']['access_token']
    request = urllib.request.Request(
        'https://chatgpt.com/backend-api/codex/models?client_version=0.163.0',
        headers={'Authorization': 'Bearer ' + token, 'ChatGPT-Account-Id': ident,
                 'User-Agent': 'codex_cli_rs/0.163.0', 'originator': 'codex_cli_rs'})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status == 200
    except urllib.error.HTTPError as error:
        if error.code == 401:
            return False
        raise LoginError('provider_check_unavailable') from None
    except (OSError, urllib.error.URLError):
        raise LoginError('provider_check_unavailable') from None


def select_login(source: bytes, receiving: bytes, expected_account_sha256: str,
                 *, validate=access_valid) -> tuple[str, bytes]:
    expected = hashlib.sha256(account(source).encode()).hexdigest()
    if expected != expected_account_sha256 or account(receiving) != account(source):
        raise LoginError('receiving_account_preserved')
    if validate(receiving):
        return 'retained_valid_receiving_login', receiving
    if not validate(source):
        raise LoginError('source_device_login_required')
    return 'selected_valid_source_login', source


# Uses the already deployed native WebSocket client, not a second daemon/client
# implementation. Only these two account operations are issued; no turn starts.
RELOAD = r'''
import hashlib,importlib.util,json,time,sys
binary,helper,expected_account=sys.argv[1:]
spec=importlib.util.spec_from_file_location('receiving_native',helper)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
native=module.Native(binary)
try:
 for refresh in (False,True):
  error=None
  for index,method,params in [(1,'account/read',{'refreshToken':refresh}),
                             (2,'account/rateLimits/read',{})]:
   ident=8100+index+int(refresh)*10
   native.send({'id':ident,'method':method,'params':params})
   deadline=time.monotonic()+40
   while time.monotonic()<deadline:
    reply=native.messages.get(timeout=max(.01,deadline-time.monotonic()))
    if reply.get('id')!=ident:continue
    if 'error' in reply:error=reply['error'].get('code')
    elif method=='account/read':
     result=reply.get('result') or {}
     account=result.get('account') or {}
     routing=result.get('workspaceRouting') or {}
     actual=routing.get('chatgptAccountId')
     if account.get('type')!='chatgpt' or not isinstance(actual,str) or hashlib.sha256(actual.encode()).hexdigest()!=expected_account:
      print(json.dumps({'ok':False,'code':'native_account_unconfirmed'}));raise SystemExit(2)
    break
   else:raise TimeoutError()
   if error is not None:break
  if error is None:
   print(json.dumps({'ok':True,'native_account_and_quota':True,'guarded_reload':refresh}))
   break
 else:
  print(json.dumps({'ok':False,'code':error}));raise SystemExit(2)
finally:native.close()
'''


INSTALL = r'''
import sys,json,os,hashlib,tempfile
from pathlib import Path
code,home,uid,gid=sys.argv[1:];uid=int(uid);gid=int(gid)
sys.path.insert(0,code)
from clusterctl.onboarding_accounts import install_shared_cache
request=json.load(sys.stdin);destination=Path(home)/'.codex/auth.json'
before=destination.read_bytes()
if hashlib.sha256(before).hexdigest()!=request['before_sha256']:
 raise SystemExit('receiving_login_changed')
old=json.loads(before);new=json.loads(request['source'])
if old['tokens']['account_id']!=new['tokens']['account_id']:
 raise SystemExit('receiving_account_preserved')
history_root=destination.parent/'provider-login-history'
history_root.mkdir(mode=0o700,exist_ok=True)
if history_root.is_symlink() or history_root.stat().st_mode&0o077:
 raise SystemExit('private_login_history_required')
history=history_root/request['before_sha256']
history.mkdir(mode=0o700,exist_ok=True)
if history.is_symlink() or history.stat().st_mode&0o077:
 raise SystemExit('private_login_history_required')
backup=history/'auth.json'
if backup.exists():
 if backup.read_bytes()!=before:raise SystemExit('login_history_conflict')
else:
 fd=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(fd,'wb') as stream:
  stream.write(before);stream.flush();os.fsync(stream.fileno())
destination.unlink()
try:
 with tempfile.TemporaryDirectory(prefix='codex-login-',dir=destination.parent) as folder:
  source=Path(folder)/'auth.json';source.write_text(request['source']);source.chmod(0o600)
  install_shared_cache(source,destination,uid=uid,gid=gid,account=new['tokens']['account_id'])
except BaseException:
 if not destination.exists():
  fd=os.open(destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
  with os.fdopen(fd,'wb') as stream:
   stream.write(before);stream.flush();os.fsync(stream.fileno())
   os.fchown(stream.fileno(),uid,gid)
 raise
print(json.dumps({'installed':True,'same_account':True,'preimage_retained':True}))
'''


def incus(receiver: dict, args: list[str], *, owner=False, payload=None) -> str:
    command = ['incus', 'exec', receiver['instance']]
    if owner:
        command += ['--user', str(receiver['uid']), '--group', str(receiver['gid']),
                    '--cwd', receiver['home'], '--env', 'HOME=' + receiver['home'],
                    '--env', 'CODEX_HOME=' + receiver['home'] + '/.codex']
    result = subprocess.run(command + ['--', *args], input=payload,
                            text=True, capture_output=True, timeout=180)
    if result.returncode:
        raise LoginError('receiving_operation_failed')
    return result.stdout


def refresh(source: bytes, receiver: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix='hosted-codex-login-') as temporary:
        path = Path(temporary)/'auth.json'
        result = subprocess.run(['incus', 'file', 'pull', receiver['instance'] +
                                 receiver['home'] + '/.codex/auth.json', str(path)],
                                capture_output=True, timeout=60)
        if result.returncode:
            raise LoginError('receiving_login_unavailable')
        current = private_file(path)
        selection, chosen = select_login(source, current, receiver['account_sha256'])
        if chosen != current:
            units = receiver['units']
            active = [u for u in units if incus(receiver,
                ['systemctl','show',u,'-p','ActiveState','--value']).strip() == 'active']
            try:
                incus(receiver, ['systemctl','stop',*units])
                incus(receiver, ['python3','-I','-c',INSTALL,receiver['code'],receiver['home'],
                    str(receiver['uid']),str(receiver['gid'])], payload=json.dumps({
                    'before_sha256':hashlib.sha256(current).hexdigest(),
                    'source':chosen.decode()}))
            finally:
                if active:
                    incus(receiver,['systemctl','start',*active])
        proof = json.loads(incus(receiver, ['python3','-I','-c',RELOAD,
            receiver['binary'],receiver['native_helper'],receiver['account_sha256']], owner=True))
        if proof.get('ok') is not True:
            raise LoginError('native_login_reload_unconfirmed')
        return {'receiver':receiver['name'],'selection':selection,**proof}


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    args=parser.parse_args()
    os.umask(0o077)
    try:
        config=json.loads(private_file(args.config))
        if config.get('schema')!='cluster.hosted-codex-login/v1' or not config.get('receivers'):
            raise LoginError('explicit_receivers_required')
        source=private_file(Path(config['source_login']))
        for receiver in config['receivers']:
            print(json.dumps(refresh(source,receiver)),flush=True)
        return 0
    except (LoginError,ValueError,KeyError,OSError,subprocess.TimeoutExpired) as error:
        # Neither credential values nor credential-bearing HTTP exceptions escape.
        reason = str(error) if isinstance(error, LoginError) else 'login_refresh_incomplete'
        print(json.dumps({'ok':False,'reason':reason,
                          'action':'Inspect the selected receiver; do not replay inputs.'}),flush=True)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
