#!/usr/bin/env python3
"""Own-user on-demand WebBridge lifecycle; no root grant or account transfer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import stat
import subprocess
import time
import urllib.request

UNITS=('kimi-webbridge-browser.service','kimi-webbridge-daemon.service','kimi-webbridge-display.service')
ORIGIN='http://127.0.0.1:10086'


def home():
    user=pwd.getpwuid(os.getuid())
    if user.pw_name!='agent' or os.getuid()<1000 or Path.home()!=Path(user.pw_dir):
        raise ValueError('own_companion_user_required')
    return Path(user.pw_dir)


def private(path,directory=False):
    info=path.lstat()
    if (path.is_symlink() or info.st_uid!=os.getuid() or info.st_mode & 0o077
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise ValueError('owner_private_browser_state_required')


def state():
    root=home()/'.local/state/children-browser';root.mkdir(parents=True,exist_ok=True,mode=0o700)
    private(root,True)
    if sum(p.stat().st_size for p in root.rglob('*') if p.is_file())>1024*1024:
        raise ValueError('browser_control_state_capacity')
    return root


def save(path,value):
    raw=json.dumps(value,sort_keys=True).encode()
    if len(raw)>65536 or path.is_symlink():raise ValueError('browser_state_capacity_or_custody')
    temporary=path.with_suffix('.next')
    if temporary.exists():private(temporary)
    with temporary.open('wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    temporary.chmod(0o600);temporary.replace(path)


def binding():
    p=state()/'binding.json';private(p)
    if p.stat().st_size>65536:raise ValueError('browser_binding_capacity')
    value=json.loads(p.read_text())
    if value.get('schema')!='children-browser-binding/v1':raise ValueError('unknown_browser_binding')
    return value


def verify_runtime(runtime,base=Path('/opt/children-maintenance/browser'),owner_uid=0):
    runtime=Path(runtime)
    if (not runtime.is_absolute() or runtime.resolve()!=runtime
            or not runtime.is_relative_to(base)):
        raise ValueError('selected_public_browser_runtime_required')
    p=runtime/'runtime.json';info=p.lstat()
    if p.is_symlink() or info.st_uid!=owner_uid or info.st_mode & 0o022 or info.st_size>65536:
        raise ValueError('browser_runtime_custody')
    value=json.loads(p.read_text())
    if value.get('schema')!='children-webbridge-runtime/v1' or value.get('version')!='2.0.22':
        raise ValueError('unqualified_browser_runtime')
    if (not isinstance(value.get('files'),dict) or not 2<=len(value['files'])<=512
            or not {'kimi-webbridge','extension/manifest.json'}<=set(value['files'])):
        raise ValueError('incomplete_browser_runtime')
    total=0
    for name,digest in value['files'].items():
        item=runtime/name
        if Path(name).is_absolute() or '..' in Path(name).parts or item.resolve()!=item:
            raise ValueError('browser_runtime_path')
        info=item.stat();total+=info.st_size
        if (not item.is_file() or info.st_uid!=owner_uid or info.st_mode & 0o022
                or total>32*1024*1024 or hashlib.sha256(item.read_bytes()).hexdigest()!=digest):
            raise ValueError('browser_runtime_bytes')
    return value


def initialize(runtime=None):
    root=home()/'.kimi-webbridge';root.mkdir(mode=0o700,exist_ok=True);private(root,True)
    p=state()/'binding.json'
    if p.exists():
        current=binding()
        if runtime is not None and current['runtime']!=str(runtime):
            raise ValueError('existing_browser_binding_requires_reconciliation')
        runtime=Path(current['runtime'])
    elif runtime is None:raise ValueError('initial_public_runtime_selection_required')
    verify_runtime(runtime)
    for name in ['bin','chromium-profile']:
        directory=root/name;directory.mkdir(mode=0o700,exist_ok=True);private(directory,True)
    binary=root/'bin/kimi-webbridge'
    extension=root/'extension'
    for link,destination in [(binary,Path(runtime)/'kimi-webbridge'),(extension,Path(runtime)/'extension')]:
        if link.is_symlink():
            if link.resolve()!=destination:raise ValueError('existing_browser_code_selection_changed')
        elif link.exists():raise ValueError('existing_browser_installation_preserved')
        else:link.symlink_to(destination)
    authority=root/'Xauthority'
    if authority.exists():private(authority)
    else:
        # Secret travels through stdin, not argv/logs or an exported credential.
        text='add :77 . '+secrets.token_hex(16)+'\n'
        result=subprocess.run(['xauth','-f',str(authority),'source','-'],input=text,
                              stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True,timeout=5)
        if result.returncode:raise ValueError('own_display_authority_initialization_failed')
        authority.chmod(0o600);private(authority)
    value={'schema':'children-browser-binding/v1','runtime':str(runtime),
           'origin':ORIGIN,'display':':77','profile':str(root/'chromium-profile'),
           'audience':'own-virtual-loopback-only','account_sign_in':'not-performed'}
    if p.exists():
        if binding()!=value:raise ValueError('existing_browser_binding_preserved')
    else:save(p,value)
    return {'state':'installed','version':'2.0.22','profile_preserved':True,'private_display_authority':True}


def environment():
    root=Path('/run/user')/str(os.getuid());info=root.stat()
    if info.st_uid!=os.getuid() or info.st_mode & 0o077 or not(root/'bus').exists():
        raise ValueError('own_user_manager_unavailable')
    return {**os.environ,'XDG_RUNTIME_DIR':str(root),'DBUS_SESSION_BUS_ADDRESS':'unix:path='+str(root/'bus')}


def units():
    result={}
    for unit in UNITS:
        reply=subprocess.run(['systemctl','--user','show',unit,'-p','LoadState','-p','ActiveState','-p','SubState'],
                             env=environment(),capture_output=True,text=True,timeout=5)
        if reply.returncode or len(reply.stdout)>8192:raise ValueError('own_browser_units_unavailable')
        value=dict(line.split('=',1) for line in reply.stdout.splitlines())
        if value.get('LoadState')!='loaded':raise ValueError('own_browser_unit_not_installed')
        result[unit]=value
    return result


def daemon():
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(ORIGIN+'/status',timeout=2) as reply:
        if reply.geturl()!=ORIGIN+'/status':raise ValueError('local_browser_redirect')
        raw=reply.read(65537)
    if len(raw)>65536:raise ValueError('browser_status_capacity')
    value=json.loads(raw)
    return {k:value.get(k) for k in ['running','version','extension_connected']}


def inspect():
    binding();current=units();browser=current[UNITS[0]]
    if browser['ActiveState']=='inactive' and browser['SubState']=='dead':
        return {'schema':'children-browser-status/v1','state':'standby','intentional':True}
    if any(v['ActiveState']!='active' for v in current.values()):
        return {'schema':'children-browser-status/v1','state':'unavailable','reason':'managed_unit_unavailable'}
    try:
        bridge=daemon()
        ready=(bridge.get('running') is True and bridge.get('extension_connected') is True
               and bridge.get('version') in ('2.0.22','v2.0.22'))
    except (OSError,ValueError):bridge={};ready=False
    return {'schema':'children-browser-status/v1','state':'ready' if ready else 'unavailable',
            'bridge':bridge,'ownership':'task-session-close-required; unknown activity is preserved'}


def wait_dependencies():
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        try:
            if Path('/tmp/.X11-unix/X77').is_socket() and daemon().get('running') is True:return {'state':'prerequisites-ready'}
        except (OSError,ValueError):pass
        time.sleep(.2)
    raise ValueError('own_browser_prerequisites_unavailable')


def start():
    initialize()
    subprocess.run(['systemctl','--user','start',UNITS[0]],env=environment(),check=True,timeout=25)
    deadline=time.monotonic()+25
    while time.monotonic()<deadline:
        result=inspect()
        if result['state']=='ready':return result
        time.sleep(.25)
    raise ValueError('browser_functional_readiness_pending')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['init','wait','start','status','stop'])
    parser.add_argument('--runtime',type=Path)
    args=parser.parse_args();os.umask(0o077)
    try:
        if args.action=='init':result=initialize(args.runtime)
        elif args.action=='wait':result=wait_dependencies()
        elif args.action=='start':result=start()
        elif args.action=='status':result=inspect()
        else:
            # Explicit owning task action, never invoked by a periodic idle guess.
            binding()
            subprocess.run(['systemctl','--user','stop',*UNITS],env=environment(),check=True,timeout=25)
            result=inspect()
        print(json.dumps(result,sort_keys=True))
        return 0 if result['state']!='unavailable' else 2
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print(json.dumps({'schema':'children-browser-status/v1','state':'unavailable','reason':type(error).__name__}))
        return 2


if __name__=='__main__':raise SystemExit(main())
