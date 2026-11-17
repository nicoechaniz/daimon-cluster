"""Keep a new VM's private runtime databases on its native, bounded root disk.

Canonical home paths stay unchanged. This is one boot prerequisite, not another
memory store, account, scheduler or model admission route.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

from .onboarding import OnboardingError

UNIT = 'daimon-companion-state.service'
CONSUMERS = ('daimon-onboarding-codex.service', 'daimon-onboarding-matrix.service',
             'children-conversation-native.service', 'children-conversation-web.service',
             'daimon-home.service')

BOOTSTRAP = r'''import json,os,stat,subprocess,sys,time,uuid
from pathlib import Path

HOME=Path('/home/agent')
BASE=Path('/var/lib/daimon-companion-state')
ROLES=('.agents','.local','.codex')

def private(path,uid=0):
 if any(p.is_symlink() for p in (path,*path.parents)):raise RuntimeError('state_path_refused')
 path.mkdir(mode=0o700,parents=True,exist_ok=True)
 s=path.stat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=uid or s.st_mode&0o077:raise RuntimeError('state_owner_refused')

def save(path,value):
 temporary=path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
 fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as stream:
  json.dump(value,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
 os.replace(temporary,path)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)

def run(argv):
 r=subprocess.run(argv,capture_output=True,timeout=90,check=False)
 if r.returncode:raise RuntimeError('state_operation_refused')
 return r.stdout

def mounted(target,source):
 if not target.is_mount():return False
 a,b=target.stat(),source.stat()
 if (a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino):raise RuntimeError('foreign_state_mount_preserved')
 return True

def native(root,home):
 return root.stat().st_dev==Path('/').stat().st_dev and root.stat().st_dev!=home.stat().st_dev

def activate(value):
 if os.geteuid()!=0 or set(value)!={'schema','plan_digest','name'} or value['schema']!='cluster-vm-state/v1':raise RuntimeError('state_request_refused')
 if len(value['plan_digest'])!=64 or any(c not in '0123456789abcdef' for c in value['plan_digest']):raise RuntimeError('state_request_refused')
 root=BASE/value['plan_digest'];private(BASE);private(root)
 record=root/'current.json'
 state=json.loads(record.read_text()) if record.exists() else {'request':value,'copied':[]}
 if state.get('request')!=value or any(x not in ROLES for x in state.get('copied',[])):raise RuntimeError('state_request_changed')
 end=time.monotonic()+60
 while not HOME.is_mount():
  if time.monotonic()>=end:raise RuntimeError('state_home_mount_unavailable')
  time.sleep(.05)
 if not native(root,HOME):raise RuntimeError('native_state_filesystem_required')
 for role in ROLES:
  source=root/role;target=HOME/role
  if source.exists():private(source,1000)
  else:
   source.mkdir(mode=0o700);os.chown(source,1000,1000)
  if mounted(target,source):continue
  if target.exists():private(target,1000)
  else:
   target.mkdir(mode=0o700);os.chown(target,1000,1000)
  if role not in state['copied']:
   # Only initial, inactive context may be moved. A completed identity/runtime
   # cannot enter a fresh migration under another plan or lose its live writes.
   matrix=HOME/'.local/state/daimon-onboarding'/value['name']/'matrix'
   if matrix.exists():raise RuntimeError('existing_identity_state_preserved')
   count=total=0
   for parent,dirs,files in os.walk(target,followlinks=False):
    for name in files:
     p=Path(parent)/name;s=p.lstat();count+=1;total+=s.st_size
     if not (stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode)):raise RuntimeError('state_file_refused')
     if count>20000 or total>1024**3:raise RuntimeError('state_copy_capacity')
   run(['/usr/bin/rsync','--archive','--one-file-system','--checksum','--fsync',str(target)+'/',str(source)+'/'])
   changed=run(['/usr/bin/rsync','--archive','--one-file-system','--checksum','--dry-run','--itemize-changes',str(target)+'/',str(source)+'/'])
   if changed.strip():raise RuntimeError('state_copy_readback_failed')
   state['copied'].append(role);save(record,state)
  run(['/usr/bin/mount','--bind',str(source),str(target)])
  if not mounted(target,source):raise RuntimeError('state_mount_unconfirmed')
 state['ready']=True;save(record,state)
 print(json.dumps({'ready':True,'canonical_paths_preserved':True,'native_root_disk':True}))

if __name__=='__main__':
 try:activate(json.loads(Path(sys.argv[1]).read_text()))
 except Exception:
  print(json.dumps({'ready':False,'error':'companion_native_state_unavailable'}));raise SystemExit(1)
'''


def unit():
    return ('[Unit]\nDescription=Bounded companion private state on native VM disk\n'
        'After=incus-agent.service\nBefore=' + ' '.join(CONSUMERS) + '\n'
        '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
        'ExecStart=/usr/bin/python3 -B -I /usr/local/libexec/daimon-companion-state.py '
        '/var/lib/daimon-companion-state/config.json\n'
        'TimeoutStartSec=300\nMemoryMax=192M\nTasksMax=32\nUMask=0077\n'
        '[Install]\nWantedBy=multi-user.target\n').encode()


def install(plan_digest, name):
    if (os.geteuid() != 0 or not isinstance(plan_digest, str)
            or not re.fullmatch('[0-9a-f]{64}', plan_digest)
            or not isinstance(name, str) or not re.fullmatch('[a-z0-9][a-z0-9-]{0,30}', name)):
        raise OnboardingError('companion_native_state_required')
    def write(path, raw, mode):
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise OnboardingError('companion_native_state_required')
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if path.exists():
            if path.read_bytes() != raw or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
                raise OnboardingError('existing_companion_state_preserved')
        else:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
    config = Path('/var/lib/daimon-companion-state')
    config.mkdir(mode=0o700, exist_ok=True)
    write(config/'config.json', json.dumps(dict(schema='cluster-vm-state/v1',
        plan_digest=plan_digest, name=name), sort_keys=True).encode(), 0o600)
    script = Path('/usr/local/libexec/daimon-companion-state.py')
    write(script, BOOTSTRAP.encode(), 0o555)
    write(Path('/etc/systemd/system')/UNIT, unit(), 0o644)
    dropin = ('[Unit]\nRequires='+UNIT+'\nAfter='+UNIT+'\n').encode()
    for consumer in CONSUMERS:
        write(Path('/etc/systemd/system')/(consumer+'.d/companion-state.conf'), dropin, 0o644)
    for argv in (['systemctl','daemon-reload'], ['systemctl','enable',UNIT],
                 ['/usr/bin/python3','-B','-I',str(script),str(config/'config.json')]):
        result = subprocess.run(argv, capture_output=True, timeout=300, check=False)
        if result.returncode:
            raise OnboardingError('companion_native_state_required')
