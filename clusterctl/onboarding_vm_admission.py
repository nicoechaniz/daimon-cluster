"""Bounded guest-loopback relay to an explicitly selected existing authority.

KVM supports host-bound NAT proxy devices, not the container's instance-bound
reverse proxy. Reuse systemd-socket-proxyd, as existing relocated VMs do. The
signed admission protocol remains the authority; this carries no administrator
credential and exposes no guest listener beyond loopback.
"""
from __future__ import annotations

import ipaddress
import json


def request(endpoint, port, plan_digest, *, apply):
    import re
    if (not isinstance(endpoint, str) or endpoint.count(':') != 1
            or type(port) is not int or not 1024 <= port <= 65535
            or not isinstance(plan_digest, str) or not re.fullmatch('[a-f0-9]{64}', plan_digest)):
        raise ValueError('vm_admission_endpoint_required')
    host, remote_port = endpoint.split(':')
    address = ipaddress.IPv4Address(host)
    if (str(address) != host or not address.is_private or address.is_loopback
            or address.is_link_local or address.is_multicast or address.is_unspecified
            or not remote_port.isdecimal() or not 1024 <= int(remote_port) <= 65535):
        raise ValueError('vm_admission_endpoint_required')
    socket = ('[Unit]\nDescription=Own authenticated Cluster admission relay\n'
        'After=network-online.target\n[Socket]\nListenStream=127.0.0.1:'+str(port)+'\n'
        'NoDelay=yes\nBacklog=16\n[Install]\nWantedBy=sockets.target\n')
    service = ('[Unit]\nDescription=Forward only the selected authenticated authority\n'
        '[Service]\nExecStart=/usr/lib/systemd/systemd-socket-proxyd --exit-idle-time=5min '+endpoint+'\n'
        'DynamicUser=yes\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\n'
        'IPAddressDeny=any\nIPAddressAllow=localhost\nIPAddressAllow='+host+'/32\n'
        'MemoryMax=32M\nCPUQuota=10%\nTasksMax=16\nLimitNOFILE=64\n')
    return dict(plan_digest=plan_digest, endpoint=endpoint, port=port, apply=apply,
        files={'daimon-cluster-admission.socket':socket,'daimon-cluster-admission.service':service})


PROGRAM = r'''
import os,json,stat,subprocess,sys
from pathlib import Path
assert os.geteuid()==0
v=json.loads(sys.stdin.read(8193));assert set(v)=={'plan_digest','endpoint','port','apply','files'}
assert set(v['files'])=={'daimon-cluster-admission.socket','daimon-cluster-admission.service'}
root=Path('/etc/systemd/system'); state=Path('/var/lib/daimon-companion-admission.json')
selected={k:v[k] for k in ('plan_digest','endpoint','port','files')}
def owned(p):
 assert not any(x.is_symlink() for x in (p,*p.parents))
 s=p.stat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and s.st_nlink==1 and s.st_size<=8192
 return p.read_text()
if state.exists():assert json.loads(owned(state))==selected,'existing_vm_admission_preserved'
missing=[]
for name,raw in v['files'].items():
 p=root/name
 if p.exists() or p.is_symlink():assert owned(p)==raw,'existing_vm_admission_preserved'
 else:missing.append(name)
def run(a):
 p=subprocess.run(a,capture_output=True,text=True,timeout=12);assert p.returncode==0,'vm_admission_command_failed';return p.stdout
if missing and not v['apply']:print(json.dumps({'ready':False}));raise SystemExit(0)
if v['apply']:
 for name in missing:
  p=root/name;fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
  with os.fdopen(fd,'w') as f:f.write(v['files'][name]);f.flush();os.fsync(f.fileno())
 if not state.exists():
  fd=os.open(state,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as f:json.dump(selected,f);f.flush();os.fsync(f.fileno())
 run(['systemctl','daemon-reload'])
 run(['systemctl','enable','--now','daimon-cluster-admission.socket'])
fields=dict(line.split('=',1) for line in run(['systemctl','show','daimon-cluster-admission.socket','-p','ActiveState','-p','Listen','-p','FragmentPath','-p','DropInPaths']).splitlines() if '=' in line)
assert fields.get('DropInPaths')=='' and fields.get('FragmentPath')==str(root/'daimon-cluster-admission.socket')
ready=fields.get('ActiveState')=='active' and fields.get('Listen')=='127.0.0.1:'+str(v['port'])+' (Stream)'
print(json.dumps({'ready':ready}))
'''


def reconcile(backend, plan, endpoint, port, *, apply, deadline_ns=None):
    from .onboarding import digest, OnboardingError
    value = request(endpoint, port, digest(plan), apply=apply)
    result = json.loads(backend.execute_body(plan, ['/usr/bin/python3','-B','-I','-c',PROGRAM],
        uid=0,gid=0,input_data=json.dumps(value),timeout_seconds=45,deadline_ns=deadline_ns))
    if not isinstance(result,dict) or set(result) != {'ready'} or type(result['ready']) is not bool:
        raise OnboardingError('vm_admission_relay_unconfirmed')
    return result['ready']
