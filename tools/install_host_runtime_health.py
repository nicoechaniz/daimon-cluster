"""Install host observation using an existing Alerts core and receiving route.

Operator-only setup once per host; the onboarding worker enrolls future bodies.
No guest credential, bot consumer, model or conversation control is installed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import pwd
import re
import secrets
import subprocess
import uuid
from pathlib import Path
from clusterctl import being_seed, onboarding_release
from clusterctl.onboarding import OnboardingError, private_directory


def replace(path, raw):
    before = onboarding_release.regular(path, uid=path.stat().st_uid) if path.exists() else None
    if before == raw:
        return
    if before is not None:
        backup = path.with_name(path.name + '.' + hashlib.sha256(before).hexdigest() + '.previous')
        if not backup.exists():
            backup.write_bytes(before);backup.chmod(0o600)
    temporary = path.with_name('.' + path.name + '.candidate-' + uuid.uuid4().hex)
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as out:
            out.write(raw);out.flush();os.fsync(out.fileno())
            if path.exists():os.fchown(out.fileno(),path.stat().st_uid,path.stat().st_gid)
        if (onboarding_release.regular(path,uid=path.stat().st_uid) if path.exists() else None) != before:
            raise OnboardingError('host_health_concurrent_change')
        os.replace(temporary,path)
    finally:
        temporary.unlink(missing_ok=True)


def install(*, core_config: Path, source: Path, registry: Path, scope: str,
            adapter: str, host_resource: str, core_systemd_scope='user', run=subprocess.run) -> dict:
    if os.geteuid()!=0:
        raise OnboardingError('host_operator_required')
    for name in (scope,adapter,host_resource):
        if not re.fullmatch('[A-Za-z0-9_-]{1,70}',name):raise OnboardingError('host_health_scope_required')
    registry=private_directory(registry)
    directory=private_directory(registry.parent/'observer',create=True)
    raw=onboarding_release.regular(core_config,uid=core_config.stat().st_uid)
    core=json.loads(raw);owner=pwd.getpwuid(core_config.stat().st_uid)
    freshness=core['freshness_seconds']
    if type(freshness) is not int or freshness<25 or core_systemd_scope not in ('user','system'):
        raise OnboardingError('host_health_freshness_required')
    if not any(r==dict(receiving_scope=scope,adapter_id=adapter) for r in core['routes']):
        raise OnboardingError('existing_alerts_route_required')
    listen=core['listen']
    if not isinstance(listen,str) or not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}',listen):
        raise OnboardingError('existing_local_alerts_required')
    files={name:onboarding_release.regular(source/name,uid=0) for name in ('service_monitor.py','client.py')}
    fingerprint=hashlib.sha256(b''.join(files[k] for k in sorted(files))).hexdigest()
    release=Path('/opt/daimon-runtime-health')/fingerprint;release.mkdir(mode=0o755,parents=True,exist_ok=True)
    for name,content in files.items():
        path=release/name
        if path.exists():
            if onboarding_release.regular(path,uid=0)!=content:raise OnboardingError('host_health_source_preserved')
        else:path.write_bytes(content);path.chmod(0o644)
    token_path=directory/'publish.token'
    if token_path.exists():token=onboarding_release.regular(token_path,uid=0,limit=1024).decode().strip()
    else:
        token=secrets.token_hex(32)
        with token_path.open('x') as stream:stream.write(token+'\n')
        token_path.chmod(0o600)
    if token_path.stat().st_mode & 0o077 or not re.fullmatch('[0-9a-f]{64}',token):
        raise OnboardingError('private_host_health_token_required')
    producer='hosted-enrollments';observer=producer+'-observer'
    actor=dict(actor_id=producer,token_sha256=hashlib.sha256(token.encode()).hexdigest(),
               producers=[producer,observer],scopes=[scope],adapters=[],grants=['publish','observe','status'])
    prior=next((a for a in core['actors'] if a['actor_id']==producer),None)
    if prior is not None and prior!=actor:raise OnboardingError('host_health_actor_preserved')
    if prior is None:
        core['actors'].append(actor);replace(core_config,(json.dumps(core,indent=2)+'\n').encode())
    if core_systemd_scope=='user':
        reload=['runuser','-u',owner.pw_name,'--','env',f'XDG_RUNTIME_DIR=/run/user/{owner.pw_uid}',
                'systemctl','--user','restart','daimon-alerts.service']
    elif core_systemd_scope=='system':reload=['systemctl','restart','daimon-alerts.service']
    else:raise OnboardingError('host_health_manager_required')
    run(reload,capture_output=True,check=True,timeout=30)
    config=dict(base_url='http://'+listen,token_file=str(token_path),state_dir=str(directory/'state'),
                producer_id=producer,observer_id=observer,receiving_scope=scope,targets=[dict(
                id='hosted-bodies',resource_ref=host_resource,kind='enrollment_registry',
                registry=str(registry),incus_binary='/usr/bin/incus',full_avg60_percent=5)])
    config_path=directory/'config.json';replace(config_path,(json.dumps(config,indent=2)+'\n').encode())
    interval=max(1,min(15,freshness//2));heartbeat=10
    units=Path('/etc/systemd/system')
    command=' '.join(json.dumps(str(a).replace('%','%%').replace('$','$$')) for a in
        ('/usr/bin/python3','-B',release/'service_monitor.py','--config',config_path))
    service=f'''[Unit]
Description=Observe enrolled hosted native runtimes and memory without model turns
[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart={command}
TimeoutStartSec=180
MemoryMax=256M
'''
    timer=f'''[Unit]
Description=Keep enrolled resource observations current
[Timer]
OnBootSec=15
OnUnitInactiveSec={interval}
AccuracySec=1
Unit=daimon-cluster-runtime-health.service
[Install]
WantedBy=timers.target
'''
    for name,value in [('daimon-cluster-runtime-health.service',service),('daimon-cluster-runtime-health.timer',timer)]:
        replace(units/name,value.encode())
    run(['systemctl','daemon-reload'],capture_output=True,check=True,timeout=30)
    run(['systemctl','enable','--now','daimon-cluster-runtime-health.timer'],capture_output=True,check=True,timeout=30)
    return dict(installed=True,source_sha256=fingerprint,registry=str(registry),interval_seconds=interval,heartbeat_seconds=heartbeat)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for flag in ('core-config','source','registry'):p.add_argument('--'+flag,type=Path,required=True)
    p.add_argument('--host-resource',required=True)
    p.add_argument('--scope',required=True);p.add_argument('--adapter',required=True)
    p.add_argument('--core-systemd-scope',choices=('user','system'),default='user')
    args=p.parse_args()
    try:print(json.dumps(install(core_config=args.core_config,source=args.source,registry=args.registry,
                                scope=args.scope,adapter=args.adapter,host_resource=args.host_resource,core_systemd_scope=args.core_systemd_scope)))
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):raise SystemExit('host_runtime_health_install_refused') from None

if __name__=='__main__':main()
