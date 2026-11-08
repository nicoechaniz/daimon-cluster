"""Finite, fixed-scope host/onboarding reader for the authenticated Fleet UI.

The socket-activated owner selects all inputs in private configuration. Clients
supply no commands or paths. No model, inbox, provisioning or repair is run.
"""
from __future__ import annotations
import concurrent.futures
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

LIMIT = 131072


def run(argv, source, timeout=16):
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
    poll = selectors.DefaultSelector()
    poll.register(child.stdout, selectors.EVENT_READ, True)
    poll.register(child.stderr, selectors.EVENT_READ, False)
    output = bytearray(); seen = 0; deadline = time.monotonic() + timeout
    try:
        child.stdin.write(source.encode()); child.stdin.close()
        while poll.get_map():
            if time.monotonic() >= deadline:
                raise ValueError('observation_timeout')
            for key, _ in poll.select(min(.2, max(0, deadline-time.monotonic()))):
                raw = os.read(key.fd, 65536)
                if not raw:
                    poll.unregister(key.fileobj); continue
                seen += len(raw)
                if seen > LIMIT:
                    raise ValueError('observation_limit')
                if key.data: output.extend(raw)
        if child.wait(timeout=max(.01, deadline-time.monotonic())):
            raise ValueError('observation_unavailable')
        return json.loads(output)
    finally:
        poll.close()
        if child.poll() is None: os.killpg(child.pid, signal.SIGKILL)
        child.wait(); child.stdout.close(); child.stderr.close()


PREPARATION = r'''
def private_record(path):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>131072:raise ValueError('record_unavailable')
    return json.loads(p.read_text())

preparations=[]
root=Path(spec['jobs'])
if not root.is_dir() or root.is_symlink():raise ValueError('jobs_unavailable')
paths=sorted(root.glob('*/job.json'))
if len(paths)>16:raise ValueError('job_limit')
instances=json.loads(subprocess.run(['incus','list','--format=json'],capture_output=True,text=True,timeout=4,check=True).stdout)
if len(instances)>128:raise ValueError('instance_limit')
by_name={r['name']:r for r in instances}
for path in paths:
    job=private_record(path)
    if job.get('schema')!='cluster-onboarding-job/v1':raise ValueError('job_schema')
    plan=job['plan'];name=plan['name']
    if name!=path.parent.name or re.fullmatch('[a-z][a-z0-9-]{0,62}',name) is None:raise ValueError('job_identity')
    row={'name':name,'host':socket.gethostname(),'hosting':'Incus','physical_state':'unavailable','observed_at_ms':int(time.time()*1000),'stage':job['stage'],'job_state':job['state'],'services':{}}
    instance=by_name.get(spec['instance_prefix']+name)
    if instance:
        row['physical_state']=instance.get('status','unknown').lower()
        config=instance.get('expanded_config',{})
        row['hosting']='Incus · '+config.get('limits.cpu','?')+' CPU / '+config.get('limits.memory','?')
        if row['physical_state']=='running':
            try:
                result=subprocess.run(['incus','exec',instance['name'],'--','systemctl','show',*spec['services'],'--property=Id,LoadState,ActiveState'],capture_output=True,text=True,timeout=3,check=True)
                for block in result.stdout.strip().split('\n\n'):
                    value=dict(l.split('=',1) for l in block.splitlines() if '=' in l)
                    if value.get('Id') in spec['services']:row['services'][value['Id']]=value.get('ActiveState','unknown') if value.get('LoadState')=='loaded' else 'not-installed'
            except (OSError,ValueError,subprocess.SubprocessError):row['services_state']='unavailable'
    preparations.append(row)
'''


def collect(config, *, execute=run):
    source = Path(config['probe_source']).read_bytes()
    if hashlib.sha256(source).hexdigest() != config['probe_sha256']:
        raise ValueError('changed_probe_source')
    source = source.decode().rsplit("\nif __name__ == '__main__':", 1)[0]
    if not 1 <= len(config['targets']) <= 8:
        raise ValueError('bounded_targets_required')
    def read(target):
        label = {k: target[k] for k in ('id', 'label', 'scope')}
        label.update(state='unavailable', attempted_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
        try:
            spec = target['probe']
            program = source+'\nimport subprocess,re,socket\nspec='+repr(spec)+'\nreading=probe(spec)\n'
            if 'jobs' in spec: program += PREPARATION
            else: program += '\npreparations=[]\n'
            program += '\nprint(json.dumps(dict(reading=reading,preparations=preparations)))\n'
            data = execute(target['command'], program)
            label.update(state='available', reading=data['reading'])
            return label, data['preparations']
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            return label, []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(read, config['targets']))
    return {'schema':'cluster-fleet-observation/v1','observed_at_ms':int(time.time()*1000),
            'health':{'schema':'computer-health/v1','targets':[r[0] for r in rows]},
            'preparations':[p for r in rows for p in r[1]],
            'partial':any(r[0]['state']!='available' for r in rows)}


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',type=Path,required=True);args=parser.parse_args()
    os.umask(0o077)
    if args.config.is_symlink() or args.config.stat().st_uid!=os.geteuid() or args.config.stat().st_mode&0o077:
        raise ValueError('private_owner_configuration_required')
    if args.config.stat().st_size>32768:raise ValueError('configuration_limit')
    config=json.loads(args.config.read_text());state=Path(config['state']);state.mkdir(mode=0o700,parents=True,exist_ok=True)
    if state.is_symlink() or state.stat().st_uid!=os.geteuid() or state.stat().st_mode&0o077:
        raise ValueError('private_state_required')
    with (state/'lock').open('a+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        current=state/'current.json'
        if current.exists() and 0 <= time.time()-current.stat().st_mtime < 5:
            raw=current.read_bytes()
        else:
            result=collect(config);raw=json.dumps(result).encode()
            if len(raw)>LIMIT:raise ValueError('report_limit')
            temporary=state/'current.next';temporary.write_bytes(raw);temporary.chmod(0o600);temporary.replace(current)
        if len(raw)>LIMIT:raise ValueError('report_limit')
        print(raw.decode(),flush=True)


if __name__=='__main__':main()
