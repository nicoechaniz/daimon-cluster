"""Apply a prepared native visibility successor in one resumable invocation.

Reuse the existing owner writers, physical placements and reader clients. No
onboarding, provider input, goal control or new background service is involved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


# One fixed program crosses the existing administrative route. Payloads are JSON
# on stdin, never interpolated into Python or a shell command.
WORKER = r'''
import hashlib,json,os,pwd,subprocess,sys,time
from pathlib import Path

def atomic(path,value):
    raw=(json.dumps(value,sort_keys=True)+'\n').encode()
    if len(raw)>512*1024:raise ValueError('visibility_record_too_large')
    temporary=path.with_suffix('.next')
    with temporary.open('wb') as out:
        out.write(raw);out.flush();os.fsync(out.fileno())
    temporary.chmod(0o600);os.replace(temporary,path)
    fd=os.open(path.parent,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def owner(payload):
    launch=payload['launch'];c=launch['owner_config'];common=payload['intent']
    name=launch['name'];mode=payload['mode'];directory=Path(launch['owner'])
    receipt=directory/('receipt.json' if mode=='sign' else 'publication-receipt.json')
    if receipt.exists():
        saved=json.loads(receipt.read_text())
        assert saved['operation_id']==common['operation_id'] and saved['name']==name
        return saved
    sdk=Path(c['sdk']);sys.prefix=sys.exec_prefix=str(sdk/'venv')
    sys.path[:0]=[c['code'],str(sdk/'runtime-imports')]
    from clusterctl import onboarding_group_admission as social
    from daimon_matrix import operator_messaging
    from daimon_matrix.messaging_config import config_digest
    if name=='compaii':
        from clusterctl.onboarding_source import Source
        instance=Source(json.loads(Path(c['config']).read_text()),code=Path(c['code']),code_digest=c['code_digest'])
        runtime,group,writer=instance.root,instance.outputs/'tribe',instance.writer
    else:
        from clusterctl.onboarding_target import Target
        instance=Target(Path(c['home']),json.loads(Path(c['plan']).read_text()),
            json.loads(Path(c['genesis']).read_text()),code=Path(c['code']),code_digest=c['code_digest'])
        runtime,group,writer=instance.package/'runtime',instance.root/'tribe',instance._runtime_writer
    raw=(runtime/'runtime.json').read_bytes();bundle=json.loads(raw)
    assert hashlib.sha256(raw).hexdigest()==c['runtime_sha256']
    assert bundle['manifest']==common['public'][name]['public']['authority']['manifest']
    closure={v['public']['authority']['manifest']['being_ref']:v['public']
        for n,v in common['public'].items() if n!=name}
    if mode=='sign':
        # Refuse an unfinished earlier owner attempt; inspect it rather than
        # replacing an original whose effect is not established.
        assert not (directory/'started.json').exists(),'visibility_owner_outcome_unconfirmed'
        with writer():
            hosted=social.load_owner_runtime(runtime,instance._reader,
                authorities=social.public_authorities(bundle,closure))
            bindings=[]
            for target,selected in common['destinations'].items():
                doc=operator_messaging.group_visibility_disclosure(hosted,group/'application',
                    approved_destination=selected['destination'],issued_at_ms=common['issued_at_ms'],
                    local_being_ref=selected['being_ref'])
                assert doc==common['canonical_disclosures'][target]
                binding=operator_messaging.accept_group_visibility(hosted,group/'application',doc,
                    approved_destination=selected['destination'])
                bindings.append(dict(name=target,disclosure=doc,
                    disclosure_sha256=config_digest(doc),binding=binding))
            assert (runtime/'runtime.json').read_bytes()==raw
        value=dict(name=name,operation_id=common['operation_id'],bindings=bindings,
            models=0,published=False)
    else:
        selected=payload['publication'];installation=group/'visibility/installation.json'
        before=json.loads(installation.read_text())['document']
        key=installation.parent/before['secrets']['proof_key_file']
        key_before=(key.stat().st_ino,key.read_bytes())
        command=dict(operation_id=common['operation_id'],step='portable-visibility-successor',
            action='visibility-publish',params=dict(disclosure=selected['disclosure'],
                bindings=selected['bindings'],expected_installation_sha256=selected['predecessor_sha256'],
                initial_configuration=None,replacement_configuration=dict(
                    destination=selected['disclosure']['destination'],
                    publication_backend=selected['publication_backend'])))
        result=instance.group_publication(command,authority_closure=closure,
            deadline_ns=time.monotonic_ns()+130_000_000_000)
        after=json.loads(installation.read_text())['document']
        assert after['disclosure']==selected['disclosure']
        assert after['publication_backend']==selected['publication_backend']
        assert after['generation']==selected['predecessor_generation']+1
        assert key_before==(key.stat().st_ino,key.read_bytes())
        value=dict(name=name,operation_id=common['operation_id'],result=result,
            installation=str(installation),installation_sha256=config_digest(after),generation=after['generation'],
            proof_key_preserved=True,published=True,models=0)
    atomic(receipt,value)
    return value

def system(*args):
    return subprocess.check_output(['systemctl',*args],text=True,timeout=45).strip()

def maintain(payload):
    assert os.geteuid()==0
    directory=Path(payload['directory']);launch=json.loads((directory/'launch.json').read_text())
    assert launch['operation_id']==payload['intent']['operation_id']
    payload['launch']=launch;c=launch['owner_config'];unit=launch['unit']
    assert unit in {'compaii-matrix-itaca.service','daimon-onboarding-matrix.service'}
    sys.path.insert(0,c['code'])
    from clusterctl.onboarding_service import selection_lock
    receipt=Path(launch['owner'])/('receipt.json' if payload['mode']=='sign' else 'publication-receipt.json')
    if receipt.exists():
        saved=json.loads(receipt.read_text())
        assert saved['operation_id']==payload['intent']['operation_id'] and saved['name']==launch['name']
        return {'receipt':saved,'retained':True,'lifecycle':0}
    record=directory/('apply-'+payload['mode']+'.json')
    with selection_lock(Path('/etc/systemd/system')/unit):
        command=system('show',unit,'-p','ExecStart','--value').split(' ; start_time=',1)[0]
        assert hashlib.sha256(command.encode()).hexdigest()==c['stable_command_sha256']
        runtime=Path(c['runtime'])/'runtime.json';raw=runtime.read_bytes()
        assert hashlib.sha256(raw).hexdigest()==c['runtime_sha256']
        protected={u:system('show',u,'-p','MainPID','-p','InvocationID') for u in launch['protected_units']}
        assert all('MainPID=0' not in x for x in protected.values())
        state=dict(operation_id=launch['operation_id'],phase='stop-requested',mode=payload['mode'])
        atomic(record,state)
        try:
            system('stop',unit)
            assert system('show',unit,'-p','MainPID','--value')=='0'
            state['phase']='owner-requested';atomic(record,state)
            account=pwd.getpwnam(launch['user'])
            completed=subprocess.run([str(Path(c['sdk'])/'venv/bin/python'),'-B','-I','-S','-c',
                payload['worker'],'owner'],input=json.dumps(payload),text=True,capture_output=True,
                timeout=150,user=account.pw_uid,group=account.pw_gid,extra_groups=())
            if completed.returncode:
                raise RuntimeError(completed.stderr[-2500:])
            result=json.loads(completed.stdout)
            state.update(complete=True,receipt=result)
        except Exception as error:
            state.update(complete=False,error=str(error)[-2500:])
            raise
        finally:
            unchanged=(system('show',unit,'-p','ExecStart','--value').split(' ; start_time=',1)[0]==command
                and runtime.read_bytes()==raw)
            if unchanged:system('start',unit)
            state.update(phase='restored' if unchanged else 'later_selection_preserved',
                runtime_unchanged=runtime.read_bytes()==raw,
                protected_processes_preserved=all(system('show',u,'-p','MainPID','-p','InvocationID')==v
                    for u,v in protected.items()))
            atomic(record,state)
        assert unchanged and state['protected_processes_preserved']
        return {'receipt':result,'retained':False,'lifecycle':1}

def restore(payload):
    directory=Path(payload['directory']);launch=json.loads((directory/'launch.json').read_text())
    record=directory/('apply-'+payload['mode']+'.json')
    if not record.exists():return
    state=json.loads(record.read_text())
    if state['phase'] in {'restored','later_selection_preserved'}:return
    c=launch['owner_config'];sys.path.insert(0,c['code'])
    from clusterctl.onboarding_service import selection_lock
    unit=launch['unit']
    with selection_lock(Path('/etc/systemd/system')/unit):
        command=system('show',unit,'-p','ExecStart','--value').split(' ; start_time=',1)[0]
        same=(hashlib.sha256(command.encode()).hexdigest()==c['stable_command_sha256']
            and hashlib.sha256((Path(c['runtime'])/'runtime.json').read_bytes()).hexdigest()==c['runtime_sha256'])
        if same:system('start',unit)
        state.update(phase='restored' if same else 'later_selection_preserved',watchdog_restored=same)
        atomic(record,state)

def arm(payload):
    assert os.geteuid()==0
    launch=json.loads(json.dumps(payload['launch']));c=launch['owner_config'];unit=launch['unit']
    assert unit in {'compaii-matrix-itaca.service','daimon-onboarding-matrix.service'}
    sys.path.insert(0,c['code'])
    from clusterctl.onboarding_service import selection_lock
    from clusterctl.owner_process import ProcessPresence
    account=pwd.getpwnam(launch['user'])
    assert payload['process']['uid']==account.pw_uid
    with selection_lock(Path('/etc/systemd/system')/unit), ProcessPresence(payload['process']) as presence:
        group=system('show',unit,'-p','ControlGroup','--value')
        actual=Path('/proc')/str(payload['process']['pid'])/'cgroup'
        assert group.startswith('/') and any(line.split(':',2)[-1] in {group} or
            line.split(':',2)[-1].startswith(group+'/') for line in actual.read_text().splitlines())
        runtime=Path(c['runtime'])/'runtime.json'
        assert hashlib.sha256(runtime.read_bytes()).hexdigest()==c['runtime_sha256']
        command=system('show',unit,'-p','ExecStart','--value').split(' ; start_time=',1)[0]
        c['stable_command_sha256']=hashlib.sha256(command.encode()).hexdigest()
        directory=Path(payload['directory']);owner=Path(launch['owner'])
        expected_owner=(Path(c['config']).parent/'messaging-maintenance' if 'config' in c
            else Path(c['runtime']).parents[1]/'maintenance')
        expected_stage=Path(c['code']).parent if 'config' in c else Path('/opt/daimon-matrix-maintenance')
        assert owner.parent==expected_owner and directory.parent==expected_stage
        for path in (directory,owner):
            assert path.parent.is_dir() and not any(p.is_symlink() for p in (path,*path.parents))
        directory.mkdir(mode=0o700,exist_ok=True)
        assert directory.stat().st_uid==0 and not directory.stat().st_mode&0o077
        if not owner.exists():
            owner.mkdir(mode=0o700);os.chown(owner,account.pw_uid,account.pw_gid)
        assert owner.stat().st_uid==account.pw_uid and not owner.stat().st_mode&0o077
        destination=directory/'launch.json'
        if destination.exists():assert json.loads(destination.read_text())==launch,'visibility_launch_changed'
        else:
            presence.verify();atomic(destination,launch)
    return {'done':True,'response':{'armed':True}}

def launch(payload):
    directory=Path(payload['directory']);settings=json.loads((directory/'launch.json').read_text())
    receipt=Path(settings['owner'])/('receipt.json' if payload['mode']=='sign' else 'publication-receipt.json')
    if receipt.exists():
        value=json.loads(receipt.read_text())
        assert value['operation_id']==payload['intent']['operation_id'] and value['name']==settings['name']
        if payload['mode']=='publish':
            c=settings['owner_config'];sdk=Path(c['sdk'])
            sys.path[:0]=[c['code'],str(sdk/'runtime-imports')]
            from daimon_matrix.messaging_config import config_digest
            current=json.loads(Path(value['installation']).read_text())['document']
            assert config_digest(current)==value['installation_sha256'],'visibility_later_publication_preserved'
        return dict(done=True,response={'receipt':value,'retained':True,'lifecycle':0})
    request=directory/('apply-'+payload['mode']+'.request.json')
    record=directory/('apply-'+payload['mode']+'.json')
    if request.exists():
        assert json.loads(request.read_text())==payload,'visibility_request_changed'
        if record.exists():
            value=json.loads(record.read_text())
            if value.get('complete') and value['phase']=='restored':
                return dict(done=True,response={'receipt':value['receipt'],'retained':False,'lifecycle':1})
        unit='matrix-visibility-'+payload['mode']+'-'+payload['intent']['operation_id']+'.service'
        active=system('show',unit,'-p','ActiveState','--value')
        if active in {'failed','inactive'}:
            raise RuntimeError('visibility_job_failed_inspect_retained_result')
        return dict(done=False,unit=unit)
    atomic(request,payload)
    script=directory/('apply-'+payload['mode']+'.worker.py')
    script.write_text(payload['worker']);script.chmod(0o600)
    unit='matrix-visibility-'+payload['mode']+'-'+payload['intent']['operation_id']
    subprocess.run(['systemd-run','--quiet','--collect','--unit='+unit,'-p','Type=exec',
        '-p','RuntimeMaxSec=340','-p','TimeoutStopSec=60',
        '-p','MemoryMax=512M','-p','CPUQuota=50%','-p','TasksMax=64',
        '-p','ExecStopPost='+sys.executable+' -B -I '+str(script)+' restore '+str(request),
        sys.executable,'-B','-I',str(script),'run',str(request)],check=True,capture_output=True,text=True)
    return dict(done=False,unit=unit+'.service')

payload=json.load(open(sys.argv[2])) if sys.argv[1] in {'run','restore'} else json.load(sys.stdin)
if sys.argv[1]=='owner':result=owner(payload)
elif sys.argv[1]=='restore':restore(payload);result={'restoration_checked':True}
elif sys.argv[1]=='run':result=maintain(payload)
elif sys.argv[1]=='arm':result=arm(payload)
else:result=launch(payload)
print(json.dumps(result))
'''


def private_json(path: Path, *, limit=512*1024) -> dict:
    info = path.lstat()
    if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('root_owned_visibility_request_required')
    raw = path.read_bytes()
    if len(raw) > limit:
        raise ValueError('visibility_request_too_large')
    return json.loads(raw)


def prepare_rollout(request, result, deadline, *, save, run_update, observe, arm,
                    read_spec=private_json, clock=time.monotonic):
    """Resume existing native journals, then pin only the selected Matrix owners."""
    updates = result.setdefault('native_updates', {})
    for selected in request.get('native_updates', []):
        spec = read_spec(Path(selected))
        digest = hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()
        retained = updates.get(selected)
        if retained is not None:
            if retained['spec_sha256'] != digest:
                raise ValueError('visibility_native_update_changed')
            if retained.get('result', {}).get('complete'):
                continue
        if deadline-clock() < spec['max_seconds']:
            raise TimeoutError('visibility_native_update_deadline')
        updates[selected] = dict(spec_sha256=digest, phase='submitted')
        save(result)
        observed = run_update(spec)
        updates[selected].update(phase='observed', result={
            key:observed[key] for key in ('schema','complete','operation_id',
                'candidate_digest','receiving_readiness','failure') if key in observed})
        save(result)
        if not observed.get('complete'):
            raise ValueError('visibility_native_update_incomplete')
    armed = result.setdefault('armed', {})
    for name, route in request['owners'].items():
        if 'launch' not in route or armed.get(name):
            continue
        if deadline <= clock():
            raise TimeoutError('visibility_operation_deadline')
        current = observe(name, deadline-clock())
        if (current['code_digest'] != route['launch']['owner_config']['code_digest']
                or current['matrix_sdk'] != route['expected_sdk_wheel']):
            raise ValueError('visibility_selected_sdk_required')
        response = arm(name, route, current['process'], deadline-clock())
        if response.get('armed') is not True:
            raise ValueError('visibility_owner_arm_unconfirmed')
        armed[name] = True
        save(result)


def apply(request: dict, *, dispatch, observe, save, finish, clock=time.monotonic,
          prepare=None, initial=None) -> dict:
    """One fixed plan; completed signatures/publications are retained, not replayed."""
    intent = request['intent']
    if (set(request['publications']) != set(intent['canonical_disclosures'])
            or not set(request['publications']) <= set(request['owners'])):
        raise ValueError('visibility_owner_set_changed')
    receipts = {}
    deadline = clock() + request['max_seconds']
    result = dict(operation_id=intent['operation_id'], complete=False, owners={}, publications={}, models=0)
    if initial is not None:
        if initial['operation_id'] != intent['operation_id']:
            raise ValueError('visibility_operation_changed')
        result.update(initial)
        result['complete']=False
    if prepare is not None:
        prepare(result,deadline)
    for name, route in request['owners'].items():
        if clock() >= deadline:
            raise TimeoutError('visibility_operation_deadline')
        response = dispatch(name, dict(mode='sign', directory=route['directory'], intent=intent,
            worker=WORKER), min(190, deadline-clock()))
        receipt = response['receipt']
        if receipt['operation_id'] != intent['operation_id'] or receipt['name'] != name:
            raise ValueError('visibility_receipt_changed')
        rows = receipt['bindings']
        if len(rows) != len(intent['canonical_disclosures']):
            raise ValueError('visibility_acceptance_incomplete')
        for row in rows:
            if row['disclosure'] != intent['canonical_disclosures'][row['name']]:
                raise ValueError('visibility_disclosure_changed')
        receipts[name] = receipt
        result['owners'][name] = dict(accepted=len(rows), retained=response['retained'])
        if response['lifecycle']:
            observe(name, deadline-clock())
        save(result)
    for name, publication in request['publications'].items():
        doc = intent['canonical_disclosures'][name]
        bindings = [next(row['binding'] for row in receipts[actor]['bindings'] if row['name'] == name)
            for actor in request['owners']]
        response = dispatch(name, dict(mode='publish', directory=request['owners'][name]['directory'],
            intent=intent, worker=WORKER, publication={**publication, 'disclosure':doc,
                'bindings':bindings}), min(190, deadline-clock()))
        result['publications'][name] = response['receipt']
        if response['lifecycle']:
            observe(name, deadline-clock())
        save(result)
    # A changed publication policy can invalidate the shared reader basis even
    # when every local gate still displays its previous positive intent.
    result['reader_completion'] = finish(result, deadline-clock())
    result['complete'] = True
    save(result)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        raise ValueError('visibility_maintenance_root_required')
    request = private_json(args.request)
    if request.get('schema') != 'cluster-tribe-visibility-maintenance/v1':
        raise ValueError('visibility_maintenance_request_required')
    if not 1 <= len(request['owners']) <= 256 or not 1 <= request['max_seconds'] <= 1800:
        raise ValueError('visibility_maintenance_bounds_required')
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from clusterctl.onboarding_managed import maintenance_backend, code_update_reader_clients
    reader_routes = private_json(Path(request['readers']))
    registry = reader_routes['owners']
    reader_clients = code_update_reader_clients(reader_routes)
    backends = {}
    for key, row in request['backends'].items():
        backends[key] = maintenance_backend(row['host_config'],row.get('vm_qualification'),row['targets'])
    output = Path(request['result'])
    compile(WORKER, 'visibility-owner-worker', 'exec')

    def save(value):
        raw = json.dumps(value, indent=2)+'\n'
        if len(raw.encode()) > 1024*1024:
            raise ValueError('visibility_result_too_large')
        temporary = output.with_suffix('.next')
        temporary.write_text(raw)
        temporary.chmod(0o600)
        os.replace(temporary,output)

    def dispatch(name, payload, seconds):
        route = request['owners'][name]
        command = [sys.executable if route.get('backend') is None else '/usr/bin/python3',
            '-B','-I','-c',WORKER,'arm' if payload['mode']=='arm' else 'launch']
        deadline = time.monotonic()+seconds
        while time.monotonic() < deadline:
            remaining = min(55,deadline-time.monotonic())
            if route.get('backend') is None:
                completed = subprocess.run(command,input=json.dumps(payload),text=True,
                    capture_output=True,timeout=remaining)
                if completed.returncode:
                    raise RuntimeError(completed.stderr[-2500:])
                raw = completed.stdout
            else:
                backend,plans = backends[route['backend']]
                raw = backend.execute_body(plans[route['job']], command, uid=0,gid=0,
                    input_data=json.dumps(payload),timeout_seconds=remaining)
            observed = json.loads(raw)
            if observed['done']:
                return observed['response']
            time.sleep(min(2,max(0,deadline-time.monotonic())))
        raise TimeoutError('visibility_job_still_retained')

    def observe(name, seconds):
        route = request['owners'][name]
        client = reader_clients[route['reader']]
        client.deadline_ns = time.monotonic_ns()+int(min(55,seconds)*1e9)
        status = client._call({'action':'status'})
        if status['gate']['phase'] != 'select' or status['gate']['process_id'] != status['process']['pid']:
            raise ValueError('visibility_current_reader_unavailable')

    def finish(result, seconds):
        from clusterctl.onboarding import digest
        from clusterctl.onboarding_owner_control import _selection
        from clusterctl.onboarding_receiving_update import refresh_current_readers
        clients = {route['reader']: reader_clients[route['reader']]
            for route in request['owners'].values()}
        deadline = time.monotonic_ns()+int(min(480,seconds)*1e9)
        selections = {}
        for name, client in clients.items():
            client.deadline_ns = deadline
            selections[name] = _selection(client._call({'action':'status'}))
        return refresh_current_readers(clients, selections=selections,
            operation_id=request['intent']['operation_id'],
            release_digest=digest({name: row['installation_sha256']
                for name,row in result['publications'].items()}),
            deadline_ns=deadline, checkpoint=Path(request['reader_checkpoint']),
            nonadmitted=frozenset(name for name in clients if not registry[name]['require_admitted']))

    def prepare(result, deadline):
        from clusterctl.onboarding_managed import run_native_profile_update, run_code_update
        from clusterctl.onboarding_owner_control import _selection

        def run_update(spec):
            if spec['schema'] == 'cluster-native-profile-maintenance/v1':
                return run_native_profile_update(spec)
            return run_code_update(spec)

        def selected(name, seconds):
            client = reader_clients[request['owners'][name]['reader']]
            client.deadline_ns = time.monotonic_ns()+int(min(55,seconds)*1e9)
            status = client._call({'action':'status'})
            value = _selection(status)
            return dict(code_digest=value['receiving_code'],matrix_sdk=value['matrix_sdk'],
                process=status['process'])

        def arm_owner(name, route, process, seconds):
            return dispatch(name,dict(mode='arm',directory=route['directory'],
                launch=route['launch'],process=process),min(55,seconds))

        prepare_rollout(request,result,deadline,save=save,run_update=run_update,
            observe=selected,arm=arm_owner)

    try:
        initial = private_json(output,limit=1024*1024) if output.exists() else None
        result = apply(request,dispatch=dispatch,observe=observe,save=save,finish=finish,
            prepare=prepare,initial=initial)
    except Exception as error:
        diagnostic = output.with_suffix('.diagnostic')
        diagnostic.write_text(str(error)[-8192:])
        diagnostic.chmod(0o600)
        print(json.dumps(dict(complete=False,error='visibility_maintenance_incomplete',result_recorded=True)))
        return 1
    print(json.dumps(dict(complete=result['complete'],owners=len(result['owners']),
        publications=len(result['publications']),models=0)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
