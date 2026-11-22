"""Committed-identity hook and exact reload recovery; no guest/model starts."""
import os
import hashlib
from types import SimpleNamespace

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import CONVERSATION_PLAN_SCHEMA, JobStore, OnboardingError, digest
from clusterctl.onboarding_homes import configure
from clusterctl.onboarding_progress import Progress
from tests.test_onboarding import FixtureBackend, plan
from tests.test_onboarding_conversation import request


def test_gateway_helper_uses_exact_current_sdk_tree_and_refuses_mutation(tmp_path):
    from clusterctl.onboarding_companion_homes import gateway_imports
    parent = tmp_path/'sdk'
    parent.mkdir(mode=0o700)
    root = parent/'runtime-imports'
    root.mkdir(mode=0o700)
    module = root/'selected_sdk.py'
    module.write_bytes(b'CURRENT_SCHEMA = True\n')
    module.chmod(0o600)
    hashes = {'selected_sdk.py': hashlib.sha256(module.read_bytes()).hexdigest()}
    selection = {'path': str(root), 'sdk_digest': 'a'*64, 'files_sha256': digest(hashes)}
    being_seed._write(parent/'runtime-imports.json', {
        'schema':'cluster-onboarding-runtime-imports/v1',
        'sdk_digest':selection['sdk_digest'], 'files_sha256':selection['files_sha256']})
    assert gateway_imports(selection) == root
    module.write_bytes(b'CURRENT_SCHEMA = False\n')
    with pytest.raises(OnboardingError, match='companion_gateway_imports_changed'):
        gateway_imports(selection)
    module.write_bytes(b'CURRENT_SCHEMA = True\n')
    extra = root/'unselected.py'
    extra.write_bytes(b'not a selected dependency')
    with pytest.raises(OnboardingError, match='companion_gateway_imports_changed'):
        gateway_imports(selection)


def assembled(tmp_path):
    backend=FixtureBackend()
    value=plan(browser=False)
    value['schema']=CONVERSATION_PLAN_SCHEMA
    store=JobStore(tmp_path/'jobs')
    pending=store.submit(value,backend)
    progress_path=tmp_path/'progress'
    progress_path.mkdir(mode=0o750)
    progress=Progress(progress_path,worker_uid=os.getuid())
    progress.publish(pending)
    req=request()
    req.update(name=value['name'],plan_digest=digest(value))
    backend._conversation_request=lambda _plan:req
    backend._ceremony=lambda _plan:SimpleNamespace(public_identity=lambda _p:{'verified-fixture':'public'})
    selected=dict(schema='dm.home-companion-onboarding/v1',state=str(tmp_path/'home-jobs'),
        gateway=dict(config=str(tmp_path/'config'),python='/usr/bin/python3'),
        pairs={value['name']:dict(owner=value['owner'],plan_digest=digest(value),
            human_name='Own human',vpn_url='https://private-fixture.example')})
    file=tmp_path/'homes.json'
    being_seed._write(file,selected)
    homes=configure(file,progress=progress_path,store=store,backend=lambda:backend,worker_uid=os.getuid())
    calls=[]
    state={'ready':False,'hidden':False}
    def gateway(action,request,**options):
        calls.append(action)
        if action=='register':
            return dict(status='home-configured',home_ref=req['home_ref'],actor=req['being_ref'],human_ref=req['human_ref'])
        if state['hidden']:
            return {'state':'configuration-missing'}
        return {'state':'ready','pair_matched':True} if state['ready'] else {'state':'not-loaded'}
    homes._gateway=gateway
    homes._unit=lambda:{'ActiveState':'active','MainPID':'42','InvocationID':'original'}
    return homes,store,backend,progress,value,pending,calls,state,file


def committed(store,backend,progress):
    for _ in range(4):
        value=store.tick('eko',backend)
        progress.publish(value)
    assert value['completed_steps'][-1]=='identity'
    return value


def test_home_hook_only_uses_committed_identity_and_recovers_lost_reload_reply(tmp_path):
    homes,store,backend,progress,plan,pending,calls,state,_=assembled(tmp_path)
    assert homes(pending)=={'state':'not-selected'} and calls==[]
    ready=committed(store,backend,progress)
    original=being_seed._read(store.directory('eko')/'job.json')
    reloads=[]
    def reload():
        reloads.append('existing-home-unit')
        state['ready']=True
        raise TimeoutError('reply lost after actual fixture reload effect')
    homes._reload=reload
    with pytest.raises(TimeoutError):
        homes(ready)
    record=being_seed._read(homes.state/'eko.json')
    assert record['phase']=='reload-intent'
    assert homes.reconcile_committed('eko')=={'state':'complete'}
    assert calls.count('register')==1 and len(reloads)==1
    assert being_seed._read(store.directory('eko')/'job.json')==original
    # A later missing registration is not permission to recreate it.
    state['hidden']=True
    count=len(calls)
    assert homes(ready)['state']=='complete' and len(calls)==count
    assert homes.conversation_access(plan,backend._conversation_request(plan),False).state=='waiting'
    assert calls.count('register')==1 and len(reloads)==1


def test_unknown_reload_is_observed_without_repeating_restart(tmp_path):
    homes,store,backend,progress,_,_,calls,_,_=assembled(tmp_path)
    ready=committed(store,backend,progress)
    reloads=[]
    homes._reload=lambda:reloads.append('dispatched')
    assert homes(ready)['state']=='waiting'
    assert homes(ready)['state']=='waiting'
    assert calls.count('register')==1 and reloads==['dispatched']
    assert being_seed._read(homes.state/'eko.json')['phase']=='reload-intent'


def test_revoked_grant_and_later_configuration_stop_before_gateway_work(tmp_path):
    homes,store,backend,progress,_,_,calls,_,file=assembled(tmp_path)
    ready=committed(store,backend,progress)
    backend.granted=False
    with pytest.raises(OnboardingError,match='host_authorization_required'):
        homes(ready)
    assert calls==[]
    backend.granted=True
    selected=being_seed._read(file)
    selected['pairs']['eko']['human_name']='Later human direction'
    being_seed._write(file,selected)
    with pytest.raises(OnboardingError,match='configuration_changed'):
        homes(ready)
    assert calls==[]


def test_uncommitted_progress_cannot_prepare_an_identity(tmp_path):
    homes,store,backend,progress,_,pending,calls,_,_=assembled(tmp_path)
    for _ in range(4):
        ready=store.tick('eko',backend)
    # Caller knows the right plan, but the actual receiving projection is old.
    with pytest.raises(OnboardingError,match='committed_identity_required'):
        homes(ready)
    assert progress.read('eko',owner=pending['owner'])==pending and calls==[]


def test_existing_worker_wires_home_after_identity_without_another_launcher(tmp_path):
    from clusterctl.onboarding_worker import Worker
    homes,store,backend,progress,_,_,calls,state,_=assembled(tmp_path)
    state['ready']=True
    worker=Worker(store,lambda:backend,publish=progress.publish,homes=homes)
    for _ in range(3):
        worker._tick('eko')
    assert calls==[]
    result=worker._tick('eko')
    assert result['completed_steps'][-1]=='identity'
    assert calls==['register','probe']
    assert being_seed._read(homes.state/'eko.json')['phase']=='complete'


def test_capacity_refuses_without_discarding_retained_work(tmp_path):
    homes,store,backend,progress,_,_,calls,_,file=assembled(tmp_path)
    retained=homes.state/'earlier.json'
    retained.write_bytes(b'x'*4097)
    retained.chmod(0o600)
    with pytest.raises(OnboardingError,match='state_capacity'):
        configure(file,progress=progress.root,store=store,backend=lambda:backend,worker_uid=os.getuid())
    assert retained.read_bytes()==b'x'*4097 and calls==[]


def test_routed_home_uses_same_worker_and_waits_for_actual_route_effect(tmp_path, monkeypatch):
    from tests.test_onboarding_conversation_routes import assembled as routed_fixture
    from clusterctl import onboarding_conversation_routes
    homes,store,backend,progress,plan,_,calls,_,file=assembled(tmp_path)
    routed_root=tmp_path/'routing'
    routed_root.mkdir()
    writer,_,route_state,route_calls,_=routed_fixture(routed_root)
    selected=being_seed._read(file)
    selected.update(schema='dm.home-companion-onboarding/v2',routes=writer.value)
    being_seed._write(file,selected)
    homes=configure(file,progress=progress.root,store=store,backend=lambda:backend,worker_uid=os.getuid())
    backend.config=SimpleNamespace(conversation_proxy_by_name={'eko':dict(listen_host='10.20.30.40',listen_port=18741)})
    request_value=backend._conversation_request(plan)
    def gateway(action,request,**options):
        calls.append(action)
        if action=='routing':
            return {'state':'configured','home_backend':'http://127.0.0.1:8820'}
        if action=='register':
            return dict(status='home-configured',home_ref=request_value['home_ref'],actor=request_value['being_ref'],human_ref=request_value['human_ref'])
        return {'state':'ready','pair_matched':True}
    homes._gateway=gateway
    monkeypatch.setattr(onboarding_conversation_routes,'Routes',lambda value:writer)
    route_state['effect']=False
    ready=committed(store,backend,progress)
    assert homes(ready)['state']=='waiting'
    assert calls==['register','probe','routing']
    assert being_seed._read(homes.state/'eko.json')['phase']=='configured'
    # A delayed real effect becomes observable under the original route intent.
    route_state['loaded']=digest({'file':writer.path.read_text()})
    assert homes.reconcile_committed('eko')=={'state':'complete'}
    assert route_calls.count('reload')==1 and calls.count('register')==1
    count=len(calls)
    assert homes(ready)=={'state':'complete'} and len(calls)==count


def test_busy_route_maintenance_does_not_block_independent_native_job_progress(tmp_path):
    from dataclasses import replace
    from clusterctl.onboarding_worker import Worker
    homes,store,backend,progress,_,_,_,state,_=assembled(tmp_path)
    homes.value=dict(homes.value,schema='dm.home-companion-onboarding/v2',routes={})
    homes.selection_path=None
    state['ready']=True
    def busy(*args):
        raise OnboardingError('conversation_route_voice_active')
    homes._routes=busy
    original_observe=backend.observe
    def observe(plan,stage,operation):
        result=original_observe(plan,stage,operation)
        if stage=='access' and result.state=='complete':
            return replace(result,facts=dict(result.facts,provider_configured=True))
        return result
    backend.observe=observe
    ready=committed(store,backend,progress)
    assert homes(ready)=={'state':'waiting','reason':'conversation_route_voice_active'}
    worker=Worker(store,lambda:backend,publish=progress.publish,homes=homes)
    after=worker._tick('eko')
    assert 'access' in after['completed_steps']
    assert being_seed._read(homes.state/'eko.json')['phase']=='configured'


def test_finite_full_conversation_resumes_same_body_and_home_after_wait(tmp_path):
    """Real job/Home journals span every stage; substrate effects are fixtures."""
    import time
    from dataclasses import replace
    from clusterctl.onboarding import CONVERSATION_STAGES, Observation
    from clusterctl.onboarding_worker import Worker
    homes,store,backend,progress,plan,_,calls,state,_=assembled(tmp_path)
    state['ready']=True
    original=backend.observe
    waiting={'enabled':True}
    def observe(selected,stage,operation):
        if stage=='conversation' and waiting['enabled']:
            return Observation('waiting',reason='connection_data_required')
        result=original(selected,stage,operation)
        if result.state=='complete' and stage in {'access','acceptance'}:
            facts=dict(result.facts,provider_configured=True)
            if stage=='acceptance':
                assert being_seed._read(homes.state/'eko.json')['phase']=='complete'
                facts.update(conversation_verified=True,shared_login_verified=True,
                    native_running_verified=True,tribe_membership_verified=True)
            return replace(result,facts=facts)
        return result
    backend.observe=observe
    entry={'url':'https://fixture.example.org/interaction/?view=conversation&client=standalone'}
    backend.companion_entry=lambda _plan:entry
    worker=Worker(store,lambda:backend,publish=progress.publish,homes=homes)
    status,result=worker.until(plan['name'],deadline=time.monotonic()+3)
    assert status==2 and result['stage']=='conversation'
    before=store._load(plan['name'])
    environment=before['steps']['environment'].copy()
    waiting['enabled']=False
    status,result=worker.until(plan['name'],deadline=time.monotonic()+3)
    assert status==0 and result['entry']==entry
    assert result['completed_steps']==list(CONVERSATION_STAGES)
    assert store._load(plan['name'])['steps']['environment']==environment
    assert [stage for _,stage,_ in backend.calls]==list(CONVERSATION_STAGES)
    assert calls.count('register')==1
    journal=(store.directory(plan['name'])/'job.json').read_bytes()
    effects=list(backend.calls)
    assert worker.until(plan['name'],deadline=time.monotonic()+3)[0]==0
    assert (store.directory(plan['name'])/'job.json').read_bytes()==journal
    assert backend.calls==effects


def test_new_foreground_refuses_missing_home_before_job_or_substrate(tmp_path,monkeypatch,capsys):
    from clusterctl import onboarding_host,onboarding_worker
    from tests.test_onboarding import FixtureBackend
    backend=FixtureBackend()
    value=plan(browser=False)
    value['schema']=CONVERSATION_PLAN_SCHEMA
    grants=tmp_path/'grants'
    grants.mkdir(mode=0o700)
    being_seed._write(grants/(value['name']+'.json'),{'plan':value})
    config=SimpleNamespace(jobs=tmp_path/'jobs',grants=grants,progress=tmp_path/'progress')
    monkeypatch.setattr(onboarding_host,'CurrentHostConfig',lambda _:SimpleNamespace(current=lambda:config))
    monkeypatch.setattr(onboarding_host,'HostBackend',lambda _:backend)
    assert onboarding_worker.main(['--config',str(tmp_path/'owner.json'),'--until',value['name']])==1
    import json
    output=json.loads(capsys.readouterr().out)
    assert output['diagnostic']['code']=='companion_home_configuration_required'
    assert not config.jobs.exists() and backend.calls==[]


def test_new_foreground_refuses_missing_conversation_before_job_or_substrate(tmp_path, monkeypatch, capsys):
    import json
    from clusterctl import onboarding_host, onboarding_worker
    backend = FixtureBackend()
    value = plan(browser=False)
    value['schema'] = CONVERSATION_PLAN_SCHEMA
    grants = tmp_path/'grants'
    grants.mkdir(mode=0o700)
    being_seed._write(grants/(value['name']+'.json'), {'plan': value})
    config = SimpleNamespace(jobs=tmp_path/'jobs', grants=grants, progress=tmp_path/'progress')
    monkeypatch.setattr(onboarding_host, 'CurrentHostConfig',
        lambda _: SimpleNamespace(current=lambda: config))
    monkeypatch.setattr(onboarding_host, 'HostBackend', lambda _: backend)
    # Home preparation is already satisfied. Missing pair/runtime input must
    # still refuse before freezing a job or asking the substrate to allocate.
    monkeypatch.setattr(onboarding_worker, 'prepare_companion_homes', lambda *args: None)
    monkeypatch.setattr(onboarding_worker, 'supervise',
        lambda *args, **kwargs: pytest.fail('Missing Conversation must not launch a worker'))
    assert onboarding_worker.main(['--config', str(tmp_path/'owner.json'),
        '--until', value['name']]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output['diagnostic']['code'] == 'conversation_selection_required'
    assert not config.jobs.exists() and backend.calls == []


def test_foreground_home_preparation_preserves_exact_pair(tmp_path):
    from clusterctl.onboarding_worker import prepare_companion_homes
    homes,store,backend,progress,selected,_,calls,_,file=assembled(tmp_path)
    config=SimpleNamespace(progress=progress.root)
    prepare_companion_homes(config,selected,store,file)
    assert calls==[] and backend.calls==[]
    changed=being_seed._read(file)
    changed['pairs'][selected['name']]['owner']='different-owner'
    being_seed._write(file,changed)
    with pytest.raises(OnboardingError,match='companion_home_configuration_required'):
        prepare_companion_homes(config,selected,store,file)
    assert calls==[] and backend.calls==[]


def test_new_owner_denial_reloads_only_exact_config_newer_than_process(tmp_path):
    homes,store,backend,progress,_,_,_,state,file = assembled(tmp_path)
    ready = committed(store,backend,progress)
    config = tmp_path/'config'
    config.write_bytes(b'new exact gateway selection')
    checksum = hashlib.sha256(config.read_bytes()).hexdigest()
    original = homes._gateway
    def gateway(action, request, **options):
        if action == 'register':
            return {**original(action,request,**options), 'config_digest':checksum}
        return {'state':'unavailable'}
    homes._gateway = gateway
    homes._unit = lambda:dict(ActiveState='active', MainPID='42',
        process_start_epoch_ns=1, config_mtime_ns=2)
    reloads=[]
    homes._reload=lambda:reloads.append('exact-new-config')
    assert homes(ready)['state']=='waiting'
    assert homes(ready)['state']=='waiting'
    assert reloads==['exact-new-config']
    assert being_seed._read(homes.state/'eko.json')['phase']=='reload-intent'


def test_live_owner_denial_is_not_treated_as_missing_configuration(tmp_path):
    homes,store,backend,progress,_,_,_,_,_=assembled(tmp_path)
    ready=committed(store,backend,progress)
    original=homes._gateway
    homes._gateway=lambda action,request,**kw: original(action,request,**kw) if action=='register' else {'state':'unavailable'}
    homes._unit=lambda:dict(ActiveState='active', MainPID='42',
        process_start_epoch_ns=3, config_mtime_ns=2)
    homes._reload=lambda:pytest.fail('Live denial cannot trigger restart')
    assert homes(ready)['state']=='waiting'


def test_gateway_probe_requires_loaded_conversation_route(tmp_path):
    """A matching pair alone must not finish delivery; exercise the real probe."""
    import json
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from pathlib import Path
    import subprocess
    import sys
    from threading import Thread
    from clusterctl.onboarding_companion_homes import GATEWAY
    from tests.test_home_host import configuration, write

    config = configuration(tmp_path)
    home = config['homes']['one']
    observed = dict(schema='dm.human-endpoint/v1', home_ref='one',
                    human={'ref':'human-one'}, owner_being_ref=home['owner_being_ref'], applications=[])

    class Owner(BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.path == '/owner/one/human-endpoint'
            assert self.headers['Authorization'] == 'Bearer fixture-owner'
            self.rfile.read(int(self.headers['Content-Length']))
            raw = json.dumps(observed).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Owner)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config['owner_port'] = server.server_port
        path = tmp_path/'config.json'
        write(path, json.dumps(config).encode())
        payload = dict(action='probe', config=str(path), request=dict(home_ref='one',
            human_ref='human-one', being_ref=home['owner_being_ref'], origin=home['public_url']))

        def probe():
            result = subprocess.run([sys.executable, '-I', '-B', '-c', GATEWAY,
                str(Path(__file__).resolve().parents[1])], input=json.dumps(payload),
                capture_output=True, text=True, timeout=10)
            assert result.returncode == 0, result.stderr
            return json.loads(result.stdout)

        assert probe() == {'state':'not-loaded'}
        payload['action'] = 'pairing'
        assert probe() == {k: observed[k] for k in ('schema', 'home_ref', 'owner_being_ref', 'human')}
        payload['action'] = 'probe'
        observed['applications'] = [dict(capability='interaction',
            url=home['public_url']+'/other/', state='configured')]
        assert probe() == {'state':'not-loaded'}
        observed['applications'][0]['url'] = home['public_url']+'/interaction/'
        assert probe() == {'state':'ready', 'pair_matched':True}
        observed['human']['ref'] = 'another-human'
        assert probe() == {'state':'unavailable'}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize('selector', ['selected', 'missing', 'relative', 'duplicate'])
def test_home_route_uses_actual_gateway_receivers(tmp_path, monkeypatch, selector):
    import subprocess
    import sys
    from clusterctl.onboarding_companion_homes import CompanionHomes

    config = tmp_path/'gateway.json'
    config.write_text('{}')
    receivers = tmp_path/'receivers.json'
    args = ['--config', str(config)]
    if selector != 'missing':
        args += ['--miniapp-receivers', 'relative.json' if selector == 'relative' else str(receivers)]
    if selector == 'duplicate':
        args += ['--miniapp-receivers', str(tmp_path/'other.json')]
    # Wait for the child to enter Python before inspecting its command line.
    import select
    child = subprocess.Popen(
        [sys.executable, '-c', 'import time; print("ready", flush=True); time.sleep(30)', *args],
        stdout=subprocess.PIPE, text=True,
    )
    try:
        assert child.stdout is not None
        readable, _, _ = select.select([child.stdout], [], [], 3)
        assert readable and child.stdout.readline() == 'ready\n'
        homes = object.__new__(CompanionHomes)
        homes.value = {'gateway': {'config': str(config)}}
        monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: SimpleNamespace(
            returncode=0, stdout=f'MainPID={child.pid}\nInvocationID=fixture\nActiveState=active\n'))
        if selector == 'selected':
            assert homes._unit(receivers=True)['receivers_file'] == str(receivers)
        else:
            with pytest.raises(OnboardingError, match='companion_gateway_receivers_required'):
                homes._unit(receivers=True)
        assert 'receivers_file' not in homes._unit()
    finally:
        child.terminate()
        child.wait(timeout=3)
        if child.stdout is not None:
            child.stdout.close()


@pytest.mark.parametrize("own_human", [True, False])
def test_selected_native_client_is_inside_home_completion_and_reuses_receipt(tmp_path, monkeypatch, own_human):
    import json
    from pathlib import Path
    from tests.test_home_host import configuration, write
    from clusterctl.onboarding_homes import IncusProvider
    homes,store,backend,progress,selected,_,_,state,file = assembled(tmp_path)
    ready = committed(store,backend,progress)
    state['ready'] = True
    request = backend._conversation_request(selected)
    config_path = tmp_path/'gateway/config.json'
    config = configuration(config_path.parent)
    config['homes'][request['home_ref']] = dict(config['homes'].pop('one'),
        owner_being_ref=request['being_ref'], public_url=request['origin'], name=request['label'])
    write(config_path,json.dumps(config).encode())
    value = being_seed._read(file)
    value['gateway']['config'] = str(config_path)
    value['native_client'] = dict(provider_file=str(tmp_path/'public-provider.py'),
        provider_sha256='a'*64,repository=str(tmp_path/'public-source'),skills_commit='b'*40)
    being_seed._write(file,value)
    homes = configure(file,progress=progress.root,store=store,backend=lambda:backend,worker_uid=os.getuid())
    homes._gateway = lambda action,req,**kw: (
        dict(status='home-configured',home_ref=req['home_ref'],actor=req['being_ref'],human_ref=req['human_ref'])
        if action=='register' else {'state':'ready','pair_matched':True})
    calls = []
    def receive(self, placement):
        calls.append(placement)
        assert placement['delivery']['owner_being_ref'] == request['being_ref']
        declaration = being_seed._read(Path(placement['declaration_file']))
        assert 'store' not in declaration['binding']
        return {'state':'complete','human_endpoint':dict(human={'ref':request['human_ref'] if own_human else 'another-human'},
            applications=[{'capability':'interaction','url':request['origin']+'/interaction/'}])}
    monkeypatch.setattr(IncusProvider,'_reconcile',receive)
    if not own_human:
        with pytest.raises(OnboardingError, match='native_client_receiving_unconfirmed'):
            homes(ready)
        retained = being_seed._read(homes.state/(selected['name']+'.json'))
        assert retained['phase'] != 'complete' and 'native_client' not in retained
        return
    assert homes(ready) == {'state':'complete'}
    assert homes(ready) == {'state':'complete'}
    assert len(calls) == 1
    receipt = being_seed._read(homes.state/(selected['name']+'.json'))
    assert receipt['native_client']['client_verified'] is True
    assert receipt['native_client']['model_uptake'] is False
