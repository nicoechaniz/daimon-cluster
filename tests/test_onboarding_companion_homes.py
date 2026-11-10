"""Committed-identity hook and exact reload recovery; no guest/model starts."""
import os
from types import SimpleNamespace

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import CONVERSATION_PLAN_SCHEMA, JobStore, OnboardingError, digest
from clusterctl.onboarding_homes import configure
from clusterctl.onboarding_progress import Progress
from tests.test_onboarding import FixtureBackend, plan
from tests.test_onboarding_conversation import request


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
    observed = dict(human={'ref':'human-one'}, owner_being_ref=home['owner_being_ref'],
                    applications=[])

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
    receivers = tmp_path/'receivers.json'
    args = ['--config', str(config)]
    if selector != 'missing':
        args += ['--miniapp-receivers', 'relative.json' if selector == 'relative' else str(receivers)]
    if selector == 'duplicate':
        args += ['--miniapp-receivers', str(tmp_path/'other.json')]
    # A real process cmdline, with no service changes or receiver impersonation.
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)', *args])
    try:
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
