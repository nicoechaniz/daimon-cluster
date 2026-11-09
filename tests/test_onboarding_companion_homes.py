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
