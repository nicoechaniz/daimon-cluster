"""Original receive choreography preserves terminal membership and other owners."""
import copy
from contextlib import contextmanager
from types import SimpleNamespace
import time
import uuid

import pytest

from clusterctl import onboarding_receive_flow as flow
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_code_successor import plan_update
from clusterctl.operation_journal import OperationJournal


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    plan = {'name':'new'}
    selected = dict(schema=flow.SCHEMA,
        helpers=dict(schema='cluster-membership-maintenance/v1', owners={name:dict(
            code='/public/'+name, code_digest='a'*64, journal='/private/'+name) for name in ('old','new')}),
        key=dict(provider_ref='new', route_ref='new', key_ref='new', secret_file='new.key',
            endpoint='http://127.0.0.2:1234/dm-messaging/v1/message'),
        intake_endpoint='http://127.0.0.1:1234/dm-messaging/v1/message',
        listen=dict(host='127.0.0.1', port=1234), policy=dict(classification='shareable',max_ttl_ms=60000),
        stores={k:k+'.sqlite' for k in ('records','envelopes','opaque-evidence','opaque-message')},
        authority_order=None)
    admission = dict(tribe_ref='tribe', receivers={name:dict(being_ref=name,embodiment_id='body-'+name)
        for name in ('old','new')})
    social = dict(operation_id=str(uuid.uuid4()), owner_contexts={k:'b'*64 for k in ('old','new')},
        authority_closure={name:dict(authority=dict(manifest=dict(embodiments=[dict(
            embodiment_id='body-'+name,body_ref='label-'+name,status='active')]))) for name in ('old','new')})
    journal = OperationJournal(tmp_path/'journal')
    row = plan_update(journal,target='original',manifest_digest='c'*64,expected_precondition=dict(senders=[{'name':'old'}]),
        intended_transition=dict(portal_admission=dict(social=social)),audit_identity={'actor':'fixture'})
    journal.advance(row['operation_id'],'completed',result={'original-membership':'complete'})
    events, effects, replies, lose = [], {}, {}, []
    class Owner:
        def __init__(self,name):
            self.name=name
            self.deadline_ns=None
            self.maintenance=None
        def base_status(self):
            return dict(server=dict(embodiment_id='body-'+self.name), runtime_status=dict(loaded_runtime=dict(
                qualified_startup=dict(code_digest='1'*64,matrix_wheel_sha256='2'*64),runtime_bundle_sha256='3'*64)))
        def status(self):
            return dict(runtime_status=dict(loaded_runtime=self.base_status()['runtime_status']['loaded_runtime'],
                loaded_application=dict(application_sha256='4'*64,publication_sha256='5'*64,
                    visibility=dict(installation_sha256='6'*64))))
        def group_publication(self,command,**options):
            action=command['action']
            events.append((self.name,action))
            if action=='context-preview':
                assert self.name=='new'
                return dict(schema='cluster-group-owner-context-preview/v1',owner_context_sha256='b'*64,
                    predecessor_selection_sha256=None,communication_plan=dict(target_version=4,plan_sha256='e'*64))
            if action=='receive-route-preview':
                assert self.name=='old'
                return dict(schema='cluster-receive-route-preview/v1',operation_id=social['operation_id'],
                    being_ref='old',origin=dict(embodiment_id='body-old'),runtime_bundle_sha256='3'*64,
                    route=dict(selected['key'],secret_file='old.key',secret_sha256='7'*64),
                    source=dict(kind='application',application_sha256='4'*64,publication_sha256='5'*64))
            assert self.name=='new', 'existing member received a mutation'
            if command['step'] not in replies:
                effects[command['step']]=effects.get(command['step'],0)+1
                result=dict(schema='cluster-group-publication-result/v1',status='recorded',
                    receiving_readiness='unobserved',**{k:command[k] for k in ('step','action','operation_id')})
                if action=='receive-communication-prepare':
                    result['migration']=dict(target_version=4,source_plan_sha256=command['params']['expected_plan_sha256'])
                elif action=='receive-key':
                    result['route']=dict(selected['key'],secret_sha256='8'*64)
                elif action=='receive-application':
                    assert all(isinstance(v,dict) and set(v)=={'receive_import'} for v in command['params']['secret_sources'].values())
                    result.update(application_sha256='9'*64,publication_sha256='a'*64)
                elif action=='receive-snapshot':
                    result.update(outbound_release=False, group=dict(application_sha256='9'*64,publication_sha256='a'*64))
                replies[command['step']]=result
            if lose and lose[0]==action:
                lose.pop(0)
                raise OSError('lost native reply after retained effect')
            return copy.deepcopy(replies[command['step']])
    owners={name:Owner(name) for name in ('old','new')}
    def helper(owner,selected,**kw):
        events.append((owner.name,'helper'))
        owner.maintenance=(selected['code'],selected['code_digest'])
    monkeypatch.setattr(flow,'Endpoint',helper)
    @contextmanager
    def preserved(only,selected,**kw):
        assert set(only)=={'new'} and set(selected['owners'])=={'new'}
        assert kw['phase']=='receive'
        assert 0 < kw['deadline_ns']-time.monotonic_ns() <= 60_000_000_000
        latest=journal.get(row['operation_id'])
        if not kw.get('restore_only',False):
            observed=dict(latest['runtime_observation'] or {},receive_maintenance={'fixture':'owned original phase'})
            journal.advance(row['operation_id'],latest['state'],runtime_observation=observed,
                expected_runtime_observation=latest['runtime_observation'])
        events.append(('new','recover' if kw.get('restore_only',False) else 'pause'))
        try:
            yield kw['validate']
        finally:
            events.append(('new','restore'))
    monkeypatch.setattr(flow,'preserved',preserved)
    def relay(source,target,outgoing,incoming,*,validate):
        validate()
        assert target is owners['new']
        assert incoming['source']=={}
        events.append((source.name,'relay'))
        return dict(schema='cluster-receive-resource-transfer-result/v1',route_sha256=digest(outgoing['route']),
            provenance_sha256='d'*64,secret_source='receive-imports/'+digest(outgoing['route'])+'.key',
            receiving_readiness='unobserved')
    monkeypatch.setattr(flow,'relay',relay)
    return SimpleNamespace(plan=plan,selected=selected,admission=admission,journal=journal,row=row,
        owners=owners,events=events,effects=effects,replies=replies,lose=lose)


def run(fixture, validate=lambda:None):
    f=fixture
    return flow.publish(plan=f.plan,selected=f.selected,journal=f.journal,row=f.journal.get(f.row['operation_id']),
        admission=f.admission,owners=f.owners,validate=validate,deadline_ns=time.monotonic_ns()+10_000_000_000)


def test_original_receive_sequence_restores_before_result_and_preserves_membership(fixture):
    f=fixture
    result=run(f)
    assert result['outbound_release'] is False and result['receiving_readiness']=='unobserved'
    assert f.events[-1]==('new','restore')
    assert f.journal.get(f.row['operation_id'])['result']=={'original-membership':'complete'}
    assert f.journal.get(f.row['operation_id'])['state']=='completed'
    assert all(o.deadline_ns is None and o.maintenance is None for o in f.owners.values())
    before=copy.deepcopy(f.effects)
    f.events.clear()
    assert run(f)==result
    assert f.effects==before
    assert ('new','pause') not in f.events and ('new','recover') in f.events
    assert not any(name=='old' and action not in {'helper','receive-route-preview','relay'} for name,action in f.events)


@pytest.mark.parametrize('lost',['receive-communication-prepare','receive-key','receive-application','selection','receive-snapshot'])
def test_lost_native_result_resumes_original_commands_without_reenrollment_or_key_replacement(fixture,lost):
    f=fixture
    f.lose.append(lost)
    with pytest.raises(OSError):
        run(f)
    assert f.events[-1]==('new','restore')
    assert run(f)['outbound_release'] is False
    assert all(count==1 for count in f.effects.values())
    assert f.journal.get(f.row['operation_id'])['result']=={'original-membership':'complete'}


def test_lost_root_receipt_reconciles_recorded_native_result(fixture,monkeypatch):
    f=fixture
    advance=f.journal.advance
    fail=[True]
    def lose(*args,**kwargs):
        result=advance(*args,**kwargs)
        if fail and result['runtime_observation'].get('receive_application',{}).get('application',{}).get('result'):
            fail.clear()
            raise OSError('lost host checkpoint acknowledgment')
        return result
    monkeypatch.setattr(f.journal,'advance',lose)
    with pytest.raises(OSError):
        run(f)
    assert run(f)['outbound_release'] is False
    assert f.effects['receive-application']==1


def test_changed_preparation_refuses_before_another_helper_or_pause(fixture):
    f=fixture
    run(f)
    f.events.clear()
    f.selected['listen']['port']=2345
    f.selected['intake_endpoint']='http://127.0.0.1:2345/dm-messaging/v1/message'
    with pytest.raises(OnboardingError,match='original_changed'):
        run(f)
    assert not f.events


def test_changed_old_loaded_publication_refuses_before_entrant_pause(fixture,monkeypatch):
    f=fixture
    status=f.owners['old'].status
    def changed():
        value=status()
        value['runtime_status']['loaded_application']['application_sha256']='f'*64
        return value
    monkeypatch.setattr(f.owners['old'],'status',changed)
    with pytest.raises(OnboardingError,match='source_changed'):
        run(f)
    assert not f.effects and ('new','pause') not in f.events


@pytest.mark.parametrize('field,value',[('policy',{'classification':'private','max_ttl_ms':60000}),
    ('stores',{'relationships':'/adult/private-history'}),
    ('stores',{k:k+'.sqlite' for k in ('relationships','inbox','outgoing-context','outbox','opaque-evidence','opaque-message')}),('listen',{'host':'127.0.0.1','port':False}),
    ('intake_endpoint','http://127.0.0.1:7654/dm-messaging/v1/message'),('authority_order',['x','x'])])
def test_invalid_configuration_cannot_prepare_helpers_or_keys(fixture,field,value):
    f=fixture
    f.selected[field]=value
    with pytest.raises(OnboardingError,match='preparation_required'):
        run(f)
    assert not f.events


@pytest.mark.parametrize('gap',[None,'entrant-unselected','old-unselected','missing-reader','wrong-being','membership','unobserved-member','expired-proof','expired-credential'])
def test_observation_requires_fresh_all_required_readers_and_preserves_old_visibility(fixture,monkeypatch,gap):
    from clusterctl import onboarding_receiving_update as receiving
    f=fixture
    run(f)
    readers=[dict(schema='dm.receiving.reader/v2',being_ref=name,embodiment_id='body-'+name,
        validity=dict(mode='until-revoked',not_before_ms=0)) for name in ('new','old')]
    roster=dict(schema='dm.runtime.tribe-roster/v1',tribe_ref='tribe',
        audience=[{k:r[k] for k in ('being_ref','embodiment_id')} for r in readers],
        membership_proofs=[],required_authority_epochs=[],roster_sha256='c'*64)
    if gap=='unobserved-member':
        roster['audience']=roster['audience']+[dict(being_ref='another',embodiment_id='body-another')]
    calls=[]
    def proof(owner,*,expected_selection,expires_at_ms,receive_only):
        name=owner.name
        assert receive_only == (name=='new')
        assert expected_selection['application_sha256']==('9' if name=='new' else '4')*64
        assert expected_selection['visibility_installation_sha256']==(None if name=='new' else '6'*64)
        assert time.time_ns()//1_000_000 < expires_at_ms <= time.time_ns()//1_000_000+60000
        calls.append(name)
        gate=dict(phase='select',readers=copy.deepcopy(readers))
        if (gap=='entrant-unselected' and name=='new') or (gap=='old-unselected' and name=='old'):
            gate['phase']='unselected'
        if gap=='missing-reader':
            gate['readers']=gate['readers'][:1]
        native_roster=copy.deepcopy(roster)
        if gap=='membership' and name=='old':
            native_roster['membership_proofs']=['changed']
        reader=copy.deepcopy(next(r for r in readers if r['being_ref']==name))
        if gap=='wrong-being' and name=='old':
            reader['being_ref']='foreign'
        if gap=='expired-credential' and name=='old':
            reader['validity']=dict(mode='finite',not_before_ms=0,not_after_ms=time.time_ns()//1_000_000-1)
        return dict(reader=reader,gate=gate,roster=native_roster,
            identity_expires_at_ms=time.time_ns()//1_000_000-1 if gap=='expired-proof' and name=='old' else expires_at_ms)
    monkeypatch.setattr(receiving,'observe_current_reader',proof)
    before=f.journal.get(f.row['operation_id'])
    def observe():
        return flow.observe(plan=f.plan,selected=f.selected,row=before,admission=f.admission,
            owners=f.owners,validate=lambda:None,deadline_ns=time.monotonic_ns()+10_000_000_000)
    if gap in {'wrong-being','membership','unobserved-member','expired-proof','expired-credential'}:
        with pytest.raises(OnboardingError):
            observe()
    else:
        result=observe()
        assert result.state==('complete' if gap is None else 'waiting')
        if gap is None:
            assert result.facts=={'tribe_reader_selection_verified':True}
    assert calls==['new','old']
    assert f.journal.get(f.row['operation_id'])==before
    assert all(o.deadline_ns is None and o.maintenance is None for o in f.owners.values())


def test_pending_snapshot_reply_cannot_satisfy_receiving_observation(fixture):
    f=fixture
    f.lose.append('receive-snapshot')
    with pytest.raises(OSError):
        run(f)
    f.events.clear()
    result=flow.observe(plan=f.plan,selected=f.selected,row=f.journal.get(f.row['operation_id']),
        admission=f.admission,owners=f.owners,validate=lambda:None,deadline_ns=time.monotonic_ns()+5_000_000_000)
    assert result.state=='waiting' and not f.events


def test_original_scope_recovery_precedes_fresh_base_status(fixture,monkeypatch):
    f=fixture
    current=f.journal.get(f.row['operation_id'])
    observed=dict(receive_application=dict(schema='cluster-companion-receive-phase/v1',
        binding=digest(dict(original_intent=f.row['intent'],preparation=f.selected))),receive_maintenance={'original':'pending'})
    f.journal.advance(f.row['operation_id'],current['state'],runtime_observation=observed)
    stopped=[True]
    original=f.owners['new'].base_status
    def status():
        assert not stopped[0], 'fresh base read preceded original owned recovery'
        return original()
    monkeypatch.setattr(f.owners['new'],'base_status',status)
    scope=flow.preserved
    @contextmanager
    def recover(*args,**kwargs):
        if kwargs.get('restore_only'):
            stopped[0]=False
        with scope(*args,**kwargs) as check:
            yield check
    monkeypatch.setattr(flow,'preserved',recover)
    assert run(f)['outbound_release'] is False
    assert f.events.index(('new','recover')) < f.events.index(('new','pause'))


@pytest.mark.parametrize('stage',['matrix','acceptance'])
def test_existing_worker_advances_receive_after_completed_membership_without_reenrollment(fixture,monkeypatch,stage):
    from clusterctl import onboarding_group_coordinator as module
    f=fixture
    coordinator=object.__new__(module.GroupCoordinator)
    coordinator.store=SimpleNamespace(_load=lambda n:dict(plan=f.plan,stage=stage))
    coordinator.settings={'receive_preparations':{digest(f.plan):f.selected}}
    row=copy.deepcopy(f.row)
    row['intended_transition']['membership_only']={'schema':'cluster-native-membership-only/v1'}
    monkeypatch.setattr(coordinator,'_binding',lambda p:(f.journal,row,f.admission))
    events=[]
    def membership(*args,**kwargs):
        events.append('membership')
        return {'native':'retained'}
    def receive(*args,**kwargs):
        assert kwargs['select_current'] is True
        events.append('receive')
        return {'receiving':'phase'}
    monkeypatch.setattr(coordinator,'advance_membership_only',membership)
    monkeypatch.setattr(coordinator,'advance_receive_only',receive)
    assert coordinator.advance('new')=={'receiving':'phase'}
    assert events==(['membership','receive'] if stage=='matrix' else ['receive'])


def test_coordinator_retains_actual_restoration_and_completed_retry_acquires_no_owners(fixture,monkeypatch,tmp_path):
    from clusterctl import onboarding_group_coordinator as module
    f=fixture
    coordinator=object.__new__(module.GroupCoordinator)
    pin=digest(f.plan)
    coordinator.path=tmp_path/'configuration.json'
    coordinator.store=SimpleNamespace(_load=lambda n:dict(plan=f.plan,stage='acceptance'))
    coordinator.settings=dict(receive_preparations={pin:f.selected},admissions={pin:f.row['operation_id']},
        owners={name:{'binding':name} for name in f.owners},tribe_ref='tribe')
    coordinator.backend=SimpleNamespace(authorize=lambda *a:True,_consented=lambda *a,**kw:True,
        _decision=lambda p:True,_ceremony=lambda p:SimpleNamespace(authorize=lambda p:True))
    monkeypatch.setattr(coordinator,'_binding',lambda p:(f.journal,f.journal.get(f.row['operation_id']),f.admission))
    monkeypatch.setattr(coordinator,'_owners',lambda a:f.owners)
    monkeypatch.setattr(module,'configuration',lambda p:coordinator.settings)
    monkeypatch.setattr(module,'finish_membership_only',lambda j,r,result:result)
    result=coordinator.advance_receive_only('new')
    assert f.events[-1]==('new','restore')
    current=f.journal.get(f.row['operation_id'])
    assert current['result']=={'original-membership':'complete'}
    assert current['runtime_observation']['receive_application']['restoration']['snapshot_sha256']==digest(result)
    monkeypatch.setattr(coordinator,'_owners',lambda a:pytest.fail('confirmed restoration retry acquired owners'))
    assert coordinator.advance_receive_only('new')==result
    assert f.journal.get(f.row['operation_id'])==current



def test_existing_selected_application_refuses_initial_publication_before_pause_or_new_key(fixture,monkeypatch):
    f=fixture
    dispatch=f.owners['new'].group_publication
    def existing(command,**kwargs):
        value=dispatch(command,**kwargs)
        if command['action']=='context-preview':
            value['predecessor_selection_sha256']='a'*64
        return value
    monkeypatch.setattr(f.owners['new'],'group_publication',existing)
    with pytest.raises(OnboardingError,match='existing_application_preserved'):
        run(f)
    assert ('new','pause') not in f.events
    assert not f.effects



def test_worker_reports_closed_receive_failures_without_serializing_private_exception_text():
    from clusterctl.onboarding import refusal_diagnostic
    for code in ('companion_receive_original_changed','receiving_current_required_reader_missing','receive_resource_capacity'):
        assert refusal_diagnostic(OnboardingError(code),stage='host-preparation')['code']==code
    unknown=refusal_diagnostic(OnboardingError('some-private-key-or-path'),stage='host-preparation')
    assert 'some-private-key' not in str(unknown)



def test_preparation_can_use_existing_outer_budget_without_extending_native_guard(fixture):
    f=fixture
    result=flow.publish(plan=f.plan,selected=f.selected,journal=f.journal,row=f.journal.get(f.row['operation_id']),
        admission=f.admission,owners=f.owners,validate=lambda:None,deadline_ns=time.monotonic_ns()+300_000_000_000)
    assert result['outbound_release'] is False


@pytest.fixture
def native_readers(fixture, monkeypatch, tmp_path):
    """Use the real native gate CAS; no daemon/model or child identity is made."""
    import os
    from daimon_matrix.native_egress import MandatoryEgressController
    f = fixture
    snapshot = run(f)
    row = f.journal.get(f.row['operation_id'])
    observed = copy.deepcopy(row['runtime_observation'])
    observed['receive_application']['restoration'] = dict(schema='cluster-companion-receive-restored/v1',
        operation_id=row['operation_id'], snapshot_sha256=digest(snapshot), preparation_sha256=digest(f.selected))
    f.journal.advance(row['operation_id'], row['state'], runtime_observation=observed)
    controllers = {name:MandatoryEgressController(policy={}, proof_key=b'k'*32, transport=None)
        for name in f.owners}
    for native in controllers.values():
        native.register_reader_channel('tribe', 'a'*64, controlled=True)
    requests, effects, lost = {}, [], []
    readers = [dict(schema='dm.receiving.reader/v2',being_ref=name,embodiment_id='body-'+name,
        incarnation_id='incarnation-'+name,credential_id='credential-'+name,authority_manifest_hash='a'*64,
        receiving_selection_sha256='b'*64,loaded_view_sha256='c'*64,
        validity=dict(mode='until-revoked',not_before_ms=0),wire_read=['dm.tribe.conversation/v1'],
        authority_epochs=['a'*64]) for name in sorted(f.owners)]
    def gate(name):
        return controllers[name].reader_snapshot('tribe',deadline_ns=time.monotonic_ns()+5_000_000_000)
    def collect(**options):
        options['validate']()
        return {name:dict(reader=copy.deepcopy(next(r for r in readers if r['being_ref']==name)),
            gate=gate(name),roster=dict(roster_sha256=digest(name)),
            expected=dict(process=dict(pid=os.getpid()),server=dict(embodiment_id='body-'+name),selection={}))
            for name in f.owners}, dict(readers=copy.deepcopy(readers),membership_basis_sha256='d'*64)
    monkeypatch.setattr(flow,'_collect',collect)
    for name,owner in f.owners.items():
        owner.root = tmp_path/name
        def apply(command,path,*,name=name):
            key=(name,str(path))
            if key in requests:
                assert requests[key] == command, 'immutable private request changed'
            else:
                requests[key]=copy.deepcopy(command)
            marker=name+'-'+command['phase']
            if lost and lost[0]==marker+'-before':
                lost.pop(0)
                raise OSError('lost before native dispatch')
            if command['phase']=='select':
                assert all(gate(n)['phase'] in {'revoke','select'}
                    and gate(n)['operation_id']==command['operation_id'] for n in f.owners)
            before=gate(name)
            # The actual owner API verifies local signed-roster CAS separately.
            assert command['expected_roster_sha256']==digest(name)
            native_command={k:v for k,v in command.items() if k!='expected_roster_sha256'}
            accepted=controllers[name].select_readers(native_command,request_sha256=digest(dict(key=key,command=command)),
                deadline_ns=time.monotonic_ns()+5_000_000_000)
            if accepted['head']!=before['head']:
                effects.append(marker)
            if lost and lost[0]==marker+'-after':
                lost.pop(0)
                raise OSError('lost after native acceptance')
            return dict(schema='cluster-receiving-owner-control-observation/v1',gate=accepted,
                process=dict(pid=os.getpid()),server=dict(embodiment_id='body-'+name),
                request_sha256=accepted['request_sha256'],command_sha256=digest(command))
        owner.prepare_apply_control=apply
    def select(validate=lambda:None):
        return flow.select_readers(plan=f.plan,selected=f.selected,row=f.journal.get(f.row['operation_id']),
            journal=f.journal,admission=f.admission,owners=f.owners,validate=validate,
            deadline_ns=time.monotonic_ns()+10_000_000_000)
    return SimpleNamespace(f=f,controllers=controllers,requests=requests,effects=effects,lost=lost,
        readers=readers,gate=gate,select=select)


@pytest.mark.parametrize('lost',[None,'new-revoke-before','new-revoke-after','old-revoke-after',
    'new-select-before','new-select-after','old-select-after'])
def test_current_native_barrier_resumes_same_original_controls_and_preserves_membership(native_readers,lost):
    f=native_readers
    if lost is not None:
        f.lost.append(lost)
        with pytest.raises(OSError,match='lost'):
            f.select()
    assert f.select()==dict(tribe_reader_selection_verified=True)
    row=f.f.journal.get(f.f.row['operation_id'])
    assert row['state']=='completed' and row['result']=={'original-membership':'complete'}
    assert f.effects==['new-revoke','old-revoke','new-select','old-select']
    assert all(f.gate(n)['readers']==f.readers for n in f.f.owners)
    requests=copy.deepcopy(f.requests)
    assert f.select()==dict(tribe_reader_selection_verified=True)
    assert f.requests==requests and len(f.effects)==4
    assert all(o.deadline_ns is None and o.maintenance is None for o in f.f.owners.values())


def test_current_native_barrier_keeps_partial_work_across_foreground_window(native_readers):
    f=native_readers
    def expires():
        if len(f.effects)==1:
            raise OnboardingError('receiving_host_deadline_expired')
    with pytest.raises(OnboardingError,match='deadline_expired'):
        f.select(expires)
    assert f.effects==['new-revoke']
    assert f.select()==dict(tribe_reader_selection_verified=True)
    assert f.effects==['new-revoke','old-revoke','new-select','old-select']


def test_changed_current_vector_cannot_enable_partial_cohort(native_readers):
    f=native_readers
    f.lost.append('old-revoke-after')
    with pytest.raises(OSError):
        f.select()
    f.readers[0]['loaded_view_sha256']='e'*64
    before=copy.deepcopy(f.effects)
    with pytest.raises(OnboardingError,match='reader_control_changed'):
        f.select()
    assert f.effects==before and all(f.gate(n)['phase']=='revoke' for n in f.f.owners)


def test_current_selection_requires_actual_original_restoration(native_readers):
    f=native_readers
    row=f.f.journal.get(f.f.row['operation_id'])
    observed=copy.deepcopy(row['runtime_observation'])
    del observed['receive_application']['restoration']
    f.f.journal.advance(row['operation_id'],row['state'],runtime_observation=observed)
    with pytest.raises(OnboardingError,match='restoration_required'):
        f.select()
    assert not f.requests


def test_worker_current_controls_begin_only_after_retained_restoration(fixture, monkeypatch, tmp_path):
    from clusterctl import onboarding_group_coordinator as module
    f=fixture
    coordinator=object.__new__(module.GroupCoordinator)
    pin=digest(f.plan)
    coordinator.path=tmp_path/'configuration.json'
    coordinator.store=SimpleNamespace(_load=lambda n:dict(plan=f.plan,stage='acceptance'))
    coordinator.settings=dict(receive_preparations={pin:f.selected},admissions={pin:f.row['operation_id']},
        owners={name:{'binding':name} for name in f.owners},tribe_ref='tribe')
    coordinator.backend=SimpleNamespace(authorize=lambda *a:True,_consented=lambda *a,**kw:True,
        _decision=lambda p:True,_ceremony=lambda p:SimpleNamespace(authorize=lambda p:True))
    monkeypatch.setattr(coordinator,'_binding',lambda p:(f.journal,f.journal.get(f.row['operation_id']),f.admission))
    monkeypatch.setattr(coordinator,'_owners',lambda a:f.owners)
    monkeypatch.setattr(module,'configuration',lambda p:coordinator.settings)
    monkeypatch.setattr(module,'finish_membership_only',lambda j,r,result:result)
    calls=[]
    def select(**options):
        assert f.events[-1]==('new','restore')
        state=options['row']['runtime_observation']['receive_application']
        assert state['restoration']['snapshot_sha256']==digest(state['snapshot']['result'])
        options['validate']()
        calls.append(options['row']['operation_id'])
        return dict(tribe_reader_selection_verified=True)
    monkeypatch.setattr(flow,'select_readers',select)
    result=coordinator.advance_receive_only('new', select_current=True)
    assert calls==[f.row['operation_id']] and result['outbound_release'] is False
    assert f.journal.get(f.row['operation_id'])['result']=={'original-membership':'complete'}


def test_other_native_revocation_is_preserved_without_takeover(native_readers):
    f=native_readers
    before=f.gate('old')
    command=dict(schema='dm.runtime.reader-selection/v2',channel_id='tribe',
        process_instance_id=before['process_instance_id'],expected_head=before['head'],
        operation_id=str(uuid.uuid4()),release_digest='f'*64,phase='revoke',readers=[])
    f.controllers['old'].select_readers(command,request_sha256=digest(command),
        deadline_ns=time.monotonic_ns()+5_000_000_000)
    foreign=f.gate('old')
    with pytest.raises(OnboardingError,match='reader_control_changed'):
        f.select()
    assert f.gate('old')==foreign and not f.requests
    assert f.gate('new')['phase']=='unselected'


def test_unobserved_control_reply_keeps_exact_native_recovery(native_readers,monkeypatch):
    f=native_readers
    owner=f.f.owners['new']
    native=owner.prepare_apply_control
    def bad(command,path):
        result=native(command,path)
        result['command_sha256']='0'*64
        return result
    monkeypatch.setattr(owner,'prepare_apply_control',bad)
    with pytest.raises(OnboardingError,match='reader_control_unobserved'):
        f.select()
    assert f.effects==['new-revoke']
    monkeypatch.setattr(owner,'prepare_apply_control',native)
    assert f.select()==dict(tribe_reader_selection_verified=True)
    assert f.effects==['new-revoke','old-revoke','new-select','old-select']
