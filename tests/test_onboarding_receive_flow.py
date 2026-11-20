"""Original receive choreography preserves terminal membership and other owners."""
import copy
from contextlib import contextmanager
from types import SimpleNamespace
from pathlib import Path
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


@pytest.mark.parametrize('gap',[None,'entrant-unselected','old-unselected','missing-reader','wrong-being','membership','unobserved-member','unobserved-sibling-body','expired-proof','expired-credential'])
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
    if gap=='unobserved-sibling-body':
        roster['audience']=roster['audience']+[dict(being_ref='old',embodiment_id='historical-body-old')]
    calls=[]
    def proof(owner,*,expected_selection,expires_at_ms,receive_only,require_admitted):
        assert require_admitted is True
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
        assert result.state==('complete' if gap in (None,'unobserved-sibling-body') else 'waiting')
        if gap in (None,'unobserved-sibling-body'):
            assert result.facts=={'tribe_reader_selection_verified':True}
    assert sorted(calls)==['new','old']
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


def test_explicit_current_sibling_receiver_cannot_be_omitted():
    proof=dict(reader=dict(being_ref='member',embodiment_id='current'),
        roster=dict(audience=[dict(being_ref='member',embodiment_id='current'),
                              dict(being_ref='member',embodiment_id='second-current')]))
    receivers={'first':dict(being_ref='member',embodiment_id='current'),
               'second':dict(being_ref='member',embodiment_id='second-current')}
    with pytest.raises(OnboardingError,match='current_required_reader_missing'):
        flow.require_current_reader_coverage({'first':proof},receivers)


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


@pytest.mark.parametrize('stage',['matrix','acceptance',None])
def test_existing_worker_advances_receive_after_completed_membership_without_reenrollment(fixture,monkeypatch,stage):
    from clusterctl import onboarding_group_coordinator as module
    f=fixture
    coordinator=object.__new__(module.GroupCoordinator)
    coordinator.store=SimpleNamespace(_load=lambda n:dict(plan=f.plan,stage=stage,state='complete' if stage is None else 'pending'))
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


@pytest.mark.parametrize('stage',['acceptance',None])
@pytest.mark.parametrize('defer',[False,True,'uncertain','unchanged'])
def test_coordinator_retains_actual_restoration_and_completed_retry_acquires_no_owners(fixture,monkeypatch,tmp_path,stage,defer):
    from clusterctl import onboarding_group_coordinator as module
    f=fixture
    coordinator=object.__new__(module.GroupCoordinator)
    pin=digest(f.plan)
    coordinator.path=tmp_path/'configuration.json'
    coordinator.store=SimpleNamespace(_load=lambda n:dict(plan=f.plan,stage=stage,state='complete' if stage is None else 'pending'))
    coordinator.settings=dict(receive_preparations={pin:f.selected},admissions={pin:f.row['operation_id']},
        owners={name:{'binding':name} for name in f.owners},tribe_ref='tribe')
    coordinator.backend=SimpleNamespace(authorize=lambda *a:True,_consented=lambda *a,**kw:True,
        _decision=lambda p:True,_ceremony=lambda p:SimpleNamespace(authorize=lambda p:True))
    monkeypatch.setattr(coordinator,'_binding',lambda p:(f.journal,f.journal.get(f.row['operation_id']),f.admission))
    monkeypatch.setattr(coordinator,'_owners',lambda a:f.owners)
    monkeypatch.setattr(module,'configuration',lambda p:coordinator.settings)
    monkeypatch.setattr(module,'finish_membership_only',lambda j,r,result:result)
    if defer in (True, 'uncertain'):
        relay = flow.relay
        lost = []
        def bounded(source, target, outgoing, incoming, **kwargs):
            if source is f.owners['old'] and not lost:
                assert f.events[-1] != ('new','restore')
                lost.append(True)
                error = OnboardingError('receiving_owner_deadline_expired')
                if defer == 'uncertain':
                    error.add_note('Scoped Matrix restoration is unobserved')
                raise error
            return relay(source, target, outgoing, incoming, **kwargs)
        monkeypatch.setattr(flow, 'relay', bounded)
    if defer == 'unchanged':
        calls = []
        def unavailable(*args, **kwargs):
            calls.append(True)
            raise OnboardingError('receiving_owner_deadline_expired')
        monkeypatch.setattr(flow, 'Endpoint', unavailable)
    if defer in ('uncertain', 'unchanged'):
        with pytest.raises(OnboardingError, match='receiving_owner_deadline_expired') as error:
            coordinator.advance_receive_only('new')
        if defer == 'uncertain':
            assert error.value.__notes__ and len(lost) == 1
        else:
            assert calls == [True] and not f.effects
        return
    result=coordinator.advance_receive_only('new')
    assert f.events.count(('new','restore')) == (3 if defer else 1)
    assert all(count == 1 for count in f.effects.values())
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
            identity_expires_at_ms=time.time_ns()//1_000_000+60_000,
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
    def select(validate=lambda:None, selection_updates=None, maintenance_updates=None):
        return flow.select_readers(plan=f.plan,selected=f.selected,row=f.journal.get(f.row['operation_id']),
            journal=f.journal,admission=f.admission,owners=f.owners,validate=validate,
            deadline_ns=time.monotonic_ns()+10_000_000_000, selection_updates=selection_updates, maintenance_updates=maintenance_updates)
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


def test_reader_preparation_runs_independent_owners_together_before_controls(native_readers, monkeypatch):
    import threading
    f = native_readers
    endpoint = flow.Endpoint
    barrier = threading.Barrier(len(f.f.owners))
    def prepare(*args, **kwargs):
        assert not f.effects
        barrier.wait(timeout=2)
        return endpoint(*args, **kwargs)
    monkeypatch.setattr(flow, 'Endpoint', prepare)
    assert f.select() == dict(tribe_reader_selection_verified=True)


@pytest.mark.parametrize('lost_ack', [False, True])
def test_code_update_selects_new_vector_without_replaying_original_native_controls(native_readers, monkeypatch, lost_ack):
    f = native_readers
    f.select()
    original = copy.deepcopy(f.f.journal.get(f.f.row['operation_id'])['runtime_observation'][
        'receive_application']['reader_selection'])
    f.readers[0]['receiving_selection_sha256'] = 'e'*64
    updates = {'new': {'receiving_code': 'qualified-successor'}}
    if lost_ack:
        f.lost.append('new-select-after')
        with pytest.raises(OSError):
            f.select(selection_updates=updates)
    assert f.select(selection_updates=updates) == dict(tribe_reader_selection_verified=True)
    phase = f.f.journal.get(f.f.row['operation_id'])['runtime_observation']['receive_application']
    assert phase['reader_selection_previous'] == original
    assert phase['reader_selection']['selection_updates_sha256'] == digest(updates)
    assert f.effects == ['new-revoke', 'old-revoke', 'new-select', 'old-select']*2
    assert f.select(selection_updates=updates) == dict(tribe_reader_selection_verified=True)
    assert len(f.effects) == 8
    collect = flow._collect
    def current(**options):
        assert options['selection_updates'] == updates
        return collect(**options)
    monkeypatch.setattr(flow, '_collect', current)
    assert f.select() == dict(tribe_reader_selection_verified=True)
    assert len(f.effects) == 8


def test_authenticated_restart_refreshes_completed_native_barrier_without_software_change(native_readers):
    from daimon_matrix.native_egress import MandatoryEgressController
    f = native_readers
    f.select()
    original = copy.deepcopy(f.f.journal.get(f.f.row['operation_id'])['runtime_observation'][
        'receive_application']['reader_selection'])
    original_operation = f.gate('new')['operation_id']
    restarted = MandatoryEgressController(policy={}, proof_key=b'k'*32, transport=None)
    restarted.register_reader_channel('tribe', 'a'*64, controlled=True)
    f.controllers['new'] = restarted
    assert f.select() == dict(tribe_reader_selection_verified=True)
    assert f.gate('new')['operation_id'] != original_operation
    assert f.gate('old')['operation_id'] == f.gate('new')['operation_id']
    assert len(f.effects) == 8
    phase = f.f.journal.get(f.f.row['operation_id'])['runtime_observation']['receive_application']
    assert phase['reader_selection_previous'] == original
    assert f.select() == dict(tribe_reader_selection_verified=True)
    assert len(f.effects) == 8


def test_restart_never_supersedes_an_unfinished_native_barrier(native_readers):
    from daimon_matrix.native_egress import MandatoryEgressController
    f = native_readers
    f.lost.append('new-revoke-after')
    with pytest.raises(OSError):
        f.select()
    original = copy.deepcopy(f.f.journal.get(f.f.row['operation_id']))
    restarted = MandatoryEgressController(policy={}, proof_key=b'k'*32, transport=None)
    restarted.register_reader_channel('tribe', 'a'*64, controlled=True)
    f.controllers['old'] = restarted
    with pytest.raises(OnboardingError, match='reader_control_changed'):
        f.select()
    assert f.f.journal.get(f.f.row['operation_id']) == original
    assert f.effects == ['new-revoke']


@pytest.mark.parametrize('expire_after_first_select', [False, True])
def test_current_selection_reuses_only_unexpired_complete_proofs(native_readers, monkeypatch,
                                                                expire_after_first_select):
    f = native_readers
    original = flow._collect
    rounds = []
    def collect(**options):
        result = original(**options)
        rounds.append(result[0])
        return result
    monkeypatch.setattr(flow, '_collect', collect)
    apply = f.f.owners['new'].prepare_apply_control
    def select(command, path):
        result = apply(command, path)
        if expire_after_first_select and command['phase'] == 'select':
            for proof in rounds[-1].values():
                proof['identity_expires_at_ms'] = 0
        return result
    f.f.owners['new'].prepare_apply_control = select
    assert f.select() == dict(tribe_reader_selection_verified=True)
    # Initial vector and final full read are mandatory. An expired vector adds
    # one complete refresh before the next native positive control.
    assert len(rounds) == (3 if expire_after_first_select else 2)
    assert f.effects == ['new-revoke', 'old-revoke', 'new-select', 'old-select']


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


def test_owned_ingress_recovers_lost_add_before_native_pause_or_key_creation(fixture,monkeypatch):
    from clusterctl import onboarding_conversation_proxy as proxy
    f=fixture
    f.selected['ingress']=dict(listen_host='10.20.30.40',listen_port=18768)
    f.selected['key']['endpoint']='http://10.20.30.40:18768/dm-messaging/v1/message'
    owner=f.owners['new']
    owner.backend=object()
    owner.plan=f.plan
    calls=[]
    def reconcile(backend,plan,listener,request,**options):
        assert backend is owner.backend and plan==f.plan
        assert listener==f.selected['ingress']
        assert request==dict(port=1234,listen_host='127.0.0.1')
        assert options==dict(device_name='matrix-message',apply=True)
        calls.append('same-owned-ingress')
        if len(calls)==1:
            raise TimeoutError('lost original device reply')
        return SimpleNamespace(state='complete')
    monkeypatch.setattr(proxy,'reconcile_listener',reconcile)
    with pytest.raises(TimeoutError):
        run(f)
    assert ('new','pause') not in f.events and not f.effects
    phase=f.journal.get(f.row['operation_id'])['runtime_observation']['receive_application']
    assert phase['ingress_intent']==dict(device='matrix-message',listener=f.selected['ingress'],guest_port=1234)
    assert 'ingress' not in phase
    assert run(f)['outbound_release'] is False
    assert len(calls)==2 and all(count==1 for count in f.effects.values())
    assert run(f)['outbound_release'] is False and len(calls)==2
    retained=f.journal.get(f.row['operation_id'])['runtime_observation']['receive_application']['ingress']
    assert retained==dict(device='matrix-message',listener=f.selected['ingress'],guest_port=1234,state='complete')


@pytest.mark.parametrize('mismatch',['public-host','public-port','guest-host'])
def test_ingress_configuration_binds_transport_and_actual_guest_listener(fixture,mismatch):
    f=fixture
    f.selected['ingress']=dict(listen_host='10.20.30.40',listen_port=18768,
        vm=dict(nic='eth0',network='incusbr0',address='10.100.0.10'))
    f.selected['key']['endpoint']='http://10.20.30.40:18768/dm-messaging/v1/message'
    f.selected['listen']['host']='10.100.0.10'
    f.selected['intake_endpoint']='http://10.100.0.10:1234/dm-messaging/v1/message'
    assert flow.configuration(f.selected,f.owners)==f.selected
    if mismatch=='public-host':
        f.selected['key']['endpoint']='http://10.20.30.41:18768/dm-messaging/v1/message'
    elif mismatch=='public-port':
        f.selected['key']['endpoint']='http://10.20.30.40:18769/dm-messaging/v1/message'
    else:
        f.selected['listen']['host']='10.100.0.11'
        f.selected['intake_endpoint']='http://10.100.0.11:1234/dm-messaging/v1/message'
    with pytest.raises(OnboardingError,match='companion_receive_preparation_required'):
        run(f)
    assert not f.events


def test_current_collection_keeps_source_and_guest_identity_contracts_distinct(fixture, monkeypatch):
    from clusterctl import onboarding_receiving_update as receiving
    f = fixture
    run(f)
    source = object.__new__(receiving.SourceGroupClient)
    source.deadline_ns, source.maintenance = None, None
    f.owners['old'] = source
    calls = []
    class Collected(Exception):
        pass
    def identity(owner, *, require_admitted, **kwargs):
        calls.append(require_admitted)
        if owner is source:
            assert require_admitted is False
            raise Collected
        assert require_admitted is True
        return dict(reader=dict(being_ref='new', embodiment_id='body-new'))
    monkeypatch.setattr(receiving, 'observe_current_reader', identity)
    with pytest.raises(Collected):
        flow._collect(plan=f.plan, selected=f.selected, row=f.journal.get(f.row['operation_id']),
            admission=f.admission, owners=f.owners, validate=lambda:None,
            deadline_ns=time.monotonic_ns()+10_000_000_000, prepare=False)
    assert sorted(calls) == [False, True]


@pytest.mark.parametrize('field', ['runtime_bundle_sha256', 'application_sha256', 'visibility_installation_sha256'])
def test_code_selection_update_cannot_change_identity_application_or_outbound(fixture, field):
    f = fixture
    snapshot = run(f)
    row = f.journal.get(f.row['operation_id'])
    phase = row['runtime_observation']['receive_application']
    selected = dict(phase['baseline'], application_sha256=snapshot['group']['application_sha256'],
        publication_sha256=snapshot['group']['publication_sha256'], visibility_installation_sha256=None)
    selected[field] = 'f'*64
    with pytest.raises(OnboardingError, match='companion_receive_source_changed'):
        flow._collect(plan=f.plan, selected=f.selected, row=row,
            admission=f.admission, owners=f.owners, validate=lambda:None,
            deadline_ns=time.monotonic_ns()+10_000_000_000, prepare=False,
            selection_updates={'new': selected})


def test_current_reader_collection_observes_independent_owners_in_one_validity_window(fixture, monkeypatch):
    import threading
    from clusterctl import onboarding_receiving_update as receiving
    f = fixture
    run(f)
    barrier = threading.Barrier(2)
    audience = [dict(being_ref=name, embodiment_id='body-'+name) for name in f.owners]
    def identity(owner, **kwargs):
        barrier.wait(timeout=2)
        return dict(reader=dict(being_ref=owner.name, embodiment_id='body-'+owner.name),
            identity_expires_at_ms=time.time_ns()//1_000_000+60000, roster=dict(audience=audience))
    monkeypatch.setattr(receiving, 'observe_current_reader', identity)
    monkeypatch.setattr(receiving, 'conversation_cohort', lambda proofs: {'cohort':'unchanged checks'})
    monkeypatch.setattr(receiving, '_reader_active', lambda reader, now: True)
    proofs, cohort = flow._collect(plan=f.plan, selected=f.selected,
        row=f.journal.get(f.row['operation_id']), admission=f.admission, owners=f.owners,
        validate=lambda:None, deadline_ns=time.monotonic_ns()+10_000_000_000, prepare=False)
    assert set(proofs) == set(f.owners) and cohort == {'cohort':'unchanged checks'}


@pytest.mark.parametrize('lost', [False, True])
@pytest.mark.parametrize('sdk_changed',[False,True])
def test_controller_child_preserves_published_phase_and_original_identity(fixture, monkeypatch, tmp_path, lost, sdk_changed):
    from clusterctl import onboarding_receiving_update as receiving
    from clusterctl import onboarding_host
    f = fixture
    snapshot = run(f)
    before = f.journal.get(f.row['operation_id'])
    observed = copy.deepcopy(before['runtime_observation'])
    phase = observed['receive_application']
    phase['restoration'] = {'verified':'original guard restored'}
    f.journal.advance(before['operation_id'], before['state'], runtime_observation=observed,
        expected_runtime_observation=before['runtime_observation'])
    original_phase = copy.deepcopy(phase)
    from clusterctl import onboarding_code_successor
    monkeypatch.setattr(onboarding_code_successor,'sdk_parameters',lambda *a,**kw:
        {'matrix_wheel_sha256':'0'*64 if sdk_changed else phase['baseline']['matrix_sdk']})
    host_path = tmp_path/'host.json'
    from clusterctl import being_seed
    being_seed._write(host_path, {'schema':'protected fixture'})
    config = object()
    monkeypatch.setattr(onboarding_host.HostConfig, 'load', lambda path: config)
    backend = SimpleNamespace(config=config)
    preparation = dict(code='/qualified/code',code_digest='c'*64,manifest_path='/qualified/manifest.json',
        manifest_digest='d'*64,expires_at_ms=time.time_ns()//1_000_000+60000,host_config=str(host_path))
    calls = []
    def mounted(plan, candidate, **kwargs):
        assert plan == f.plan and kwargs['prepare'] is True
        calls.append('mount')
        return True
    backend.runtime_available = mounted
    result = dict(schema='cluster-guest-bootstrap-loaded/v1',code_digest='c'*64,
        loaded_runtime=dict(runtime_bundle_sha256='e'*64,qualified_startup={'matrix_wheel_sha256':phase['baseline']['matrix_sdk']}),
        loaded_application=dict(application_sha256=snapshot['group']['application_sha256'],
            publication_sha256=snapshot['group']['publication_sha256'],
            visibility=dict(installation_sha256=None,release_enabled=False)))
    def prepare(*args, **kwargs):
        calls.append('prepare')
        assert not kwargs.get('installed_only', False), 'cold pinned SDK preparation must not require a manual install'
        return dict(plan=f.plan,owner=dict(group={**snapshot['group'],'installation_sha256':None}),root={}), {'original':'native request'}
    monkeypatch.setattr(receiving, 'prepare_guest_bootstrap', prepare)
    pending_loss = [True] if lost else []
    class Native:
        def __init__(self, journal, child, backend, name):
            self.journal, self.child = journal, child
            assert name == 'new'
        def execute(self, **kwargs):
            child = self.journal.get(self.child)
            if not (child['runtime_observation'] or {}).get('native_loaded'):
                calls.append('native effect')
                self.journal.advance(self.child,'runtime-dispatching',runtime_observation={'native_loaded':result})
            if pending_loss:
                pending_loss.pop()
                raise OSError('lost after native load')
            return result
    monkeypatch.setattr(receiving,'GuestBootstrapController',Native)
    def execute():
        return flow.ensure_controller(plan=f.plan,preparation=preparation,backend=backend,config_path=host_path,
            journal=f.journal,row=f.journal.get(f.row['operation_id']),validate=lambda:None,
            deadline_ns=time.monotonic_ns()+10_000_000_000)
    if sdk_changed:
        with pytest.raises(OnboardingError,match='controller_sdk_changed'):
            execute()
        assert not calls
        assert f.journal.get(f.row['operation_id'])['runtime_observation']['receive_application'] == original_phase
        return
    if lost:
        with pytest.raises(OSError,match='lost after native load'):
            execute()
    forward = execute()
    assert execute() == forward
    assert calls == ['mount','prepare','native effect']
    parent = f.journal.get(f.row['operation_id'])
    assert parent['runtime_observation']['receive_application'] == original_phase
    assert parent['result'] == before['result'] and parent['intent'] == before['intent']
    assert forward['selection']['runtime_bundle_sha256'] == 'e'*64
    assert forward['selection']['visibility_installation_sha256'] is None
    assert f.journal.get(forward['child_operation_id'])['state'] == 'completed'


@pytest.mark.parametrize('gap',[None,'sdk','runtime','body'])
def test_compatible_controller_load_is_adopted_without_repeating_failed_publication(fixture,monkeypatch,tmp_path,gap):
    from clusterctl import being_seed,onboarding_receiving_update as receiving,onboarding_host
    from clusterctl.onboarding_code_successor import plan_update
    f=fixture
    snapshot=run(f)
    parent=f.journal.get(f.row['operation_id'])
    observed=copy.deepcopy(parent['runtime_observation'])
    phase=observed['receive_application']
    phase['restoration']={'actual':'restored'}
    host=tmp_path/'host.json'
    being_seed._write(host,{})
    prep=dict(code='/qualified/failed',code_digest='c'*64,manifest_path='/qualified/failed.json',
        manifest_digest='d'*64,expires_at_ms=1,host_config=str(host))
    binding=dict(schema='cluster-companion-receive-controller/v1',parent=parent['operation_id'],
        parent_intent_sha256=digest(parent['intent']),receive_binding=phase['binding'],
        snapshot_sha256=digest(snapshot),preparation_sha256=digest(prep))
    child=plan_update(f.journal,manifest_digest='d'*64,
        target='companion-receive-controller:'+parent['operation_id'],
        expected_precondition=dict(companion_receive=binding,guest_bootstraps={'new':{
            'owner':{'being_ref':'new','origin':{'embodiment_id':'body-new'}}}}),
        intended_transition={},audit_identity={'actor':'fixture'})
    published={'runtime_sha256':'7'*64}
    f.journal.advance(child['operation_id'],'runtime-dispatching',runtime_observation={
        'guest_bootstraps':{'new':{'owner_published':published}}})
    observed['receive_controller']=dict(binding=binding,child_operation_id=child['operation_id'])
    f.journal.advance(parent['operation_id'],parent['state'],runtime_observation=observed,
        expected_runtime_observation=parent['runtime_observation'])
    before=f.journal.get(parent['operation_id'])
    owner=f.owners['new']
    owner.plan=f.plan
    owner.candidate=(Path('/qualified/recovery'),'a'*64)
    monkeypatch.setattr(receiving,'preflight',lambda *a,**kw:{
        'matrix_wheel_sha256':'0'*64 if gap=='sdk' else phase['baseline']['matrix_sdk']})
    calls=[]
    def proof(*args,**kwargs):
        calls.append('fresh proof')
        assert kwargs['expected_selection']['runtime_bundle_sha256']==published['runtime_sha256']
        assert kwargs['require_admitted'] and kwargs['receive_only']
        if gap=='runtime':
            raise OnboardingError('receiving_cohort_selection_changed')
        return {'reader':{'being_ref':'foreign' if gap=='body' else 'new','embodiment_id':'body-new'}}
    monkeypatch.setattr(receiving,'observe_current_reader',proof)
    def adopt():
        return flow.adopt_controller_software_recovery(plan=f.plan,owner=owner,
            code=owner.candidate[0],code_digest=owner.candidate[1],manifest_path=tmp_path/'manifest.json',
            manifest_digest='b'*64,journal=f.journal,row=before,validate=lambda:None,
            deadline_ns=time.monotonic_ns()+10_000_000_000)
    if gap:
        with pytest.raises(OnboardingError):
            adopt()
        assert f.journal.get(parent['operation_id'])==before
        assert f.journal.get(child['operation_id'])['state']=='runtime-dispatching'
        return
    result=adopt()
    assert calls==['fresh proof'] and result['selection']['receiving_code']=='a'*64
    assert f.journal.get(child['operation_id'])['state']=='degraded'
    current=f.journal.get(parent['operation_id'])
    assert current['runtime_observation']['receive_application']==before['runtime_observation']['receive_application']
    config=object()
    monkeypatch.setattr(onboarding_host.HostConfig,'load',lambda p:config)
    class NeverExecute:
        def __init__(self,*a,**kw):pytest.fail('repeated failed native publication')
    monkeypatch.setattr(receiving,'GuestBootstrapController',NeverExecute)
    assert flow.ensure_controller(plan=f.plan,preparation=prep,backend=SimpleNamespace(config=config),
        config_path=host,journal=f.journal,row=current,validate=lambda:None,
        deadline_ns=time.monotonic_ns()+10_000_000_000)==result


def test_reader_helper_correction_retains_pending_native_control(native_readers, monkeypatch):
    f = native_readers
    f.lost.append('old-select-before')
    with pytest.raises(OSError):
        f.select()
    before = copy.deepcopy(f.requests)
    original_preparation = copy.deepcopy(f.f.selected)
    replacement = {**f.f.selected['helpers']['owners']['old'],
        'code': '/qualified/compact-observer', 'code_digest': 'f' * 64}
    seen = []
    endpoint = flow.Endpoint
    def prepare(owner, selected, **options):
        seen.append(copy.deepcopy(selected))
        return endpoint(owner, selected, **options)
    monkeypatch.setattr(flow, 'Endpoint', prepare)
    assert f.select(maintenance_updates={'old': replacement}) == {'tribe_reader_selection_verified': True}
    assert replacement in seen and f.f.selected == original_preparation
    assert all(f.requests[key] == command for key, command in before.items())
    phase = f.f.journal.get(f.f.row['operation_id'])['runtime_observation']['receive_application']
    assert phase['reader_maintenance'] == {'old': replacement}
    seen.clear()
    assert f.select() == {'tribe_reader_selection_verified': True}
    assert replacement in seen


def test_reader_helper_correction_cannot_change_owner_journal(native_readers):
    f = native_readers
    replacement = {**f.f.selected['helpers']['owners']['old'], 'journal': '/another/owner-journal'}
    with pytest.raises(OnboardingError, match='maintenance_configuration_required'):
        f.select(maintenance_updates={'old': replacement})
    assert f.effects == []
