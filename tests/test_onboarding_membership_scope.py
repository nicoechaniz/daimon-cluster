"""Original journal orchestration restores partial guards and preserves owner state."""
from types import SimpleNamespace
import time

import pytest

from clusterctl import onboarding_membership_scope as scope
from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_code_successor import plan_update
from clusterctl.operation_journal import OperationJournal


@pytest.fixture
def setup(tmp_path, monkeypatch):
    journal = OperationJournal(tmp_path / 'journal')
    row = plan_update(journal, target='original', manifest_digest='a' * 64,
        expected_precondition={}, intended_transition={}, audit_identity={'actor': 'fixture'})
    owners = {name: SimpleNamespace(deadline_ns=None, maintenance=None) for name in ('one', 'two')}
    selected = dict(schema=scope.SCHEMA, owners={name: dict(code='/qualified/' + name,
        code_digest='a' * 64, journal='/own/journal') for name in owners})
    events, failures = [], set()
    class Session:
        def __init__(self, name): self.name = name
        def call(self, packet):
            assert packet == {'check': True}
            events.append(('check', self.name))
            if 'check-' + self.name in failures:
                raise OnboardingError('check-failed')
            return {'paused': True}
        def __exit__(self, *error):
            events.append(('restore', self.name))
            if 'restore-' + self.name in failures:
                raise OnboardingError('restore-failed')
    class Endpoint:
        def __init__(self, owner, selected, **kwargs):
            self.name = next(name for name, item in owners.items() if item is owner)
            events.append(('prepare', self.name))
            if 'prepare-' + self.name in failures:
                raise OnboardingError('prepare-failed')
            owner.maintenance = (selected['code'], selected['code_digest'])
        def recover(self):
            events.append(('recover', self.name))
            if 'recover-' + self.name in failures:
                raise OnboardingError('recover-failed')
        def open(self):
            # Every recovery must finish before any new pause.
            assert {name for phase, name in events if phase == 'recover'} == set(owners)
            current = journal.get(row['operation_id'])
            observed = current['runtime_observation']
            assert any(observed.get(field, {}).get('recipe') == selected
                for field in ('membership_maintenance', 'receive_maintenance'))
            events.append(('pause', self.name))
            if 'pause-' + self.name in failures:
                raise OnboardingError('pause-failed')
            return Session(self.name)
    monkeypatch.setattr(scope, 'Endpoint', Endpoint)
    return journal, row, owners, selected, events, failures


def run(setup, **kwargs):
    journal, row, owners, selected, events, failures = setup
    return scope.preserved(owners, selected, journal=journal, row=journal.get(row['operation_id']),
        deadline_ns=time.monotonic_ns() + 10_000_000_000, validate=lambda: None, **kwargs)


def test_full_scope_prepares_recovers_pauses_and_restores_after_native_writer_exit(setup):
    journal, row, owners, selected, events, failures = setup
    with run(setup) as check:
        assert {name for phase, name in events if phase == 'pause'} == set(owners)
        events.append(('native-writer-exited', 'all'))
        check()
    assert events.index(('native-writer-exited', 'all')) < next(i for i, e in enumerate(events) if e[0] == 'restore')
    assert {name for phase, name in events if phase == 'restore'} == set(owners)
    assert all(o.deadline_ns is None and o.maintenance is None for o in owners.values())
    # Reconciliation keeps the exact retained recipe/binding, not another operation.
    retained = journal.get(row['operation_id'])['runtime_observation']
    with run(setup, restore_only=True):
        pass
    assert journal.get(row['operation_id'])['runtime_observation'] == retained
    assert sum(phase == 'pause' for phase, _ in events) == 2


@pytest.mark.parametrize('maintenance_phase', ['membership', 'receive'])
@pytest.mark.parametrize('phase', ['prepare', 'recover', 'pause', 'check', 'restore'])
def test_partial_failure_restores_every_successful_guard_and_owner_fields(setup, phase, maintenance_phase):
    journal, row, owners, selected, events, failures = setup
    failures.add(phase + '-two')
    with pytest.raises(OnboardingError):
        with run(setup, phase=maintenance_phase):
            if phase in {'prepare', 'recover', 'pause', 'check'}:
                pytest.fail('native effects admitted after failed preparation')
    paused = {name for step, name in events if step == 'pause'} - ({'two'} if phase == 'pause' else set())
    assert {name for step, name in events if step == 'restore'} == paused
    assert all(o.deadline_ns is None and o.maintenance is None for o in owners.values())


def test_changed_retained_recipe_refuses_before_preparation(setup):
    journal, row, owners, selected, events, failures = setup
    with run(setup):
        pass
    events.clear()
    selected['owners']['one']['journal'] = '/changed/journal'
    with pytest.raises(OnboardingError, match='original_changed'):
        with run(setup):
            pytest.fail('changed original admitted')
    assert not events


def test_restore_failure_preserves_native_error_and_reports_recovery_gap(setup):
    *_, failures = setup
    failures.add('restore-two')
    with pytest.raises(ValueError, match='native-failed') as caught:
        with run(setup):
            raise ValueError('native-failed')
    assert 'restoration is unobserved' in caught.value.__notes__[0]


@pytest.mark.parametrize('bad', [None, {}, {'schema': scope.SCHEMA, 'owners': {}},
    {'schema': scope.SCHEMA, 'owners': {'foreign': {}}}])
def test_invalid_or_unselected_targets_refused(bad):
    with pytest.raises(OnboardingError, match='configuration_required'):
        scope.configuration(bad, {'one'})


def test_coordinator_completes_only_after_guard_restore_and_completed_retry_never_opens_guard(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from clusterctl import onboarding_group_coordinator as module
    from clusterctl.onboarding import digest
    from clusterctl.onboarding_receiving_update import CohortController
    journal=OperationJournal(tmp_path/'journal')
    selected=dict(schema=scope.SCHEMA,owners={'one':dict(code='/qualified',code_digest='a'*64,journal='/own')})
    plan={'name':'one'}
    pin=digest(plan)
    row=plan_update(journal,target='original',manifest_digest='a'*64,expected_precondition={},
        intended_transition={'membership_only':{'schema':'cluster-native-membership-only/v1'}},audit_identity={})
    coordinator=object.__new__(module.GroupCoordinator)
    coordinator.store=SimpleNamespace(_load=lambda name:{'plan':plan})
    coordinator.backend=SimpleNamespace(authorize=lambda *a:True,_consented=lambda *a,**kw:True,
        _decision=lambda p:True,_ceremony=lambda p:SimpleNamespace(authorize=lambda p:True))
    coordinator.settings={'admissions':{pin:row['operation_id']},'membership_maintenance':{pin:selected}}
    coordinator.path=tmp_path/'selected.json'
    owners={'one':SimpleNamespace(deadline_ns=None,maintenance=None)}
    monkeypatch.setattr(coordinator,'_binding',lambda p:(journal,journal.get(row['operation_id']),{}))
    monkeypatch.setattr(coordinator,'_owners',lambda a:owners)
    monkeypatch.setattr(module,'configuration',lambda p:coordinator.settings)
    @contextmanager
    def job(p): yield
    monkeypatch.setattr(coordinator,'_job_scope',job)
    events=[]
    @contextmanager
    def preserved(*args,**kwargs):
        events.append('pause')
        try:
            yield lambda:events.append('check')
        finally:
            events.append('restore')
    monkeypatch.setattr(scope,'preserved',preserved)
    def admit(self,**kw):
        events.append('native-writer-closed')
        return {'signed':'retained'}
    monkeypatch.setattr(CohortController,'admit_membership_only',admit)
    def finish(j,r,result):
        assert events[-1]=='restore'
        events.append('complete')
        j.advance(r['operation_id'],'completed',result=result)
        return result
    monkeypatch.setattr(module,'finish_membership_only',finish)
    assert coordinator.advance_membership_only('one')=={'signed':'retained'}
    assert events==['pause','check','native-writer-closed','restore','complete']
    monkeypatch.setattr(coordinator,'_owners',lambda a:pytest.fail('completed retry acquired owners'))
    monkeypatch.setattr(module,'finish_membership_only',lambda j,r,result:result)
    assert coordinator.advance_membership_only('one')=={'signed':'retained'}
    assert events[-1]=='complete'


@pytest.mark.parametrize('changed', [False, True])
def test_guest_base_observation_does_not_read_group_and_rechecks_current_public_identity(tmp_path, monkeypatch, changed):
    from clusterctl import being_seed, onboarding_receiving_update, owner_process
    from clusterctl.onboarding_target import Target
    from clusterctl.onboarding import digest
    target=object.__new__(Target)
    target.root=tmp_path/'owner'
    target.root.mkdir(mode=0o700)
    target.package=tmp_path/'package'
    binding={'original':'plan'}
    being_seed._write(target.root/'plan.json',binding)
    monkeypatch.setattr(target,'_binding',lambda:binding)
    bundle={'local_origin':{'body':'own'}}
    monkeypatch.setattr(target,'document_bundle',lambda:bundle)
    class Owner:
        def __init__(self,root,socket,**kw):
            assert socket==target.package/'runtime/matrix.sock'
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def base_status(self):
            return dict(process={'pid':123},server={'body':'own'},
                runtime_status={'local_origin':{'body':'own'},'loaded_runtime':{
                    'runtime_bundle_sha256':digest(bundle),'process_id':123}})
    class Parent:
        def __init__(self,process): assert process=={'pid':123}
        def __enter__(self):
            if changed:
                being_seed._write(target.root/'plan.json',{'foreign':'plan'})
            self.process={'pid':122}
            return self
        def verify(self): pass
        def __exit__(self,*args): pass
    monkeypatch.setattr(onboarding_receiving_update,'OwnerGroupClient',Owner)
    monkeypatch.setattr(owner_process,'ParentProcessPresence',Parent)
    if changed:
        with pytest.raises(OnboardingError,match='process_changed'):
            target.base_running(deadline_ns=time.monotonic_ns()+1_000_000_000)
    else:
        assert target.base_running(deadline_ns=time.monotonic_ns()+1_000_000_000)['admission_parent']=={'pid':122}


def test_receive_phase_retains_distinct_original_claim_and_recovers_without_membership_reuse(setup, monkeypatch):
    journal, row, owners, selected, events, failures = setup
    endpoint = scope.Endpoint
    parents = []
    def tracked(*args, **kwargs):
        parents.append((kwargs['parent'], kwargs['binding']))
        return endpoint(*args, **kwargs)
    monkeypatch.setattr(scope, 'Endpoint', tracked)
    with run(setup):
        pass
    membership = journal.get(row['operation_id'])['runtime_observation']['membership_maintenance']
    original_parents = set(parents)
    parents.clear()
    # Restored membership cannot be misreported as receive-phase recovery.
    with pytest.raises(OnboardingError, match='original_required'):
        with run(setup, phase='receive', restore_only=True):
            pytest.fail('missing receive claim recovered')
    assert not parents
    with run(setup, phase='receive'):
        pass
    observed = journal.get(row['operation_id'])['runtime_observation']
    assert observed['membership_maintenance'] == membership
    assert observed['receive_maintenance']['binding'] != membership['binding']
    assert set(parents).isdisjoint(original_parents)
    receive_parents = set(parents)
    assert {parent for parent, _ in parents} == {observed['receive_maintenance']['operation_id']}
    pauses = sum(step == 'pause' for step, _ in events)
    parents.clear()
    with run(setup, phase='receive', restore_only=True):
        pass
    assert set(parents) == receive_parents
    assert sum(step == 'pause' for step, _ in events) == pauses
    assert journal.get(row['operation_id'])['runtime_observation'] == observed


@pytest.mark.parametrize('phase', ['', 'outbound', 'receive-other', None, [], {}])
def test_unselected_maintenance_phase_cannot_prepare_or_pause(setup, phase):
    *_, events, _failures = setup
    with pytest.raises(OnboardingError, match='phase_required'):
        with run(setup, phase=phase):
            pytest.fail('unsupported phase admitted')
    assert not events
