"""Ordinary reader completion preserves native CAS and exact lost-ACK commands."""
import copy
import time
from types import SimpleNamespace

import pytest

from clusterctl import onboarding_receiving_update as receiving
from clusterctl.onboarding import OnboardingError


def cohort(tmp_path, monkeypatch):
    owners = {name: SimpleNamespace(root=tmp_path/name, deadline_ns=None,
        gate=dict(phase='unselected', readers=[], head='a'*64, process_instance_id=name))
        for name in ('first', 'second')}
    calls, retained = [], {}
    fail = []
    selections = {name: dict(visibility_installation_sha256='b'*64) for name in owners}
    vector = dict(membership_basis_sha256='c'*64,
        readers=[dict(being_ref=name, embodiment_id=name) for name in owners],
        local_roster_sha256={name:'d'*64 for name in owners})

    def observe(owner, **options):
        assert options['expected_selection'] in selections.values()
        return dict(reader=copy.deepcopy(next(row for row in vector['readers']
            if row['being_ref']==owner.root.name)), gate=copy.deepcopy(owner.gate),
            identity_expires_at_ms=options['expires_at_ms'])
    monkeypatch.setattr(receiving, 'observe_current_reader', observe)
    monkeypatch.setattr(receiving, 'conversation_cohort', lambda _:copy.deepcopy(vector))
    for name, owner in owners.items():
        def apply(command, path, *, name=name, owner=owner):
            assert path.parent == owner.root/'receiving-control'
            assert path.name.startswith(command['operation_id']+'-'+command['phase'])
            prior = retained.setdefault((name,path.name), copy.deepcopy(command))
            assert command == prior  # retries cannot invent a new head/deadline
            calls.append((name,command['phase']))
            if owner.gate.get('operation_id') == command['operation_id'] and owner.gate['phase'] == command['phase']:
                return dict(gate=copy.deepcopy(owner.gate))
            assert command['expected_head'] == owner.gate['head']
            if owner.gate['phase']=='revoke':
                assert command['operation_id']==owner.gate['operation_id'], 'native reservation must stay owned'
            if command['phase']=='select':
                assert owner.gate['phase']=='revoke'
            owner.gate.update(phase=command['phase'], readers=command['readers'],
                operation_id=command['operation_id'], release_digest=command['release_digest'],
                head=('e' if command['phase']=='revoke' else 'f')*64)
            if fail and fail[0] == (name,command['phase']):
                fail.pop()
                raise OnboardingError('receiving_control_completion_uncertain')
            return dict(gate=copy.deepcopy(owner.gate))
        owner.prepare_apply_control=apply
    options = dict(selections=selections, operation_id='28d3530a-1391-4578-a153-a1335097e89d',
        release_digest='9'*64, deadline_ns=time.monotonic_ns()+60_000_000_000,
        checkpoint=tmp_path/'progress.json')
    return owners, options, calls, fail, vector


def test_ordinary_completion_and_repeat_are_no_lifecycle_and_read_only(tmp_path, monkeypatch):
    owners, options, calls, _, vector = cohort(tmp_path, monkeypatch)
    result = receiving.refresh_current_readers(owners, **options)
    assert result['receiving_readiness'] == 'qualified-local-projection'
    assert result['communication_acceptance'] == 'unobserved'
    assert calls == [('first','revoke'),('second','revoke'),('first','select'),('second','select')]
    assert all(owner.gate['readers'] == vector['readers'] and owner.deadline_ns is None for owner in owners.values())
    calls.clear()
    receiving.preflight_reader_checkpoint(options['checkpoint'], 'next-operation')
    receiving.refresh_current_readers(owners, **options)
    assert calls == []


@pytest.mark.parametrize('phase', ['revoke','select'])
def test_lost_accepted_ack_resumes_same_operation_without_repeating_effect(tmp_path, monkeypatch, phase):
    owners, options, calls, fail, _ = cohort(tmp_path, monkeypatch)
    fail.append(('first', phase))
    with pytest.raises(OnboardingError, match='completion_uncertain'):
        receiving.refresh_current_readers(owners, **options)
    assert all(owner.deadline_ns is None for owner in owners.values())
    result = receiving.refresh_current_readers(owners, **options)
    assert result['receiving_readiness'] == 'qualified-local-projection'
    assert calls.count(('first',phase)) == 1


def test_cohort_change_refuses_before_control(tmp_path, monkeypatch):
    owners, options, calls, fail, vector = cohort(tmp_path, monkeypatch)
    fail.append(('first','revoke'))
    with pytest.raises(OnboardingError):
        receiving.refresh_current_readers(owners, **options)
    vector['membership_basis_sha256']='8'*64
    calls.clear()
    with pytest.raises(OnboardingError, match='binding_conflict'):
        receiving.refresh_current_readers(owners, **options)
    assert calls == []


def test_prepared_unsubmitted_select_reuses_original_deadline_and_command(tmp_path, monkeypatch):
    owners, options, calls, _, _ = cohort(tmp_path, monkeypatch)
    original = owners['first'].prepare_apply_control
    pending = []
    def disconnect_before_submit(command, path):
        if command['phase'] == 'select' and not pending:
            pending.append(copy.deepcopy(command))
            raise OnboardingError('receiving_control_completion_uncertain')
        if command['phase'] == 'select':
            assert command == pending[0]
        return original(command, path)
    owners['first'].prepare_apply_control = disconnect_before_submit
    with pytest.raises(OnboardingError, match='completion_uncertain'):
        receiving.refresh_current_readers(owners, **options)
    # Fresh proof horizon will differ; retained command expiry must not.
    time.sleep(.002)
    receiving.refresh_current_readers(owners, **options)
    assert calls.count(('first','select')) == 1


def test_subsequent_releases_rotate_only_completed_current_and_previous(tmp_path, monkeypatch):
    from clusterctl import being_seed
    owners, options, calls, _, _ = cohort(tmp_path, monkeypatch)
    receiving.refresh_current_readers(owners, **options)
    first=being_seed._read(options['checkpoint'])
    assert first['completed']['receiving_readiness']=='qualified-local-projection'
    calls.clear()
    for operation in ('0535495b-7592-4aa7-ae87-0a1db05cc464','f86fd054-d0aa-468e-b275-06db1a6b992d'):
        options['operation_id']=operation
        receiving.refresh_current_readers(owners, **options)
    assert calls==[]  # healthy native vectors remain untouched
    current=being_seed._read(options['checkpoint'])
    previous=being_seed._read(tmp_path/'progress.previous.json')
    assert current['binding']['operation_id']=='f86fd054-d0aa-468e-b275-06db1a6b992d'
    assert previous['binding']['operation_id']=='0535495b-7592-4aa7-ae87-0a1db05cc464'
    assert len(list(tmp_path.glob('*.json')))==2


def test_new_operation_cannot_rotate_an_unfinished_predecessor(tmp_path, monkeypatch):
    from clusterctl import being_seed
    owners, options, calls, fail, _ = cohort(tmp_path, monkeypatch)
    fail.append(('first','revoke'))
    with pytest.raises(OnboardingError):
        receiving.refresh_current_readers(owners, **options)
    prior=being_seed._read(options['checkpoint'])
    options['operation_id']='0535495b-7592-4aa7-ae87-0a1db05cc464'
    calls.clear()
    with pytest.raises(OnboardingError,match='binding_conflict'):
        receiving.refresh_current_readers(owners, **options)
    assert calls==[] and being_seed._read(options['checkpoint'])==prior
    assert not (tmp_path/'progress.previous.json').exists()


def test_completion_write_failure_reconciles_native_success_without_repeating_it(tmp_path, monkeypatch):
    from clusterctl import being_seed
    owners, options, calls, _, _ = cohort(tmp_path, monkeypatch)
    write=being_seed._write
    fail=[True]
    def retain(path,value,**kwargs):
        if path==options['checkpoint'] and 'completed' in value and fail:
            fail.pop()
            raise OSError('test-owned completion write failure')
        return write(path,value,**kwargs)
    monkeypatch.setattr(being_seed,'_write',retain)
    with pytest.raises(OSError):
        receiving.refresh_current_readers(owners, **options)
    calls.clear()
    receiving.refresh_current_readers(owners, **options)
    assert calls==[]
    assert being_seed._read(options['checkpoint'])['completed']['receiving_readiness']=='qualified-local-projection'


def test_unfinished_previous_record_is_never_overwritten(tmp_path, monkeypatch):
    from clusterctl import being_seed
    owners, options, calls, _, _ = cohort(tmp_path, monkeypatch)
    receiving.refresh_current_readers(owners, **options)
    previous=tmp_path/'progress.previous.json'
    unknown=dict(schema='foreign-pending',original='preserve')
    being_seed._write(previous,unknown)
    current=being_seed._read(options['checkpoint'])
    options['operation_id']='0535495b-7592-4aa7-ae87-0a1db05cc464'
    calls.clear()
    with pytest.raises(OnboardingError,match='binding_conflict'):
        receiving.refresh_current_readers(owners, **options)
    assert calls==[] and being_seed._read(previous)==unknown
    assert being_seed._read(options['checkpoint'])==current


def test_independent_observations_overlap_before_any_control(tmp_path, monkeypatch):
    import threading
    owners, options, calls, _, _ = cohort(tmp_path, monkeypatch)
    original = receiving.observe_current_reader
    barrier = threading.Barrier(len(owners), timeout=2)
    def observe(owner, **kwargs):
        barrier.wait()  # A serial observation loop cannot make progress.
        return original(owner, **kwargs)
    monkeypatch.setattr(receiving,'observe_current_reader',observe)
    assert receiving.refresh_current_readers(owners,**options)['receiving_readiness']=='qualified-local-projection'
    assert calls==[('first','revoke'),('second','revoke'),('first','select'),('second','select')]


def test_aliasing_one_owner_cannot_race_its_observation_context(tmp_path, monkeypatch):
    owners, options, calls, _, _ = cohort(tmp_path, monkeypatch)
    owners['second']=owners['first']
    with pytest.raises(OnboardingError,match='current_reader_binding_required'):
        receiving.refresh_current_readers(owners,**options)
    assert calls==[]


@pytest.mark.parametrize('phase',['revoke','select'])
def test_process_replacement_keeps_old_command_and_binds_new_control(tmp_path, monkeypatch, phase):
    import json
    owners, options, calls, _, _ = cohort(tmp_path, monkeypatch)
    owner=owners['second']
    original=owner.prepare_apply_control
    replaced=[]
    def restart_before_ack(command,path):
        if command['phase']==phase and not replaced:
            replaced.append(copy.deepcopy(command))
            owner.gate.update(phase='unselected',readers=[],head='7'*64,process_instance_id='replacement')
            raise OnboardingError('receiving_control_completion_uncertain')
        return original(command,path)
    owner.prepare_apply_control=restart_before_ack
    with pytest.raises(OnboardingError,match='completion_uncertain'):
        receiving.refresh_current_readers(owners,**options)
    assert receiving.refresh_current_readers(owners,**options)['receiving_readiness']=='qualified-local-projection'
    saved=json.loads(options['checkpoint'].read_bytes())
    assert saved['superseded_generations'][0]['commands']['second:'+phase]==replaced[0]
    revoke=saved['commands']['second:revoke']
    select=saved['commands']['second:select']
    assert revoke['operation_id']==select['operation_id']==options['operation_id']
    assert len(saved['control_slot'])==64
    assert revoke['process_instance_id']==select['process_instance_id']=='replacement'
    assert calls.count(('second',phase))==1
    calls.clear()
    receiving.refresh_current_readers(owners,**options)
    assert calls==[]


@pytest.mark.parametrize('authority_change',[False,True])
def test_restart_rebinds_only_loaded_view_and_preserves_old_generation(tmp_path, monkeypatch, authority_change):
    import json
    owners, options, calls, _, vector = cohort(tmp_path, monkeypatch)
    def current_vector(_):
        return {**vector,'readers':[dict(being_ref=name,embodiment_id=name,
            loaded_view_sha256=receiving.digest(owner.gate['process_instance_id']),
            credential_id=('changed' if authority_change and name=='second'
                and owner.gate['process_instance_id']=='replacement' else name))
            for name,owner in owners.items()]}
    monkeypatch.setattr(receiving,'conversation_cohort',current_vector)
    original_observe=receiving.observe_current_reader
    def observe(owner,**kwargs):
        result=original_observe(owner,**kwargs)
        result['reader']=next(row for row in current_vector(None)['readers']
            if row['being_ref']==owner.root.name)
        return result
    monkeypatch.setattr(receiving,'observe_current_reader',observe)
    owner=owners['second']
    original=owner.prepare_apply_control
    pending=[]
    def restart(command,path):
        if command['phase']=='revoke' and not pending:
            pending.append(copy.deepcopy(command))
            owner.gate.update(phase='unselected',readers=[],head='7'*64,process_instance_id='replacement')
            raise OnboardingError('receiving_control_completion_uncertain')
        return original(command,path)
    owner.prepare_apply_control=restart
    with pytest.raises(OnboardingError,match='completion_uncertain'):
        receiving.refresh_current_readers(owners,**options)
    if authority_change:
        calls.clear()
        with pytest.raises(OnboardingError,match='control_binding_conflict'):
            receiving.refresh_current_readers(owners,**options)
        assert calls==[]
    else:
        assert receiving.refresh_current_readers(owners,**options)['receiving_readiness']=='qualified-local-projection'
        saved=json.loads(options['checkpoint'].read_bytes())
        assert saved['binding']['operation_id']==options['operation_id']
        assert saved['superseded_generations'][0]['commands']['second:revoke']==pending[0]
        assert saved['commands']['second:select']['operation_id']==options['operation_id']
        assert len(saved['control_slot'])==64
