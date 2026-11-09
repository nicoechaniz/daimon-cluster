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
        return dict(reader={}, gate=copy.deepcopy(owner.gate),
            identity_expires_at_ms=options['expires_at_ms'])
    monkeypatch.setattr(receiving, 'observe_current_reader', observe)
    monkeypatch.setattr(receiving, 'conversation_cohort', lambda _:copy.deepcopy(vector))
    for name, owner in owners.items():
        def apply(command, path, *, name=name, owner=owner):
            assert path == owner.root/'receiving-control'/(command['operation_id']+'-'+command['phase']+'.json')
            prior = retained.setdefault((name,command['phase']), copy.deepcopy(command))
            assert command == prior  # retries cannot invent a new head/deadline
            calls.append((name,command['phase']))
            if owner.gate.get('operation_id') == command['operation_id'] and owner.gate['phase'] == command['phase']:
                return dict(gate=copy.deepcopy(owner.gate))
            assert command['expected_head'] == owner.gate['head']
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
