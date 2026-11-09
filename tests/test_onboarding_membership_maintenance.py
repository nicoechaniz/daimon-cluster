"""Membership-only fixed services retain physical bindings and owned recovery."""
import copy
from types import SimpleNamespace

import pytest

from clusterctl import onboarding_membership_maintenance as maintenance
from clusterctl import receiving_worker
from clusterctl.onboarding import OnboardingError
from clusterctl.operation_journal import OperationJournal
from tests.test_receiving_worker import Manager


class MatrixFixture(maintenance.MembershipManager, Manager):
    inspect = Manager.inspect
    stop = Manager.stop
    start = Manager.start
    wait = Manager.wait

    def __init__(self, root, *, source=False, active=True):
        Manager.__init__(self, root, active=active)
        self.unit_name = maintenance.SOURCE_UNIT if source else maintenance.UNIT
        self.unit = root / self.unit_name


@pytest.mark.parametrize('source', [False, True])
@pytest.mark.parametrize('active', [False, True])
@pytest.mark.parametrize('loss', [None, 'stop', 'start'])
def test_original_matrix_state_recovers_after_coordinator_loss_without_new_stop(tmp_path, source, active, loss):
    journal = OperationJournal(tmp_path / 'journal')
    manager = MatrixFixture(tmp_path, source=source, active=active)
    manager.lose_stop, manager.lose_start = loss == 'stop', loss == 'start'
    pause = maintenance.MembershipPause(journal, 'original-admission', 'b' * 64, manager)
    pause.pause()
    # No finally: a different process recovers the durable original claim.
    recovered = maintenance.MembershipPause(journal, 'original-admission', 'b' * 64, manager)
    recovered.recover()
    recovered.recover()
    assert manager.stops == manager.starts == int(active)
    assert (manager.state['state'] == 'active') == active
    assert pause.target != receiving_worker.WorkerPause(journal, 'original-admission', 'b' * 64, manager).target
    assert journal.get(pause.row['operation_id'])['runtime_observation']['restored']


def test_changed_binding_or_service_definition_preserves_pending_matrix_recovery(tmp_path):
    journal = OperationJournal(tmp_path / 'journal')
    manager = MatrixFixture(tmp_path)
    pause = maintenance.MembershipPause(journal, 'original', 'b' * 64, manager)
    pause.pause()
    with pytest.raises(OnboardingError, match='other_operation_pending'):
        maintenance.MembershipPause(journal, 'other', 'b' * 64, manager).recover()
    with pytest.raises(OnboardingError, match='other_operation_pending'):
        maintenance.MembershipPause(journal, 'original', 'c' * 64, manager).recover()
    manager.state['definition'] = 'c' * 64
    with pytest.raises(OnboardingError, match='configuration_changed'):
        maintenance.MembershipPause(journal, 'original', 'b' * 64, manager).recover()
    assert manager.starts == 0 and manager.state['state'] == 'inactive'


def test_matrix_refuses_worker_and_unrelated_unit_managers(tmp_path):
    journal = OperationJournal(tmp_path / 'journal')
    with pytest.raises(OnboardingError, match='service_scope_required'):
        maintenance.MembershipPause(journal, 'original', 'b' * 64, Manager(tmp_path))
    manager = MatrixFixture(tmp_path)
    manager.unit_name = 'telecodex.service'
    with pytest.raises(OnboardingError, match='service_scope_required'):
        maintenance.MembershipPause(journal, 'original', 'b' * 64, manager)


@pytest.mark.parametrize('source', [False, True])
def test_stop_requires_current_authenticated_physical_binding(tmp_path, monkeypatch, source):
    monkeypatch.setattr(receiving_worker.os, 'geteuid', lambda: 0)
    manager = maintenance.MembershipManager(source=source)
    calls = []
    monkeypatch.setattr(manager, '_run', lambda *args, **kwargs: calls.append(args) or '')
    current = dict(state='active', pid='123', invocation='current', control_group='/matrix')
    monkeypatch.setattr(manager, 'inspect', lambda: copy.deepcopy(current))
    monkeypatch.setattr(maintenance.pwd, 'getpwnam', lambda _: SimpleNamespace(pw_uid=1000))
    bindings = []
    def bind(observed, inspected, **kwargs):
        bindings.append((copy.deepcopy(observed), inspected))
        return {'physical_binding': True, 'admission_parent': {'uid': 1000}}
    monkeypatch.setattr(maintenance, 'bind_admitted_service_process', bind)
    with pytest.raises(OnboardingError, match='current_process_binding_required'):
        manager.stop()
    assert not calls and not bindings
    observed = dict(process={'uid': 1000}, admission_parent={'uid': 1000})
    assert manager.bind(observed)['physical_binding'] is True
    manager.stop()
    assert calls == [('--no-block', 'stop', manager.unit_name)]
    assert len(bindings) == 2
    for key, replacement in [('pid', '999'), ('invocation', 'replacement')]:
        original = current[key]
        current[key] = replacement
        with pytest.raises(OnboardingError, match='current_process_binding_required'):
            manager.stop()
        current[key] = original
    wrong = copy.deepcopy(observed)
    wrong['process']['uid'] = 0
    with pytest.raises(OnboardingError, match='process_scope_required'):
        manager.bind(wrong)
    assert len(calls) == 1


def test_source_manager_keeps_fixed_unit_execution_and_typed_bus_path(tmp_path, monkeypatch):
    import json
    monkeypatch.setattr(receiving_worker.os, 'geteuid', lambda: 0)
    manager = maintenance.MembershipManager(source=True)
    manager.unit = tmp_path / maintenance.SOURCE_UNIT
    manager.unit.write_text('[Service]\nUser=debian\nGroup=debian\n')
    monkeypatch.setattr(receiving_worker.onboarding_release, 'regular', lambda p, **kw: p.read_bytes())
    values = dict(Id=manager.unit_name, LoadState='loaded', ActiveState='active', SubState='running',
        MainPID='123', InvocationID='one', Job='0', Result='success', ExecMainCode='0', ExecMainStatus='0',
        FragmentPath=str(manager.unit), DropInPaths='', User='debian', Group='debian',
        KillMode='control-group', TimeoutStopUSec='30s', ControlGroup='/system.slice/' + manager.unit_name)
    bus_paths = []
    def run(*args, bus=False):
        if not bus:
            assert args[1] == manager.unit_name
            return '\n'.join(key + '=' + value for key, value in values.items())
        bus_paths.append(args[-3])
        if args[-1] == 'EnvironmentFiles':
            return json.dumps({'type': 'a(sb)', 'data': []})
        return json.dumps({'type': 'a(sasbttttuii)', 'data': [
            ['/own-loader', ['/own-loader'], False, 0, 0, 0, 0, 0, 0, 0]]})
    monkeypatch.setattr(manager, '_run', run)
    before = manager.inspect()
    assert before['control_group'] == values['ControlGroup']
    assert set(bus_paths) == {'/org/freedesktop/systemd1/unit/compaii_2dmatrix_2ditaca_2eservice'}
    values['User'] = 'root'
    with pytest.raises(OnboardingError, match='binding_required'):
        manager.inspect()


def test_existing_worker_claim_identity_and_profile_are_unchanged(tmp_path):
    from clusterctl.onboarding import digest
    journal = OperationJournal(tmp_path / 'journal')
    manager = Manager(tmp_path)
    pause = receiving_worker.WorkerPause(journal, 'original-worker', 'b' * 64, manager)
    assert pause.target == 'receiving-worker:daimon-onboarding-worker.service'
    assert pause.claim_digest == digest(dict(unit='daimon-onboarding-worker.service',
        profile='scoped-worker-preservation/v1'))
    try:
        pause.pause()
        claim = pause._claim()
        assert claim['expected_precondition'] == {'unit': receiving_worker.UNIT}
        assert claim['intended_transition'] == {'profile': 'scoped-worker-preservation/v1'}
    finally:
        pause.restore()
