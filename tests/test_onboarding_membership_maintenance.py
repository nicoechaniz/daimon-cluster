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
        KillMode='control-group', TimeoutStopUSec='30s', KillSignal='15', ControlGroup='/system.slice/' + manager.unit_name)
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


def test_scope_close_observes_restore_after_execution_deadline_without_more_calls(tmp_path):
    import json
    import sys
    import time
    from clusterctl.onboarding_group_session import OwnerConversation
    deadline = time.monotonic_ns() + 1_000_000_000
    argv = [sys.executable, '-B', '-m', 'tests.membership_guard_fixture', str(tmp_path), str(deadline), '0.25']
    with OwnerConversation(argv, {'observation': {'process': {'fixture': True}}}, deadline_ns=deadline,
                           cleanup_seconds=3) as session:
        assert session.call({'check': True}) == {'paused': True}
        # Simulate caller work using the last of its admission horizon.
        time.sleep(max(0, (deadline - time.monotonic_ns()) / 1e9) + .05)
        with pytest.raises(OnboardingError, match='deadline_expired'):
            session.call({'check': True})
        process = session.process
    assert process.returncode == 0 and session.deadline_ns == deadline
    with pytest.raises(OnboardingError, match='session_closed'):
        session.call({'check': True})
    value = json.loads((tmp_path / 'manager.json').read_text())
    assert value['state']['state'] == 'active' and value['stops'] == value['starts'] == 1


def test_killed_controller_closes_pipe_and_guard_restores_same_owned_stop(tmp_path):
    import json
    import os
    import select
    import signal
    import subprocess
    import sys
    controller = '''
import json,subprocess,sys,time
from clusterctl.onboarding_group_session import OwnerConversation
argv=[sys.executable,'-B','-m','tests.membership_guard_fixture',sys.argv[1],str(time.monotonic_ns()+1_500_000_000),'0']
with OwnerConversation(argv,{'observation':{'process':{'fixture':True}}},deadline_ns=time.monotonic_ns()+1_500_000_000,cleanup_seconds=3) as session:
 print(json.dumps({'guard_pid':session.process.pid}),flush=True)
 time.sleep(30)
'''
    parent = subprocess.Popen([sys.executable, '-B', '-c', controller, str(tmp_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    guard_fd = None
    try:
        assert select.select([parent.stdout], [], [], 5)[0]
        guard_pid = json.loads(parent.stdout.readline())['guard_pid']
        guard_fd = os.pidfd_open(guard_pid)
        assert json.loads((tmp_path / 'manager.json').read_text())['state']['state'] == 'inactive'
        parent.kill()  # No interpreting-turn finally or explicit release runs.
        assert parent.wait(timeout=5) == -signal.SIGKILL
        # Separate native owner sessions may retain writers to the original
        # horizon. Controller death must not restart into that bounded window.
        assert not select.select([guard_fd], [], [], .15)[0]
        assert json.loads((tmp_path / 'manager.json').read_text())['state']['state'] == 'inactive'
        assert select.select([guard_fd], [], [], 5)[0]
        value = json.loads((tmp_path / 'manager.json').read_text())
        assert value['state']['state'] == 'active' and value['stops'] == value['starts'] == 1
        journal = OperationJournal.existing(tmp_path / 'journal')
        pause = maintenance.MembershipPause(journal, 'original', 'b' * 64, MatrixFixture(tmp_path))
        restored = pause.journal.get(pause._claim()['runtime_observation']['cycle_id'])
        assert restored['runtime_observation']['guard_exit'] == {
            'reason': 'receiving_owner_session_closed', 'restoration': 'observed'}
    finally:
        if parent.poll() is None:
            parent.kill()
        parent.wait(timeout=5)
        parent.stdout.close()
        parent.stderr.close()
        if guard_fd is not None:
            os.close(guard_fd)


def test_manager_calls_share_original_deadline_and_do_not_dispatch_after_expiry(monkeypatch):
    import time
    monkeypatch.setattr(receiving_worker.os, 'geteuid', lambda: 0)
    manager = maintenance.MembershipManager(source=True)
    calls = []
    def run(argv, **kwargs):
        calls.append(kwargs['timeout'])
        return SimpleNamespace(returncode=0, stdout='observed')
    monkeypatch.setattr(receiving_worker.subprocess, 'run', run)
    manager.deadline_ns = time.monotonic_ns() - 1
    with pytest.raises(OnboardingError, match='deadline_expired'):
        manager.start()
    assert not calls
    manager.deadline_ns = time.monotonic_ns() + 100_000_000
    manager.start()
    assert len(calls) == 1 and 0 < calls[0] <= .1


def test_operator_recovers_original_before_expired_deadline_and_does_not_start_new_pause(tmp_path, monkeypatch, capsys):
    import time
    import uuid
    operation = str(uuid.uuid4())
    manager = MatrixFixture(tmp_path)
    journal = OperationJournal(tmp_path / 'journal')
    pause = maintenance.MembershipPause(journal, operation, 'b' * 64, manager)
    pause.pause()
    args = ['--journal', str(tmp_path / 'journal'), '--operation-id', operation,
        '--binding-sha256', 'b' * 64, '--observation-deadline-ns', str(time.monotonic_ns() - 1)]
    assert maintenance.main(args, manager_factory=lambda **kw: manager) == 2
    assert manager.state['state'] == 'active' and manager.stops == manager.starts == 1
    assert 'membership_maintenance_unavailable' in capsys.readouterr().err
    assert maintenance.main([*args, '--recover-only'], manager_factory=lambda **kw: manager) == 0
    assert manager.stops == manager.starts == 1
    assert '"recovered": false' in capsys.readouterr().out


def test_operator_capacity_refuses_new_stop_without_pruning_original_state(tmp_path, monkeypatch, capsys):
    import time
    import uuid
    manager = MatrixFixture(tmp_path)
    root = tmp_path / 'journal'
    journal = OperationJournal(root)
    marker = root / 'protected-original'
    with marker.open('wb') as f:
        f.truncate(15 * 1024**2)
    assert maintenance.main(['--journal', str(root), '--operation-id', str(uuid.uuid4()),
        '--binding-sha256', 'b' * 64, '--observation-deadline-ns',
        str(time.monotonic_ns() + 10_000_000_000)], manager_factory=lambda **kw: manager) == 2
    assert manager.stops == manager.starts == 0
    assert marker.stat().st_size == 15 * 1024**2
    assert journal.list_all() == []


def test_scope_term_restores_before_process_exit(tmp_path):
    import json
    import signal
    import sys
    import time
    from clusterctl.onboarding_group_session import OwnerConversation
    deadline = time.monotonic_ns() + 1_000_000_000
    with OwnerConversation([sys.executable, '-B', '-m', 'tests.membership_guard_fixture',
            str(tmp_path), str(deadline), '0'], {'observation': {'process': {'fixture': True}}},
            deadline_ns=deadline, cleanup_seconds=3) as session:
        process = session.process
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=3) == 0
        value = json.loads((tmp_path / 'manager.json').read_text())
        assert value['state']['state'] == 'active' and value['starts'] == value['stops'] == 1


def test_native_maintenance_uses_existing_root_transport_and_rebased_admission_clock(tmp_path, monkeypatch):
    import hashlib
    import json
    import sys
    import time
    from pathlib import Path
    from clusterctl.native_body import NativeBody, REMOTE_LAUNCH
    body = object.__new__(NativeBody)
    object.__setattr__(body, 'value', dict(bootstrap_python=sys.executable, home=str(tmp_path),
        machine_id_sha256=hashlib.sha256(Path('/etc/machine-id').read_bytes().strip()).hexdigest()))
    seen = []
    def transport(self, command, **options):
        request = json.loads(command[-1])
        seen.append(request)
        assert request['owner_clock'] and request['uid'] == request['gid'] == 0
        # The captured production request selects the already supported root
        # route. This test deliberately keeps its ordinary unprivileged UID.
        fixture = REMOTE_LAUNCH.replace('os.setgroups([])', 'pass').replace(
            "os.setgid(request['gid']);os.setuid(request['uid'])", 'pass')
        return [sys.executable, '-B', '-c', fixture, command[-1]]
    monkeypatch.setattr(NativeBody, '_transport_command', transport)
    deadline = time.monotonic_ns() + 5_000_000_000
    program = ('import sys;sys.path.insert(0,' + repr(str(Path.cwd())) + ');'
        'from tests.membership_guard_fixture import main;'
        'deadline=sys.argv[sys.argv.index("--observation-deadline-ns")+1];'
        'sys.argv=[sys.argv[0],sys.argv[1],deadline,"0"];main()')
    argv = [sys.executable, '-B', '-c', program, str(tmp_path), '--observation-deadline-ns', '1']
    validations = []
    with body.membership_maintenance_conversation(argv, {'observation': {'process': {'fixture': True}}},
            deadline_ns=deadline, validate=lambda: validations.append(True)) as scope:
        assert scope.cleanup_seconds == 90 and scope.deadline_ns == deadline
        assert not scope.writer_held()  # A service pause is not a native writer.
        assert scope.call({'check': True}) == {'paused': True}
    value = json.loads((tmp_path / 'manager.json').read_text())
    assert value['state']['state'] == 'active' and value['starts'] == value['stops'] == 1
    assert len(seen) == 1 and len(validations) >= 3


@pytest.mark.parametrize('matrix', [False, True])
def test_normal_matrix_term_is_distinct_from_worker_exit_and_forced_kill(tmp_path, matrix):
    journal = OperationJournal(tmp_path / 'journal')
    manager = MatrixFixture(tmp_path) if matrix else Manager(tmp_path)
    original_stop = manager.stop
    def term_stop():
        original_stop()
        manager.state.update(exit_code='2', exit_status='15')
    manager.stop = term_stop
    pause = (maintenance.MembershipPause(journal, 'original', 'b' * 64, manager) if matrix
        else receiving_worker.WorkerPause(journal, 'original', 'b' * 64, manager))
    try:
        if matrix:
            pause.pause()
        else:
            with pytest.raises(OnboardingError, match='drain_uncertain'):
                pause.pause()
    finally:
        pause.restore()
    assert manager.starts == manager.stops == 1
    manager.stop = lambda: (original_stop(), manager.state.update(exit_code='2', exit_status='9'))
    try:
        with pytest.raises(OnboardingError, match='drain_uncertain'):
            pause.pause()
    finally:
        pause.restore()
    assert manager.starts == manager.stops == 2
