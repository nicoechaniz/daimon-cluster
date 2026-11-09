"""Local Matrix-only preservation for the existing membership admission caller.

The finite root CLI holds the fixed unit's existing selection lock and the
original admission operation. It installs no service and performs no membership
dispatch. Recovery uses the same durable journal before deadline/candidate
preflight; it never dispatches a native membership request.
"""
from __future__ import annotations

import copy
import pwd
import signal
import time

from .onboarding import OnboardingError
from .onboarding_service import UNIT, bind_admitted_service_process, bind_service_parent_process, selection_lock
from .operation_journal import JournalError, OperationJournal
from .receiving_worker import WorkerManager, _OwnedServicePause

SOURCE_UNIT = 'compaii-matrix-itaca.service'


class MembershipManager(WorkerManager):
    """Only the installed Source or receiving guest Matrix system service.

    An authenticated base-runtime observation must be physically bound before
    any stop. A restarted/replaced process must be freshly observed, never
    stopped under the old observation. Restoration requires no new native read.
    """
    execution_identity: dict[str, str]
    extra_fields = frozenset({'ControlGroup', 'KillSignal'})
    accepted_stop_exits = frozenset({('1', '0'), ('2', '15')})
    bind_process = staticmethod(bind_service_parent_process)

    def __init__(self, *, source: bool = False):
        if type(source) is not bool:
            raise OnboardingError('membership_service_scope_required')
        self.unit_name = SOURCE_UNIT if source else UNIT
        user = 'debian' if source else 'agent'
        self.execution_identity = {'User': user, 'Group': user, 'KillSignal': '15'}
        self._observed: dict | None = None
        self._bound: dict | None = None
        super().__init__()

    def bind(self, observed: dict) -> dict:
        """Caller supplies genuine own base-status, not group-readiness proof."""
        try:
            expected_uid = pwd.getpwnam(self.execution_identity['User']).pw_uid
            if (observed['process']['uid'] != expected_uid
                    or 'admission_parent' in observed and observed['admission_parent']['uid'] != expected_uid):
                raise OnboardingError('receiving_matrix_process_scope_required')
            before = self.inspect()
            manager = dict(ActiveState=before['state'], MainPID=before['pid'],
                ControlGroup=before['control_group'], InvocationID=before['invocation'])
            binding = bind_admitted_service_process(observed, {'manager': manager},
                bind_process=self.bind_process, derive_parent=True)
            if binding['admission_parent']['uid'] != expected_uid:
                raise OnboardingError('receiving_matrix_process_scope_required')
            if self.inspect() != before:
                raise OnboardingError('receiving_matrix_process_scope_required')
        except (KeyError, TypeError, OSError):
            raise OnboardingError('receiving_matrix_process_scope_required') from None
        self._observed, self._bound = copy.deepcopy(observed), before
        return binding

    def stop(self) -> None:
        if self._observed is None or self._bound is None or self.inspect() != self._bound:
            raise OnboardingError('membership_current_process_binding_required')
        self.bind(self._observed)
        super().stop()


class MembershipPause(_OwnedServicePause):
    """Separate claim namespace; old worker pauses cannot acquire Matrix effects.

    Use only within the original admission operation and fixed-unit selection
    lock. A live coordinator must restore in finally; supervised callers must
    use the finite root guard to survive coordinator loss. The original
    coordinator selects that guard explicitly; this class alone is not a
    crash-safe command supervisor.
    """
    def __init__(self, journal: OperationJournal, parent: str, binding: str,
                 manager: MembershipManager):
        if not isinstance(manager, MembershipManager) or manager.unit_name not in {SOURCE_UNIT, UNIT}:
            raise OnboardingError('membership_service_scope_required')
        super().__init__(journal, parent, binding, manager, unit_name=manager.unit_name,
            prefix='membership-matrix', profile='scoped-membership-preservation/v1',
            actor='onboarding-membership-maintenance')


def _serve_scope(pause: MembershipPause, reader: int, writer: int, *, deadline_ns: int,
                cleanup_seconds: float = 90) -> None:
    """Finite root-side hold over the existing owner-frame transport.

    Start in the transport's independent session. EOF, TERM/HUP and the original
    execution deadline all restore the exact owned stop. The coordinator's exit
    does not kill this helper's restoration. Killing this helper itself or losing
    the host leaves the durable claim for the same operation's next recovery.
    No membership call, scheduler or service installation is performed here.
    """
    from .onboarding_group_session import Frames
    if (type(cleanup_seconds) not in {int, float} or not 0 < cleanup_seconds <= 90
            or type(deadline_ns) is not int):
        raise OnboardingError('membership_cleanup_bound_required')
    manager = pause.manager
    previous_handlers = {}
    reason = 'scope-error'
    acknowledged = False
    held = False
    frames = None

    def interrupted(_signal, _frame):
        raise OnboardingError('membership_scope_interrupted')

    try:
        for number in (signal.SIGTERM, signal.SIGHUP):
            previous_handlers[number] = signal.signal(number, interrupted)
        # Recover a prior owned pause even when this invocation's candidate or
        # execution deadline is no longer usable. Never start a fresh pause here.
        manager.deadline_ns = time.monotonic_ns() + int(cleanup_seconds * 1_000_000_000)
        pause.recover()
        manager.deadline_ns = deadline_ns
        frames = Frames(reader, writer, deadline_ns)
        initial = frames.read()
        if (set(initial) != {'observation'} or not isinstance(initial['observation'], dict)
                or set(initial['observation']) not in ({'process'}, {'process', 'admission_parent'})):
            raise OnboardingError('membership_scope_observation_required')
        manager.bind(initial['observation'])
        pause.pause()
        frames.write({'ready': True})
        held = True
        while True:
            request = frames.read()
            if request == {'close': True}:
                reason, acknowledged = 'closed', True
                break
            if (set(request) != {'sequence', 'packet'} or type(request['sequence']) is not int
                    or request['sequence'] <= 0 or request['packet'] != {'check': True}):
                raise OnboardingError('membership_scope_request_required')
            current = manager.inspect()
            if pause.row is None:
                raise OnboardingError('membership_scope_quiescence_lost')
            before = pause.row['expected_precondition']['baseline']
            if (current['definition'] != before['definition'] or current['state'] != 'inactive'
                    or current['pid'] != '0' or current['job'] != '0'):
                raise OnboardingError('membership_scope_quiescence_lost')
            frames.write({'sequence': request['sequence'], 'result': {'paused': True}})
    except OnboardingError as error:
        reason = str(error)
        if reason not in {'receiving_owner_session_closed', 'receiving_owner_deadline_expired',
                          'membership_scope_interrupted'}:
            raise
    finally:
        # Stop dispatches have their own finite admission horizon. Restoration
        # has a separate bounded reserve and does not re-author any membership.
        for number in previous_handlers:
            signal.signal(number, signal.SIG_IGN)
        # A lost controller can leave separate native owner CLI processes
        # holding writers until their original receiving deadlines. Explicit
        # close follows their observed exit; EOF/TERM must first let that fixed
        # horizon elapse. Never restart the daemon into a still-owned writer.
        if held and not acknowledged:
            while time.monotonic_ns() < deadline_ns:
                time.sleep(min(.1, (deadline_ns - time.monotonic_ns()) / 1_000_000_000))
        manager.deadline_ns = time.monotonic_ns() + int(cleanup_seconds * 1_000_000_000)
        try:
            pause.restore()
            if pause.row is not None and 'guard_exit' not in (pause.row['runtime_observation'] or {}):
                pause._record('guard_exit', {'reason': reason, 'restoration': 'observed'})
            if held and frames is not None:
                frames.deadline_ns = manager.deadline_ns
                try:
                    frames.write({'closed': True})
                except (OSError, OnboardingError):
                    if acknowledged:
                        raise
        finally:
            for number, previous in previous_handlers.items():
                signal.signal(number, previous)


def serve_scope(pause: MembershipPause, reader: int, writer: int, *, deadline_ns: int,
                cleanup_seconds: float = 90) -> None:
    """Own the existing unit selection lock through pause and restoration."""
    with selection_lock(pause.manager.unit):
        _serve_scope(pause, reader, writer, deadline_ns=deadline_ns,
            cleanup_seconds=cleanup_seconds)


def main(argv=None, *, manager_factory=MembershipManager) -> int:
    """Root operator invoked by an already qualified original-job transport."""
    import argparse
    import json
    from pathlib import Path
    import re
    import sys
    import uuid
    from .onboarding import private_directory
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--journal', type=Path, required=True)
    parser.add_argument('--operation-id', required=True)
    parser.add_argument('--binding-sha256', required=True)
    parser.add_argument('--source', action='store_true')
    parser.add_argument('--recover-only', action='store_true')
    parser.add_argument('--observation-deadline-ns', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if (str(uuid.UUID(args.operation_id)) != args.operation_id
                or re.fullmatch('[0-9a-f]{64}', args.binding_sha256) is None
                or not args.journal.is_absolute() or '..' in args.journal.parts):
            raise OnboardingError('membership_scope_binding_required')
        manager = manager_factory(source=args.source)
        # This fixed-unit lock is also held by bootstrap/selection. Recover the
        # same pending operation before execution deadline or capacity preflight.
        with selection_lock(manager.unit):
            root = private_directory(args.journal, create=True)
            journal = OperationJournal(root)
            pause = MembershipPause(journal, args.operation_id, args.binding_sha256, manager)
            manager.deadline_ns = time.monotonic_ns() + 90_000_000_000
            pending = pause._latest_open() is not None
            previous_handlers = {number: signal.signal(number, signal.SIG_IGN)
                for number in (signal.SIGTERM, signal.SIGHUP)}
            try:
                pause.recover()
            finally:
                for number, previous in previous_handlers.items():
                    signal.signal(number, previous)
            if args.recover_only:
                print(json.dumps(dict(schema='cluster-membership-maintenance-recovery/v1',
                    recovered=pending, receiving_readiness='unobserved')))
                return 0
            if not 0 < args.observation_deadline_ns-time.monotonic_ns() <= 60_000_000_000:
                raise OnboardingError('receiving_owner_deadline_expired')
            # Reserve one MiB for the current cycle and unconditional recovery;
            # at capacity keep every original and refuse only a new owned stop.
            size = sum(p.stat().st_size for p in root.iterdir() if p.is_file())
            if size >= 15 * 1024**2:
                raise OnboardingError('membership_scope_retention_capacity')
            _serve_scope(pause, sys.stdin.fileno(), sys.stdout.fileno(),
                deadline_ns=args.observation_deadline_ns)
            return 0
    except (OnboardingError, JournalError, ValueError, OSError):
        # No raw manager commands, private locations or native content in output.
        print(json.dumps({'error': 'membership_maintenance_unavailable'}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
