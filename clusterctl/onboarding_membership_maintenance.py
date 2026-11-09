"""Local Matrix-only preservation for the existing membership admission caller.

No CLI, service installation or automatic stop is introduced. The root-side
caller holds the fixed unit's existing selection lock and its original admission
operation. Recovery uses the same durable journal before deadline/candidate
preflight; it never dispatches a native membership request.
"""
from __future__ import annotations

import copy
import pwd

from .onboarding import OnboardingError
from .onboarding_service import UNIT, bind_admitted_service_process, bind_service_parent_process
from .operation_journal import OperationJournal
from .receiving_worker import WorkerManager, _OwnedServicePause

SOURCE_UNIT = 'compaii-matrix-itaca.service'


class MembershipManager(WorkerManager):
    """Only the installed Source or receiving guest Matrix system service.

    An authenticated base-runtime observation must be physically bound before
    any stop. A restarted/replaced process must be freshly observed, never
    stopped under the old observation. Restoration requires no new native read.
    """
    execution_identity: dict[str, str]
    extra_fields = frozenset({'ControlGroup'})
    bind_process = staticmethod(bind_service_parent_process)

    def __init__(self, *, source: bool = False):
        if type(source) is not bool:
            raise OnboardingError('membership_service_scope_required')
        self.unit_name = SOURCE_UNIT if source else UNIT
        user = 'debian' if source else 'agent'
        self.execution_identity = {'User': user, 'Group': user}
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
    also invoke recover on process exit. This class alone is not a crash-safe
    command supervisor and is not yet wired into the provisioning worker.
    """
    def __init__(self, journal: OperationJournal, parent: str, binding: str,
                 manager: MembershipManager):
        if not isinstance(manager, MembershipManager) or manager.unit_name not in {SOURCE_UNIT, UNIT}:
            raise OnboardingError('membership_service_scope_required')
        super().__init__(journal, parent, binding, manager, unit_name=manager.unit_name,
            prefix='membership-matrix', profile='scoped-membership-preservation/v1',
            actor='onboarding-membership-maintenance')
