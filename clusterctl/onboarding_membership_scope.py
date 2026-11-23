"""Original-job orchestration of finite Matrix preservation, never new enrollment."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import onboarding_code_successor, onboarding_release
from .onboarding import OnboardingError, digest
from .onboarding_group_session import OwnerConversation
from .onboarding_service import code_command

SCHEMA = 'cluster-membership-maintenance/v1'
MODULE = 'clusterctl.onboarding_membership_maintenance'


def configuration(value: dict, names) -> dict:
    try:
        if (set(value) != {'schema', 'owners'} or value['schema'] != SCHEMA
                or not isinstance(value['owners'], dict) or not 1 <= len(value['owners']) <= 16
                or not set(value['owners']) <= set(names)):
            raise ValueError
        for row in value['owners'].values():
            if (set(row) != {'code', 'code_digest', 'journal'}
                    or not isinstance(row['code_digest'], str)
                    or re.fullmatch('[0-9a-f]{64}', row['code_digest']) is None
                    or any(not isinstance(row[key], str) or not Path(row[key]).is_absolute()
                        or '..' in Path(row[key]).parts for key in ('code', 'journal'))):
                raise ValueError
    except (KeyError, TypeError, ValueError):
        raise OnboardingError('membership_maintenance_configuration_required') from None
    return copy.deepcopy(value)


class Endpoint:
    def __init__(self, owner, selected: dict, *, parent: str, binding: str, deadline_ns: int, validate):
        self.owner, self.selected, self.deadline = owner, selected, deadline_ns
        self.observation = None
        self.validate = validate
        self.candidate = Path(selected['code']), selected['code_digest']
        self.source = not hasattr(owner, 'backend')
        if self.source:
            onboarding_code_successor.selection(*self.candidate, owner.code, owner.code_digest, uid=owner.code_uid)
            self.body, self.code = None, self.candidate[0]
            self.python = Path('/usr/bin/python3')
        else:
            backend, plan = owner.backend, owner.plan
            if not backend.runtime_available(plan, self.candidate, prepare=True, deadline_ns=deadline_ns):
                raise OnboardingError('qualified_onboarding_candidate_mount_required')
            self.code, _, _ = backend._runtime_paths(plan, backend._receiving_base(plan), candidate=self.candidate)
            self.body = backend._runtime_body(plan)
            if self.body is None and backend.run is not backend._run:
                raise OnboardingError('membership_maintenance_transport_required')
            self.python = backend.body_python(plan)
        manifest = json.loads(onboarding_release.regular(self.candidate[0] / 'release.json',
            uid=owner.code_uid if self.source else os.geteuid()))
        paths = {item['path'] for item in manifest['files']}
        if not {'clusterctl/onboarding_membership_scope.py',
                'clusterctl/onboarding_membership_maintenance.py'} <= paths:
            raise OnboardingError('membership_maintenance_helper_required')
        self.arguments = ['--journal', selected['journal'], '--operation-id', parent,
            '--binding-sha256', binding, '--observation-deadline-ns', str(deadline_ns)]
        if self.source:
            self.arguments.append('--source')
        owner.maintenance = self.candidate

    def command(self, *, recovery=False):
        command = code_command(self.python, self.code, MODULE,
            self.arguments + (['--recover-only'] if recovery else []))
        if not self.source and self.body is None:
            command = self.owner.backend.owner_clock_argv(command, deadline_ns=self.deadline)
        return command

    def recover(self):
        # Recovery is observation/restoration of this original claim. It never
        # obtains a fresh native process or starts a new pause.
        command = self.command(recovery=True)
        if self.source:
            result = subprocess.run(command, capture_output=True, text=True, timeout=95,
                start_new_session=True, env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
            if result.returncode or len(result.stdout.encode()) > 4096:
                raise OnboardingError('membership_maintenance_recovery_unobserved')
            raw = result.stdout
        else:
            raw = self.owner.backend.execute_body(self.owner.plan, command, uid=0, gid=0,
                timeout_seconds=60, deadline_ns=self.deadline)
        value = json.loads(raw)
        if (set(value) != {'schema', 'recovered', 'receiving_readiness'}
                or value['schema'] != 'cluster-membership-maintenance-recovery/v1'
                or type(value['recovered']) is not bool or value['receiving_readiness'] != 'unobserved'):
            raise OnboardingError('membership_maintenance_recovery_unobserved')

    def open(self):
        self.validate()
        observed = self.owner.base_status() if self.observation is None else self.observation
        packet = {'observation': {key: observed[key] for key in ('process', 'admission_parent') if key in observed}}
        if self.body is not None:
            scope = self.body.membership_maintenance_conversation(self.command(), packet,
                deadline_ns=self.deadline, validate=self.validate)
        else:
            argv = self.command()
            if not self.source:
                argv = ['incus', '--force-local', 'exec', self.owner.backend.instance(self.owner.plan),
                    '--user', '0', '--group', '0', '--', *argv]
            scope = OwnerConversation(argv, packet, deadline_ns=self.deadline, validate=self.validate,
                cleanup_seconds=90, native_writer=False, env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
        scope.__enter__()
        return scope

    def prepare(self):
        # Authenticate before consuming the stopped-service window. The guard
        # later binds this exact process to the current unit and /proc identity;
        # a replacement refuses instead of borrowing the earlier observation.
        self.validate()
        self.observation = self.owner.base_status()

    def scope_deadline(self, deadline_ns):
        self.deadline = deadline_ns
        self.arguments[self.arguments.index('--observation-deadline-ns')+1] = str(deadline_ns)


def _parallel(items, action):
    outcomes, errors = {}, []
    with ThreadPoolExecutor(max_workers=min(16, len(items))) as workers:
        futures = {workers.submit(action, value): name for name, value in items.items()}
        for future in as_completed(futures):
            try:
                outcomes[futures[future]] = future.result()
            except BaseException as error:
                errors.append(error)
    return outcomes, errors


@contextmanager
def preserved(owners, selected, *, journal, row, deadline_ns, validate, restore_only=False,
              phase='membership', continuation_sha256=None, generation=None):
    """All preparations/recoveries precede any pause; all writer exit precedes restore."""
    if not isinstance(phase, str) or phase not in {'membership', 'receive'}:
        raise OnboardingError('membership_maintenance_phase_required')
    selected = configuration(selected, owners)
    if set(selected['owners']) != set(owners):
        raise OnboardingError('membership_maintenance_configuration_required')
    # Keep historical membership claims byte-identical. Receiving is a distinct
    # phase of the original job, never a reuse of its already restored pause.
    identity = {'operation_id': row['operation_id'], 'intent': row['intent'], 'recipe': selected}
    if continuation_sha256 is not None:
        if phase != 'membership' or re.fullmatch('[0-9a-f]{64}', continuation_sha256) is None:
            raise OnboardingError('membership_maintenance_configuration_required')
        identity['continuation_sha256'] = continuation_sha256
    parent = row['operation_id']
    if phase == 'receive':
        identity['phase'] = phase
        parent = str(uuid.uuid5(uuid.NAMESPACE_URL, 'onboarding-receive-maintenance:'+parent))
    binding = digest(identity)
    field = phase+'_maintenance'
    if continuation_sha256 is not None:
        field = 'membership_continuation_maintenance'
    if generation is not None:
        if (continuation_sha256 is None or not isinstance(generation, str)
                or str(uuid.UUID(generation)) != generation):
            raise OnboardingError('membership_maintenance_configuration_required')
        field += '-'+generation
    retained = (row['runtime_observation'] or {}).get(field)
    expected = dict(recipe=selected, binding=binding)
    if phase == 'receive':
        expected['operation_id'] = parent
        if restore_only and retained is None:
            raise OnboardingError('membership_maintenance_original_required')
    if retained is not None and retained != expected:
        previous_identity = {'operation_id': row['operation_id'], 'intent': row['intent'],
            'recipe': retained.get('recipe'), 'continuation_sha256': continuation_sha256}
        if (continuation_sha256 is None or digest(previous_identity) != retained.get('binding')):
            raise OnboardingError('membership_maintenance_original_changed')
        # Operator-selected compatible code repair, not another social attempt
        # or a refreshed grant. Preserve the old scope under its exact binding.
        field += '-'+binding
        retained = (row['runtime_observation'] or {}).get(field)
        if retained is not None and retained != expected:
            raise OnboardingError('membership_maintenance_original_changed')
    previous = {name: (owner.deadline_ns, owner.maintenance) for name, owner in owners.items()}
    sessions = {}
    try:
        for owner in owners.values():
            owner.deadline_ns = deadline_ns
        endpoints, errors = _parallel({name: (owner, selected['owners'][name]) for name, owner in owners.items()},
            lambda pair: Endpoint(pair[0], pair[1],
            parent=parent, binding=binding, deadline_ns=deadline_ns, validate=validate))
        if errors:
            raise errors[0]
        _, errors = _parallel(endpoints, lambda endpoint: endpoint.recover())
        if errors:
            raise errors[0]
        if restore_only:
            yield lambda: None
            return
        _, errors = _parallel(endpoints, lambda endpoint: endpoint.prepare()
            if callable(getattr(endpoint, 'prepare', None)) else None)
        if errors:
            raise errors[0]
        # Preparation has its own finite parent budget. No pause exists yet.
        # All actual guards and native effects share one fresh <=60s horizon.
        effect_deadline = min(deadline_ns, time.monotonic_ns()+60_000_000_000)
        for owner in owners.values():
            owner.deadline_ns = effect_deadline
        for endpoint in endpoints.values():
            setter = getattr(endpoint, 'scope_deadline', None)
            if callable(setter):
                setter(effect_deadline)
        validate()
        if retained is None:
            current = journal.get(row['operation_id'])
            observed = dict(current['runtime_observation'] or {})
            observed[field] = expected
            journal.advance(row['operation_id'], current['state'], runtime_observation=observed,
                expected_runtime_observation=current['runtime_observation'])
        sessions, errors = _parallel(endpoints, lambda endpoint: endpoint.open())
        if errors:
            raise errors[0]
        def check():
            validate()
            _, failures = _parallel(sessions, lambda scope: scope.call({'check': True}))
            if failures:
                raise failures[0]
        setattr(check, 'deadline_ns', effect_deadline)
        check()
        yield check
    finally:
        error_info = sys.exc_info()
        try:
            if sessions:
                _, errors = _parallel(sessions, lambda scope: scope.__exit__(*error_info))
                if errors:
                    if error_info[1] is None:
                        raise OnboardingError('membership_maintenance_restore_unobserved') from errors[0]
                    error_info[1].add_note('Scoped Matrix restoration is unobserved; inspect the retained original operation.')
        finally:
            for name, owner in owners.items():
                owner.deadline_ns, owner.maintenance = previous[name]
