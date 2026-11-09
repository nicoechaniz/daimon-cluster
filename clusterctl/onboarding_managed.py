"""Worker reconciliation of configured admission, guest service and registry."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager, nullcontext
import hashlib
import json
import math
import re
import uuid
from pathlib import Path
import time

from . import being_seed, onboarding_admission
from .admission import AdmissionEndpoint
from .onboarding_registry import OwnerRegistry
from .fences import Ed25519Signer
from .onboarding import JobStore, Observation, OnboardingError, digest, private_directory
from .onboarding_service import UNIT
from .production_fences import ed25519_fingerprint


def _code_update_group(value: dict, *, published: bool = False) -> dict | None:
    """Freeze the existing group and publication without changing release policy."""
    group = value.get('group')
    if group is None:
        return None
    app = (value.get('group_runtime_status') or {}).get('loaded_application')
    visibility = app.get('visibility', {}) if isinstance(app, dict) else {}
    if (not isinstance(group, dict) or not isinstance(app, dict)
            or visibility.get('release_enabled') is not published
            or any(not isinstance(app.get(key), str) or re.fullmatch('[0-9a-f]{64}', app[key]) is None
                for key in ('application_sha256', 'publication_sha256'))
            or not published and visibility.get('installation_sha256') is not None
            or published and (visibility.get('catalog_validation') != 'validated'
                or any(not isinstance(visibility.get(key), str)
                    or re.fullmatch('[0-9a-f]{64}', visibility[key]) is None
                    for key in ('installation_sha256', 'policy_sha256')))):
        raise OnboardingError('native_code_update_closed_group_required')
    result = dict(selected=group, application_sha256=app['application_sha256'],
        publication_sha256=app['publication_sha256'], outbound_release=published)
    if published:
        result.update(installation_sha256=visibility['installation_sha256'],
            policy_sha256=visibility['policy_sha256'])
    return result



class ManagedRuntime:
    def __init__(self, backend):
        self.backend = backend
        config = backend.config
        self.settings = being_seed._read(config.admission)
        value = self.settings
        fields = {'schema', 'host_port', 'guest_port', 'authority_key_id', 'authority_public_key',
                  'registrar_key_id', 'registrar_key', 'registry', 'state', 'visibility_installation'}
        admission_only = value.get('schema') == 'cluster-onboarding-managed-runtime/v2'
        if (set(value) - {'messaging_application'} != fields | ({'mode'} if admission_only else set())
                or value.get('schema') not in {'cluster-onboarding-managed-runtime/v1', 'cluster-onboarding-managed-runtime/v2'}
                or any(type(value[key]) is not int or not 1 <= value[key] <= 65535
                       for key in ('host_port', 'guest_port'))
                or any(not isinstance(value[key], str) or not value[key]
                       for key in ('authority_key_id', 'registrar_key_id'))):
            raise OnboardingError('invalid_onboarding_managed_configuration')
        # This explicit selection admits the existing body with closed outbound.
        # It cannot downgrade a selected social/peer application or acquire its
        # completion semantics. Legacy v1 remains visibility-gated.
        if admission_only and (value.get('mode') != 'native-admission-only'
                or value.get('visibility_installation') is not None
                or value.get('messaging_application') is not None
                or getattr(config, 'group_admission', None) is not None
                or getattr(config, 'peer', None) is not None):
            raise OnboardingError('invalid_onboarding_managed_configuration')
        ed25519_fingerprint(value['authority_public_key'])
        for key in ('registrar_key', 'registry', 'state'):
            if not isinstance(value[key], str) or not Path(value[key]).is_absolute():
                raise OnboardingError('invalid_onboarding_managed_configuration')
        self.registry = OwnerRegistry(Path(value['registry']))
        self.state = private_directory(Path(value['state']))
        visibility = value['visibility_installation']
        if visibility is not None and (not isinstance(visibility, str)
                or not Path(visibility).is_absolute() or '..' in Path(visibility).parts
                or not Path(visibility).is_relative_to('/home/agent')):
            raise OnboardingError('invalid_onboarding_managed_configuration')

        app = value.get('messaging_application')
        if app is not None and (visibility is None or not isinstance(app, str)
                or not Path(app).is_absolute() or '..' in Path(app).parts
                or not Path(app).is_relative_to('/home/agent')):
            raise OnboardingError('invalid_onboarding_managed_configuration')

    def update_native_code(self, plan: dict, candidate: tuple[Path, str], *,
                           operation_id: str, timeout_seconds: float = 120,
                           receive_only_group: bool = False, published_group: bool = False) -> dict:
        """Select code for an admitted body through its existing unit writer.

        No group publication or controller renewal is involved. The durable
        request binds the actual admitted predecessor and changes only ExecStart;
        root's existing bootstrap journal reconciles lost stop/select/start ACKs.
        Identity, credentials, native stores and Conversation are preserved.
        The complete operation includes cold SDK preparation within its declared envelope;
        each owner/physical request remains capped at 60 seconds and shares the
        original overall deadline. No internal deadline is renewed.
        An existing group and publication are frozen across the update. Published
        groups explicitly migrate catalogs under their stopped native owner;
        they never repeat enrollment or publication. Retain one current
        and one previous completed receipt; unfinished effects require exact
        reconciliation and can never be replaced by a new operation.
        """
        from .onboarding_service import command
        if (type(receive_only_group) is not bool or type(published_group) is not bool
                or receive_only_group and published_group
                or str(uuid.UUID(operation_id)) != operation_id
                or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300
                or not published_group and (self.settings.get('mode') != 'native-admission-only'
                    or self._selection(plan) != (None, None))):
            raise OnboardingError('native_code_update_requires_plain_admitted_body')
        with_group = receive_only_group or published_group
        deadline = time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
        def remaining():
            seconds = (deadline - time.monotonic_ns()) / 1_000_000_000
            if seconds <= 0:
                raise OnboardingError('receiving_host_deadline_expired')
            return min(60.0, seconds)
        directory = private_directory(self.state / plan['name'], create=True)
        with being_seed._locked(directory), ExitStack() as locks:
            jobs = private_directory(self.backend.config.jobs)
            locks.enter_context(being_seed._locked(jobs))
            store = JobStore(jobs)
            locks.enter_context(being_seed._locked(private_directory(store.directory(plan['name']))))
            job = store._load(plan['name'])
            if job['plan'] != plan or not self.backend.authorize(plan, digest(plan)):
                raise OnboardingError('receiving_initial_plan_changed')
            expected = self._expected(plan)
            if not self._registered(expected):
                raise OnboardingError('native_code_update_requires_plain_admitted_body')
            if not self.backend.runtime_available(plan, candidate, deadline_ns=deadline):
                raise OnboardingError('qualified_onboarding_candidate_mount_required')
            base = self.backend._receiving_base(plan)
            code, _args, _mounts = self.backend._runtime_paths(plan, base, candidate=candidate)
            argv = command(base, receive_only=True, runtime_code=code, runtime_digest=candidate[1])
            path = directory / 'native-code-update.json'
            pins: dict = dict(schema='cluster-native-code-update/v1', operation_id=operation_id,
                plan_digest=digest(plan), candidate_digest=candidate[1], argv=argv)
            if receive_only_group:
                pins['receive_only_group'] = True
            if published_group:
                pins.pop('argv')
                pins['published_group'] = True
            def save():
                if len(json.dumps(state).encode()) > 65536:
                    raise OnboardingError('native_code_update_record_limit')
                being_seed._write(path, state)
            def observe():
                value = self.backend._target_call(plan, 'admitted-running', candidate=candidate,
                    observation_timeout_seconds=remaining(),
                    **({'current_native': True, 'require_loaded': True} if with_group else {}))
                if (value.get('responder_association') != 'same-connection'
                        or any(value['origin'].get(key) != expected[key]
                            for key in ('body_ref', 'embodiment_id', 'incarnation_id'))
                        or (value.get('group') is not None) != with_group):
                    raise OnboardingError('native_code_update_identity_changed')
                _code_update_group(value, published=published_group)
                return value
            previous_completed = None
            if path.exists():
                state = being_seed._read(path)
                if state.get('pins') != pins:
                    prior_pins, prior_result = state.get('pins', {}), state.get('result', {})
                    if (prior_pins.get('operation_id') == operation_id
                            or state.get('dispatching') is not None
                            or len(json.dumps(state).encode()) > 65536
                            or set(state.get('effects', {})) != ({'validate', 'quiesce', 'migrate', 'select', 'start'}
                                if prior_pins.get('published_group') else {'validate', 'quiesce', 'select', 'start'})
                            or prior_result.get('operation_id') != prior_pins.get('operation_id')
                            or prior_result.get('candidate_digest') != prior_pins.get('candidate_digest')
                            or prior_result.get('schema') != 'cluster-native-code-updated/v1'):
                        raise OnboardingError('native_code_update_operation_conflict')
                    previous_completed = state
            # Mounted public code is not an installed owner interpreter. This
            # existing idempotent stage also prepares its closed import tree.
            sdk = self.backend._target_call(plan, 'sdk-prepare', candidate=candidate,
                observation_timeout_seconds=remaining())
            if sdk.get('ready') is not True:
                raise OnboardingError('native_code_update_sdk_unready')
            if not path.exists() or previous_completed is not None:
                before = observe()
                previous = {key: before[key] for key in ('process', 'admission_parent')}
                physical = self.backend._guest_service_call(plan, 'bootstrap-inspect', candidate=candidate,
                    timeout_seconds=remaining(), owner_observation=previous)
                previous.update(service=physical['service'], scope=physical['scope'])
                frozen_group = _code_update_group(before, published=published_group)
                if published_group:
                    if frozen_group is None:
                        raise OnboardingError('native_code_update_migration_binding_required')
                    argv = command(base, receive_only=False, runtime_code=code, runtime_digest=candidate[1],
                        visibility=Path(frozen_group['selected']['visibility']),
                        messaging_application=Path(frozen_group['selected']['application']))
                state = dict(pins=pins, runtime_sha256=before['runtime_sha256'], origin=before['origin'],
                    request=dict(schema='cluster-guest-service-bootstrap/v1', operation_id=operation_id,
                        plan_digest=digest(plan), predecessor=previous, argv=argv), effects={})
                if previous['service'].get('entrypoint_selector') is not None:
                    state['request']['runtime_update'] = True
                if before.get('group') is not None:
                    state['closed_group'] = frozen_group
                if previous_completed is not None:
                    # The native bootstrap journal retains the exact historical
                    # effects. These two bounded owner records are observations.
                    being_seed._write(directory / 'native-code-update.previous.json', previous_completed)
                    state['previous_completed_sha256'] = digest(previous_completed)
                save()
            actions = ('validate', 'quiesce', 'migrate', 'select', 'start') if published_group else (
                'validate', 'quiesce', 'select', 'start')
            for action in actions:
                if action in state['effects']:
                    continue
                # Retain the exact request before dispatch. Root's bootstrap
                # reconciles this same operation; never mint a replacement ID.
                state['dispatching'] = action
                save()
                if action == 'migrate':
                    migrated = self.backend._target_call(plan, 'visibility-migrate',
                        candidate=candidate, observation_timeout_seconds=remaining(), visibility_migration=dict(
                            operation_id=operation_id, runtime_sha256=state['runtime_sha256'],
                            origin=state['origin'], group=state['closed_group']))
                    if (migrated.get('schema') != 'cluster-native-visibility-migrated/v1'
                            or migrated.get('operation_id') != operation_id
                            or migrated.get('runtime_sha256') != state['runtime_sha256']
                            or migrated.get('group') != state['closed_group']
                            or type(migrated.get('catalog_schema_version')) is not int):
                        raise OnboardingError('native_code_update_migration_binding_changed')
                    state['effects'][action] = migrated
                else:
                    state['effects'][action] = self.backend._guest_service_call(plan, 'bootstrap-' + action,
                        candidate=candidate, timeout_seconds=remaining(), request=state['request'])
                state.pop('dispatching', None)
                save()
            current = observe()
            if current['runtime_sha256'] != state['runtime_sha256']:
                raise OnboardingError('native_code_update_identity_changed')
            if _code_update_group(current, published=published_group) != state.get('closed_group'):
                raise OnboardingError('native_code_update_group_changed')
            if with_group and current.get('runtime_status', {}).get(
                    'loaded_runtime', {}).get('qualified_startup', {}).get('code_digest') != candidate[1]:
                raise OnboardingError('native_code_update_selection_changed')
            if published_group and current['group_runtime_status']['loaded_application'][
                    'visibility']['catalog_schema_version'] != state['effects']['migrate']['catalog_schema_version']:
                raise OnboardingError('native_code_update_selection_changed')
            physical = self.backend._guest_service_call(plan, 'bootstrap-inspect', candidate=candidate,
                timeout_seconds=remaining(), owner_observation={key: current[key]
                    for key in ('process', 'admission_parent')})
            if (physical['service']['unit_sha256'] != state['effects']['select']['selected_sha256']
                    or physical['scope']['admission_parent'] != state['effects']['start']['admission_parent']
                    or store._load(plan['name']) != job):
                raise OnboardingError('native_code_update_selection_changed')
            selected_override = state['effects']['select'].get('selector')
            if (selected_override is not None and physical['service'].get('entrypoint_selector') != dict(
                    path=selected_override['path'],sha256=selected_override['selected_sha256'])):
                raise OnboardingError('native_code_update_selection_changed')
            state['result'] = dict(schema='cluster-native-code-updated/v1',
                operation_id=operation_id, candidate_digest=candidate[1],
                runtime_sha256=current['runtime_sha256'], origin=current['origin'],
                process=current['process'], admission_parent=current['admission_parent'],
                unit_sha256=physical['service']['unit_sha256'], receiving_readiness='unobserved')
            save()
            return state['result']

    def _ready(self, plan: dict) -> bool:
        return self.settings.get('mode') == 'native-admission-only' or self._selection(plan)[1] is not None or (
            self.backend.config.qualification and plan['name'].startswith('qualify-'))

    def _selection(self, plan: dict) -> tuple[str | None, str | None]:
        if getattr(self.backend.config, 'group_admission', None) is not None:
            from .onboarding_group_coordinator import GroupCoordinator
            try:
                _row, _approved, selected = GroupCoordinator(self.backend).selection(plan)
            except OnboardingError as error:
                if str(error) != 'onboarding_group_admission_pending':
                    raise
                return None, None
            return selected['application'], selected['visibility']
        if getattr(self.backend.config, 'peer', None) is not None:
            from .onboarding_peer_host import PeerHost
            return PeerHost(self.backend).application(plan) or (None, None)
        return self.settings.get('messaging_application'), self.settings['visibility_installation']

    def _expected(self, plan: dict) -> dict:
        return self.backend._ceremony(plan).admission_coordinates(plan)

    def _proxy(self) -> dict:
        return dict(type='proxy', bind='instance', listen='tcp:127.0.0.1:' + str(self.settings['guest_port']),
                    connect='tcp:127.0.0.1:' + str(self.settings['host_port']))

    def _check_proxy(self, plan: dict, *, deadline_ns: int | None = None) -> bool:
        if deadline_ns is None:
            rows, _ = self.backend._inventory()
        else:
            rows = json.loads(self.backend._dispatch(plan, ['list', '--format=json'], deadline_ns=deadline_ns))
            if (not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
                    or sum(row.get('name') == self.backend.instance(plan) for row in rows) != 1):
                raise OnboardingError('invalid_onboarding_environment_observation')
        row = next(row for row in rows if row.get('name') == self.backend.instance(plan))
        current = row.get('expanded_devices', {}).get('onboarding-admission')
        if current is not None and current != self._proxy():
            raise OnboardingError('foreign_onboarding_admission_proxy_preserved')
        return current is not None

    def _registered(self, expected: dict, *, deadline_ns: int | None = None) -> bool:
        identifier = expected['embodiment_id']
        rows = self.registry.load(**({} if deadline_ns is None else {'deadline_ns': deadline_ns}))['embodiments']
        existing = rows.get(identifier)
        if existing is not None:
            if (existing.get('body_ref') != expected['body_ref']
                    or existing.get('hosting') != 'external-owner' or existing.get('status') != 'running'
                    or existing.get('current_incarnation_id') != expected['incarnation_id']
                    or sum(item.get('incarnation_id') == expected['incarnation_id']
                           and item.get('stopped_at_ms') is None for item in existing.get('incarnations', [])) != 1):
                raise OnboardingError('existing_onboarding_registry_preserved')
            return True
        if any(row.get('body_ref') == expected['body_ref'] or any(
                item.get('incarnation_id') == expected['incarnation_id'] for item in row.get('incarnations', []))
                for row in rows.values()):
            raise OnboardingError('existing_onboarding_registry_preserved')
        return False

    def _profile(self, plan: dict) -> dict | None:
        root = self.state / digest(plan)
        private_directory(root, create=True)
        path = root / 'confirmed.json'
        if not path.exists():
            return None
        value = being_seed._read(path)
        endpoint = dict(transport='tcp-authenticated', host='127.0.0.1', port=self.settings['guest_port'])
        if (value.get('schema') != 'cluster-onboarding-admission-profile/v1'
                or value.get('plan_digest') != digest(plan) or value.get('endpoint') != endpoint
                or value.get('authority_key_id') != self.settings['authority_key_id']
                or value.get('authority_public_key') != self.settings['authority_public_key']
                or any(value.get('enrollment', {}).get(key) != expected
                       for key, expected in self._expected(plan).items())):
            raise OnboardingError('existing_onboarding_service_profile_preserved')
        return value

    def observe(self, plan: dict) -> Observation:
        if not self._ready(plan):
            return Observation('waiting', reason='backend_unavailable')
        expected = self._expected(plan)
        registered = self._registered(expected)
        configuration = self._profile(plan)
        if configuration is None or not self._check_proxy(plan):
            return Observation('absent', safe_to_execute=True)
        properties = self.backend._dispatch(plan, ['exec', self.backend.instance(plan), '--', 'systemctl',
            'show', UNIT, '--property=ActiveState', '--property=MainPID'])
        values = dict(line.split('=', 1) for line in properties.splitlines() if '=' in line)
        if values.get('ActiveState') != 'active' or not values.get('MainPID', '').isdigit():
            return Observation('absent', safe_to_execute=True)
        options: dict = {}
        receiving = None
        if getattr(self.backend.config, 'group_admission', None) is not None:
            from .onboarding_group_coordinator import GroupCoordinator
            row, approved, group = GroupCoordinator(self.backend).selection(plan)
            receiving = row, group
            options['candidate'] = (Path(approved['candidate']['code']), approved['recipe']['prepared']['code_digest'])
            options['require_loaded'] = True
        presence = self.backend._target_call(plan, 'admitted-running', **options)
        if (presence.get('schema') != 'cluster-onboarding-runtime-presence/v1'
                or presence.get('plan_digest') != digest(plan)
                or any(presence.get('origin', {}).get(key) != expected[key]
                       for key in ('body_ref', 'embodiment_id', 'incarnation_id'))
                or presence.get('process', {}).get('pid') == int(values['MainPID'])):
            raise OnboardingError('onboarding_managed_presence_rejected')
        if receiving is not None:
            from .onboarding_group_coordinator import loaded_selection
            row, group = receiving
            try:
                observed = loaded_selection(dict(loaded_runtime=presence['runtime_status']['loaded_runtime'],
                    loaded_application=presence['group_runtime_status']['loaded_application']))
                original = row['runtime_observation']['initial_managed'][plan['name']]['intent']['owner']['origin']
                selection = row['runtime_observation']['admission_activation_plan']['plan']['receivers'][plan['name']]['selection']
                if observed != selection or presence.get('group') != group or presence.get('origin') != original:
                    raise ValueError
            except (KeyError, TypeError, ValueError, OnboardingError):
                raise OnboardingError('onboarding_managed_presence_rejected') from None
        if not registered:
            return Observation('absent', dict(native_running_verified=True), safe_to_execute=True)
        return Observation('complete', dict(verified=True, identity_verified=True))

    def prepare_admission(self, plan: dict, *, candidate: tuple[Path, str] | None = None,
                          deadline_ns: int | None = None,
                          authorization_expires_at_ms: int | None = None) -> dict:
        """Enroll the existing native holder without selecting or starting a service.

        Initial shared-group admission needs this profile before its owner
        context is frozen. Group publication and managed service startup follow
        separately; neither a profile nor a registry row proves a loaded body.
        The normal execute path reuses these same durable proposals and retries.
        """
        if ((deadline_ns is None) != (authorization_expires_at_ms is None)
                or candidate is not None and deadline_ns is None
                or deadline_ns is not None and (type(deadline_ns) is not int or deadline_ns <= 0)
                or authorization_expires_at_ms is not None and (
                    type(authorization_expires_at_ms) is not int or not 0 < authorization_expires_at_ms < 2**53)):
            raise OnboardingError('receiving_host_deadline_required')
        def remaining() -> float | None:
            if deadline_ns is None:
                return None
            assert authorization_expires_at_ms is not None
            value = min((deadline_ns - time.monotonic_ns()) / 1_000_000_000,
                (authorization_expires_at_ms - time.time_ns() // 1_000_000) / 1000)
            if value <= 0:
                raise OnboardingError('receiving_preservation_authorization_expired')
            return value
        def target(action: str, profile: dict | None = None) -> dict:
            options: dict = {} if profile is None else {'profile': profile}
            if candidate is not None:
                options['candidate'] = candidate
            budget = remaining()
            if budget is not None:
                options.update(observation_timeout_seconds=budget,
                    authorization_expires_at_ms=authorization_expires_at_ms)
            return self.backend._target_call(plan, action, **options)
        remaining()
        bounds: dict = {} if deadline_ns is None else {'deadline_ns': deadline_ns}
        expected = self._expected(plan)
        self._registered(expected, **bounds)  # Preserve foreign canonical state before enrollment.
        remaining()
        if not self._check_proxy(plan, **bounds):
            remaining()
            proxy = self._proxy()
            self.backend._dispatch(plan, ['config', 'device', 'add', self.backend.instance(plan),
                'onboarding-admission', 'proxy', *[key + '=' + value for key, value in proxy.items() if key != 'type']], **bounds)
        configuration = self._profile(plan)
        root = self.state / digest(plan)
        if configuration is None:
            proposal = root / 'candidate.json'
            configuration = being_seed._read(proposal) if proposal.exists() else None
            registered = (configuration is not None and target('admission-check', configuration).get('registered') is True)
            if not registered:
                request = target('admission-prepare')
                registrar = Ed25519Signer(self.settings['registrar_key'], self.settings['registrar_key_id'])
                configuration = onboarding_admission.profile(plan, request, expected, registrar,
                    endpoint=AdmissionEndpoint.network('127.0.0.1', self.settings['guest_port']),
                    authority_key_id=self.settings['authority_key_id'],
                    authority_public_key=self.settings['authority_public_key'])
                # Preserve every signed proposal; the pointer is only local progress.
                being_seed._write(root / ('profile-' + digest(configuration) + '.json'), configuration)
                being_seed._write(proposal, configuration)
                if target('admission-enroll', configuration) != {'registered': True}:
                    raise OnboardingError('onboarding_admission_not_current')
            assert configuration is not None
            being_seed._write(root / 'confirmed.json', configuration)
        assert configuration is not None
        remaining()
        self.backend.prepare_matrix_public(plan, {'admission.json': configuration})
        remaining()
        return configuration

    def execute(self, plan: dict) -> None:
        if getattr(self.backend.config, 'group_admission', None) is not None:
            # The coordinator owns controlled first load and steady handoff.
            # Never replace that unit through the legacy generic installer.
            if self.observe(plan).state != 'complete':
                raise OnboardingError('onboarding_group_runtime_recovery_required')
            return
        if not self._ready(plan):
            raise OnboardingError('onboarding_visibility_selection_required')
        # Reconcile a successful first start whose readiness response was lost
        # or arrived before the daemon had its lease. Never reinstall that body.
        observed = self.observe(plan)
        if observed.state == 'complete':
            return
        if observed.state == 'absent' and observed.facts.get('native_running_verified') is True:
            expected = self._expected(plan)
            self.registry.adopt_running(**{key: expected[key]
                for key in ('body_ref', 'embodiment_id', 'incarnation_id')})
            return
        self.prepare_admission(plan)
        expected = self._expected(plan)
        _, code, _ = self.backend._guest_paths(plan)
        runtime_code, runtime_args, _ = self.backend._runtime_paths(plan, code)
        launcher = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                    'from clusterctl.onboarding_service import main;raise SystemExit(main())')
        application, visibility = self._selection(plan)
        selection = (['--receive-only'] if visibility is None else ['--visibility-installation', visibility])
        if application is not None:
            selection += ['--messaging-application', application]
        self.backend._dispatch(plan, ['exec', self.backend.instance(plan), '--', 'python3', '-B', '-I', '-c',
            launcher, str(runtime_code), '--code', str(code), *runtime_args, '--plan', '/home/agent/.onboarding-input/plan.json', *selection])
        # Observe authenticated, admitted presence before committing canonical state.
        presence = self.backend._target_call(plan, 'admitted-running')
        origin = presence['origin']
        if any(origin.get(key) != expected[key] for key in ('body_ref', 'embodiment_id', 'incarnation_id')):
            raise OnboardingError('onboarding_managed_presence_rejected')
        self.registry.adopt_running(**{key: expected[key] for key in ('body_ref', 'embodiment_id', 'incarnation_id')})

    @contextmanager
    def _initial_scope(self, plan: dict, cohort):
        """Reuse operation -> jobs ownership for first load and steady selection."""
        with ExitStack() as locks:
            locks.enter_context(cohort.journal.mutation_lock(cohort.operation_id))
            jobs = private_directory(self.backend.config.jobs)
            locks.enter_context(being_seed._locked(jobs))
            store = JobStore(jobs)
            for job in store.names():
                locks.enter_context(being_seed._locked(private_directory(store.directory(job))))
            if store._load(plan['name'])['plan'] != plan or not self.backend.authorize(plan, digest(plan)):
                raise OnboardingError('receiving_initial_plan_changed')
            yield

    def execute_initial(self, plan: dict, cohort, *, timeout_seconds: float = 30,
                        start_recovery: tuple[str, tuple[Path, str]] | None = None) -> dict:
        """Retain a first native load in the existing admission operation.

        Invoke outside JobStore.tick: operation -> jobs parent -> job locks is
        the same ownership order as the maintained replacement controller.
        No sender is enabled here; full cohort adoption remains separate.
        """
        from .onboarding_receiving_update import (
            GuestBootstrapController, _manifest, guest_loaded_observation, preflight,
            preservation_authorization,
        )
        from .onboarding_service import command, initial_start_projection, unit_content
        from .operation_journal import JournalConflict
        from . import onboarding_group_recovery as recovery
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 60:
            raise OnboardingError('receiving_host_deadline_required')
        deadline = time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
        def remaining():
            result = (deadline - time.monotonic_ns()) / 1_000_000_000
            if result <= 0:
                raise OnboardingError('receiving_host_deadline_expired')
            return result

        with self._initial_scope(plan, cohort):
            name = plan['name']
            row = cohort._row()
            admission = cohort._admission(row)
            if (admission is None or name not in admission['receivers']
                    or name in {sender['name'] for sender in row['expected_precondition']['senders']}):
                raise OnboardingError('receiving_initial_admission_required')
            approved = admission['receivers'][name]
            vector = Path(approved['candidate']['code']), approved['recipe']['prepared']['code_digest']
            prepared = approved['recipe']['prepared']
            bounds = recovery.bounds(cohort.journal, row)
            deadline = recovery.effect_deadline(cohort.journal, row, 'initial-start', deadline)
            _manifest(Path(bounds['manifest_path']), row['intent']['runtime_call']['manifest_digest'],
                uid=bounds['manifest_uid'])
            checked = preflight(vector[0], vector[1], Path(bounds['manifest_path']),
                row['intent']['runtime_call']['manifest_digest'], being_ref=approved['being_ref'],
                embodiment_id=approved['embodiment_id'], code_uid=approved['candidate']['code_uid'],
                manifest_uid=bounds['manifest_uid'])
            if any(prepared.get(key) != value for key, value in checked.items()):
                raise OnboardingError('receiving_initial_candidate_changed')
            configuration = self._profile(plan)
            expected = self._expected(plan)
            self._registered(expected)
            if configuration is None or not self._check_proxy(plan, deadline_ns=deadline):
                raise OnboardingError('receiving_initial_admission_profile_required')

            def effects():
                return (cohort._row()['runtime_observation'] or {}).get('initial_managed', {}).get(name, {})

            def record(key, value):
                current = cohort._row()
                observations = dict(current['runtime_observation'] or {})
                receivers = dict(observations.get('initial_managed', {}))
                retained = dict(receivers.get(name, {}))
                if key in retained:
                    if retained[key] != value:
                        raise JournalConflict('receiving initial managed effect changed')
                    return retained[key]
                retained[key] = value
                receivers[name] = retained
                observations['initial_managed'] = receivers
                cohort.journal.advance(cohort.operation_id, current['state'], runtime_observation=observations,
                    expected_runtime_observation=current['runtime_observation'])
                return value

            binding = dict(schema='cluster-managed-initial-binding/v1', plan_digest=digest(plan),
                admission_sha256=digest(admission), profile_sha256=digest(configuration),
                receiver=approved, origin=expected)
            grant = recovery.attached(cohort.journal, row)
            if grant is not None:
                binding['continuation_sha256'] = digest(grant)
            intent = effects().get('intent')
            if intent is None:
                recovery.execution(cohort.journal, row, effect='initial-start')
                with ExitStack() as observations:
                    for sender in row['expected_precondition']['senders']:
                        observations.enter_context(cohort._owner_deadline(cohort.owners[sender['name']], deadline))
                    cohort.require_revocation_barrier()
                owner = self.backend._target_call(plan, 'receiving-bootstrap-freeze', candidate=vector,
                    bootstrap_timeout_seconds=remaining(), bootstrap_initial_service=True)
                startup = owner['observer_startup']
                if (owner['predecessor'] is not None or owner['being_ref'] != approved['being_ref']
                        or any(owner['origin'].get(key) != expected[key] for key in (
                            'body_ref', 'embodiment_id', 'incarnation_id'))
                        or owner['origin']['embodiment_id'] != approved['embodiment_id']
                        or owner['group']['selected']['tribe_ref'] != admission['tribe_ref']
                        or owner['group']['selected']['socket'] != approved['socket']
                        or any(startup.get(key) != value for key, value in dict(code_digest=vector[1],
                            matrix_commit=prepared['matrix_revision'], sdk_digest=prepared['sdk_digest'],
                            matrix_wheel_sha256=prepared['matrix_wheel_sha256'], reader=prepared['reader']).items())):
                    raise OnboardingError('receiving_initial_owner_changed')
                base = self.backend._receiving_base(plan)
                code, _, _ = self.backend._runtime_paths(plan, base, candidate=vector)
                selected = owner['group']['selected']
                frozen_owner = {key: value for key, value in owner.items() if key != 'observer_startup'}
                initial_context = dict(schema='cluster-initial-start-context/v1',
                    owner_sha256=digest(frozen_owner), profile_sha256=digest(configuration),
                    not_after_ms=bounds['expires_at_ms'])
                argv = command(base, receive_only=False, runtime_code=code, runtime_digest=vector[1],
                    visibility=Path(selected['visibility']), messaging_application=Path(selected['application']),
                    expected_initial_context=initial_context)
                native_id = GuestBootstrapController(cohort.journal, cohort.operation_id, self.backend, name)._native_operation_id()
                request = dict(schema='cluster-guest-service-initial/v1', operation_id=native_id,
                    plan_digest=digest(plan), predecessor=None, argv=argv, not_after_ms=bounds['expires_at_ms'])
                intent = record('intent', dict(binding=binding, owner=frozen_owner, request=request,
                    unit_sha256=hashlib.sha256(unit_content(argv)).hexdigest()))
            if intent['binding'] != binding:
                raise OnboardingError('receiving_initial_binding_changed')
            if name in (cohort._row()['runtime_observation'] or {}).get('initial_steady', {}):
                self._complete_initial_locked(plan, cohort, deadline=deadline)
                return effects()['controlled_loaded']
            def root_call(action, *, fresh_effect=False, **kwargs):
                budget = remaining()
                if fresh_effect:
                    recovery.execution(cohort.journal, row, effect='initial-start')
                    budget = min(budget, (bounds['expires_at_ms'] - time.time_ns() // 1_000_000) / 1000)
                    if budget <= 0:
                        raise OnboardingError('receiving_preservation_authorization_expired')
                dispatch=vector
                extra:dict={}
                execution_grant = recovery.execution(cohort.journal, row,
                    effect='initial-start', historical=True)
                if execution_grant is not None:
                    helper=execution_grant['maintenance'][name]
                    dispatch=Path(helper['code']),helper['code_digest']
                    extra['owner_deadline_ns']=deadline
                with (recovery.effect_scope(cohort.journal, row, 'initial-start', deadline_ns=deadline)
                        if fresh_effect else nullcontext()):
                    return self.backend._guest_service_call(plan, action, candidate=dispatch,
                        timeout_seconds=budget, **extra,**kwargs)
            validated = root_call('bootstrap-validate', request=intent['request'])
            dispatch_state = validated.get('dispatch_state')
            if dispatch_state not in {'not-dispatched', 'intent-retained', 'started-recorded'}:
                raise OnboardingError('receiving_initial_dispatch_unobserved')
            record('validated', {key: value for key, value in validated.items() if key != 'dispatch_state'})
            if dispatch_state == 'not-dispatched':
                preservation_authorization(intent['owner']['preservation'], bounds['expires_at_ms'])
            if 'selected' not in effects():
                record('selected', root_call('bootstrap-select', fresh_effect=dispatch_state == 'not-dispatched',
                    request=intent['request']))
            if dispatch_state == 'not-dispatched':
                current = self.backend._target_call(plan, 'receiving-bootstrap-freeze', candidate=vector,
                    bootstrap_timeout_seconds=remaining(), bootstrap_initial_service=True)
                if {key: value for key, value in current.items() if key != 'observer_startup'} != intent['owner']:
                    raise OnboardingError('receiving_initial_owner_changed')
                # Selection can consume the remaining authority horizon. A
                # retained start intent, in contrast, is never fresh permission.
                preservation_authorization(intent['owner']['preservation'], bounds['expires_at_ms'])
            # The root primitive observes a retained first invocation after a
            # lost reply. Repeating this exact call never repeats StartUnit.
            recovery_request = effects().get('start_recovery_request')
            if start_recovery is not None:
                recovery_id, implementation = start_recovery
                if (not isinstance(recovery_id, str) or str(uuid.UUID(recovery_id)) != recovery_id
                        or not isinstance(implementation[1], str)
                        or re.fullmatch('[0-9a-f]{64}', implementation[1]) is None
                        or 'started' not in effects()
                        or 'controlled_loaded' in effects() and recovery_request is None
                        or dispatch_state != 'started-recorded'):
                    raise OnboardingError('receiving_guest_start_recovery_required')
                # Retain one exact recovery request before its Root observation.
                # Retry never substitutes a new process or a new expiry.
                if recovery_request is None:
                    actual = self.backend._target_call(plan, 'admitted-running', candidate=vector,
                        observation_timeout_seconds=remaining(), require_loaded=True)
                    physical = root_call('bootstrap-inspect', owner_observation={key: actual[key]
                        for key in ('process', 'admission_parent')})
                    recovery_request = record('start_recovery_request', dict(
                        schema='cluster-guest-start-recovery/v1', operation_id=recovery_id,
                        bootstrap=intent['request'], started_sha256=digest(effects()['started']),
                        successor={**{key: actual[key] for key in ('process', 'admission_parent')},
                            'service': physical['service']}, implementation_sha256=implementation[1],
                        expires_at_ms=bounds['expires_at_ms']))
                if (recovery_request['operation_id'] != recovery_id
                        or recovery_request['implementation_sha256'] != implementation[1]):
                    raise OnboardingError('receiving_guest_start_recovery_conflict')
                if 'start_recovery_receipt' not in effects():
                    receipt = root_call('bootstrap-recover-start', request=recovery_request,
                        implementation=implementation)
                    initial_start_projection(intent['request'], effects()['started'], recovery_request, receipt)
                    record('start_recovery_receipt', receipt)
            if recovery_request is None:
                started = record('started', root_call('bootstrap-start', fresh_effect=dispatch_state == 'not-dispatched',
                    request=intent['request']))
            else:
                started = initial_start_projection(intent['request'], effects()['started'],
                    recovery_request, effects().get('start_recovery_receipt'))
            if (started.get('schema') != 'cluster-guest-service-initial-start/v1'
                    or started['service']['unit_sha256'] != intent['unit_sha256']
                    or effects()['selected']['selected_sha256'] != intent['unit_sha256']):
                raise OnboardingError('receiving_initial_service_changed')
            observed = self.backend._target_call(plan, 'admitted-running', candidate=vector,
                observation_timeout_seconds=remaining(), require_loaded=True)
            root = root_call('bootstrap-inspect', owner_observation={key: observed[key]
                for key in ('process', 'admission_parent')})
            if (root['service'] != started['service']
                    or observed['admission_parent'] != started['admission_parent']
                    or recovery_request is not None and observed['process'] != recovery_request['successor']['process']):
                raise OnboardingError('receiving_initial_service_changed')
            result = dict(schema='cluster-guest-initial-loaded/v1', **guest_loaded_observation(
                observed, root, intent['owner'], dict(runtime_digest=vector[1], prepared=prepared),
                expected_runtime=intent['owner']['runtime_sha256'], unit_sha256=intent['unit_sha256'],
                manager=started['service']['manager'], dropins=started['service'].get('dropins', {}),
                initial_observation='controlled_loaded' not in effects()))
            remaining()
            record('controlled_loaded', result)
            remaining()
            self.registry.adopt_running(**{key: expected[key] for key in ('body_ref', 'embodiment_id', 'incarnation_id')})
            remaining()
            return result

    def complete_initial(self, plan: dict, cohort, *, timeout_seconds: float = 30) -> dict:
        """Select ordinary restart policy only after qualified cohort activation.

        Retain a committed physical handoff before rechecking receiving proof;
        a lost/expired later observation cannot turn it into another first start.
        Communication acceptance and portal completion remain separate.
        """
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 60:
            raise OnboardingError('receiving_host_deadline_required')
        deadline = time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
        with self._initial_scope(plan, cohort):
            return self._complete_initial_locked(plan, cohort, deadline=deadline)

    def _complete_initial_locked(self, plan: dict, cohort, *, deadline: int) -> dict:
        from .onboarding_service import unit_content
        from .onboarding_receiving_update import guest_loaded_observation
        from .operation_journal import JournalConflict
        from . import onboarding_group_recovery as recovery
        name = plan['name']
        def remaining():
            seconds = (deadline - time.monotonic_ns()) / 1_000_000_000
            if seconds <= 0:
                raise OnboardingError('receiving_host_deadline_expired')
            return seconds

        row = cohort._row()
        execution_grant = recovery.execution(cohort.journal, row, historical=True)
        # The original continuation covers this final activation step. The
        # post-membership approval names the remaining handoff separately.
        handoff_effect = ('steady-handoff' if execution_grant is not None
            and execution_grant['schema'] == recovery.REMAINING_SCHEMA else 'activation')
        activation_plan, manifest = cohort._activation(row)
        activation = (row['runtime_observation'] or {}).get('cohort_activation')
        if (activation is None or set(row['runtime_observation'].get('sender_selections', {})) != set(cohort.owners)):
            raise OnboardingError('receiving_cohort_selection_required')
        initial = cohort._initial_lifecycle(row, name, activation_plan['receivers'][name])
        intent, loaded = initial['intent'], initial['controlled_loaded']
        approved = cohort._admission(row)['receivers'][name]
        vector = Path(approved['candidate']['code']), approved['recipe']['prepared']['code_digest']
        argv = intent['request']['argv']
        index = argv.index('--initial-context-json')
        steady_sha256 = hashlib.sha256(unit_content(argv[:index] + argv[index + 2:])).hexdigest()

        def root_call(action, *, fresh_effect=False, **options):
            nonlocal deadline
            if fresh_effect:
                deadline = recovery.effect_deadline(cohort.journal, row, handoff_effect, deadline)
            dispatch = vector
            extra = {}
            if execution_grant is not None:
                helper = execution_grant['maintenance'][name]
                dispatch = Path(helper['code']), helper['code_digest']
                extra['owner_deadline_ns'] = deadline
                if fresh_effect:
                    extra['effect_not_after_ms'] = execution_grant['expires_at_ms']
            with (recovery.effect_scope(cohort.journal, row, handoff_effect, deadline_ns=deadline)
                    if fresh_effect else nullcontext()):
                return self.backend._guest_service_call(plan, action, candidate=dispatch,
                    timeout_seconds=remaining(), **extra, **options)

        def effect():
            return (cohort._row()['runtime_observation'] or {}).get('initial_steady', {}).get(name, {})

        def record(key, value):
            current = cohort._row()
            observations = dict(current['runtime_observation'] or {})
            steady = dict(observations.get('initial_steady', {}))
            receiver = dict(steady.get(name, {}))
            if key in receiver and receiver[key] != value:
                raise JournalConflict('receiving initial steady effect changed')
            receiver[key] = value
            steady[name] = receiver
            observations['initial_steady'] = steady
            cohort.journal.advance(cohort.operation_id, current['state'], runtime_observation=observations,
                expected_runtime_observation=current['runtime_observation'])
            remaining()
            return value

        def confirmed():
            with ExitStack() as scopes:
                scopes.enter_context(cohort._observation_scope())
                for owner in cohort.owners.values():
                    scopes.enter_context(cohort._owner_deadline(owner, deadline))
                current = cohort._row()
                if 'cohort_reassessment' in (current['runtime_observation'] or {}):
                    raise OnboardingError('receiving_cohort_reassessment_required')
                return cohort._confirmed_selection(current, activation_plan, manifest, activation)

        owner_observation = {key: loaded[key] for key in ('process', 'admission_parent')}
        physical = root_call('bootstrap-inspect', owner_observation=owner_observation)
        selected_sha256 = physical['service']['unit_sha256']
        if selected_sha256 not in {intent['unit_sha256'], steady_sha256}:
            raise OnboardingError('receiving_initial_service_changed')
        request = effect().get('intent')
        if selected_sha256 == intent['unit_sha256']:
            observed_at_ms = time.time_ns() // 1_000_000
            selection = confirmed()
            remaining()
            if request is None:
                request = record('intent', dict(schema='cluster-guest-service-steady/v1',
                    operation_id=intent['request']['operation_id'], plan_digest=digest(plan),
                    initial_request_sha256=digest(intent['request']), cohort_selection_sha256=digest(selection),
                    **owner_observation, not_after_ms=min(intent['request']['not_after_ms'],
                        observed_at_ms + activation_plan['observation_window_ms']),
                    **({'start_recovery_operation_id': initial['start_recovery_request']['operation_id']}
                        if 'start_recovery_request' in initial else {})))
            elif request['cohort_selection_sha256'] != digest(selection):
                raise OnboardingError('receiving_cohort_selection_changed')
        elif request is None:
            raise OnboardingError('receiving_initial_steady_intent_required')
        if (request['initial_request_sha256'] != digest(intent['request'])
                or request['operation_id'] != intent['request']['operation_id']
                or request['plan_digest'] != digest(plan)
                or any(request[key] != value for key, value in owner_observation.items())):
            raise OnboardingError('receiving_initial_binding_changed')
        # A retained completion is historical after expiry. File-only partial
        # progress still requires authority for the remaining reload.
        if selected_sha256 == intent['unit_sha256']:
            selected = root_call('bootstrap-steady', fresh_effect=True, request=request)
        else:
            # Validate reads the root's retained completion without changing
            # files or reloading. Selected bytes alone are only partial progress.
            observed = root_call('bootstrap-validate', request=request)
            if (observed.get('schema') != 'cluster-guest-service-steady-observation/v1'
                    or observed.get('request_sha256') != digest(request)
                    or observed.get('state') not in {'pending', 'completed'}):
                raise OnboardingError('receiving_initial_service_changed')
            if observed['state'] == 'pending':
                selected = root_call('bootstrap-steady', fresh_effect=True, request=request)
            else:
                selected = observed['result']
        if (selected.get('schema') != 'cluster-guest-service-steady-selection/v1'
                or selected['request_sha256'] != digest(request)
                or selected['service']['unit_sha256'] != steady_sha256
                or selected['selected']['previous_sha256'] != intent['unit_sha256']
                or any(selected[key] != value for key, value in owner_observation.items())):
            raise OnboardingError('receiving_initial_service_changed')
        # Retain the physical receipt before post-selection qualification.
        try:
            record('selected', selected)
            if 'cohort_reassessment' in (cohort._row()['runtime_observation'] or {}):
                raise OnboardingError('receiving_cohort_reassessment_required')
            observed = self.backend._target_call(plan, 'admitted-running', candidate=vector,
                observation_timeout_seconds=remaining(), require_loaded=True)
            root = root_call('bootstrap-inspect', owner_observation={key: observed[key]
                for key in ('process', 'admission_parent')})
            current_load = guest_loaded_observation(observed, root, intent['owner'],
                dict(runtime_digest=vector[1], prepared=approved['recipe']['prepared']),
                expected_runtime=intent['owner']['runtime_sha256'], unit_sha256=steady_sha256,
                manager=selected['service']['manager'], dropins=selected['service'].get('dropins', {}),
                initial_observation=False)
            if any(current_load[key] != value for key, value in loaded.items() if key != 'schema'):
                raise OnboardingError('receiving_initial_service_changed')
            selection = confirmed()
            if digest(selection) != request['cohort_selection_sha256']:
                raise OnboardingError('receiving_cohort_selection_changed')
            remaining()
            return record('completed', dict(schema='cluster-managed-initial-steady/v1',
                initial_sha256=digest(loaded), selected_sha256=steady_sha256,
                cohort_selection_sha256=digest(selection), loaded=current_load,
                receiving_readiness='qualified-local-projection', communication_acceptance='unobserved'))
        except (OnboardingError, OSError, KeyError, ValueError, TypeError):
            current = cohort._row()
            observations = dict(current['runtime_observation'] or {})
            if 'cohort_reassessment' not in observations:
                # Persist the repair obligation even when the invocation's
                # budget no longer permits contacting any receiving owner.
                observations['cohort_reassessment'] = {}
                cohort.journal.advance(cohort.operation_id, current['state'], runtime_observation=observations,
                    expected_runtime_observation=current['runtime_observation'])
                try:
                    with ExitStack() as scopes:
                        for owner in cohort.owners.values():
                            scopes.enter_context(cohort._owner_deadline(owner, deadline))
                        cohort._fence_partial_activation(activation)
                except (OnboardingError, OSError):
                    pass  # The retained reassessment remains explicitly pending.
            raise


def validate_code_update(spec: dict) -> dict:
    """One bounded operator request over existing jobs, placements and effects."""
    try:
        if (not isinstance(spec, dict) or set(spec) - {'reader_completion'} != {
                'schema', 'host_config', 'vm_qualification', 'candidate', 'targets', 'group', 'operation_id', 'max_seconds'}
                or spec['schema'] != 'cluster-native-code-maintenance/v1'
                or type(spec['max_seconds']) is not int or not 1 <= spec['max_seconds'] <= 480
                or not isinstance(spec['candidate'], dict)
                or set(spec['candidate']) != {'code', 'code_digest'}
                or re.fullmatch('[0-9a-f]{64}', spec['candidate']['code_digest']) is None
                or not isinstance(spec['targets'], list) or not 1 <= len(spec['targets']) <= 16
                or spec['group'] not in {'none', 'closed', 'published'}
                or str(uuid.UUID(spec['operation_id'])) != spec['operation_id']
                or not isinstance(spec['host_config'], str)
                or not isinstance(spec['candidate']['code'], str)):
            raise ValueError
        for path in (spec['host_config'], spec['candidate']['code'], spec['vm_qualification'],
                     spec.get('reader_completion')):
            if path is not None and (not isinstance(path, str) or not Path(path).is_absolute()
                    or '..' in Path(path).parts):
                raise ValueError
        names = set()
        for name in spec['targets']:
            if re.fullmatch('[a-z0-9][a-z0-9-]{0,30}', name) is None or name in names:
                raise ValueError
            names.add(name)
    except (TypeError, ValueError, AttributeError, KeyError):
        raise OnboardingError('native_code_maintenance_spec_required') from None
    return spec


class ReaderCommandClient:
    """Reuse protected owner CLI routes; no network listener or new authority."""

    def __init__(self, binding: dict, *, backend=None, plan=None):
        self.root = Path(binding['root'])
        self.command = binding['command']
        self.backend, self.plan = backend, plan
        self.deadline_ns: int | None = None
        self.expected: dict | None = None

    def _call(self, value: dict) -> dict:
        import subprocess
        from .onboarding_receiving_update import _run_owner
        if self.deadline_ns is None:
            raise OnboardingError('receiving_owner_deadline_binding_required')
        remaining = min(55.0, (self.deadline_ns - time.monotonic_ns()) / 1_000_000_000)
        if remaining <= 0:
            raise OnboardingError('receiving_owner_deadline_expired')
        try:
            argv = [*self.command, '--reader-rpc', '--max-seconds', str(remaining)]
            if self.backend is not None:
                from types import SimpleNamespace
                result = SimpleNamespace(returncode=0, stdout=self.backend.execute_body(self.plan,
                    argv, uid=1000, gid=1000, input_data=json.dumps(value),
                    timeout_seconds=remaining, deadline_ns=self.deadline_ns))
            else:
                result = _run_owner(argv, input=json.dumps(value), text=True,
                    capture_output=True, timeout=remaining)
            if time.monotonic_ns() >= self.deadline_ns:
                raise OnboardingError('receiving_owner_deadline_expired')
            if result.returncode and any(line.startswith('ModuleNotFoundError:')
                    for line in getattr(result, 'stderr', '').splitlines()):
                raise OnboardingError('receiving_reader_owner_import_unavailable')
            if result.returncode or len(result.stdout.encode()) > being_seed.MAX_SELECTION:
                raise ValueError
            observed = json.loads(result.stdout)
            if not isinstance(observed, dict) or 'error' in observed:
                raise ValueError
            return observed
        except OnboardingError:
            raise
        except (OSError, ValueError, subprocess.TimeoutExpired):
            raise OnboardingError('receiving_reader_owner_unavailable') from None

    def current_reader(self, **options):
        proof = self._call(dict(action='observe', options=options))
        if proof.get('expected', {}).get('selection') != options['expected_selection']:
            raise OnboardingError('receiving_cohort_selection_changed')
        self.expected = proof['expected']
        return proof

    def prepare_apply_control(self, command: dict, path: Path):
        if (self.expected is None or path != self.root / 'receiving-control' /
                (command['operation_id'] + '-' + command['phase'] + '.json')):
            raise OnboardingError('receiving_control_binding_conflict')
        return self._call(dict(action='control', command=command, expected=self.expected))


def load_code_update_readers(path: Path) -> dict:
    """Locators select existing owner CLIs; native signed rosters select members."""
    value = being_seed._read(path, limit=being_seed.MAX_SELECTION)
    if (not isinstance(value, dict) or set(value) - {'host_config','vm_qualification'} != {'schema', 'checkpoint', 'owners'}
            or value.get('schema') != 'cluster-maintenance-reader-routes/v1'
            or not isinstance(value['owners'], dict) or not 1 <= len(value['owners']) <= 256):
        raise OnboardingError('receiving_current_reader_binding_required')
    if ('vm_qualification' in value and 'host_config' not in value
            or 'host_config' in value and not isinstance(value['host_config'],str)):
        raise OnboardingError('receiving_current_reader_binding_required')
    for selected_path in (value.get('host_config'),value.get('vm_qualification')):
        if selected_path is not None and (not isinstance(selected_path,str)
                or not Path(selected_path).is_absolute() or '..' in Path(selected_path).parts):
            raise OnboardingError('receiving_current_reader_binding_required')
    checkpoint = Path(value['checkpoint'])
    if not checkpoint.is_absolute() or '..' in checkpoint.parts:
        raise OnboardingError('receiving_current_reader_binding_required')
    fields = {'receiving_code', 'matrix_sdk', 'runtime_bundle_sha256', 'application_sha256',
        'publication_sha256', 'visibility_installation_sha256'}
    for name, binding in value['owners'].items():
        if (re.fullmatch('[a-z0-9][a-z0-9-]{0,30}', name) is None
                or not isinstance(binding, dict)
                or set(binding) - {'job'} != {'root', 'command', 'selection', 'require_admitted'}
                or 'job' in binding and (not isinstance(binding['job'], str)
                    or re.fullmatch('[a-z0-9][a-z0-9-]{0,30}', binding['job']) is None)
                or type(binding['require_admitted']) is not bool
                or not isinstance(binding['root'], str) or not Path(binding['root']).is_absolute()
                or '..' in Path(binding['root']).parts
                or not isinstance(binding['command'], list) or not 1 <= len(binding['command']) <= 64
                or any(not isinstance(arg, str) or not 1 <= len(arg) <= 16384 or '\0' in arg
                    for arg in binding['command'])
                or not (binding['selection'] is None and 'job' in binding
                    or isinstance(binding['selection'], dict) and set(binding['selection']) == fields
                    and all(item is None and key == 'visibility_installation_sha256'
                        or isinstance(item, str) and re.fullmatch('[0-9a-f]{64}', item) is not None
                        for key, item in binding['selection'].items()))):
            raise OnboardingError('receiving_current_reader_binding_required')
    return value


def code_update_reader_clients(value: dict, *, backend=None, plans=None) -> dict:
    # Reader jobs can belong to a different existing registry than the bodies
    # being updated. Keep those plans/placements with their owning executor.
    if 'host_config' in value:
        names = {binding['job'] for binding in value['owners'].values() if 'job' in binding}
        if names:
            backend, plans = maintenance_backend(value['host_config'],value.get('vm_qualification'),names)
    clients = {}
    for name, binding in value['owners'].items():
        if 'job' in binding:
            if backend is None or plans is None or binding['job'] not in plans:
                raise OnboardingError('receiving_current_reader_binding_required')
            clients[name] = ReaderCommandClient(binding, backend=backend, plan=plans[binding['job']])
        else:
            clients[name] = ReaderCommandClient(binding)
    return clients


def complete_code_update_readers(value: dict, *, operation_id: str,
                                 release_digest: str, deadline_ns: int, backend=None, plans=None,
                                 updates: dict | None = None) -> dict:
    """Resolve existing owner routes once, then use the native cohort completer."""
    from .onboarding_receiving_update import refresh_current_readers
    from .onboarding_owner_control import _selection
    clients = code_update_reader_clients(value, backend=backend, plans=plans)
    selections = {name: row['selection'] for name, row in value['owners'].items()}
    for name, binding in value['owners'].items():
        receipt = (updates or {}).get(binding.get('job',name))
        if selections[name] is not None and receipt is None:
            continue
        if (not isinstance(receipt, dict) or receipt.get('operation_id') != operation_id
                or receipt.get('candidate_digest') != release_digest):
            raise OnboardingError('receiving_code_update_receipt_required')
        client = clients[name]
        client.deadline_ns = deadline_ns
        observed = client._call(dict(action='status'))
        selection = _selection(observed)
        if (observed.get('process') != receipt.get('process')
                or observed.get('server') != receipt.get('origin')
                or selection['receiving_code'] != release_digest
                or selection['runtime_bundle_sha256'] != receipt['runtime_sha256']):
            raise OnboardingError('receiving_cohort_selection_changed')
        selections[name] = selection
    return refresh_current_readers(clients, selections=selections,
        operation_id=operation_id, release_digest=release_digest, deadline_ns=deadline_ns,
        checkpoint=Path(value['checkpoint']), nonadmitted=frozenset(name for name, row in value['owners'].items()
            if not row['require_admitted']))


def maintenance_backend(host_config: str, vm_qualification: str | None, names) -> tuple:
    """Reuse current job placements for software and reader maintenance."""
    from .onboarding_host import HostBackend, HostConfig
    config = HostConfig.load(Path(host_config))
    jobs = JobStore(config.jobs)
    plans = {name: jobs._load(name)['plan'] for name in names}
    runner = None
    if vm_qualification is not None:
        from .vm_body import RemoteIncusRunner
        qualification = Path(vm_qualification)
        admitted = being_seed._read(qualification / 'receiving.json')
        placements = {name: (qualification / (name + '-placement.json'),
            admitted['results'][name]['placement_sha256']) for name in plans}
        def no_initial_publication(*_, **__):
            raise OnboardingError('native_code_maintenance_existing_body_required')
        runner = RemoteIncusRunner(placements, plans, publish=no_initial_publication)
    backend = HostBackend(config, run=runner)
    return backend, plans


def code_update_owned_stops(backend, plans: dict, spec: dict) -> set[str]:
    """Find exact retained operations that may own an unavailable reader."""
    admission = getattr(getattr(backend,'config',None),'admission',None)
    if admission is None:
        return set()
    settings = being_seed._read(admission)
    state = Path(settings['state'])
    if not state.is_absolute() or '..' in state.parts:
        raise OnboardingError('invalid_onboarding_managed_configuration')
    owned = set()
    for name,plan in plans.items():
        path = state/name/'native-code-update.json'
        if not path.exists():
            continue
        retained = being_seed._read(path)
        pins = retained.get('pins',{})
        if (pins.get('operation_id') == spec['operation_id']
                and pins.get('candidate_digest') == spec['candidate']['code_digest']
                and pins.get('plan_digest') == digest(plan)
                and retained.get('result') is None
                and ('quiesce' in retained.get('effects',{})
                    or retained.get('dispatching') in {'quiesce','migrate','select','start'})):
            owned.add(name)
    return owned


def run_code_update(spec: dict) -> dict:
    """Reuse the owner/unit journals; never create a second batch effect journal."""
    spec = validate_code_update(spec)
    deadline = time.monotonic_ns() + spec['max_seconds'] * 1_000_000_000
    reader_routes = (load_code_update_readers(Path(spec['reader_completion']))
        if spec.get('reader_completion') is not None else None)
    if reader_routes is not None:
        from .onboarding_receiving_update import preflight_reader_checkpoint
        preflight_reader_checkpoint(Path(reader_routes['checkpoint']), spec['operation_id'])
    backend, plans = maintenance_backend(spec['host_config'],spec['vm_qualification'],spec['targets'])
    if reader_routes is not None:
        # Resolve owning jobs/placements and probe their existing owner CLIs
        # before any lifecycle effect; signed rosters still qualify membership.
        owned_stops = code_update_owned_stops(backend,plans,spec)
        for name, client in code_update_reader_clients(reader_routes, backend=backend, plans=plans).items():
            client.deadline_ns = deadline
            if reader_routes['owners'][name].get('job',name) in owned_stops:
                continue  # Its native bootstrap revalidates and restores this exact operation.
            try:
                client._call(dict(action='status'))
            except Exception as error:
                from .onboarding import refusal_diagnostic
                return dict(schema='cluster-native-code-maintenance-result/v1', complete=False,
                    candidate_digest=spec['candidate']['code_digest'], targets=[], pending=spec['targets'],
                    receiving_readiness='unobserved', reader_completion=dict(name=name,
                        phase='owner-preflight', failure=refusal_diagnostic(error, stage='current-readers')))
    owner = ManagedRuntime(backend)
    candidate = (Path(spec['candidate']['code']), spec['candidate']['code_digest'])
    results = []
    for name in spec['targets']:
        # Code preparation and the existing owner operation share this body's
        #300s envelope and the SAME batch's absolute deadline. The former120s
        # cap expired during a real published update and forced avoidable recovery.
        target_deadline = min(deadline, time.monotonic_ns() + 300_000_000_000)
        phase = 'prepare'
        try:
            if time.monotonic_ns() >= target_deadline:
                raise OnboardingError('receiving_host_deadline_expired')
            if not backend.runtime_available(plans[name], candidate, prepare=True,
                    deadline_ns=target_deadline):
                raise OnboardingError('qualified_onboarding_candidate_mount_required')
            phase = 'update'
            remaining = (target_deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                raise OnboardingError('receiving_host_deadline_expired')
            value = owner.update_native_code(plans[name], candidate,
                operation_id=spec['operation_id'], timeout_seconds=min(300.0, remaining),
                receive_only_group=spec['group'] == 'closed', published_group=spec['group'] == 'published')
            results.append(dict(name=name, operation_id=spec['operation_id'], status='updated', result=value))
        except Exception as error:
            # A retained failure may include partial effects. Keep the original
            # operation ID: another invocation reconciles it, never reenrolls.
            from .onboarding import refusal_diagnostic
            results.append(dict(name=name, operation_id=spec['operation_id'], status='incomplete',
                phase=phase, failure=refusal_diagnostic(error, stage='native-code-maintenance')))
            break
    complete = len(results) == len(spec['targets']) and all(row['status'] == 'updated' for row in results)
    readers = None
    if complete and reader_routes is not None:
        try:
            readers = complete_code_update_readers(reader_routes,
                operation_id=spec['operation_id'], release_digest=candidate[1], deadline_ns=deadline,
                backend=backend, plans=plans, updates={row['name']: row['result'] for row in results})
        except Exception as error:
            from .onboarding import refusal_diagnostic
            readers = dict(failure=refusal_diagnostic(error, stage='current-readers'))
            complete = False
    return dict(schema='cluster-native-code-maintenance-result/v1', complete=complete,
        candidate_digest=candidate[1], targets=results,
        pending=spec['targets'][len(results):],
        receiving_readiness=readers['receiving_readiness'] if readers is not None and 'failure' not in readers
            else 'unobserved', **({'reader_completion': readers} if readers is not None else {}))


def run_native_profile_update(spec: dict, *, check_only: bool = False) -> dict:
    """Compose the native H8 owner with the SAME current-reader completer."""
    import json
    from . import onboarding_release
    from .rebirth_native import ProfileOwner, run_profile_maintenance
    from .onboarding_owner_control import _selection
    from .onboarding_receiving_update import preflight_reader_checkpoint, refresh_current_readers
    extras = {'reader_completion','host_config','vm_qualification'}
    core = {key:value for key,value in spec.items() if key not in extras}
    if not 1 <= core.get('max_seconds',0) <= 180:
        raise OnboardingError('native_code_maintenance_spec_required')
    deadline = time.monotonic_ns()+core['max_seconds']*1_000_000_000
    if spec.get('reader_completion') is None:
        return run_profile_maintenance(core,check_only=check_only,deadline_ns=deadline)
    routes = load_code_update_readers(Path(spec['reader_completion']))
    if not check_only:
        preflight_reader_checkpoint(Path(routes['checkpoint']),core['operation_id'])
    names = {binding['job'] for binding in routes['owners'].values() if 'job' in binding}
    if names:
        backend, plans = maintenance_backend(spec['host_config'],spec.get('vm_qualification'),names)
    else:
        backend, plans = None, None
    clients = code_update_reader_clients(routes,backend=backend,plans=plans)
    profile = ProfileOwner(Path(core['profile']))
    settings = json.loads(onboarding_release.regular(Path(profile.profile()['config']),uid=profile.uid))
    updated = [name for name,client in clients.items() if str(client.root) == settings['runtime_root']]
    if len(updated) != 1:
        raise OnboardingError('receiving_current_reader_binding_required')
    selections = {}
    from .operation_journal import OperationJournal
    retained_journal = OperationJournal.existing(Path(core['journal']))
    retained = None if retained_journal is None else retained_journal.get(core['operation_id'])
    for name,client in clients.items():
        client.deadline_ns = deadline
        expected = routes['owners'][name]['selection']
        if (name == updated[0] and retained is not None
                and retained['state'] != 'completed'
                and retained['intent'].get('native_profile_maintenance') == core
                and 'stop_intent' in (retained['runtime_observation'] or {})):
            # This exact operation may own a stopped service. Requiring its
            # live reader before resuming would prevent its own recovery.
            frozen = _selection(retained['expected_precondition']['receiving'])
            if expected is not None and expected != frozen:
                raise OnboardingError('receiving_cohort_selection_changed')
            selections[name] = frozen
            continue
        observed = _selection(client._call(dict(action='status')))
        if (name == updated[0] and retained is not None
                and retained['intent'].get('native_profile_maintenance') == core):
            if retained.get('result') is not None:
                expected = _selection(retained['result']['loaded'])
            elif observed['receiving_code'] == core['candidate']['code_digest']:
                expected = None  # The retained native operation revalidates this candidate below.
        if expected is not None and observed != expected:
            raise OnboardingError('receiving_cohort_selection_changed')
        selections[name] = observed
    result = run_profile_maintenance(core,check_only=check_only,deadline_ns=deadline)
    if check_only:
        return {**result,'reader_routes_observed':len(clients)}
    selections[updated[0]] = _selection(result['loaded'])
    result['reader_completion'] = refresh_current_readers(clients,selections=selections,
        operation_id=core['operation_id'],release_digest=core['candidate']['code_digest'],
        deadline_ns=deadline,checkpoint=Path(routes['checkpoint']),
        nonadmitted=frozenset(name for name,binding in routes['owners'].items() if not binding['require_admitted']))
    result['receiving_readiness'] = result['reader_completion']['receiving_readiness']
    return result


def main(argv=None) -> int:
    import argparse
    import os
    from .onboarding import refusal_diagnostic
    parser = argparse.ArgumentParser(description='Bounded code/SDK maintenance of existing admitted bodies')
    parser.add_argument('--spec', type=Path, required=True,
        help='retained root-owned private code or native-profile maintenance JSON')
    parser.add_argument('--check-only', action='store_true',
        help='Inspect a native-profile maintenance request without lifecycle effects')
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise OnboardingError('native_code_maintenance_root_required')
        spec = being_seed._read(args.spec, limit=65536)
        if spec.get('schema') == 'cluster-native-profile-maintenance/v1':
            result = run_native_profile_update(spec,check_only=args.check_only)
        else:
            if args.check_only:
                raise OnboardingError('native_code_maintenance_spec_required')
            result = run_code_update(spec)
        print(json.dumps(result))
        return 0 if result.get('complete') or result.get('qualified') else 1
    except Exception as error:
        print(json.dumps(dict(schema='cluster-native-code-maintenance-result/v1', complete=False,
            failure=refusal_diagnostic(error, stage='native-code-maintenance'))))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
