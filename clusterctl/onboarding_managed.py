"""Worker reconciliation of configured admission, guest service and registry."""
from __future__ import annotations

from pathlib import Path

from . import being_seed, onboarding_admission, onboarding_mounts
from .admission import AdmissionEndpoint
from .embodiments import Registry
from .fences import Ed25519Signer
from .onboarding import Observation, OnboardingError, digest, private_directory
from .onboarding_custody import FirstCustody
from .onboarding_service import UNIT
from .production_fences import ed25519_fingerprint


class ManagedRuntime:
    def __init__(self, backend):
        self.backend = backend
        config = backend.config
        self.settings = being_seed._read(config.admission)
        value = self.settings
        fields = {'schema', 'host_port', 'guest_port', 'authority_key_id', 'authority_public_key',
                  'registrar_key_id', 'registrar_key', 'registry', 'state', 'visibility_installation'}
        if (set(value) != fields or value['schema'] != 'cluster-onboarding-managed-runtime/v1'
                or any(type(value[key]) is not int or not 1 <= value[key] <= 65535
                       for key in ('host_port', 'guest_port'))
                or any(not isinstance(value[key], str) or not value[key]
                       for key in ('authority_key_id', 'registrar_key_id'))):
            raise OnboardingError('invalid_onboarding_managed_configuration')
        ed25519_fingerprint(value['authority_public_key'])
        for key in ('registrar_key', 'registry', 'state'):
            if not isinstance(value[key], str) or not Path(value[key]).is_absolute():
                raise OnboardingError('invalid_onboarding_managed_configuration')
        self.registry = Registry(private_directory(Path(value['registry'])))
        self.state = private_directory(Path(value['state']))
        visibility = value['visibility_installation']
        if visibility is not None and (not isinstance(visibility, str)
                or not Path(visibility).is_absolute() or '..' in Path(visibility).parts
                or not Path(visibility).is_relative_to('/home/agent')):
            raise OnboardingError('invalid_onboarding_managed_configuration')

    def _ready(self, plan: dict) -> bool:
        return self.settings['visibility_installation'] is not None or (
            self.backend.config.qualification and plan['name'].startswith('qualify-'))

    def _expected(self, plan: dict) -> dict:
        config = self.backend.config
        return FirstCustody(config.custody, config.custody_grants).admission_coordinates(plan)

    def _proxy(self) -> dict:
        return dict(type='proxy', bind='instance', listen='tcp:127.0.0.1:' + str(self.settings['guest_port']),
                    connect='tcp:127.0.0.1:' + str(self.settings['host_port']))

    def _check_proxy(self, plan: dict) -> bool:
        rows, _ = self.backend._inventory()
        row = next(row for row in rows if row.get('name') == self.backend.instance(plan))
        current = row.get('expanded_devices', {}).get('onboarding-admission')
        if current is not None and current != self._proxy():
            raise OnboardingError('foreign_onboarding_admission_proxy_preserved')
        return current is not None

    def _registered(self, expected: dict) -> bool:
        identifier = expected['embodiment_id']
        rows = self.registry.load()['embodiments']
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
        presence = self.backend._target_call(plan, 'admitted-running')
        if (presence.get('schema') != 'cluster-onboarding-runtime-presence/v1'
                or presence.get('plan_digest') != digest(plan)
                or any(presence.get('origin', {}).get(key) != expected[key]
                       for key in ('body_ref', 'embodiment_id', 'incarnation_id'))
                or presence.get('process', {}).get('pid') == int(values['MainPID'])):
            raise OnboardingError('onboarding_managed_presence_rejected')
        if not registered:
            return Observation('absent', safe_to_execute=True)
        return Observation('complete', dict(verified=True, identity_verified=True))

    def execute(self, plan: dict) -> None:
        if not self._ready(plan):
            raise OnboardingError('onboarding_visibility_selection_required')
        expected = self._expected(plan)
        self._registered(expected)  # Refuse foreign canonical state before launch.
        if not self._check_proxy(plan):
            proxy = self._proxy()
            self.backend._dispatch(plan, ['config', 'device', 'add', self.backend.instance(plan),
                'onboarding-admission', 'proxy', *[key + '=' + value for key, value in proxy.items() if key != 'type']])
        configuration = self._profile(plan)
        root = self.state / digest(plan)
        if configuration is None:
            candidate = root / 'candidate.json'
            configuration = being_seed._read(candidate) if candidate.exists() else None
            registered = (configuration is not None and self.backend._target_call(plan, 'admission-check',
                profile=configuration).get('registered') is True)
            if not registered:
                request = self.backend._target_call(plan, 'admission-prepare')
                registrar = Ed25519Signer(self.settings['registrar_key'], self.settings['registrar_key_id'])
                configuration = onboarding_admission.profile(plan, request, expected, registrar,
                    endpoint=AdmissionEndpoint.network('127.0.0.1', self.settings['guest_port']),
                    authority_key_id=self.settings['authority_key_id'],
                    authority_public_key=self.settings['authority_public_key'])
                # Preserve every signed proposal; the pointer is only local progress.
                being_seed._write(root / ('profile-' + digest(configuration) + '.json'), configuration)
                being_seed._write(candidate, configuration)
                if self.backend._target_call(plan, 'admission-enroll', profile=configuration) != {'registered': True}:
                    raise OnboardingError('onboarding_admission_not_current')
            assert configuration is not None
            being_seed._write(root / 'confirmed.json', configuration)
        assert configuration is not None
        onboarding_mounts.prepare_matrix_public(self.backend.config.views, plan, {'admission.json': configuration})
        _, code, _ = self.backend._guest_paths(plan)
        launcher = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                    'from clusterctl.onboarding_service import main;raise SystemExit(main())')
        selection = (['--receive-only'] if self.settings['visibility_installation'] is None else
                     ['--visibility-installation', self.settings['visibility_installation']])
        self.backend._dispatch(plan, ['exec', self.backend.instance(plan), '--', 'python3', '-B', '-I', '-c',
            launcher, str(code), '--code', str(code), '--plan', '/home/agent/.onboarding-input/plan.json', *selection])
        # Observe authenticated, admitted presence before committing canonical state.
        presence = self.backend._target_call(plan, 'admitted-running')
        origin = presence['origin']
        if any(origin.get(key) != expected[key] for key in ('body_ref', 'embodiment_id', 'incarnation_id')):
            raise OnboardingError('onboarding_managed_presence_rejected')
        self.registry.adopt_running(**{key: expected[key] for key in ('body_ref', 'embodiment_id', 'incarnation_id')})
