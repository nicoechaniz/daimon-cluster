"""Root-selected account metadata and independent receiving native login."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from . import being_seed
from .onboarding import Observation, OnboardingError, digest, private_directory
from .onboarding_actions import Actions, SCHEMA as ACTION_SCHEMA
from .onboarding_provider import SCHEMA
from .onboarding_service import publish


class ManagedAccount:
    def __init__(self, host):
        self.host, self.config = host, host.config

    def profile(self, plan: dict) -> dict:
        if self.config.accounts is None:
            raise OnboardingError('account_authorization_required')
        private_directory(self.config.accounts)
        value = being_seed._read(self.config.accounts / (plan['account_profile'] + '.json'))
        if (set(value) != {'schema', 'name', 'account_id'}
                or value.get('schema') != 'cluster-onboarding-account/v1'
                or value.get('name') != plan['account_profile']
                or not isinstance(value.get('account_id'), str)
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,160}', value['account_id'])):
            raise OnboardingError('account_authorization_required')
        return value

    def mount(self, plan: dict) -> dict:
        if self.config.views is None:
            raise OnboardingError('receiving_code_configuration_required')
        return dict(type='disk', source=str(self.config.views / digest(plan) / 'account-public'),
                    path='/home/agent/.onboarding-account', readonly='true', shift='true')

    def command(self, plan: dict, action: str) -> dict:
        _, code, _ = self.host._guest_paths(plan)
        launcher = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                    'from clusterctl.onboarding_provider import main;raise SystemExit(main())')
        identity = [] if action == 'install' else ['--user', '1000', '--group', '1000', '--env', 'HOME=/home/agent']
        output = self.host._dispatch(plan, ['exec', self.host.instance(plan), *identity, '--',
            'python3', '-B', '-I', '-c', launcher, str(code), action, '--code', str(code),
            '--plan', '/home/agent/.onboarding-input/plan.json'])
        value = json.loads(output)
        if (not isinstance(value, dict) or action != 'install' and (
                value.get('schema') != SCHEMA or value.get('plan_digest') != digest(plan))):
            raise OnboardingError('invalid_onboarding_observation')
        return value

    def _action(self, plan: dict, action: dict | None) -> None:
        if self.config.progress is None:
            raise OnboardingError('invalid_onboarding_host_configuration')
        Actions(self.config.progress, worker_uid=os.geteuid()).publish(dict(schema=ACTION_SCHEMA,
            name=plan['name'], owner=plan['owner'], plan_digest=digest(plan), action=action))

    def observe(self, plan: dict) -> Observation:
        try:
            profile = self.profile(plan)
        except FileNotFoundError:
            return Observation('waiting', reason='account_authorization_required')
        if not self.host._mounted(plan, {'onboarding-account-public': self.mount(plan)}):
            return Observation('absent', safe_to_execute=True)
        value = self.command(plan, 'observe')
        self._action(plan, value.get('action'))
        if value.get('authorized') is not True:
            return (Observation('waiting', reason='account_authorization_required') if value.get('login_running')
                    else Observation('absent', safe_to_execute=True))
        if value.get('account_id') != profile['account_id']:
            return Observation('waiting', reason='account_authorization_required')
        receipt = value.get('probe_receipt')
        if receipt is None:
            return Observation('absent', safe_to_execute=True)
        if (not isinstance(receipt, dict) or receipt.get('schema') != SCHEMA
                or receipt.get('plan_digest') != digest(plan) or receipt.get('provider_verified') is not True):
            raise OnboardingError('invalid_onboarding_observation')
        # Both proofs are required. A successful provider probe and listening
        # SSH unit do not establish an actual receiving human CLI session.
        return Observation('waiting', reason='human_contact_required')

    def execute(self, plan: dict) -> None:
        profile, mount = self.profile(plan), self.mount(plan)
        source = Path(mount['source'])
        being_seed._path(source)
        source.mkdir(mode=0o755, exist_ok=True)
        publish(source / 'profile.json', json.dumps(profile, sort_keys=True).encode(), mode=0o644)
        if not self.host._mounted(plan, {'onboarding-account-public': mount}):
            self.host._dispatch(plan, ['config', 'device', 'add', self.host.instance(plan),
                'onboarding-account-public', 'disk', *[key + '=' + value for key, value in mount.items() if key != 'type']])
        value = self.command(plan, 'observe')
        if value.get('authorized'):
            if value.get('account_id') != profile['account_id']:
                raise OnboardingError('account_authorization_required')
            self.command(plan, 'probe')
        else:
            self.command(plan, 'install')
