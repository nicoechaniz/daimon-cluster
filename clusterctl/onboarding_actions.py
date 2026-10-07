"""Owner-authenticated device approval, separate from redacted job progress."""
from __future__ import annotations

import re

from . import being_seed
from .onboarding import OnboardingError
from .onboarding_progress import Progress

SCHEMA = 'cluster-onboarding-owner-action/v1'
DEVICE_URL = 'https://auth.openai.com/codex/device'


def validate(value: object) -> dict:
    if (not isinstance(value, dict) or set(value) != {'schema', 'name', 'owner', 'plan_digest', 'action'}
            or value.get('schema') != SCHEMA
            or any(not isinstance(value[key], str) or not being_seed.NAME.fullmatch(value[key])
                   for key in ('name', 'owner'))
            or not isinstance(value['plan_digest'], str) or not re.fullmatch(r'[a-f0-9]{64}', value['plan_digest'])):
        raise OnboardingError('invalid_onboarding_owner_action')
    action = value['action']
    if action is not None and (
            not isinstance(action, dict) or set(action) != {'kind', 'verification_uri', 'user_code', 'deadline_ms'}
            or action.get('kind') != 'openai-device-login' or action.get('verification_uri') != DEVICE_URL
            or not isinstance(action.get('user_code'), str)
            or not re.fullmatch(r'[A-Z0-9]{4,6}-[A-Z0-9]{4,6}', action['user_code'])
            or type(action.get('deadline_ms')) is not int or action['deadline_ms'] < 0):
        raise OnboardingError('invalid_onboarding_owner_action')
    return value


class Actions(Progress):
    suffix = '.action.json'
    validate = staticmethod(validate)
