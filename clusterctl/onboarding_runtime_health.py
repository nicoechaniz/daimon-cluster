"""Register authorized hosted resources with the existing host Alerts observer.

No guest credentials, peer attention, model turns or conversation recovery.
The host retains its own receiving scope and delivery route.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from . import being_seed, onboarding_release
from .onboarding import OnboardingError, digest, private_directory

SCHEMA = 'cluster-runtime-health-enrollment/v1'


def reconcile(directory: Path | None, store, backend, result: dict) -> dict:
    if directory is None or 'telegram' not in result.get('completed_steps', []):
        return dict(enrolled=False)
    if not isinstance(result.get('name'), str) or not being_seed.NAME.fullmatch(result['name']):
        raise OnboardingError('runtime_health_enrollment_refused')
    marker = directory / ('.failure-' + result['name'])
    try:
        value = _register(directory, store, backend, result)
    except (OSError, ValueError, KeyError, TypeError):
        # Independent operational failure, never rewrite completed onboarding.
        # The existing host observer reads this marker and publishes an alert.
        private_directory(directory)
        with being_seed._locked(directory):
            if not marker.exists():
                being_seed._write(marker, dict(reason='enrollment_unavailable'))
        raise
    with being_seed._locked(directory):
        if marker.exists():
            onboarding_release.regular(marker, uid=os.geteuid(), limit=4096)
            marker.unlink()
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    return value


def _register(directory, store, backend, result):
    record = store._load(result['name'])
    plan = record['plan']
    if (record['plan_digest'] != result['plan_digest']
            or record['steps']['telegram']['state'] != 'complete'
            or not backend.authorize(plan, digest(plan))):
        raise OnboardingError('runtime_health_enrollment_refused')
    private_directory(directory)
    value = dict(schema=SCHEMA, name=plan['name'], instance=backend.instance(plan),
                 resource_ref='container-' + backend.instance(plan), plan_digest=digest(plan))
    path = directory / (plan['name'] + '.json')
    with being_seed._locked(directory):
        if path.exists():
            if json.loads(onboarding_release.regular(path, uid=os.geteuid(), limit=4096)) != value:
                raise OnboardingError('runtime_health_enrollment_preserved')
        else:
            if len(list(directory.glob('*.json'))) >= 16:
                raise OnboardingError('runtime_health_capacity_exceeded')
            being_seed._write(path, value)
    return dict(enrolled=True)
