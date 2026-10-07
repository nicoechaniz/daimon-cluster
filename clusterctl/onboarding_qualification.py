"""Delete only explicitly marked disposable receiving qualification resources."""
from __future__ import annotations

import json

from .onboarding import OnboardingError, digest, validate_plan
from .onboarding_host import HostBackend


def cleanup_disposable(backend: HostBackend, plan: dict) -> None:
    plan = validate_plan(plan)
    if not plan['name'].startswith('qualify-') or not backend.authorize(plan, digest(plan)):
        raise OnboardingError('disposable_qualification_authorization_required')
    instances, volumes = backend._inventory()
    name = backend.instance(plan)
    rows = [row for row in instances if row.get('name') == name]
    homes = [row for row in volumes if row.get('name') == name + '-home' and row.get('type') == 'custom']
    if len(rows) > 1 or len(homes) > 1:
        raise OnboardingError('disposable_qualification_conflict')
    if rows and rows[0].get('config', {}).get('user.dm.onboarding-disposable') != digest(plan):
        raise OnboardingError('disposable_qualification_marker_required')
    if homes:
        volume = json.loads(backend.run(['query', '/1.0/storage-pools/' + backend.config.pool
                                        + '/volumes/custom/' + name + '-home']))
        if volume.get('config', {}).get('user.dm.onboarding-disposable') != digest(plan):
            raise OnboardingError('disposable_qualification_marker_required')
    # The same resource observations used by provisioning verify quota, image,
    # host grant and attachment before deleting either independently owned item.
    if backend._environment(plan).state not in {'absent', 'complete'}:
        raise OnboardingError('disposable_qualification_conflict')
    if rows:
        backend._dispatch(plan, ['delete', name, '--force'])
    if homes:
        backend._dispatch(plan, ['storage', 'volume', 'delete', backend.config.pool, name + '-home'])
