"""Device approval stays on the private owner's surface, with no host authority."""
import dataclasses
import os
import time

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_actions import Actions, DEVICE_URL, SCHEMA, validate
from tests.test_being_seed import KEY, http_server
from tests.test_onboarding import plan


def action():
    return dict(schema=SCHEMA, name='eko', owner='sai', plan_digest=digest(plan()),
                action=dict(kind='openai-device-login', verification_uri=DEVICE_URL,
                            user_code='ABCD-EFGHI', deadline_ms=int(time.time() * 1000) + 60000))


def test_private_http_action_owner_scope_no_store_expiry_and_clearing(tmp_path):
    state, progress = tmp_path / 'state', tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    with http_server(state) as (server, request):
        being_seed.create(state, dict(name='eko', label='Eko', mode='import'), owner='sai', key=KEY)
        server.deps = dataclasses.replace(server.deps, seed_only=True,
            onboarding_progress=str(progress), onboarding_worker_uid=os.geteuid())
        publisher = Actions(progress, worker_uid=os.geteuid())
        value = action()
        publisher.publish(value)
        endpoint = '/v1/seeds/eko/onboarding/action'
        assert request(endpoint, owner='ani')[0] == 404
        assert request(endpoint, owner='reader')[0] == 403
        status, headers, result = request(endpoint, owner='sai')
        assert status == 200 and headers['Cache-Control'] == 'no-store'
        assert result == value
        assert request(endpoint, 'POST', {}, owner='sai')[0] == 405
        publisher.publish({**value, 'action': {**value['action'], 'deadline_ms': 0}})
        assert request(endpoint, owner='sai')[2]['action'] is None
        publisher.publish({**value, 'action': None})
        assert request(endpoint, owner='sai')[2]['action'] is None
        assert 'ABCD-EFGHI' not in str(request('/v1/seeds', owner='sai')[2])


@pytest.mark.parametrize('change', [dict(verification_uri='https://untrusted.example/device'),
    dict(access_token='secret fixture'), dict(user_code='not a native code'), dict(deadline_ms=True)])
def test_action_rejects_extra_credentials_foreign_uri_and_bad_codes(change):
    value = action()
    with pytest.raises(OnboardingError, match='invalid_onboarding_owner_action'):
        validate({**value, 'action': {**value['action'], **change}})
