import copy
import json
from types import SimpleNamespace

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_conversation_proxy import configuration, desired, reconcile
from tests.test_onboarding import plan


def fixture():
    value = plan(browser=False)
    listener = dict(listen_host='10.20.30.40', listen_port=18741)
    device = desired(listener, 8800)
    state = dict(type='container', devices={}, expanded_devices={})
    calls = []
    def dispatch(_plan, argv):
        calls.append(argv)
        if argv[0] == 'query':
            return json.dumps(state)
        assert argv[:5] == ['config', 'device', 'add', 'dm-eko', 'conversation-web']
        state['devices']['conversation-web'] = copy.deepcopy(device)
        state['expanded_devices']['conversation-web'] = copy.deepcopy(device)
        return ''
    backend = SimpleNamespace(config=SimpleNamespace(conversation_proxy_by_name={'eko': listener}),
        instance=lambda p: 'dm-'+p['name'], _dispatch=dispatch, authorize=lambda p, pin: True)
    return backend, value, state, calls, device


def test_absent_proxy_is_observed_then_same_existing_writer_reconciles_lost_reply():
    backend, value, state, calls, device = fixture()
    observed = reconcile(backend, value, {'port': 8800}, apply=False)
    assert observed.state == 'absent' and observed.safe_to_execute
    assert all(c[0] == 'query' for c in calls)
    original = backend._dispatch
    def lose_add_reply(plan, argv):
        result = original(plan, argv)
        if argv[0] == 'config':
            raise TimeoutError('Reply lost after the fixture added the selected device')
        return result
    backend._dispatch = lose_add_reply
    with pytest.raises(TimeoutError):
        reconcile(backend, value, {'port': 8800}, apply=True)
    assert state['devices']['conversation-web'] == device
    assert reconcile(backend, value, {'port': 8800}, apply=True).state == 'complete'
    assert sum(c[0] == 'config' for c in calls) == 1


@pytest.mark.parametrize('inherited', [False, True])
def test_foreign_proxy_is_preserved_without_mutation(inherited):
    backend, value, state, calls, device = fixture()
    state['expanded_devices' if inherited else 'devices']['conversation-web'] = dict(device, connect='tcp:127.0.0.1:9999')
    before = copy.deepcopy(state)
    with pytest.raises(OnboardingError, match='existing_conversation_proxy_preserved'):
        reconcile(backend, value, {'port': 8800}, apply=True)
    assert state == before and all(c[0] == 'query' for c in calls)


def test_existing_inherited_match_is_not_overridden_and_vm_needs_own_adapter():
    backend, value, state, calls, device = fixture()
    state['expanded_devices']['conversation-web'] = device
    assert reconcile(backend, value, {'port': 8800}, apply=True).state == 'complete'
    assert 'conversation-web' not in state['devices']
    state['type'] = 'virtual-machine'
    with pytest.raises(OnboardingError, match='conversation_proxy_placement_unsupported'):
        reconcile(backend, value, {'port': 8800}, apply=True)
    assert all(c[0] == 'query' for c in calls)


def test_revocation_and_unselected_old_jobs_never_create_listener():
    backend, value, state, calls, _ = fixture()
    backend.authorize = lambda p, pin: False
    with pytest.raises(OnboardingError, match='host_authorization_required'):
        reconcile(backend, value, {'port': 8800}, apply=True)
    assert state['devices'] == {} and all(c[0] == 'query' for c in calls)
    backend.config.conversation_proxy_by_name = None
    calls.clear()
    assert reconcile(backend, value, {'port': 8800}, apply=True) is None
    assert calls == []


@pytest.mark.parametrize('host', ['0.0.0.0', '127.0.0.1', '::', '::1', 'example.com', '8.8.8.8', 'fe80::1'])
def test_listener_requires_explicit_private_non_wildcard_address(host):
    with pytest.raises(OnboardingError, match='conversation_proxy_configuration_required'):
        configuration({'eko': dict(listen_host=host, listen_port=18741)})


def test_duplicate_listener_and_boolean_port_refused():
    with pytest.raises(OnboardingError):
        configuration({'eko':dict(listen_host='10.0.0.1',listen_port=True)})
    with pytest.raises(OnboardingError):
        configuration({name:dict(listen_host='10.0.0.1',listen_port=18741) for name in ['eko', 'other']})
