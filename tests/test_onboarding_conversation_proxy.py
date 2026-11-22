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


def vm_fixture():
    backend, value, state, calls, _ = fixture()
    listener = dict(listen_host='10.20.30.40', listen_port=18741,
        vm=dict(nic='eth0', network='incusbr0', address='10.100.0.10'))
    backend.config.conversation_proxy_by_name = {'eko': listener}
    device = desired(listener, 8800)
    state.update(type='virtual-machine', expanded_devices={'eth0': dict(type='nic',
        network='incusbr0', name='eth0', hwaddr='00:16:3e:00:00:11', **{'ipv4.address':'10.100.0.10'})})
    network = dict(managed=True, type='bridge', config={'ipv4.address':'10.100.0.1/24'})
    live = dict(network={'ens3': dict(hwaddr='00:16:3e:00:00:11', addresses=[dict(family='inet',address='10.100.0.10')])})
    routes = [dict(dst='default',gateway='10.100.0.1',dev='ens3')]
    def dispatch(_plan, argv):
        calls.append(argv)
        if argv == ['query','/1.0/networks/incusbr0']:
            return json.dumps(network)
        if argv == ['query','/1.0/instances/dm-eko/state']:
            return json.dumps(live)
        if argv[0] == 'query':
            return json.dumps(state)
        assert argv[:5] == ['config','device','add','dm-eko','conversation-web']
        state['devices']['conversation-web']=copy.deepcopy(device)
        state['expanded_devices']['conversation-web']=copy.deepcopy(device)
        return ''
    def execute(plan, argv, **kwargs):
        assert plan==value and argv==['/usr/sbin/ip','-j','-4','route','show','default']
        assert kwargs==dict(uid=0,gid=0,timeout_seconds=10)
        return json.dumps(routes)
    backend._dispatch=dispatch
    backend.execute_body=execute
    request=dict(port=8800,listen_host='10.100.0.10')
    return backend,value,state,calls,device,request,network,live,routes


def test_vm_nat_reuses_proxy_writer_and_recovers_lost_reply_without_rewrite():
    backend,value,state,calls,device,request,*_=vm_fixture()
    assert device['nat']=='true' and device['connect']=='tcp:10.100.0.10:8800'
    assert reconcile(backend,value,request,apply=False).state=='absent'
    original=backend._dispatch
    def lost(plan,argv):
        result=original(plan,argv)
        if argv[0]=='config':
            raise TimeoutError('lost retained NAT add reply')
        return result
    backend._dispatch=lost
    with pytest.raises(TimeoutError):
        reconcile(backend,value,request,apply=True)
    assert reconcile(backend,value,request,apply=True).state=='complete'
    assert sum(c[0]=='config' for c in calls)==1


@pytest.mark.parametrize('gap', ['nic','static','managed','gateway','route','live','listener','mac'])
def test_vm_nat_requires_actual_own_static_nic_live_ip_and_host_gateway(gap):
    backend,value,state,calls,_,request,network,live,routes=vm_fixture()
    if gap=='nic':
        state['expanded_devices']['eth0']['network']='foreign'
    if gap=='static':
        state['expanded_devices']['eth0'].pop('ipv4.address')
    if gap=='managed':
        network['managed']=False
    if gap=='gateway':
        network['config']['ipv4.dhcp.gateway']='10.100.0.2'
    if gap=='route':
        routes[0]['gateway']='10.100.0.2'
    if gap=='live':
        live['network']['ens3']['addresses']=[]
    if gap=='listener':
        request.pop('listen_host')
    if gap=='mac':
        live['network']['ens3']['hwaddr']='00:16:3e:00:00:22'
    with pytest.raises(OnboardingError,match='conversation_proxy_vm_network_required'):
        reconcile(backend,value,request,apply=True)
    assert all(c[0]=='query' for c in calls) and state['devices']=={}


@pytest.mark.parametrize('address',['127.0.0.1','0.0.0.0','8.8.8.8','10.20.30.40','fe80::1','::1'])
def test_vm_nat_configuration_never_selects_loopback_public_or_wildcard_target(address):
    backend,*_=vm_fixture()
    backend.config.conversation_proxy_by_name['eko']['vm']['address']=address
    with pytest.raises(OnboardingError,match='conversation_proxy_configuration_required'):
        configuration(backend.config.conversation_proxy_by_name)
