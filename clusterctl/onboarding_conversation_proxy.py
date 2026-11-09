"""Reconcile the selected Conversation listener through the existing Incus writer.

This is part of the existing Conversation stage, not another launcher. It owns
only the conversation-web device; a different existing device is preserved.
"""
from __future__ import annotations

import ipaddress
import json
import re

from . import being_seed
from .onboarding import Observation, OnboardingError, digest


def configuration(value):
    if not isinstance(value, dict) or not 1 <= len(value) <= 64:
        raise OnboardingError('conversation_proxy_configuration_required')
    result = {}
    listeners = set()
    for name, row in value.items():
        if (not isinstance(name, str) or not being_seed.NAME.fullmatch(name)
                or not isinstance(row, dict) or set(row) - {'vm'} != {'listen_host', 'listen_port'}
                or not isinstance(row['listen_host'], str)
                or type(row['listen_port']) is not int or not 1024 <= row['listen_port'] <= 65535):
            raise OnboardingError('conversation_proxy_configuration_required')
        try:
            address = ipaddress.ip_address(row['listen_host'])
        except ValueError:
            raise OnboardingError('conversation_proxy_configuration_required') from None
        if (not address.is_private or address.is_loopback or address.is_unspecified
                or address.is_multicast or address.is_link_local
                or str(address) != row['listen_host']):
            raise OnboardingError('conversation_proxy_configuration_required')
        if 'vm' in row:
            vm = row['vm']
            if (not isinstance(vm, dict) or set(vm) != {'nic', 'network', 'address'}
                    or any(not isinstance(vm[k], str) or not being_seed.NAME.fullmatch(vm[k])
                        for k in ('nic', 'network'))):
                raise OnboardingError('conversation_proxy_configuration_required')
            try:
                target = ipaddress.ip_address(vm['address'])
                if (str(target) != vm['address'] or target.version != 4 or address.version != 4
                        or not target.is_private or target.is_loopback or target.is_unspecified
                        or target.is_multicast or target.is_link_local or target == address):
                    raise ValueError
            except (ValueError, TypeError):
                raise OnboardingError('conversation_proxy_configuration_required') from None
        listener = (str(address), row['listen_port'])
        if listener in listeners:
            raise OnboardingError('conversation_proxy_configuration_required')
        listeners.add(listener)
        result[name] = dict(row)
    return result


def desired(listener, guest_port):
    if type(guest_port) is not int or not 1024 <= guest_port <= 65535:
        raise OnboardingError('conversation_proxy_configuration_required')
    host = listener['listen_host']
    if ':' in host:
        host = '[' + host + ']'
    target = listener['vm']['address'] if 'vm' in listener else '127.0.0.1'
    return dict(type='proxy', bind='host',
                listen=f'tcp:{host}:{listener["listen_port"]}',
                connect=f'tcp:{target}:{guest_port}',
                **({'nat': 'true'} if 'vm' in listener else {}))


def verify_vm_network(backend, plan, observed, listener, run):
    """NAT needs this own static NIC and the actual host gateway, not loopback."""
    vm = listener['vm']
    nic = observed.get('expanded_devices', {}).get(vm['nic'], {})
    if (nic.get('type') != 'nic' or nic.get('network') != vm['network']
            or nic.get('ipv4.address') != vm['address']):
        raise OnboardingError('conversation_proxy_vm_network_required')
    network = json.loads(run(['query', '/1.0/networks/' + vm['network']]))
    if network.get('managed') is not True or network.get('type') != 'bridge':
        raise OnboardingError('conversation_proxy_vm_network_required')
    try:
        gateway = ipaddress.ip_interface(network['config']['ipv4.address'])
        target = ipaddress.ip_address(vm['address'])
        if (gateway.version != 4 or target not in gateway.network
                or target in (gateway.ip, gateway.network.network_address, gateway.network.broadcast_address)
                or network['config'].get('ipv4.dhcp.gateway', str(gateway.ip)) != str(gateway.ip)):
            raise ValueError
    except (KeyError, ValueError, TypeError):
        raise OnboardingError('conversation_proxy_vm_network_required') from None
    # A VM guest's predictable Linux name need not equal the Incus device key
    # (actual Oliva: eth0 vs enp5s0). Bind its live interface through this NIC's
    # actual MAC, not by guessing a guest name or choosing any matching address.
    mac = nic.get('hwaddr', observed.get('config', {}).get('volatile.' + vm['nic'] + '.hwaddr'))
    if not isinstance(mac, str) or re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac) is None:
        raise OnboardingError('conversation_proxy_vm_network_required')
    state = json.loads(run(['query', '/1.0/instances/' + backend.instance(plan) + '/state']))
    interfaces = [(name, item) for name, item in state.get('network', {}).items()
        if isinstance(item.get('hwaddr'), str) and item['hwaddr'].lower() == mac.lower()]
    if len(interfaces) != 1:
        raise OnboardingError('conversation_proxy_vm_network_required')
    interface, live = interfaces[0]
    if not any(a.get('family') == 'inet' and a.get('address') == vm['address']
               for a in live.get('addresses', [])):
        raise OnboardingError('conversation_proxy_vm_network_required')
    raw = backend.execute_body(plan, ['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'default'],
        uid=0, gid=0, timeout_seconds=10)
    if len(raw.encode()) > 16384:
        raise OnboardingError('conversation_proxy_vm_network_required')
    routes = json.loads(raw)
    if (not isinstance(routes, list) or len(routes) != 1 or routes[0].get('gateway') != str(gateway.ip)
            or routes[0].get('dev') != interface or routes[0].get('dst') != 'default'):
        raise OnboardingError('conversation_proxy_vm_network_required')


def reconcile(backend, plan, request, *, apply):
    selected = backend.config.conversation_proxy_by_name
    if selected is None or plan['name'] not in selected:
        return None  # Existing unselected jobs retain their original contract.
    listener = configuration(selected)[plan['name']]
    device = desired(listener, request['port'])
    instance = backend.instance(plan)
    def run(argv):
        value = backend._dispatch(plan, argv)
        if len(value.encode()) > 262144:
            raise OnboardingError('conversation_proxy_observation_unavailable')
        return value
    try:
        observed = json.loads(run(['query', '/1.0/instances/' + instance]))
        expected_type = 'virtual-machine' if 'vm' in listener else 'container'
        if observed.get('type') != expected_type:
            raise OnboardingError('conversation_proxy_placement_unsupported')
        if 'vm' in listener:
            vm = listener['vm']
            if request.get('listen_host') != vm['address']:
                raise OnboardingError('conversation_proxy_vm_network_required')
            verify_vm_network(backend, plan, observed, listener, run)
        local = observed.get('devices', {}).get('conversation-web')
        effective = observed.get('expanded_devices', {}).get('conversation-web', local)
        if local is not None and local != device or effective is not None and effective != device:
            raise OnboardingError('existing_conversation_proxy_preserved')
        if effective == device:
            return Observation('complete')
        if not apply:
            return Observation('absent', safe_to_execute=True)
        if not backend.authorize(plan, digest(plan)):
            raise OnboardingError('host_authorization_required')
        from .homes.host import ensure_proxy
        ensure_proxy(run, instance, 'conversation-web', device)
        return Observation('complete')
    except OnboardingError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError):
        raise OnboardingError('conversation_proxy_observation_unavailable') from None
