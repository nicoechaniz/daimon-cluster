"""Reconcile the selected Conversation listener through the existing Incus writer.

This is part of the existing Conversation stage, not another launcher. It owns
only the conversation-web device; a different existing device is preserved.
"""
from __future__ import annotations

import ipaddress
import json

from . import being_seed
from .onboarding import Observation, OnboardingError, digest


def configuration(value):
    if not isinstance(value, dict) or not 1 <= len(value) <= 64:
        raise OnboardingError('conversation_proxy_configuration_required')
    result = {}
    listeners = set()
    for name, row in value.items():
        if (not isinstance(name, str) or not being_seed.NAME.fullmatch(name)
                or not isinstance(row, dict) or set(row) != {'listen_host', 'listen_port'}
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
    return dict(type='proxy', bind='host',
                listen=f'tcp:{host}:{listener["listen_port"]}',
                connect=f'tcp:127.0.0.1:{guest_port}')


def reconcile(backend, plan, request, *, apply):
    selected = backend.config.conversation_proxy_by_name
    if selected is None or plan['name'] not in selected:
        return None  # Existing unselected jobs retain their original contract.
    listener = configuration(selected)[plan['name']]
    device = desired(listener, request['port'])
    instance = backend.instance(plan)
    def run(argv):
        value = backend._dispatch(plan, argv)
        if len(value) > 262144:
            raise OnboardingError('conversation_proxy_observation_unavailable')
        return value
    try:
        observed = json.loads(run(['query', '/1.0/instances/' + instance]))
        if observed.get('type') != 'container':
            # VM forwarding has different Incus semantics; qualify it explicitly.
            raise OnboardingError('conversation_proxy_placement_unsupported')
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
    except (ValueError, KeyError, TypeError):
        raise OnboardingError('conversation_proxy_observation_unavailable') from None
