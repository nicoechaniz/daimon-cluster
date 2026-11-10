"""Own-service deployment through explicit operator capabilities, disabled by default."""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import subprocess
from urllib.parse import quote, urlsplit

from ..operation_journal import OperationJournal
from ..onboarding_conversation_routes import Routes, LIMIT, configuration as route_configuration
from .policy import validate_audience
from .service_package import (MAX_ARCHIVE, RESERVED, canonical, closed, exact, path,
                              request, sha, unpack)
from .service_runtime import receiver, key


@closed
def configuration(value):
    exact(value, 'schema state grants', 'invalid_service_deploy_configuration')
    if value['schema'] != 'dm.home-service-capabilities/v1':
        raise ValueError('invalid_service_deploy_configuration')
    path(value['state'])
    if not isinstance(value['grants'], list) or len(value['grants']) > 32:
        raise ValueError('service_grant_capacity')
    identities, prefixes, listeners, units, route_states, locations = set(), set(), set(), set(), set(), []
    for g in value['grants']:
        exact(g, 'receiver prefix upstream command route_command routes auth_backend', 'invalid_service_grant')
        c = receiver(g['receiver'])
        if not re.fullmatch(r'/[a-z][a-z0-9-]{0,47}/', g['prefix']) or g['prefix'].strip('/') in RESERVED:
            raise ValueError('service_reserved_prefix')
        # Hostnames, upstreams, ports and transports are operator input only.
        upstream = urlsplit('http://' + g['upstream'])
        auth = urlsplit(g['auth_backend'])
        try:
            address = ipaddress.ip_address(upstream.hostname or '')
            if (not address.is_private or address.is_unspecified or address.is_multicast
                    or upstream.port is None or not 1024 <= upstream.port <= 65535
                    or upstream.netloc != g['upstream']
                    or any(ord(ch) < 33 for ch in g['upstream'] + g['auth_backend'])
                    or upstream.path or upstream.username or upstream.password or upstream.query or upstream.fragment
                    or auth.scheme != 'http' or auth.hostname != '127.0.0.1'
                    or auth.port is None or not 1024 <= auth.port <= 65535
                    or auth.username or auth.password or auth.path or auth.query or auth.fragment):
                raise ValueError
        except ValueError:
            raise ValueError('service_fixed_private_upstream_required') from None
        for command in (g['command'], g['route_command']):
            if (not isinstance(command, list) or not 1 <= len(command) <= 24
                    or any(not isinstance(a, str) or not a or any(ord(ch) < 32 for ch in a) for a in command)):
                raise ValueError('service_fixed_executor_required')
            path(command[0])
        route_configuration(g['routes'])
        for field in ('root', 'code', 'data'):
            candidate = path(c[field])
            if any(machine == c['machine_sha256'] and (
                    candidate.is_relative_to(old) or old.is_relative_to(candidate)) for machine, old in locations):
                raise ValueError('service_capability_storage_collision')
            locations.append((c['machine_sha256'], candidate))
        identity = (c['home'], c['service'])
        prefix = (c['home'], g['prefix'])
        unit = (c['machine_sha256'], c['root'])
        listener = (c['machine_sha256'], c['port'])
        if (identity in identities or prefix in prefixes or unit in units or listener in listeners
                or g['routes']['state'] in route_states):
            raise ValueError('service_capability_collision')
        identities.add(identity)
        prefixes.add(prefix)
        units.add(unit)
        listeners.add(listener)
        route_states.add(g['routes']['state'])
    return value


class ServiceRoutes(Routes):
    @staticmethod
    def render(request, listener, home_backend):
        name, origin = request['name'], request['origin']
        host = urlsplit(origin).netloc
        if not re.fullmatch(r'[a-z0-9.-]+', host):
            raise ValueError('service_origin_denied')
        prefix, upstream, auth = listener['prefix'], listener['upstream'], listener['auth_backend']
        # Forward-auth is enforced for every request, independent of Node code.
        # Never forward spoofed actor identity or the operator owner credential.
        return (f' # BEGIN home-service:{name}\n'
                f' @home_service_{name} {{\n  host {host}\n  path {prefix}*\n }}\n'
                f' handle @home_service_{name} {{\n  route {{\n'
                f'   forward_auth {auth.removeprefix("http://")} {{\n'
                f'    uri /service-access/{name}\n    header_up Host {host}\n'
                '    header_up -Authorization\n    header_up -X-Daimon-Home\n'
                '    header_up X-Daimon-Vpn 0\n   }\n'
                f'   reverse_proxy {upstream} {{\n'
                '    header_up -X-Daimon-Home\n    header_up -X-Daimon-Actor\n'
                '    header_up -X-Daimon-Actor-Kind\n    header_up -X-Daimon-Vpn\n'
                '    header_up -Authorization\n   }\n  }\n }\n'
                f' # END home-service:{name}\n').encode()

    @staticmethod
    def compose(before, request, block, anchor):
        if len(before) > LIMIT:
            raise ValueError('service_route_capacity')
        text = before.decode()
        start, end = '# BEGIN home-service:' + request['name'], '# END home-service:' + request['name']
        lines = text.splitlines(keepends=True)
        starts = [i for i, line in enumerate(lines) if line.strip() == start]
        ends = [i for i, line in enumerate(lines) if line.strip() == end]
        if starts or ends:
            if (len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]
                    or ''.join(lines[starts[0]:ends[0]+1]).strip().encode() != block.strip()):
                raise ValueError('service_concurrent_route_preserved')
            return before
        # This writer requires a per-service reserved insertion anchor, placed
        # by the gateway owner ahead of catch-all handlers. No speculative parse.
        positions = [i for i, line in enumerate(lines) if line.rstrip('\n') == anchor]
        if len(positions) != 1 or not anchor.endswith(request['name']):
            raise ValueError('service_reserved_route_anchor_required')
        if request['prefix'] in text:
            raise ValueError('service_existing_prefix_preserved')
        lines.insert(positions[0], block.decode())
        result = ''.join(lines).encode()
        if len(result) > LIMIT:
            raise ValueError('service_route_capacity')
        return result


class Deployments:
    def __init__(self, value):
        self.config = configuration(value)
        self.state = path(value['state'])
        self.journal = OperationJournal(self.state)

    def grant(self, app, home, owner, service):
        current_owner = app.authority.actor(owner.ref)
        matches = [g for g in self.config['grants'] if g['receiver']['home'] == home
                   and g['receiver']['owner'] == owner.ref and g['receiver']['service'] == service]
        if (len(matches) != 1 or app.homes[home]['owner_being_ref'] != owner.ref
                or not current_owner or not current_owner.enabled or current_owner.revision != owner.revision):
            raise ValueError('service_capability_denied')
        return matches[0]

    def execute(self, grant, value, raw=None):
        envelope = dict(schema='dm.home-service-executor/v1', action='apply' if raw is not None else 'observe',
                        capability=sha(canonical(grant['receiver'])), request_id=value['request_id'],
                        digest=value['package']['sha256'], previous=value['previous'],
                        package=base64.b64encode(raw).decode() if raw is not None else None)
        # argv is fixed in the protected operator capability. Owner payloads
        # cannot select a command, destination, UID, port or host profile.
        try:
            result = subprocess.run(grant['command'], input=canonical(envelope), capture_output=True,
                                    timeout=100, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
            if len(result.stdout) > 16384:
                return {'state': 'uncertain', 'digest': envelope['digest']}
            observed = json.loads(result.stdout)
            if (isinstance(observed, dict) and set(observed) == {'state', 'digest', 'error'}
                    and observed['state'] in {'refused', 'uncertain'}
                    and observed['digest'] == envelope['digest']
                    and isinstance(observed['error'], str)
                    and re.fullmatch(r'[a-z][a-z0-9_]{1,79}', observed['error'])):
                return observed
            if result.returncode:
                return {'state': 'uncertain', 'digest': envelope['digest']}
            exact(observed, 'state digest', 'invalid_service_executor_observation')
            if (observed['state'] not in {'absent', 'ready', 'uncertain', 'superseded'}
                    or observed['digest'] != envelope['digest']):
                raise ValueError('invalid_service_executor_observation')
            return observed
        except (OSError, subprocess.SubprocessError, ValueError):
            return {'state': 'uncertain', 'digest': envelope['digest']}

    def route(self, app, home, grant):
        from .service_routes import declaration
        selected = declaration(grant, app.homes[home]['public_url'])
        call = {'schema': 'dm.home-service-route-call/v1', 'capability': sha(canonical(selected))}
        try:
            result = subprocess.run(grant['route_command'], input=canonical(call), capture_output=True,
                        timeout=185, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
            if result.returncode or len(result.stdout) > 16384:
                return {'state': 'unconfirmed'}
            observed = json.loads(result.stdout)
            if observed != {'state': 'complete', 'route_loaded': True}:
                return {'state': 'unconfirmed'}
            return observed
        except (OSError, ValueError, subprocess.SubprocessError):
            return {'state': 'unconfirmed'}

    @staticmethod
    def _audience(app, value):
        validate_audience(value['audience'], known_actor=app.authority.actor,
                          known_tribe=lambda ref: ref in app.authority.tribes())
        if value['audience']['visibility'] == 'vpn':
            raise ValueError('service_vpn_route_unconfigured')

    def deploy(self, app, home, owner, value, *, authorize=lambda: True):
        request(value)
        self._audience(app, value)
        g = self.grant(app, home, owner, value['service'])
        c = g['receiver']
        # A local manifest alone is not a committed package or an ownership proof.
        package = value['package']
        selected = app.registry.version(home=home, resource=package['resource'], version=package['version'])
        if (not selected or selected.get('kind') != 'artifact' or package['file'] not in selected.get('files', [])
                or not any(e['artifact_ref'] == package['resource'] for e in app.publication(home)['entries'])):
            raise ValueError('service_own_committed_package_required')
        with app.locks[home]:
            if len(self.journal.list_all(limit=129)) >= 128 and not self.journal.latest_for_idempotency_key(key(c)+':'+value['request_id']):
                raise ValueError('service_operation_capacity')
            previous_op = self.journal.latest_for_idempotency_key(key(c)+':'+value['request_id'])
            call = {'grant': sha(canonical(g)), 'request': value}
            if previous_op and previous_op['intent']['runtime_call'] != call:
                raise ValueError('service_request_conflict')
            op = previous_op or self.journal.plan(operation='home-service-deploy/v1', target=key(c),
                    idempotency_key=key(c)+':'+value['request_id'],
                    intent={'runtime_call': {'grant': sha(canonical(g)), 'request': value}},
                    expected_precondition={'digest': value['previous']},
                    intended_transition={'digest': package['sha256']},
                    audit_identity={'home': home, 'owner': owner.ref})
            with self.journal.mutation_lock(op['operation_id']):
                if op['state'] == 'completed':
                    return {**op['result'], 'retained': True}
                if op['state'] == 'planned':
                    raw = self.package(app, home, value, c)
                    if not authorize():
                        raise ValueError('service_owner_revoked')
                    self.journal.advance(op['operation_id'], 'runtime-dispatching')
                    observed = self.execute(g, value, raw)
                else:
                    observed = self.execute(g, value)
                    if observed['state'] == 'absent':
                        # Receiving journal/lock proves no dispatch intent.
                        # Same exact request is idempotent at that writer, too.
                        raw = self.package(app, home, value, c)
                        if not authorize():
                            raise ValueError('service_owner_revoked')
                        observed = self.execute(g, value, raw)
                if observed['state'] != 'ready':
                    code = observed.get('error', 'service_receiving_unconfirmed')
                    current = self.journal.get(op['operation_id'])
                    self.journal.advance(op['operation_id'], current['state'], last_error=code)
                    return {'state': observed['state'], 'request_id': value['request_id'],
                            'digest': package['sha256'], 'error': code}
                self.journal.advance(op['operation_id'], 'runtime-applied', runtime_observation=observed)
                self._audience(app, value)
                self.grant(app, home, owner, value['service'])
                if not authorize():
                    raise ValueError('service_owner_revoked')
                routed = self.route(app, home, g)
                if routed.get('state') != 'complete':
                    return {'state': 'route-unconfirmed', 'request_id': value['request_id'], 'digest': package['sha256']}
                # Publication is finalized by the same owner's ordinary link/sync.
                return {'state': 'publication-required', 'request_id': value['request_id'],
                        'digest': package['sha256'], 'url': app.homes[home]['public_url'] + g['prefix']}

    @staticmethod
    def package(app, home, value, c):
        package = value['package']
        with app.backends[home].open('/_home/artifact/' + package['resource'] + '/' +
                package['version'] + '/' + quote(package['file'], safe='/'), timeout=15) as response:
            if response.headers.get('X-Home-Version') != package['version']:
                raise ValueError('service_package_delivery_version_mismatch')
            raw = response.read(MAX_ARCHIVE + 1)
        parsed, _ = unpack(raw, package['sha256'])
        if parsed['service'] != c['service'] or parsed['state_schema'] != c['state_schema']:
            raise ValueError('service_state_or_identity_mismatch')
        return raw

    def finalize(self, app, home, owner, payload, *, authorize=lambda: True):
        exact(payload, 'request resource version', 'invalid_service_finalize')
        value = request(payload['request'])
        self._audience(app, value)
        g = self.grant(app, home, owner, value['service'])
        c = g['receiver']
        op = self.journal.latest_for_idempotency_key(key(c)+':'+value['request_id'])
        if (not op or op['intent']['runtime_call'] != {'grant': sha(canonical(g)), 'request': value}
                or op['state'] not in {'runtime-applied', 'completed'}):
            raise ValueError('service_operation_not_ready')
        current = app.publication(home)
        entry = next((e for e in current['entries'] if e['artifact_ref'] == payload['resource']), None)
        exact_version = app.registry.version(home=home, resource=payload['resource'], version=payload['version'])
        from .registry import immutable_record
        if (not entry or entry.get('version_ref') != payload['version'] or immutable_record(entry) != exact_version
                or entry.get('kind') != 'link' or entry.get('url') != app.homes[home]['public_url'] + g['prefix']
                or entry.get('application') != {'schema': 'dm.application/v1', 'mode': 'shared'}
                or any(entry.get(k) != v for k, v in value['audience'].items())
                or any(entry.get(k) != value['app'][k] for k in ('title', 'summary'))):
            raise ValueError('service_exact_app_publication_required')
        if self.execute(g, value)['state'] != 'ready':
            raise ValueError('service_runtime_unconfirmed')
        if not authorize():
            raise ValueError('service_owner_revoked')
        self.grant(app, home, owner, value['service'])
        result = {'state': 'complete', 'request_id': value['request_id'], 'digest': value['package']['sha256'],
                  'url': entry['url'], 'resource': entry['artifact_ref'], 'version': entry['version_ref']}
        self.journal.advance(op['operation_id'], 'completed', logical_observation={'resource': payload['resource'],
                             'version': payload['version']}, result=result)
        return result

    def login_return(self, home, service_key, forwarded_uri):
        """Return only this capability's local path for browser login recovery."""
        for grant in self.config['grants']:
            if grant['receiver']['home'] == home and 's-' + key(grant['receiver']) == service_key:
                from .service import return_target
                try:
                    selected = return_target(forwarded_uri)
                except ValueError:
                    return grant['prefix']
                return selected if urlsplit(selected).path.startswith(grant['prefix']) else grant['prefix']
        return None

    def access(self, app, home, subject, service_key):
        """Current capability, exact committed App version and live audience required."""
        for g in self.config['grants']:
            c = g['receiver']
            if c['home'] != home or 's-' + key(c) != service_key:
                continue
            owner = app.authority.actor(c['owner'])
            if not owner or not owner.enabled:
                return False
            self.grant(app, home, owner, c['service'])
            op = self.journal.latest_for_target(key(c))
            if not op or op['state'] != 'completed' or op['intent']['runtime_call']['grant'] != sha(canonical(g)):
                return False
            result = op['result']
            entry = app.selected(home, result['resource'], 'current', subject)
            return bool(entry and entry['version_ref'] == result['version']
                        and app.policy.allows(op['intent']['runtime_call']['request']['audience'],
                                              home=home, subject=subject))
        return False
