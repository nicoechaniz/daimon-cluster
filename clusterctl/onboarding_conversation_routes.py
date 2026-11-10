"""Owned HTTPS route composition in the existing finite companion worker.

The selected gateway keeps its Caddy process/configuration. Only an absent
companion block is added; current differing blocks and unknown effects survive.
"""
from __future__ import annotations

import hashlib
from contextlib import nullcontext
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import urllib.request
from urllib.parse import urlsplit

from . import being_seed
from .onboarding import OnboardingError, digest, private_directory
from .onboarding_conversation import ConversationError, atomic, bounded_command, selection
from .onboarding_conversation_proxy import configuration as listeners
from .onboarding_custody import document
from .onboarding_release import regular

LIMIT = 65536


def configuration(value):
    if (not isinstance(value, dict) or set(value)-{'maintenance'} != {'config', 'state', 'anchor'}
            or any(not isinstance(value[k], str) or not Path(value[k]).is_absolute()
                   or '..' in Path(value[k]).parts for k in ('config', 'state'))
            or not isinstance(value['anchor'], str) or not 1 <= len(value['anchor']) <= 256
            or any(ord(c) < 32 and c != '\t' for c in value['anchor'])):
        raise OnboardingError('conversation_route_configuration_required')
    if 'maintenance' in value:
        from .onboarding_conversation_maintenance import configuration as maintenance_configuration
        maintenance_configuration(value['maintenance'])
    return dict(value)


def interaction_upstreams(value, *, within=False):
    result = set()
    if isinstance(value, dict):
        within = within or any(any(path in {'/interaction','/interaction*'}
                                  or path.startswith('/interaction/')
                                  for path in match.get('path', []))
                              for match in value.get('match', []) if isinstance(match, dict))
        if within and value.get('handler') == 'invoke':
            raise OnboardingError('conversation_route_maintenance_required')
        if within and value.get('handler') == 'reverse_proxy':
            upstreams = value.get('upstreams')
            if not isinstance(upstreams,list) or not upstreams:
                raise OnboardingError('conversation_route_maintenance_required')
            for upstream in upstreams:
                dial = upstream.get('dial')
                if not isinstance(dial, str) or '{' in dial or not dial:
                    raise OnboardingError('conversation_route_maintenance_required')
                result.add(dial)
        for child in value.values():
            result.update(interaction_upstreams(child, within=within))
    elif isinstance(value, list):
        for child in value:
            result.update(interaction_upstreams(child, within=within))
    return result


def render(request, listener, home_backend):
    selection(request)
    name = request['name']
    listener = listeners({name: listener})[name]
    hostname = urlsplit(request['origin']).hostname
    if (len(hostname) > 253 or any(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) is None
                                  for label in hostname.split('.'))):
        raise OnboardingError('conversation_route_configuration_required')
    try:
        home = urlsplit(home_backend)
        if (home.scheme != 'http' or home.hostname != '127.0.0.1'
                or home.netloc != f'127.0.0.1:{home.port}' or not 1024 <= home.port <= 65535
                or home.path or home.query or home.fragment):
            raise ValueError
    except (TypeError, ValueError):
        raise OnboardingError('conversation_route_configuration_required') from None
    address = listener['listen_host']
    if ':' in address:
        address = '[' + address + ']'
    upstream = f'{address}:{listener["listen_port"]}'
    return f''' # BEGIN child-conversation:{name}
 @child_conversation_{name} host {hostname}
 handle @child_conversation_{name} {{
  route {{
   @child_{name}_root {{
    method GET HEAD
    path /
   }}
   redir @child_{name}_root /interaction/?view=conversation&client=standalone 302
   redir /interaction /interaction/ 308
   handle_path /interaction/* {{
    reverse_proxy {upstream} {{
     header_up X-Forwarded-Prefix /interaction
     header_up -X-Daimon-Home
     header_up -X-Daimon-Vpn
     header_up -X-Daimon-Actor
     header_up -X-Daimon-Actor-Kind
    }}
   }}
   reverse_proxy {home.netloc} {{
    header_up -X-Daimon-Home
    header_up X-Daimon-Vpn 0
   }}
  }}
 }}
 # END child-conversation:{name}
'''.encode()


def compose(before, request, block, anchor):
    if len(before) > LIMIT:
        raise OnboardingError('conversation_route_capacity')
    lines = before.decode().splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.strip() == '# BEGIN child-conversation:'+request['name']]
    ends = [i for i, line in enumerate(lines) if line.strip() == '# END child-conversation:'+request['name']]
    if starts or ends:
        if (len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]
                or ''.join(lines[starts[0]:ends[0]+1]).strip().encode() != block.strip()):
            raise OnboardingError('existing_conversation_route_preserved')
        return before
    # Do not shadow an existing unmarked route for this exact hostname.
    host = re.escape(urlsplit(request['origin']).hostname)
    if re.search(r'(?<![a-zA-Z0-9_.-])'+host+r'(?![a-zA-Z0-9_.-])', before.decode()):
        raise OnboardingError('existing_conversation_route_preserved')
    positions = [i for i, line in enumerate(lines) if line.rstrip('\n') == anchor]
    if len(positions) != 1:
        raise OnboardingError('conversation_route_anchor_changed')
    lines.insert(positions[0], block.decode())
    result = ''.join(lines).encode()
    if len(result) > LIMIT:
        raise OnboardingError('conversation_route_capacity')
    return result


def operation(value):
    if (not isinstance(value, dict)
            or not {'schema', 'name', 'pins', 'phase', 'before', 'after', 'adapted'} <= set(value)
            or set(value) - {'schema', 'name', 'pins', 'phase', 'before', 'after', 'adapted', 'predecessor', 'loaded_process'}
            or value.get('schema') != 'cluster-conversation-route/v1'
            or not isinstance(value.get('name'), str) or not being_seed.NAME.fullmatch(value['name'])
            or value.get('phase') not in {'prepared', 'reload-intent', 'complete'}
            or any(not isinstance(value[k], str) or re.fullmatch('[0-9a-f]{64}', value[k]) is None
                   for k in ('pins', 'before', 'after', 'adapted'))
            or value['phase'] == 'reload-intent' and 'predecessor' not in value
            or value['phase'] == 'complete' and 'loaded_process' not in value):
        raise OnboardingError('conversation_route_checkpoint_changed')
    for key in ('predecessor', 'loaded_process'):
        if key in value:
            process = value[key]
            if (not isinstance(process, dict) or set(process) != {'pid', 'invocation', 'started'}
                    or any(not isinstance(process[k], str) for k in process)
                    or re.fullmatch(r'[1-9][0-9]{0,9}', process['pid']) is None
                    or re.fullmatch(r'[0-9a-f]{32}', process['invocation']) is None
                    or re.fullmatch(r'[0-9]{1,24}', process['started']) is None):
                raise OnboardingError('conversation_route_checkpoint_changed')
    return value


class Routes:
    # Specialized maintained service writers reuse the same finite CAS/reload
    # journal; only their closed route renderer and insertion matcher differ.
    render = staticmethod(render)
    compose = staticmethod(compose)
    def __init__(self, value):
        self.value = configuration(value)
        self.path = Path(value['config'])
        self.state = private_directory(Path(value['state']), create=True)
        entries = list(self.state.iterdir())
        if (len(entries) > 24 or any(p.is_symlink() or not p.is_file() for p in entries)
                or sum(p.stat().st_size for p in entries) > 512*1024
                or any(p.stat().st_size > (LIMIT if p.name in {'before.caddyfile', 'candidate.caddyfile'} else 4096)
                       for p in entries)):
            raise OnboardingError('conversation_route_capacity')

    def _read(self):
        return regular(self.path, uid=os.geteuid(), limit=LIMIT)

    def _process(self):
        raw = bounded_command(['systemctl', 'show', 'caddy.service', '-p', 'MainPID',
                               '-p', 'InvocationID', '-p', 'ActiveState'], seconds=4)
        values = dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)
        pid = values.get('MainPID', '0')
        if not pid.isdigit() or pid == '0' or values.get('ActiveState') != 'active':
            raise OnboardingError('conversation_route_service_unobserved')
        args = (Path('/proc')/pid/'cmdline').read_bytes().split(b'\0')
        if not any(a == b'--config' and b == os.fsencode(self.path) for a, b in zip(args, args[1:])):
            raise OnboardingError('conversation_route_service_binding_changed')
        started = (Path('/proc')/pid/'stat').read_text().rsplit(')', 1)[1].split()[19]
        return dict(pid=pid, invocation=values['InvocationID'], started=started)

    def _command(self, process, *args):
        if self._process() != process:
            raise OnboardingError('conversation_route_service_changed')
        path = Path('/proc')/process['pid']
        # Reuse only this loaded service's binary/environment. Secret values stay
        # in memory and never enter arguments, diagnostics or the route journal.
        environment = dict(item.split('=', 1) for item in (path/'environ').read_bytes().decode().split('\0') if '=' in item)
        try:
            return bounded_command([str(path/'exe'), *args], seconds=20, env=environment)
        except (OSError, subprocess.TimeoutExpired, ConversationError):
            code = ('conversation_route_reload_unconfirmed' if args[0] == 'reload'
                    else 'conversation_route_validation_refused')
            raise OnboardingError(code) from None

    def _adapt(self, process, path):
        raw = self._command(process, 'adapt', '--config', str(path), '--adapter', 'caddyfile')
        return digest(json.loads(raw))

    def _live_configuration(self, process):
        # The default loopback admin listener must belong to this exact loaded
        # process, rather than an unrelated local HTTP responder.
        paths = list((Path('/proc')/process['pid']/'fd').iterdir())
        if len(paths) > 4096:
            raise OnboardingError('conversation_route_service_unobserved')
        sockets = set()
        for path in paths:
            try:
                target = os.readlink(path)
                if target.startswith('socket:['):
                    sockets.add(target[8:-1])
            except FileNotFoundError:
                pass
        tcp = Path('/proc/net/tcp').read_text()
        if len(tcp) > 1024*1024 or not any(
                fields[1] == '0100007F:07E3' and fields[3] == '0A' and fields[9] in sockets
                for line in tcp.splitlines()[1:] if len(fields := line.split()) >= 10):
            raise OnboardingError('conversation_route_admin_unobserved')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        url = 'http://127.0.0.1:2019/config/'
        with opener.open(url, timeout=3) as response:
            raw = response.read(262145)
            if response.status != 200 or response.geturl() != url or len(raw) > 262144:
                raise OnboardingError('conversation_route_admin_unobserved')
        if self._process() != process:
            raise OnboardingError('conversation_route_service_changed')
        return json.loads(raw)

    def _live(self, process):
        return digest(self._live_configuration(process))

    def _maintenance(self, process):
        from .onboarding_conversation_maintenance import guard
        required = interaction_upstreams(self._live_configuration(process))
        targets = self.value.get('maintenance', [])
        if required - {row['upstream'] for row in targets}:
            raise OnboardingError('conversation_route_maintenance_required')
        return guard(targets) if targets else nullcontext(lambda: None)

    def _save(self, path, value):
        if len(json.dumps(value).encode()) > 4096:
            raise OnboardingError('conversation_route_capacity')
        being_seed._write(path, value)

    def _finish(self, active, process):
        if hashlib.sha256(self._read()).hexdigest() != active['after'] or self._live(process) != active['adapted']:
            return False
        active = dict(active, phase='complete', loaded_process=process)
        self._save(self.state/(active['name']+'.json'), active)
        self._save(self.state/'active.json', active)
        return True

    def reconcile(self, request, listener, home_backend, *, apply, authorize):
        block = self.render(request, listener, home_backend)
        pins = digest(dict(request=request, listener=listener, home_backend=home_backend, routing=self.value))
        with being_seed._locked(self.state):
            active_path = self.state/'active.json'
            active = operation(document(active_path)) if active_path.exists() else None
            process = self._process()
            if active and active.get('phase') != 'complete' and active.get('pins') != pins:
                if not self._finish(active, process):
                    raise OnboardingError('conversation_route_operation_pending')
                active = None
            receipt = self.state/(request['name']+'.json')
            if receipt.exists() and operation(document(receipt)).get('pins') != pins:
                raise OnboardingError('existing_conversation_route_preserved')
            before = self._read()
            after = self.compose(before, request, block, self.value['anchor'])
            if active and active.get('pins') == pins and active.get('phase') != 'complete':
                if self._finish(active, process):
                    return {'state':'complete', 'route_loaded':True}
                if active['phase'] == 'reload-intent':
                    return {'state':'waiting', 'reason':'conversation_route_reload_unconfirmed'}
            elif before == after:
                if self._adapt(process, self.path) != self._live(process):
                    return {'state':'waiting', 'reason':'conversation_route_runtime_unconfirmed'}
                return {'state':'complete', 'route_loaded':True}
            elif not apply:
                return {'state':'absent'}
            else:
                if self._adapt(process, self.path) != self._live(process):
                    raise OnboardingError('conversation_route_runtime_unconfirmed')
                receipts = [p for p in self.state.glob('*.json') if p.name != 'active.json']
                if not receipt.exists() and len(receipts) >= 16:
                    raise OnboardingError('conversation_route_capacity')
                atomic(self.state/'before.caddyfile', before, mode=0o600)
                atomic(self.state/'candidate.caddyfile', after, mode=0o600)
                self._command(process, 'validate', '--config', str(self.state/'candidate.caddyfile'), '--adapter', 'caddyfile')
                active = dict(schema='cluster-conversation-route/v1', name=request['name'], pins=pins,
                    phase='prepared', before=hashlib.sha256(before).hexdigest(), after=hashlib.sha256(after).hexdigest(),
                    adapted=self._adapt(process, self.state/'candidate.caddyfile'))
                self._save(active_path, active)
            if not apply:
                return {'state':'waiting'}
            with self._maintenance(process) as fence:
                if not authorize():
                    raise OnboardingError('host_authorization_required')
                fence()
                current = self._read()
                if hashlib.sha256(current).hexdigest() == active['before']:
                    candidate = regular(self.state/'candidate.caddyfile', uid=os.geteuid(), limit=LIMIT)
                    if hashlib.sha256(candidate).hexdigest() != active['after']:
                        raise OnboardingError('conversation_route_checkpoint_changed')
                    atomic(self.path, candidate, mode=stat.S_IMODE(self.path.stat().st_mode))
                elif hashlib.sha256(current).hexdigest() != active['after']:
                    raise OnboardingError('conversation_route_concurrent_configuration_preserved')
                fence()
                active.update(phase='reload-intent', predecessor=process)
                self._save(active_path, active)
                # A lost reply is observed above, never dispatched again.
                self._command(process, 'reload', '--config', str(self.path), '--adapter', 'caddyfile')
                if self._finish(active, process):
                    return {'state':'complete', 'route_loaded':True}
                return {'state':'waiting', 'reason':'conversation_route_reload_unconfirmed'}
