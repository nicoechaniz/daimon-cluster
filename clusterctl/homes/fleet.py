"""Optional foreground Cluster dashboard in the existing authenticated Home.

This is a read-only application of current Cluster admission discovery. It
does not load runtime custody, read messages, start models or control guests.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path


def native_inventory(root: Path) -> dict:
    from daimon_matrix.client import ClientConfig, LocalClient
    from daimon_matrix.codex_matrix_binding import read_native_capability_key
    from daimon_matrix.messaging_config import protected_read

    runtime_raw = protected_read(root / 'runtime.json')
    runtime = json.loads(runtime_raw)
    client_raw = protected_read(root / 'client.json')
    descriptor = os.open(root / 'client.key', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    key = None
    try:
        key = read_native_capability_key(descriptor)
        config = ClientConfig.load(root / 'client.json', key)
    finally:
        os.close(descriptor)
        if key is not None:
            key[:] = bytes(len(key))
    socket = Path(runtime['socket'])
    if not socket.is_absolute():
        socket = root / socket
    if (protected_read(root / 'runtime.json') != runtime_raw
            or protected_read(root / 'client.json') != client_raw):
        raise ValueError('fleet_binding_changed')
    _, response = LocalClient(socket, config).scope_resolve({
        'scope': '/all', 'view': 'discovery', 'tribe_ref': None,
        'request_id': str(uuid.uuid4()),
    })
    if response.get('ok') is not True:
        raise ValueError('fleet_discovery_unavailable')
    return response['result']


class Fleet:
    def __init__(self, config, *, reader=native_inventory):
        if (not isinstance(config, dict)
                or not {'schema', 'home', 'readers', 'runtime_root', 'placements', 'planned'} <= set(config)
                or set(config) - {'schema', 'home', 'readers', 'runtime_root', 'placements', 'planned', 'observability'}
                or config.get('schema') != 'cluster-home-dashboard/v1'
                or not isinstance(config['home'], str)
                or not isinstance(config['readers'], list) or not 1 <= len(config['readers']) <= 64
                or any(not isinstance(r, str) or not r.startswith('human:telegram:') for r in config['readers'])
                or not isinstance(config['placements'], dict) or len(config['placements']) > 64
                or not isinstance(config['planned'], list) or len(config['planned']) > 16):
            raise ValueError('invalid_cluster_dashboard')
        root = Path(config['runtime_root'])
        if not root.is_absolute() or '..' in root.parts:
            raise ValueError('invalid_cluster_dashboard')
        for row in [*config['placements'].values(), *config['planned']]:
            if (not isinstance(row, dict) or set(row) != {'name', 'host', 'hosting'}
                    or any(not isinstance(v, str) or not 1 <= len(v) <= 128 for v in row.values())):
                raise ValueError('invalid_cluster_dashboard')
        observe = config.get('observability', {})
        if (not isinstance(observe, dict) or set(observe) - {'health_file', 'alerts'}):
            raise ValueError('invalid_observability')
        if 'health_file' in observe and (not isinstance(observe['health_file'], str)
                or not Path(observe['health_file']).is_absolute()):
            raise ValueError('invalid_observability')
        if 'alerts' in observe and (not isinstance(observe['alerts'], dict)
                or set(observe['alerts']) != {'base_url', 'token_file'}
                or any(not isinstance(v, str) for v in observe['alerts'].values())
                or not Path(observe['alerts']['token_file']).is_absolute()):
            raise ValueError('invalid_observability')
        self.config, self.root, self.reader = config, root, reader
        self.lock = threading.Lock()
        self.cached = None
        self.cached_until = 0.0

    def snapshot(self):
        # Coalesce concurrent browser requests without a timer or persisted copy.
        with self.lock:
            if self.cached is not None and time.monotonic() < self.cached_until:
                return self.cached
            source = self.reader(self.root)
            if (source.get('schema') != 'dm.scope.discovery/v1' or source.get('scope') != '/all'
                    or type(source.get('partial')) is not bool
                    or type(source.get('evaluated_at_ms')) is not int
                    or not isinstance(source.get('members'), list) or len(source['members']) > 64):
                raise ValueError('invalid_fleet_discovery')
            rows, ids = [], set()
            for member in source['members']:
                identifier = member.get('embodiment_id')
                if (not isinstance(identifier, str) or identifier in ids
                        or not isinstance(member.get('body_ref'), str)
                        or type(member.get('lease_expires_at_ms')) is not int):
                    raise ValueError('invalid_fleet_member')
                ids.add(identifier)
                placement = self.config['placements'].get(identifier, {})
                rows.append({
                    'name': placement.get('name', member['body_ref']),
                    'host': placement.get('host', 'Placement unverified'),
                    'hosting': placement.get('hosting', 'Unverified'),
                    'body_ref': member['body_ref'],
                    'embodiment_id': identifier,
                    'lease_expires_at_ms': member['lease_expires_at_ms'],
                    'process_response': member.get('process_response', 'not-observed'),
                })
            # Never return credentials, proofs, fence tokens or native histories.
            value = {'schema': 'cluster-home-fleet/v1', 'observed_at_ms': source['evaluated_at_ms'],
                     'partial': source['partial'], 'coverage': 'current-local-cluster-admissions',
                     'instances': rows, 'planned': self.config['planned']}
            from .observability import observations
            value['observability'] = observations(self.config.get('observability', {}))
            self.cached, self.cached_until = value, time.monotonic() + 3
            return value


def routes(handler, app, path, home, subject, vpn):
    fleet = getattr(app, 'cluster_dashboard', None)
    if not fleet or home != fleet.config['home']:
        handler.respond(404, {})
        return
    if path == '/cluster/':
        handler.respond(200, (Path(__file__).parent / 'assets' / 'cluster.html').read_bytes(),
                        'text/html; charset=utf-8')
        return
    if path in ('/cluster/app.js', '/cluster/app.css'):
        filename, kind = ('cluster.js', 'text/javascript; charset=utf-8') if path.endswith('.js') else ('cluster.css', 'text/css; charset=utf-8')
        handler.respond(200, (Path(__file__).parent / 'assets' / filename).read_bytes(), kind)
        return
    if path != '/cluster/api/fleet':
        handler.respond(404, {})
        return
    if vpn or not subject or subject.kind != 'human':
        handler.respond(401, {'error': 'shared_sign_in_required'})
        return
    if subject.ref not in fleet.config['readers']:
        handler.respond(403, {'error': 'fleet_access_not_granted'})
        return
    try:
        value = fleet.snapshot()
    except Exception:
        handler.respond(503, {'error': 'inventory_unavailable'})
        return
    # Recheck current identity/grants after the native I/O.
    _, _, current, _, _, _ = handler.context()
    if not current or current.ref != subject.ref or current.ref not in fleet.config['readers']:
        handler.respond(403, {'error': 'fleet_access_changed'})
        return
    handler.respond(200, value)
