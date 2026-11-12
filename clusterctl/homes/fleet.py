"""Optional foreground Cluster dashboard in the existing authenticated Home.

This is a read-only application of current Cluster admission discovery. It
does not load runtime custody, read messages, start models or control guests.
"""
from __future__ import annotations

import json
import os
import socket
import stat
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


def observation_socket(path, *, view=None):
    reference=Path(path)
    info=reference.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:
        raise ValueError('private_observation_socket_required')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(12 if view=='resources' else 42);connection.connect(str(reference));raw=bytearray()
        if view is not None:
            if view not in ('all','resources'):raise ValueError('invalid_observation_view')
            connection.sendall(json.dumps({'view':view}).encode()+b'\n')
            connection.shutdown(socket.SHUT_WR)
        while True:
            data=connection.recv(min(65536,131073-len(raw)))
            if not data:break
            raw.extend(data)
            if len(raw)>131072:raise ValueError('observation_limit')
    value=json.loads(raw)
    if (value.get('schema')!='cluster-fleet-observation/v1'
            or type(value.get('observed_at_ms')) is not int
            or not -1000 <= time.time()*1000-value['observed_at_ms'] <= 30000
            or not isinstance(value.get('preparations'),list) or len(value['preparations'])>16
            or not isinstance(value.get('health'),dict)):
        raise ValueError('invalid_live_observation')
    clean=[]
    for row in value['preparations']:
        item={key:row[key] for key in ('name','host','hosting','physical_state','stage','job_state','observed_at_ms')}
        if (type(item['observed_at_ms']) is not int or any(not isinstance(v,str) or len(v)>128
                for k,v in item.items() if k!='observed_at_ms')
                or not isinstance(row.get('services'),dict) or len(row['services'])>8):
            raise ValueError('invalid_preparation_observation')
        item['services']={}
        for key,state in row['services'].items():
            if not isinstance(key,str) or len(key)>128 or state not in (
                    'active','inactive','failed','activating','deactivating','not-installed','unknown'):
                raise ValueError('invalid_service_observation')
            item['services'][key]=state
        clean.append(item)
    return dict(value,preparations=clean)


class Fleet:
    def __init__(self, config, *, reader=native_inventory):
        if (not isinstance(config, dict)
                or not {'schema', 'home', 'readers', 'runtime_root', 'placements', 'planned'} <= set(config)
                or set(config) - {'schema', 'home', 'readers', 'runtime_root', 'placements', 'planned', 'observability', 'observer_socket'}
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
        if 'observer_socket' in config and (not isinstance(config['observer_socket'],str)
                or not Path(config['observer_socket']).is_absolute() or '..' in Path(config['observer_socket']).parts):
            raise ValueError('invalid_observation_socket')
        self.config, self.root, self.reader = config, root, reader
        self.lock = threading.Lock()
        self.cached = None
        self.cached_until = 0.0
        self.resources_lock=threading.Lock()
        self.resources_cached=None
        self.resources_until=0.0

    def resources(self):
        # Slow usage/admission I/O has a different lock and cannot block this lane.
        from .observability import observations
        with self.resources_lock:
            if self.resources_cached and time.monotonic()<self.resources_until:
                return self.resources_cached
            live=None
            try:
                if self.config.get('observer_socket'):
                    live=observation_socket(self.config['observer_socket'],view='resources')
            except (OSError,ValueError,KeyError,TypeError):
                pass
            observation=observations(self.config.get('observability',{}),
                                     health_report=live['health'] if live else None)
            previous=(self.resources_cached or {}).get('observability',{})
            if live is None:
                observation['health_state']='unavailable'
                if previous.get('health'):observation['health']=previous['health']
            if observation['alerts_state']=='observed':
                observation['alerts_observed_at_ms']=int(time.time()*1000)
            elif previous.get('alerts_observed_at_ms'):
                observation['alerts']=previous.get('alerts',[])
                observation['alerts_observed_at_ms']=previous['alerts_observed_at_ms']
            result={'schema':'cluster-home-resources/v1','observed_at_ms':int(time.time()*1000),
                    'observability':observation,'sample_max_age_seconds':15}
            self.resources_cached=result
            self.resources_until=time.monotonic()+1
            return result

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
            live=None
            if self.config.get('observer_socket'):
                # The same authenticated foreground read triggers this fixed-scope
                # owner collector. No client-supplied command, new timer or model.
                value['planned']=[]
                try:
                    live=observation_socket(self.config['observer_socket'])
                    # Reconcile actual existing virtuals with signed bodies. A
                    # retained legacy onboarding job is not a new preparation.
                    matched=set()
                    for body in rows:
                        candidates=[p for p in live['preparations']
                            if p['name'].casefold()==body['name'].casefold() and p['host']==body['host']]
                        if len(candidates)==1:
                            p=candidates[0];matched.add(p['name'])
                            body['physical']={k:p[k] for k in ('physical_state','services','observed_at_ms')}
                    value['planned']=[p for p in live['preparations'] if p['name'] not in matched]
                    value['preparation_state']='partial' if live.get('partial') else 'observed'
                except (OSError,ValueError,KeyError,TypeError):
                    value['preparation_state']='unavailable'
            value['observability'] = observations(self.config.get('observability', {}),
                health_report=live['health'] if live else None)
            if live and isinstance(live.get('usage'), dict):
                # This source is a fixed-scope owner collector, never client input.
                value['usage'] = live['usage']
            self.cached, self.cached_until = value, time.monotonic() + 3
            return value


def routes(handler, app, path, home, subject, vpn):
    fleet = getattr(app, 'cluster_dashboard', None)
    if not fleet or home != fleet.config['home']:
        handler.respond(404, {})
        return
    if path == '/cluster/':
        from .build_label import digest, stamp
        assets = Path(__file__).parent / 'assets'
        body = stamp((assets / 'cluster.html').read_bytes(), digest([assets / n for n in ('cluster.html','cluster.js','cluster.css')]))
        handler.respond(200, body, 'text/html; charset=utf-8')
        return
    if path in ('/cluster/app.js', '/cluster/app.css'):
        filename, kind = ('cluster.js', 'text/javascript; charset=utf-8') if path.endswith('.js') else ('cluster.css', 'text/css; charset=utf-8')
        handler.respond(200, (Path(__file__).parent / 'assets' / filename).read_bytes(), kind)
        return
    if path not in ('/cluster/api/fleet','/cluster/api/resources'):
        handler.respond(404, {})
        return
    if vpn or not subject or subject.kind != 'human':
        handler.respond(401, {'error': 'shared_sign_in_required'})
        return
    if subject.ref not in fleet.config['readers']:
        handler.respond(403, {'error': 'fleet_access_not_granted'})
        return
    try:
        value = fleet.resources() if path.endswith('/resources') else fleet.snapshot()
    except Exception:
        handler.respond(503, {'error': 'inventory_unavailable'})
        return
    # Recheck current identity/grants after the native I/O.
    _, _, current, _, _, _ = handler.context()
    if not current or current.ref != subject.ref or current.ref not in fleet.config['readers']:
        handler.respond(403, {'error': 'fleet_access_changed'})
        return
    handler.respond(200, value)
