"""Read-only, bounded projections for the authenticated fleet dashboard.

Health is a dated Pulso reading, never an inferred host liveness claim. Alerts
remain scoped by their existing receiving credential; no writes are supported.
"""
from __future__ import annotations

import json
import os
import stat
import urllib.request
from urllib.parse import urlsplit


def private_bytes(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError('unsafe_observation_reference')
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('observation_too_large')
    return raw


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def observations(config):
    value = {'health': None, 'health_state': 'unconfigured',
             'alerts': [], 'alerts_state': 'unconfigured', 'alerts_partial': False}
    if config.get('health_file'):
        try:
            report = json.loads(private_bytes(config['health_file'], 131072))
            if (report.get('schema') != 'computer-health/v1'
                    or not isinstance(report.get('targets'), list) or len(report['targets']) > 8):
                raise ValueError('invalid_health_report')
            # The collector owns the safe report contract. Never return its private config.
            targets = []
            for target in report['targets']:
                row = {k: target[k] for k in ('id', 'label', 'scope', 'state', 'attempted_at')}
                if any(not isinstance(v, str) or len(v) > 200 for v in row.values()):
                    raise ValueError('invalid_health_target')
                reading = target.get('reading')
                if reading:
                    clean = {k: reading[k] for k in ('observed_at', 'scope', 'sample_seconds')}
                    fields = {
                        'memory': ('kind', 'current_bytes', 'limit_bytes', 'total_bytes', 'available_bytes'),
                        'cpu': ('percent', 'logical_capacity', 'interval_seconds'),
                    }
                    for name, keys in fields.items():
                        raw = reading.get(name)
                        clean[name] = {k: raw[k] for k in keys if k in raw} if isinstance(raw, dict) else None
                    for name, keys in {'disks': ('label', 'total_bytes', 'available_bytes', 'unavailable'),
                                       'services': ('label', 'active')}.items():
                        raw = reading.get(name, [])
                        if not isinstance(raw, list) or len(raw) > 16:
                            raise ValueError('invalid_health_reading')
                        clean[name] = [{k: r[k] for k in keys if k in r} for r in raw]
                    row['reading'] = clean
                targets.append(row)
            value.update(health={'targets': targets}, health_state='observed')
        except (OSError, ValueError, TypeError, KeyError):
            value['health_state'] = 'unavailable'
    if config.get('alerts'):
        try:
            binding = config['alerts']
            base = binding['base_url']
            parts = urlsplit(base)
            if (parts.scheme != 'http' or parts.hostname not in ('127.0.0.1', '::1')
                    or not parts.port or parts.path or parts.query or parts.fragment
                    or parts.username or parts.password):
                raise ValueError('invalid_alerts_endpoint')
            token = private_bytes(binding['token_file'], 4096).decode().strip()
            if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
                raise ValueError('invalid_alerts_credential')
            request = urllib.request.Request(base + '/v1/incidents?processing_state=open&limit=100',
                headers={'Authorization': 'Bearer ' + token})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            with opener.open(request, timeout=3) as response:
                raw = response.read(1048577)
            if len(raw) > 1048576:
                raise ValueError('alerts_too_large')
            page = json.loads(raw)
            if not isinstance(page.get('items'), list) or len(page['items']) > 100:
                raise ValueError('invalid_alerts_page')
            rows = []
            for item in page['items']:
                projection = item['projection']
                row = {key: projection[key] for key in (
                    'producer_id', 'incident_id', 'resource_ref', 'severity', 'summary',
                    'action', 'processing_state', 'updated_at')}
                if (row['processing_state'] != 'open' or type(row['updated_at']) is not int
                        or any(not isinstance(row[k], str) or len(row[k]) > 500
                               for k in row if k != 'updated_at')):
                    raise ValueError('invalid_alerts_projection')
                row.update(freshness=item['freshness'],
                           acknowledged=bool(item['acknowledgments']))
                rows.append(row)
            value.update(alerts=rows, alerts_state='observed',
                         alerts_partial=page.get('next_cursor') is not None)
        except (OSError, ValueError, TypeError, KeyError):
            value['alerts_state'] = 'unavailable'
    return value
