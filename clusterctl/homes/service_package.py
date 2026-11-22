"""Closed Node HTTP package contract; no install hooks, network or shell."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
from functools import wraps

from ..onboarding_release import inventory, regular

MAX_ARCHIVE = 32 * 1024**2
MAX_UNPACKED = 128 * 1024**2
MAX_FILES = 4096
HEX = re.compile(r'[a-f0-9]{64}')
NAME = re.compile(r'[a-z][a-z0-9-]{0,47}')
RESERVED = {'access', 'interaction', 'cluster', 'owner', 'api', 'r', 'view', 'works',
            'catalog', 'fonts', 'homemaker', 'review-notes', 'service-access'}


def closed(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (TypeError, KeyError, AttributeError, tarfile.TarError) as error:
            raise ValueError('invalid_service_contract') from error
    return checked


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def exact(value, keys, error):
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        raise ValueError(error)


def relative(value):
    if (not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', value)
            or any(p in {'', '.', '..'} for p in value.split('/'))):
        raise ValueError('service_package_path_denied')
    return value


def path(value):
    if (not isinstance(value, str) or not value.startswith('/')
            or not re.fullmatch(r'/[A-Za-z0-9_./-]+', value)):
        raise ValueError('service_operator_path_required')
    relative(value[1:])
    return Path(value)


@closed
def manifest(value):
    exact(value, 'schema service runtime entry state_schema health files', 'invalid_service_package')
    if (value['schema'] != 'dm.home-service-package/v1' or value['runtime'] != 'node24-http'
            or not isinstance(value['service'], str) or not NAME.fullmatch(value['service'])
            or not isinstance(value['state_schema'], str) or not NAME.fullmatch(value['state_schema'])):
        raise ValueError('invalid_service_package')
    relative(value['entry'])
    exact(value['health'], 'path sha256', 'invalid_service_health')
    if (not re.fullmatch(r'/[a-zA-Z0-9_/-]{0,128}', value['health']['path'])
            or not HEX.fullmatch(value['health']['sha256'])):
        raise ValueError('invalid_service_health')
    files = value['files']
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError('service_package_capacity')
    for row in files:
        exact(row, 'path sha256', 'invalid_service_file')
        relative(row['path'])
        if row['path'] == 'service.json' or not HEX.fullmatch(row['sha256']):
            raise ValueError('invalid_service_file')
    names = [r['path'] for r in files]
    if len(set(names)) != len(names) or value['entry'] not in names:
        raise ValueError('invalid_service_file')
    return value


@closed
def unpack(raw, expected):
    """Return verified bytes, before creating any path. Tar extract is never used."""
    if len(raw) > MAX_ARCHIVE or not HEX.fullmatch(expected) or sha(raw) != expected:
        raise ValueError('service_package_digest_mismatch')
    files, size = {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            name = relative(member.name)
            size += member.size
            if (not member.isfile() or member.issparse() or member.pax_headers
                    or member.mode & 0o7022 or member.name in files
                    or member.size > 32 * 1024**2 or size > MAX_UNPACKED
                    or len(files) >= MAX_FILES + 1):
                raise ValueError('service_package_member_denied')
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError('service_package_member_denied')
            with stream:
                files[name] = stream.read(member.size + 1)
            if len(files[name]) != member.size:
                raise ValueError('service_package_member_denied')
    value = manifest(json.loads(files['service.json']))
    if ({name: sha(data) for name, data in files.items() if name != 'service.json'}
            != {r['path']: r['sha256'] for r in value['files']}):
        raise ValueError('service_package_inventory_mismatch')
    # A file cannot also be an ancestor directory.
    if any(str(p) in files for n in files for p in Path(n).parents if str(p) != '.'):
        raise ValueError('service_package_path_denied')
    return value, files


def verify_tree(root, value, *, uid):
    """Reuse the receiving release inventory/regular-file verification."""
    actual = inventory(root, uid=uid)
    expected = [{'path': 'service.json', 'sha256': sha(canonical(value))}, *value['files']]
    if sorted(actual, key=lambda r: r['path']) != sorted(expected, key=lambda r: r['path']):
        raise ValueError('service_package_inventory_mismatch')
    regular(root / value['entry'], uid=uid)


@closed
def request(value):
    exact(value, 'schema service request_id package previous audience app', 'invalid_service_request')
    if (value['schema'] != 'dm.home-service-deploy/v1'
            or not isinstance(value['service'], str) or not NAME.fullmatch(value['service'])
            or not isinstance(value['request_id'], str)
            or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', value['request_id'])
            or value['previous'] is not None and not HEX.fullmatch(value['previous'])):
        raise ValueError('invalid_service_request')
    exact(value['package'], 'resource version file sha256', 'invalid_service_package_reference')
    p = value['package']
    if (not re.fullmatch('[a-f0-9]{32}', p['resource']) or not HEX.fullmatch(p['version'])
            or not HEX.fullmatch(p['sha256'])):
        raise ValueError('invalid_service_package_reference')
    relative(p['file'])
    exact(value['audience'], 'visibility recipients tribes', 'invalid_service_audience')
    exact(value['app'], 'title summary decision', 'invalid_service_app_metadata')
    if any(not isinstance(value['app'][k], str) or not 1 <= len(value['app'][k]) <= limit
           for k, limit in (('title', 1024), ('summary', 8192), ('decision', 1024))):
        raise ValueError('invalid_service_app_metadata')
    return value
