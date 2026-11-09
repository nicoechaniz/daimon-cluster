"""Own resource-key preparation inside an original native publication operation.

No Matrix identity key, credentials, foreign key copy, service or model is made.
Only public route metadata leaves this private owner-local intent.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
from pathlib import Path
import re
import stat
from secrets import token_bytes
from urllib.parse import urlsplit

from . import being_seed
from .onboarding import OnboardingError, digest, private_directory
from .onboarding_conversation import atomic


SCHEMA = 'cluster-receive-key-intent/v1'
FIELDS = {'provider_ref', 'route_ref', 'key_ref', 'endpoint', 'secret_file'}


def parameters(value: dict) -> dict:
    try:
        if (not isinstance(value, dict) or set(value) != FIELDS
                or any(not isinstance(value[key], str) or not 1 <= len(value[key]) <= 256
                       for key in FIELDS)
                or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', value['secret_file']) is None
                or value['secret_file'] in {'intent.json', 'lock', 'client.key'}):
            raise ValueError
        endpoint = urlsplit(value['endpoint'])
        if (endpoint.scheme != 'http' or not endpoint.hostname
                or endpoint.port is None or endpoint.username is not None or endpoint.password is not None
                or endpoint.query or endpoint.fragment or endpoint.path != '/dm-messaging/v1/message'):
            raise ValueError
        ipaddress.IPv4Address(endpoint.hostname)
    except (KeyError, TypeError, ValueError):
        raise OnboardingError('receive_key_parameters_required') from None
    return dict(value)


def prepare(hosted, group_root: Path, operation: Path, command: dict) -> dict:
    """Retain once before exposing a hash; retries never create another key.

    publication_request holds the existing native writer and private journal
    lock. The same original operation may finish copying its retained key after
    publication; a different operation cannot remint keys for an existing app.
    """
    params = parameters(command['params'])
    directory = operation / 'receive-key'
    if not (directory / 'intent.json').exists():
        count = 0
        for index, sibling in enumerate(operation.parent.iterdir()):
            if index >= 256:
                raise OnboardingError('receive_key_capacity')
            if sibling != operation and (sibling / 'receive-key/intent.json').exists():
                count += 1
        if count >= 16:
            raise OnboardingError('receive_key_capacity')
    private_directory(directory, create=True)
    entries = list(directory.iterdir())
    if (len(entries) > 6 or any(p.is_symlink() or not p.is_file() for p in entries)
            or any(p.stat().st_size > 4096 for p in entries)
            or sum(p.stat().st_size for p in entries) > 8192):
        raise OnboardingError('receive_key_capacity')
    bundle = being_seed._read(hosted.state_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    pins = digest(dict(command=command, runtime_bundle_sha256=digest(bundle),
                       group_root=str(group_root)))
    path = directory / 'intent.json'
    key_path = directory / params['secret_file']
    if path.exists():
        value = being_seed._read(path, limit=4096)
        if (set(value) != {'schema', 'pins', 'key_hex'} or value['schema'] != SCHEMA
                or value['pins'] != pins or not isinstance(value['key_hex'], str)
                or re.fullmatch('[0-9a-f]{64}', value['key_hex']) is None):
            raise OnboardingError('receive_key_intent_conflict')
    else:
        if (any(p.exists() or p.is_symlink() for p in
                (group_root / 'application', group_root / 'selection.json', key_path))):
            raise OnboardingError('receive_key_existing_application_preserved')
        value = dict(schema=SCHEMA, pins=pins, key_hex=token_bytes(32).hex())
        being_seed._write(path, value, limit=4096)
    key = bytes.fromhex(value['key_hex'])
    if key_path.exists() or key_path.is_symlink():
        being_seed._path(key_path)
        fd = os.open(key_path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1
                    or info.st_size != 32 or stream.read(33) != key):
                raise OnboardingError('receive_key_existing_key_preserved')
    else:
        # The private intent is durable first. The established atomic writer
        # replaces only this absent leaf under the original journal/native lock.
        atomic(key_path, key, mode=0o600)
    # Finish directory durability even after an observed-but-unconfirmed rename.
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return dict(route={**params, 'secret_sha256': hashlib.sha256(key).hexdigest()},
                resource_key_retained=True)
