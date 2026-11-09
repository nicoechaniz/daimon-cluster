"""Own resource-key preparation inside an original native publication operation.

No Matrix identity key, account, service or model is made. Public publication
results contain metadata only; explicit private transport can share resource
keys inside the selected cohort without exposing them as publication receipts.
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


def _private_key(path: Path, expected: str) -> bytes:
    being_seed._path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        raw = stream.read(33)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size != 32
            or len(raw) != 32 or hashlib.sha256(raw).hexdigest() != expected):
        raise OnboardingError('receive_resource_private_key_required')
    return raw


def transfer_packet(request: dict) -> dict:
    """Validate private wire shape without any file access or public journaling."""
    import copy
    import json
    import uuid
    try:
        if (not isinstance(request, dict) or len(json.dumps(request).encode()) > 16384
                or set(request) != {'schema', 'action', 'operation_id', 'owner_context_sha256', 'route', 'source'}
                or request['schema'] != 'cluster-private-receive-resource/v1'
                or request['action'] not in {'export', 'import'}
                or str(uuid.UUID(request['operation_id'])) != request['operation_id']
                or not isinstance(request['owner_context_sha256'], str)
                or re.fullmatch('[0-9a-f]{64}', request['owner_context_sha256']) is None
                or not isinstance(request['route'], dict)
                or set(request['route']) != FIELDS | {'secret_sha256'}
                or re.fullmatch('[0-9a-f]{64}', request['route']['secret_sha256']) is None
                or not isinstance(request['source'], dict)):
            raise ValueError
        parameters({key: request['route'][key] for key in FIELDS})
    except (KeyError, TypeError, ValueError, AttributeError, OnboardingError):
        raise OnboardingError('receive_resource_request_required') from None
    return copy.deepcopy(request)


def private_transfer(runtime: Path, group: Path, journal: Path, request: dict, *, deadline_ns: int) -> dict:
    """Machine-only private pipe through the existing granted owner transport.

    Export may contain a resource secret and MUST NOT be journaled or exposed as
    a public result. Import retains only its public provenance plus the private
    key file. This opens no native writer, identity key or provider connection.
    """
    import copy
    import json
    import time
    request = transfer_packet(request)
    for path in (runtime, group, journal):
        if not path.is_absolute() or '..' in path.parts:
            raise OnboardingError('receive_resource_request_required')
        private_directory(path)
    source = request['source']

    def budget():
        if type(deadline_ns) is not int or not time.monotonic_ns() < deadline_ns <= time.monotonic_ns()+60_000_000_000:
            raise OnboardingError('receive_resource_deadline_required')

    budget()
    with being_seed._locked(journal):
        operation = private_directory(journal / request['operation_id'])
        context = being_seed._read(operation/'owner/context.json', limit=being_seed.MAX_SELECTION)
        bundle = being_seed._read(runtime/'runtime.json', limit=being_seed.MAX_SELECTION)
        if (digest(context) != request['owner_context_sha256']
                or context.get('identity', {}).get('runtime_root') != str(runtime)
                or context['identity'].get('group_root') != str(group)
                or context['identity'].get('runtime_bundle_sha256') != digest(bundle)):
            raise OnboardingError('receive_resource_owner_changed')
        route = request['route']
        if request['action'] == 'export':
            public = _export_resource(runtime, group, operation, bundle, context, route, source)
            raw, provenance = public
            budget()
            if being_seed._read(runtime/'runtime.json', limit=being_seed.MAX_SELECTION) != bundle:
                raise OnboardingError('receive_resource_owner_changed')
            return dict(schema='cluster-private-receive-resource-export/v1',
                route=copy.deepcopy(route), provenance=provenance, key_hex=raw.hex())
        if (set(source) != {'schema', 'route', 'provenance', 'key_hex'}
                or source['schema'] != 'cluster-private-receive-resource-export/v1'
                or source['route'] != route or not isinstance(source['provenance'], dict)
                or set(source['provenance']) != {'runtime_bundle_sha256', 'source_sha256'}
                or any(not isinstance(v, str) or re.fullmatch('[0-9a-f]{64}', v) is None
                       for v in source['provenance'].values())
                or not isinstance(source['key_hex'], str) or re.fullmatch('[0-9a-f]{64}', source['key_hex']) is None):
            raise OnboardingError('receive_resource_private_packet_required')
        raw = bytes.fromhex(source['key_hex'])
        if hashlib.sha256(raw).hexdigest() != route['secret_sha256']:
            raise OnboardingError('receive_resource_private_packet_required')
        directory = operation/'receive-imports'
        if not directory.exists():
            occupied = 0
            for index, sibling in enumerate(journal.iterdir()):
                if index >= 256:
                    raise OnboardingError('receive_resource_capacity')
                if sibling != operation and (sibling/'receive-imports').exists():
                    occupied += 1
            if occupied >= 16:
                raise OnboardingError('receive_resource_capacity')
        directory = private_directory(directory, create=True)
        slot = digest(route)
        metadata = directory/(slot+'.json')
        key_path = directory/(slot+'.key')
        # Bound new imports; exact recovery remains available at capacity.
        entries: list[Path] = []
        for item in directory.iterdir():
            if len(entries) >= 34:
                raise OnboardingError('receive_resource_capacity')
            entries.append(item)
        if (any(p.is_symlink() or not p.is_file() for p in entries)
                or any(p.stat().st_size > 4096 for p in entries)
                or sum(p.stat().st_size for p in entries) > 73728):
            raise OnboardingError('receive_resource_capacity')
        occupied_bytes = sum(p.stat().st_size for p in entries)
        selected = dict(schema='cluster-receive-resource-import/v1',
            owner_context_sha256=digest(context), runtime_bundle_sha256=digest(bundle),
            route=route, provenance=source['provenance'])
        if len(json.dumps(selected).encode()) > 4096:
            raise OnboardingError('receive_resource_capacity')
        if metadata.exists():
            if being_seed._read(metadata, limit=4096) != selected:
                raise OnboardingError('receive_resource_original_changed')
        else:
            if len([p for p in entries if p.suffix == '.json']) >= 16:
                raise OnboardingError('receive_resource_capacity')
            if key_path.exists() or key_path.is_symlink():
                raise OnboardingError('receive_resource_existing_key_preserved')
            if occupied_bytes+4096+32 > 73728:
                raise OnboardingError('receive_resource_capacity')
            budget()
            being_seed._write(metadata, selected, limit=4096)
        budget()
        if key_path.exists() or key_path.is_symlink():
            _private_key(key_path, route['secret_sha256'])
        else:
            atomic(key_path, raw, mode=0o600)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        if being_seed._read(runtime/'runtime.json', limit=being_seed.MAX_SELECTION) != bundle:
            raise OnboardingError('receive_resource_owner_changed')
        return dict(schema='cluster-receive-resource-transfer-result/v1',
            route_sha256=digest(route), provenance_sha256=digest(selected),
            secret_source='receive-imports/'+key_path.name, receiving_readiness='unobserved')


def _export_resource(runtime, group, operation, bundle, context, route, source):
    if source.get('kind') == 'prepared' and set(source) == {'kind', 'command'}:
        from .onboarding_group_admission import publication_command
        command = publication_command(source['command'])
        if (command['action'] != 'receive-key' or command['operation_id'] != operation.name
                or command['params'] != {key: route[key] for key in FIELDS}):
            raise OnboardingError('receive_resource_source_required')
        receipt = being_seed._read(operation/'publications'/(command['step']+'.json'), limit=being_seed.MAX_SELECTION)
        result = receipt.get('result')
        if (receipt.get('schema') != 'cluster-group-publication-operation/v1'
                or receipt.get('command') != command or receipt.get('owner_context_sha256') != digest(context)
                or not isinstance(result, dict) or result.get('route') != route
                or result.get('resource_key_retained') is not True or result.get('status') != 'recorded'
                or result.get('schema') != 'cluster-group-publication-result/v1'
                or any(result.get(key) != command[key] for key in ('operation_id', 'step', 'action'))):
            raise OnboardingError('receive_resource_source_required')
        intent = being_seed._read(operation/'receive-key/intent.json', limit=4096)
        if (intent.get('schema') != SCHEMA
                or intent.get('pins') != digest(dict(command=command, runtime_bundle_sha256=digest(bundle), group_root=str(group)))):
            raise OnboardingError('receive_resource_source_required')
        raw = _private_key(operation/'receive-key'/route['secret_file'], route['secret_sha256'])
        if intent.get('key_hex') != raw.hex():
            raise OnboardingError('receive_resource_source_required')
        source_hash = digest(receipt)
    elif source.get('kind') == 'application' and set(source) == {'kind', 'application_sha256', 'publication_sha256'}:
        from daimon_matrix.messaging_config import config_digest
        app, publication = _signed_application(bundle, group)
        if (config_digest(app) != source['application_sha256']
                or config_digest(publication) != source['publication_sha256'] or app.get('intake') != route):
            raise OnboardingError('receive_resource_source_required')
        raw = _private_key(group/'application'/route['secret_file'], route['secret_sha256'])
        source_hash = config_digest(publication)
    else:
        raise OnboardingError('receive_resource_source_required')
    return raw, dict(runtime_bundle_sha256=digest(bundle), source_sha256=source_hash)



def relay(source_owner, recipient_owner, source_request: dict, recipient_request: dict, *, validate) -> dict:
    """Relay only between selected private owner pipes, returning a public receipt.

    The original coordinator supplies its current job/grant revalidation. No
    secret enters its journal, argv, diagnostics or returned observation. Exact
    retries re-read the same source and reconcile the recipient's retained file.
    """
    import copy
    source_request = transfer_packet(source_request)
    recipient_request = transfer_packet(recipient_request)
    if (source_request['action'] != 'export' or recipient_request['action'] != 'import'
            or source_request['route'] != recipient_request['route']
            or recipient_request['source'] != {}):
        raise OnboardingError('receive_resource_relay_required')
    validate()
    exported = source_owner.private_resource(source_request)
    try:
        if (not isinstance(exported, dict)
                or set(exported) != {'schema', 'route', 'provenance', 'key_hex'}
                or exported.get('schema') != 'cluster-private-receive-resource-export/v1'
                or exported.get('route') != source_request['route']):
            raise OnboardingError('receive_resource_relay_required')
        validate()
        incoming = copy.deepcopy(recipient_request)
        incoming['source'] = exported
        result = recipient_owner.private_resource(incoming)
        validate()
        expected_source = 'receive-imports/'+digest(source_request['route'])+'.key'
        if (not isinstance(result, dict) or set(result) != {'schema', 'route_sha256', 'provenance_sha256',
                                                          'secret_source', 'receiving_readiness'}
                or result.get('schema') != 'cluster-receive-resource-transfer-result/v1'
                or result.get('route_sha256') != digest(source_request['route'])
                or result.get('secret_source') != expected_source
                or result.get('receiving_readiness') != 'unobserved'
                or not isinstance(result.get('provenance_sha256'), str)
                or re.fullmatch('[0-9a-f]{64}', result['provenance_sha256']) is None):
            raise OnboardingError('receive_resource_relay_required')
        return result
    finally:
        # These values are private machine packets, never retained observations.
        exported = None


PRIVATE_ERRORS = frozenset({
    'receive_resource_request_required', 'receive_resource_deadline_required',
    'receive_resource_owner_changed', 'receive_resource_private_packet_required',
    'receive_resource_capacity', 'receive_resource_original_changed',
    'receive_resource_existing_key_preserved', 'receive_resource_source_required',
    'receive_resource_private_key_required', 'receive_resource_relay_required',
    'receive_resource_unavailable', 'receive_resource_access_refused',
})


def private_response(operation) -> dict:
    """CLI boundary: fixed diagnostics only, never arbitrary exception content."""
    try:
        return operation()
    except Exception as error:
        code = 'receive_resource_unavailable'
        if isinstance(error, OnboardingError) and str(error) in PRIVATE_ERRORS:
            code = str(error)
        elif isinstance(error, PermissionError):
            code = 'receive_resource_access_refused'
        return dict(schema='cluster-private-receive-resource-refusal/v1', error=code)


def private_result(value: dict) -> dict:
    """Recover precise private-pipe refusal without leaking its payload."""
    if value.get('schema') == 'cluster-private-receive-resource-refusal/v1':
        code = value.get('error')
        if set(value) != {'schema', 'error'} or not isinstance(code, str) or code not in PRIVATE_ERRORS:
            code = 'receive_resource_unavailable'
        raise OnboardingError(code)
    if 'error' in value:
        raise OnboardingError('receive_resource_unavailable')
    return value



def _signed_application(bundle, group):
    import time
    from daimon_matrix.canonical import unb64url
    from daimon_matrix.messaging_config import (_public_identity, _read_verified_publication,
        verify_public_binding)
    from daimon_matrix.operator_rebirth import authority_from_runtime_bundle
    authority = authority_from_runtime_bundle(bundle)
    identity = _public_identity(authority, bundle['local_origin'], bundle['runtime_id'],
        bundle['runtime_label'], time.time_ns()//1_000_000)
    key = unb64url(authority.credentials[identity['credential_id']]['body']['signing_key']['public'])
    app, _metadata, publication = _read_verified_publication(group/'application',
        lambda value, signature: verify_public_binding(identity, key, value, signature))
    return app, publication


def route_preview(runtime: Path, group: Path, operation_id: str, *, deadline_ns: int | None) -> dict:
    """Current signed own intake metadata only; no private key or native writer."""
    import copy
    import time
    from daimon_matrix.messaging_config import config_digest
    if deadline_ns is None or time.monotonic_ns() >= deadline_ns:
        raise OnboardingError('receive_resource_deadline_required')
    bundle = being_seed._read(runtime/'runtime.json', limit=being_seed.MAX_SELECTION)
    app, publication = _signed_application(bundle, group)
    route = app['intake']
    parameters({key:route[key] for key in FIELDS})
    if (time.monotonic_ns() >= deadline_ns
            or being_seed._read(runtime/'runtime.json', limit=being_seed.MAX_SELECTION) != bundle):
        raise OnboardingError('receive_resource_owner_changed')
    return dict(schema='cluster-receive-route-preview/v1', operation_id=operation_id,
        runtime_bundle_sha256=digest(bundle), being_ref=bundle['manifest']['being_ref'],
        origin=copy.deepcopy(bundle['local_origin']),
        route=copy.deepcopy(route), source=dict(kind='application',
            application_sha256=config_digest(app), publication_sha256=config_digest(publication)))



def resolve_sources(operation: Path, sources: dict) -> dict:
    """Resolve original-operation import references inside the existing writer."""
    result = {}
    for filename, source in sources.items():
        if isinstance(source, str):
            result[filename] = source
            continue
        if (not isinstance(source, dict) or set(source) != {'receive_import'}
                or not isinstance(source['receive_import'], str)
                or re.fullmatch('[0-9a-f]{64}', source['receive_import']) is None):
            raise OnboardingError('receive_resource_source_required')
        slot = source['receive_import']
        context = being_seed._read(operation/'owner/context.json', limit=being_seed.MAX_SELECTION)
        metadata = being_seed._read(operation/'receive-imports'/(slot+'.json'), limit=4096)
        route = metadata.get('route')
        if (metadata.get('schema') != 'cluster-receive-resource-import/v1'
                or metadata.get('owner_context_sha256') != digest(context)
                or not isinstance(route, dict) or digest(route) != slot
                or route.get('secret_file') != filename):
            raise OnboardingError('receive_resource_source_required')
        path = operation/'receive-imports'/(slot+'.key')
        _private_key(path, route['secret_sha256'])
        result[filename] = str(path)
    return result
