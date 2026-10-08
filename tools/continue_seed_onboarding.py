#!/usr/bin/env python3
"""Finite participant continuation; Root custody stays in its local holder."""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import http.client
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

LIMIT = 2 * 1024**2
NAME = re.compile(r'[a-z0-9][a-z0-9-]{0,30}\Z')


class ContinuationError(ValueError):
    pass


class Refused(ContinuationError):
    def __init__(self, status):
        self.status = status
        super().__init__('private_onboarding_request_refused')


def private_read(path: Path, *, limit=LIMIT) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_size > limit):
            raise ContinuationError('private_participant_file_required')
        return stream.read(limit + 1)


def private_json(path: Path) -> dict:
    value = json.loads(private_read(path))
    if not isinstance(value, dict):
        raise ContinuationError('private_participant_json_required')
    return value


@contextlib.contextmanager
def state_directory(path: Path):
    if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ContinuationError('private_continuation_directory_required')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not path.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ContinuationError('private_continuation_directory_required')
    descriptor = os.open(path / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ContinuationError('private_continuation_directory_required')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield path
    finally:
        os.close(descriptor)


def publish(path: Path, value: dict) -> None:
    raw = json.dumps(value, sort_keys=True).encode()
    if len(raw) > LIMIT:
        raise ContinuationError('bounded_public_reply_required')
    if path.exists():
        if private_read(path) != raw:
            raise ContinuationError('existing_public_reply_preserved')
        return
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if private_read(path) != raw:
                raise ContinuationError('existing_public_reply_preserved') from None
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


class API:
    def __init__(self, url: str, token: str):
        self.origin = urlsplit(url)
        if (self.origin.scheme != 'https' or not self.origin.hostname
                or self.origin.username or self.origin.password or self.origin.query
                or self.origin.fragment or self.origin.path not in {'', '/'}
                or not token or len(token) > 4096 or any(x.isspace() for x in token)):
            raise ContinuationError('private_https_onboarding_origin_required')
        self.token = token
        self.binding_origin = 'https://' + self.origin.hostname.lower() + (
            ':' + str(self.origin.port) if self.origin.port not in {None, 443} else '')

    def __call__(self, path: str, body: dict | None = None) -> dict:
        if not path.startswith('/v1/') or '?' in path or '#' in path or '..' in path:
            raise ContinuationError('fixed_onboarding_path_required')
        connection = http.client.HTTPSConnection(self.origin.hostname, self.origin.port, timeout=60)
        try:
            raw = None if body is None else json.dumps(body).encode()
            if raw is not None and len(raw) >= LIMIT:
                raise ContinuationError('bounded_participant_submission_required')
            connection.request('GET' if body is None else 'POST', path, raw,
                {'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
            response = connection.getresponse()
            data = response.read(LIMIT + 1)
            if len(data) > LIMIT:
                raise ContinuationError('bounded_onboarding_response_required')
            if response.status != 200:
                raise Refused(response.status)
            value = json.loads(data)
            if not isinstance(value, dict):
                raise ContinuationError('onboarding_response_required')
            return value
        finally:
            connection.close()


def continue_job(api, seed: str, directory: Path, *, source=None, connections=None,
                 selection=None, sign=None, timeout=14400, interval=5, clock=time.monotonic,
                 wait=time.sleep) -> dict:
    """Send missing inputs, cache exact public replies, then await the listener.

    Finite foreground HTTPS progress is not Matrix inbox attention or a daemon.
    No new approval/account selection, custody upload, model turn or bot polling.
    """
    if not NAME.fullmatch(seed) or not 1 <= timeout <= 86400 or not .1 <= interval <= 60:
        raise ContinuationError('bounded_continuation_required')
    local = '/v1/onboarding/local-body/' + seed
    base = '/v1/seeds/' + seed
    deadline = clock() + timeout
    task = api(local)
    expected = task['expected_being_ref']
    if expected is None:
        raise ContinuationError('existing_being_request_required')
    # Never carry a cached signature/participant submission to another origin,
    # owner, Root, request or environment after a copied local directory.
    binding = dict(schema='cluster-participant-continuation/v1', origin=api.binding_origin
        if isinstance(api, API) else 'fixture', name=seed, request_id=task['request_id'],
        owner=task['owner'], expected_being_ref=expected)
    publish(directory / 'binding.json', binding)
    enrollment = api(local + '/enrollment')
    if not enrollment['source_received']:
        if source is None:
            return dict(state='inputs-required', pending_inputs=['signed_existing_matrix_source'])
        if (set(source) != {'schema', 'request_id', 'identity', 'routes'}
                or source['schema'] != 'cluster-onboarding-existing-source/v1'
                or source['request_id'] != task['request_id']
                or source['identity']['document']['authority']['manifest']['being_ref'] != expected):
            raise ContinuationError('same_root_public_source_required')
        api(local + '/enrollment', source)
    needed = set(task['pending_inputs'])
    connection_fields = set()
    if 'telegram_bot_and_destination' in needed:
        connection_fields.update(('telegram_bot_token', 'telegram_chat_id'))
    if 'ssh_public_key' in needed:
        connection_fields.add('ssh_public_key')
    if connection_fields:
        if connections is None or not connection_fields <= set(connections):
            return dict(state='inputs-required', pending_inputs=sorted(needed & {
                'telegram_bot_and_destination', 'ssh_public_key'}))
        # Optional private topic is forwarded only when first sending bot data.
        if 'telegram_bot_token' in connection_fields and 'telegram_topic_id' in connections:
            connection_fields.add('telegram_topic_id')
        api(base + '/connections', {key:connections[key] for key in connection_fields})
    if 'receiving_selection_and_preparation' in needed:
        if selection is None:
            return dict(state='inputs-required', pending_inputs=['receiving_selection_and_preparation'])
        api(base + '/prepare', dict(selection=selection, defer=True))
    while clock() < deadline:
        enrollment = api(local + '/enrollment')
        if enrollment['expected_being_ref'] != expected or enrollment['request_id'] != task['request_id']:
            raise ContinuationError('existing_continuation_binding_preserved')
        frame = enrollment['handoff']
        if frame is not None and not enrollment['hosted_identity_ready']:
            if (frame['name'] != seed or frame['owner'] != task['owner']
                    or frame['payload']['base']['expected_being_ref'] != expected):
                raise ContinuationError('same_root_handoff_required')
            fingerprint = frame['request_digest']
            if not re.fullmatch(r'[0-9a-f]{64}', fingerprint):
                raise ContinuationError('exact_public_handoff_required')
            payload_digest = hashlib.sha256(json.dumps(frame['payload'], sort_keys=True,
                separators=(',', ':')).encode()).hexdigest()
            if payload_digest != fingerprint:
                raise ContinuationError('exact_public_handoff_required')
            publish(directory / (fingerprint + '.handoff.json'), frame)
            reply_path = directory / (fingerprint + '.reply.json')
            if reply_path.exists():
                reply = private_json(reply_path)
            elif sign is None:
                return dict(state='inputs-required', pending_inputs=['local_root_holder'])
            else:
                reply = sign(frame)
                publish(reply_path, reply)
            if (set(reply) != {'schema', 'request_digest', 'response'}
                    or reply['schema'] != 'cluster-onboarding-enrollment-reply/v1'
                    or reply['request_digest'] != fingerprint):
                raise ContinuationError('exact_public_reply_required')
            acknowledgment = directory / (fingerprint + '.ack.json')
            if acknowledgment.exists() and private_json(acknowledgment) != dict(
                    request_digest=fingerprint, intake_acknowledged=True):
                raise ContinuationError('existing_public_reply_preserved')
            if not acknowledgment.exists():
                try:
                    api(local + '/enrollment', reply)
                    publish(acknowledgment, dict(request_digest=fingerprint, intake_acknowledged=True))
                except Refused as error:
                    if error.status != 409:
                        raise
                    # The worker may have advanced after an earlier accepted
                    # reply. A renewed/expired frame is not falsely acknowledged.
                    newer = api(local + '/enrollment')
                    if not newer['hosted_identity_ready'] and newer['handoff'] == frame:
                        raise
        progress = api(base + '/onboarding')
        if {'matrix', 'access', 'telegram', 'welcome'} <= set(progress.get('completed_steps', [])):
            return dict(state='hosted-conversation-ready', hosted_identity_ready=True,
                human_acceptance=progress.get('active') is True)
        if progress.get('state') in {'attention-required', 'uncertain'}:
            return dict(state=progress['state'], reason=progress.get('reason', 'verification_failed'))
        wait(min(interval, max(0, deadline - clock())))
    return dict(state='timeout', preserved=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--seed', required=True)
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--token-file', required=True, type=Path)
    for name in ('source', 'connections', 'selection'):
        parser.add_argument('--' + name + '-file', type=Path)
    custody = parser.add_mutually_exclusive_group()
    custody.add_argument('--holder', type=Path)
    custody.add_argument('--root-custody', type=Path)
    password = parser.add_mutually_exclusive_group()
    password.add_argument('--password-file', type=Path)
    password.add_argument('--password-fd', type=int)
    parser.add_argument('--timeout', type=int, default=14400)
    args = parser.parse_args(argv)
    secret = bytearray()
    try:
        api = API(args.url, private_read(args.token_file, limit=4096).decode().strip())
        signer = None
        if args.holder or args.root_custody:
            def signer(frame):
                nonlocal secret
                if not secret:
                    if args.password_file is not None:
                        secret = bytearray(private_read(args.password_file, limit=4096))
                    elif args.password_fd is not None:
                        secret = bytearray(os.read(args.password_fd, 4097))
                    if not secret or len(secret) > 4096:
                        raise ContinuationError('existing_local_root_password_required')
                # Open local custody only for a published exact handoff.
                from clusterctl.onboarding_enrollment_root import sign
                return sign(frame, args.holder or args.root_custody,
                    lambda:bytearray(secret), root_custody=args.root_custody is not None)
        inputs = {name:private_json(getattr(args, name + '_file'))
            if getattr(args, name + '_file') else None for name in ('source', 'connections', 'selection')}
        with state_directory(args.state) as directory:
            result = continue_job(api, args.seed, directory, sign=signer, timeout=args.timeout, **inputs)
        print(json.dumps(result))
        return 0 if result['state'] == 'hosted-conversation-ready' else 2
    except KeyboardInterrupt:
        print(json.dumps(dict(state='stopped', preserved=True)))
        return 130
    except ContinuationError as error:
        reason = str(error)
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,79}', reason):
            reason = 'local_continuation_requires_attention'
        print(json.dumps(dict(state='attention-required', reason=reason, preserved=True)))
        return 1
    except Exception:
        # Native keystore/API failures may contain private context or URLs.
        print(json.dumps(dict(state='attention-required', reason='local_continuation_requires_attention', preserved=True)))
        return 1
    finally:
        secret[:] = b'\x00' * len(secret)


if __name__ == '__main__':
    raise SystemExit(main())
