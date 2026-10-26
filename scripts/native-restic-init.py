#!/usr/bin/env python3
"""Prepare an encrypted native backup repository and sealed recovery material.

This does not capture writers, start services, grant SSH access or establish a
usable backup. Recipients are selected by the authorized receiving operator.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import subprocess
import sys
from pathlib import Path


class PreparationError(ValueError):
    pass


def protected(path: Path, *, private: bool = False) -> bytes:
    info = path.lstat()
    forbidden = 0o077 if private else 0o022
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_mode & forbidden):
        raise PreparationError('native_backup_input_not_protected')
    return path.read_bytes()


def put(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def recipient(line: str) -> str:
    fields = line.split()
    if len(fields) >= 2 and fields[0] in {'ssh-ed25519', 'ssh-rsa'}:
        return ' '.join(fields[:2])
    if len(fields) == 1 and fields[0].startswith('age1'):
        return fields[0]
    raise PreparationError('native_backup_recipient_invalid')


def initialize(state: Path, recipients: Path, operator_public: Path) -> dict:
    if not state.is_absolute() or state == Path('/') or '..' in state.parts:
        raise PreparationError('native_backup_state_required')
    selected = sorted({recipient(line) for line in protected(recipients).decode().splitlines()
                       if line.strip() and not line.lstrip().startswith('#')})
    operator = recipient(protected(operator_public).decode().strip())
    if not selected or operator not in selected:
        raise PreparationError('native_backup_operator_recipient_required')
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PreparationError('native_backup_state_not_private')
    credentials = state / 'credentials'
    credentials.mkdir(mode=0o700, exist_ok=True)
    info = credentials.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PreparationError('native_backup_credentials_not_private')
    password = credentials / 'restic-password'
    sealed = state / 'recovery.age'
    repository = state / 'restic'
    if ((repository / 'config').exists() or sealed.exists()) and not password.exists():
        raise PreparationError('native_backup_existing_unlock_unavailable')
    retained = credentials / 'recovery-recipients.pub'
    raw = ('\n'.join(selected) + '\n').encode()
    if retained.exists():
        if protected(retained, private=True) != raw:
            raise PreparationError('native_backup_recipient_set_changed')
    else:
        put(retained, raw)
    if password.exists():
        protected(password, private=True)
    else:
        put(password, (secrets.token_urlsafe(48) + '\n').encode())
    if sealed.exists():
        protected(sealed, private=True)
    else:
        partial = state / 'recovery.age.partial'
        if partial.exists() or partial.is_symlink():
            raise PreparationError('native_backup_partial_envelope_retained')
        descriptor = os.open(partial, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            subprocess.run(['age', '-R', str(retained), str(password)],
                           check=True, stdout=output, stderr=subprocess.PIPE)
            output.flush()
            os.fsync(output.fileno())
        if len(protected(partial, private=True)) < 100:
            raise PreparationError('native_backup_envelope_unconfirmed')
        os.replace(partial, sealed)
    env = {**os.environ, 'RESTIC_REPOSITORY': str(repository),
           'RESTIC_PASSWORD_FILE': str(password), 'RESTIC_CACHE_DIR': str(state / 'restic-cache')}
    log = state / 'repository-init.log'
    with log.open('ab') as output:
        if not (repository / 'config').exists():
            subprocess.run(['restic', 'init', '--repository-version', '2', '--json'],
                           env=env, stdout=output, stderr=subprocess.STDOUT, check=True)
        subprocess.run(['restic', 'snapshots', '--json'], env=env,
                       stdout=output, stderr=subprocess.STDOUT, check=True)
    return dict(schema='native-backup-repository-preparation/v1',
        encrypted_repository_initialized=True, recovery_envelope_exists=True,
        existing_authorized_recipient_count=len(selected), backup_accepted=False,
        restore_verified=False, administrative_ssh_changed=False, body_services_changed=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--recipients', type=Path, required=True)
    parser.add_argument('--operator-public', type=Path, required=True)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise PreparationError('native_backup_operator_required')
        os.umask(0o077)
        result = initialize(args.state, args.recipients, args.operator_public)
    except PreparationError as error:
        print(json.dumps({'error': str(error)}), file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        tool = error.cmd[0] if error.cmd[0] in {'age', 'restic'} else 'unknown'
        print(json.dumps({'error': 'native_backup_tool_unconfirmed', 'tool': tool,
                          'exit_code': error.returncode}), file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print(json.dumps({'error': 'native_backup_local_io_unconfirmed'}), file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
