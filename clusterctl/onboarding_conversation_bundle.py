"""Bounded immutable public App delivery through the existing code mount route.

Only operator-selected public runtime files belong here. Pairing, accounts,
memory and mutable App state remain in the receiving body's private home.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import importlib.util
import shutil
import subprocess

from . import being_seed
from .onboarding import OnboardingError
from .onboarding_input import relative
from .onboarding_release import regular

SCHEMA = 'cluster-conversation-bundle/v1'
MARKER = 'conversation-bundle.json'
MAX_FILES = 10000
MAX_BYTES = 512 * 1024**2


def configuration(value):
    if not isinstance(value, dict) or not 1 <= len(value) <= 64:
        raise OnboardingError('conversation_bundle_selection_required')
    result = {}
    for name, row in value.items():
        if (not isinstance(name, str) or not being_seed.NAME.fullmatch(name)
                or not isinstance(row, dict) or set(row) != {'root', 'sha256'}
                or not isinstance(row['root'], str) or not Path(row['root']).is_absolute()
                or '..' in Path(row['root']).parts
                or not isinstance(row['sha256'], str)
                or not re.fullmatch('[0-9a-f]{64}', row['sha256'])):
            raise OnboardingError('conversation_bundle_selection_required')
        result[name] = (Path(row['root']), row['sha256'])
    return result


def verify(root: Path, fingerprint: str, *, uid: int):
    being_seed._path(root)
    raw = regular(root / MARKER, uid=uid, limit=2 * 1024**2)
    if hashlib.sha256(raw).hexdigest() != fingerprint:
        raise OnboardingError('conversation_bundle_changed')
    value = json.loads(raw)
    if (not isinstance(value, dict) or set(value) != {'schema', 'files'}
            or value['schema'] != SCHEMA or not isinstance(value['files'], dict)
            or not 1 <= len(value['files']) <= MAX_FILES):
        raise OnboardingError('conversation_bundle_required')
    expected = value['files']
    for name, checksum in expected.items():
        if (relative(name) != name or name == MARKER or not isinstance(checksum, str)
                or not re.fullmatch('[0-9a-f]{64}', checksum)):
            raise OnboardingError('conversation_bundle_required')
    found, total = set(), 0
    # Bound traversal as well as bytes. No links, devices or unlisted files.
    pending, entries = [root], 0
    while pending:
        directory = pending.pop()
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022
                or info.st_mode & 0o005 != 0o005):
            raise OnboardingError('conversation_bundle_required')
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                if entries > 2 * MAX_FILES:
                    raise OnboardingError('conversation_bundle_capacity')
                path = Path(child.path)
                info = child.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                    continue
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                        or info.st_mode & 0o022 or not info.st_mode & 0o004 or info.st_nlink != 1):
                    raise OnboardingError('conversation_bundle_required')
                name = path.relative_to(root).as_posix()
                if name == MARKER:
                    continue
                total += info.st_size
                if total > MAX_BYTES or name not in expected:
                    raise OnboardingError('conversation_bundle_capacity')
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, 'rb') as stream:
                    opened = os.fstat(stream.fileno())
                    if (opened.st_ino, opened.st_dev, opened.st_size, opened.st_mtime_ns) != (
                            info.st_ino, info.st_dev, info.st_size, info.st_mtime_ns):
                        raise OnboardingError('conversation_bundle_changed')
                    if hashlib.file_digest(stream, 'sha256').hexdigest() != expected[name]:
                        raise OnboardingError('conversation_bundle_changed')
                found.add(name)
    if found != set(expected):
        raise OnboardingError('conversation_bundle_changed')
    return dict(files=len(found), bytes=total)


def bootstrap_codex(fingerprint: str, *, root=Path('/opt/daimon-app'),
                    destination=Path('/usr/local/bin/codex'), prepare_dependencies=False):
    """Expose this selected public executable; never overwrite a guest login/tool."""
    verify(root, fingerprint, uid=os.geteuid())
    if prepare_dependencies:
        dependencies()
    source = root / 'bin/codex'
    if not source.is_file() or not os.access(source, os.X_OK):
        raise OnboardingError('conversation_bundle_codex_required')
    if destination.is_symlink():
        if destination.readlink() != source:
            raise OnboardingError('existing_guest_codex_preserved')
        return
    if destination.exists():
        raise OnboardingError('existing_guest_codex_preserved')
    # symlink() is atomic and refuses any concurrent differing installation.
    destination.symlink_to(source)


def dependencies(*, ready=None, run=None, release=Path('/etc/os-release')):
    """Install the missing standard Debian guest prerequisites, without a shell.

    This is called only after the selected public mount and own home are checked
    by the existing context writer. It installs no account, listener or model.
    """
    ready = ready or (lambda: importlib.util.find_spec('ensurepip') is not None
        and shutil.which('rsync') is not None and Path('/usr/bin/node').is_file())
    if ready():
        return
    facts = dict(line.split('=', 1) for line in release.read_text().splitlines() if '=' in line)
    if os.geteuid() != 0 or facts.get('ID') != 'debian' or facts.get('VERSION_ID', '').strip('"') != '13':
        raise OnboardingError('conversation_guest_dependencies_required')
    execute = run or subprocess.run
    for arguments in (['update'], ['-y', '--no-install-recommends', 'install',
                                  'python3-venv', 'rsync', 'nodejs']):
        result = execute(['/usr/bin/apt-get', '-q', '-o',
            'APT::Keep-Downloaded-Packages=false', *arguments], capture_output=True,
            timeout=90, check=False, env={'PATH': os.defpath, 'LANG': 'C.UTF-8',
                'DEBIAN_FRONTEND': 'noninteractive'})
        if result.returncode:
            raise OnboardingError('conversation_guest_dependencies_required')
    if not ready():
        raise OnboardingError('conversation_guest_dependencies_required')
