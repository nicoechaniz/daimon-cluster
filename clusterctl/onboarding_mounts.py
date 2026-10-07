"""Read-only per-body receiving inputs; never replace a receiving working copy."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from pathlib import Path

from . import being_seed, onboarding_input
from .onboarding import OnboardingError, digest, private_directory

# The qualified Debian native image has one dedicated unprivileged agent.
GUEST_UID = 1000
GUEST_GID = 1000
GUEST_HOME = Path('/home/agent')


def prepare_connections(views: Path, plan: dict, value: dict) -> Path:
    """Publish only this body's bot connection to an isolated read-only mount."""
    from daimon_matrix import keystore
    from .matrix_host import _publish_directory_noreplace
    from .onboarding_telegram import connections
    value = connections(value)
    private_directory(views)
    parent = views / digest(plan)
    private_directory(parent)
    target = parent / 'connections'
    being_seed._path(target)
    target.mkdir(mode=0o700, exist_ok=True)
    info = target.stat()
    if (info.st_uid not in {os.geteuid(), GUEST_UID} or info.st_mode & 0o077
            or not target.is_dir() or any(p.name != 'connections.json' for p in target.iterdir())):
        raise OnboardingError('existing_onboarding_connections_preserved')
    raw = json.dumps(value, sort_keys=True).encode()
    path = target / 'connections.json'
    with being_seed._locked(parent):
        if path.exists():
            from .onboarding_release import regular
            if regular(path, uid=GUEST_UID, limit=65536) != raw or path.stat().st_mode & 0o077:
                raise OnboardingError('existing_onboarding_connections_preserved')
        else:
            temporary = parent / ('.connections-' + uuid.uuid4().hex)
            keystore._atomic_write(temporary, raw)
            os.chown(temporary, GUEST_UID, GUEST_GID, follow_symlinks=False)
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                _publish_directory_noreplace(descriptor, temporary.name, 'connections/connections.json',
                    exists_code='existing_onboarding_connections_preserved')
                directory = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                os.close(descriptor)
                temporary.unlink(missing_ok=True)
        os.chown(target, GUEST_UID, GUEST_GID, follow_symlinks=False)
    return target


def prepare_matrix_public(views: Path, plan: dict, documents: dict[str, dict]) -> Path:
    """Publish only native public authorization to a read-only receiving mount."""
    from daimon_matrix import canonical, keystore
    from .matrix_host import _publish_directory_noreplace
    allowed = {'genesis.json', 'activation.json', 'credential-response.json', 'admission.json', 'peer-offer.json'}
    if not documents or not set(documents) <= allowed:
        raise OnboardingError('invalid_onboarding_public_matrix_documents')
    private_directory(views)
    parent = views / digest(plan)
    private_directory(parent, create=True)
    target = parent / 'matrix-public'
    being_seed._path(target)
    target.mkdir(mode=0o755, exist_ok=True)
    info = target.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {os.geteuid(), GUEST_UID}
            or info.st_mode & 0o022 or any(item.name not in allowed for item in target.iterdir())):
        raise OnboardingError('existing_onboarding_public_matrix_preserved')
    # Keep the publisher's directory ownership. Native atomic writes require
    # it; only individual public documents are owned by the receiving UID.
    # The private host parent and read-only guest mount protect this directory.
    os.chown(target, os.geteuid(), os.getegid(), follow_symlinks=False)
    target.chmod(0o755)
    with being_seed._locked(parent):
        for name, value in documents.items():
            raw = canonical.canonical_bytes(value)
            path = target / name
            if path.exists():
                owner = path.stat().st_uid
                if (owner not in {os.geteuid(), GUEST_UID}
                        or onboarding_input.owned_digest(path, uid=owner)[0] != hashlib.sha256(raw).hexdigest()):
                    raise OnboardingError('existing_onboarding_public_matrix_preserved')
            else:
                # Native staging remains in the private publisher directory.
                # Publication into the readable, read-only mount must neither
                # require its consumer UID nor replace a concurrent document.
                temporary = parent / ('.matrix-public-' + uuid.uuid4().hex)
                keystore._atomic_write(temporary, raw)
                os.chown(temporary, GUEST_UID, GUEST_GID, follow_symlinks=False)
                descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    _publish_directory_noreplace(descriptor, temporary.name, 'matrix-public/' + name,
                        exists_code='existing_onboarding_public_matrix_preserved')
                    target_descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        os.fsync(target_descriptor)
                    finally:
                        os.close(target_descriptor)
                finally:
                    os.close(descriptor)
                    temporary.unlink(missing_ok=True)
            os.chown(path, GUEST_UID, GUEST_GID, follow_symlinks=False)
    return target


def _directories(root: Path, target: Path) -> None:
    current = root
    for part in target.relative_to(root).parts:
        current /= part
        being_seed._path(current)
        current.mkdir(mode=0o700, exist_ok=True)
        if current.stat().st_uid not in {os.geteuid(), GUEST_UID} or current.stat().st_mode & 0o077:
            raise OnboardingError('private_onboarding_input_required')


def prepare_view(source: Path, views: Path, plan: dict) -> Path:
    """A root-private parent prevents other host UID 1000 users reading the view.

    Incus mounts just its input child read-only with id shifting. The guest can
    read its own archive and clone working memory, but cannot change the mount.
    """
    manifest = onboarding_input.verify(source, plan['seed_digest'])
    private_directory(views)
    parent = views / digest(plan)
    private_directory(parent, create=True)
    with being_seed._locked(parent):
        target = parent / 'input'
        being_seed._path(target)
        if not target.exists():
            target.mkdir(mode=0o700)
        if target.stat().st_uid not in {os.geteuid(), GUEST_UID} or target.stat().st_mode & 0o077:
            raise OnboardingError('private_onboarding_input_required')
        received = target / 'received'
        _directories(target, received)
        # Existing partial files must match; publishing never overwrites them.
        rows = [*manifest['files'], dict(path=None, sha256=hashlib.sha256((source / 'manifest.json').read_bytes()).hexdigest())]
        for row in rows:
            original = source / 'received' / row['path'] if row['path'] else source / 'manifest.json'
            copied = received / row['path'] if row['path'] else target / 'manifest.json'
            being_seed._path(copied)
            _directories(target, copied.parent)
            if copied.exists():
                owner = copied.stat().st_uid
                if owner not in {os.geteuid(), GUEST_UID} or onboarding_input.owned_digest(copied, uid=owner)[0] != row['sha256']:
                    raise OnboardingError('existing_onboarding_view_preserved')
            elif onboarding_input.owned_digest(original, uid=os.geteuid(), copy=copied)[0] != row['sha256']:
                raise OnboardingError('onboarding_input_changed')
        # Keep empty historical directories too.
        for directory in (source / 'received').rglob('*'):
            if directory.is_dir():
                path = received / directory.relative_to(source / 'received')
                being_seed._path(path)
                _directories(target, path)
        plan_file = target / 'plan.json'
        raw = json.dumps(plan, sort_keys=True).encode()
        if plan_file.exists():
            owner = plan_file.stat().st_uid
            if owner not in {os.geteuid(), GUEST_UID} or onboarding_input.owned_digest(plan_file, uid=owner)[0] != hashlib.sha256(raw).hexdigest():
                raise OnboardingError('existing_onboarding_view_preserved')
        else:
            being_seed._write(plan_file, plan)
        if {path.relative_to(received).as_posix() for path in received.rglob('*') if path.is_file()} != {
                row['path'] for row in manifest['files']}:
            raise OnboardingError('existing_onboarding_view_preserved')
        for path in (target, *target.rglob('*')):
            being_seed._path(path)
            if path.stat().st_uid not in {os.geteuid(), GUEST_UID} or path.stat().st_mode & 0o077:
                raise OnboardingError('private_onboarding_input_required')
            os.chown(path, GUEST_UID, GUEST_GID, follow_symlinks=False)
        onboarding_input.verify(target, plan['seed_digest'], uid=GUEST_UID)
        descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return target


def bootstrap_home(home: Path = GUEST_HOME) -> None:
    """Only the empty, dedicated mounted home may get its initial ownership."""
    import pwd
    import grp
    import subprocess
    being_seed._path(home)
    try:
        account = pwd.getpwnam('agent')
    except KeyError:
        # The qualified image carries tools, not a source user's account/home.
        # Create the dedicated guest identity through the maintained path.
        if home.stat().st_uid != 0 or not home.is_dir() or any(home.iterdir()):
            raise OnboardingError('existing_guest_home_preserved')
        try:
            pwd.getpwuid(GUEST_UID)
        except KeyError:
            pass
        else:
            raise OnboardingError('qualified_guest_account_conflict')
        try:
            group = grp.getgrgid(GUEST_GID)
        except KeyError:
            group = None
        if group is not None and group.gr_name != 'agent':
            raise OnboardingError('qualified_guest_account_conflict')
        argv = ['useradd', '--no-create-home', '--uid', str(GUEST_UID),
                '--home-dir', str(home), '--shell', '/bin/bash']
        argv += ['--gid', 'agent'] if group else ['--user-group']
        result = subprocess.run([*argv, 'agent'], capture_output=True, timeout=30, check=False)
        if result.returncode:
            raise OnboardingError('qualified_guest_account_creation_failed')
        account = pwd.getpwnam('agent')
    if account.pw_uid != GUEST_UID or account.pw_gid != GUEST_GID or Path(account.pw_dir) != home:
        raise OnboardingError('qualified_guest_account_required')
    info = home.stat()
    if info.st_uid == GUEST_UID and info.st_mode & 0o077 == 0:
        return
    if info.st_uid != 0 or not home.is_dir() or any(home.iterdir()):
        raise OnboardingError('existing_guest_home_preserved')
    os.chown(home, GUEST_UID, GUEST_GID, follow_symlinks=False)
    home.chmod(0o700)
    descriptor = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
