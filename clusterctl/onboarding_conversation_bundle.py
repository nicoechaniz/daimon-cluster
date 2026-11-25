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
import time

from . import being_seed
from .onboarding import OnboardingError
from .onboarding_input import relative
from .onboarding_release import regular

SCHEMA = 'cluster-conversation-bundle/v1'
MARKER = 'conversation-bundle.json'
MAX_FILES = 10000
MAX_BYTES = 1024**3


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



def selected_bundle(config, plan: dict) -> tuple[Path, str] | None:
    """Use the original job's frozen public App, never a changed default."""
    explicit = (getattr(config, 'conversation_bundle_by_name', None) or {}).get(plan['name'])
    path = config.jobs / plan['name'] / 'conversation-bundle.json'
    if not path.exists() and not path.is_symlink():
        return explicit
    from .onboarding import digest
    value = being_seed._read(path, limit=4096)
    if (set(value) != {'schema', 'plan_digest', 'selection'}
            or value['schema'] != 'cluster-companion-app-selection/v1'
            or value['plan_digest'] != digest(plan)):
        raise OnboardingError('companion_app_selection_changed')
    selected = configuration({'selected': value['selection']})['selected']
    if explicit is not None and selected != explicit:
        raise OnboardingError('companion_app_selection_changed')
    return selected


def prepare_selection(config, plan: dict, store, *, authorize) -> None:
    """Freeze an authorized cold job's common App before its first allocation.

    One <=4KiB record shares the original job's lifetime and deletion path.
    No new selection is applied to an already existing job, even if a later
    operator default becomes available. Explicit per-name choices still win.
    """
    from .onboarding import CONVERSATION_PLAN_SCHEMA, digest, private_directory
    from .onboarding_service import publish
    if plan.get('schema') != CONVERSATION_PLAN_SCHEMA:
        return
    explicit = (getattr(config, 'conversation_bundle_by_name', None) or {}).get(plan['name'])
    selected = explicit or getattr(config, 'conversation_bundle_default', None)
    path = store.directory(plan['name']) / 'conversation-bundle.json'
    if not selected and not path.exists() and not path.is_symlink():
        return
    if not authorize():
        raise OnboardingError('host_authorization_required')
    private_directory(store.root, create=True)
    with being_seed._locked(store.root):
        if path.exists() or path.is_symlink():
            retained = selected_bundle(config, plan)
            assert retained is not None
            verify(*retained, uid=os.geteuid())
            return
        if (path.parent / 'job.json').exists():
            return
        assert selected is not None
        verify(*selected, uid=os.geteuid())
        value = dict(schema='cluster-companion-app-selection/v1', plan_digest=digest(plan),
            selection=dict(root=str(selected[0]), sha256=selected[1]))
        raw = json.dumps(value, sort_keys=True).encode()
        if len(raw) > 4096:
            raise OnboardingError('conversation_bundle_selection_required')
        private_directory(path.parent, create=True)
        publish(path, raw)

def verify(root: Path, fingerprint: str, *, uid: int):
    being_seed._path(root)
    raw = regular(root / MARKER, uid=uid, limit=2 * 1024**2)
    if hashlib.sha256(raw).hexdigest() != fingerprint:
        raise OnboardingError('conversation_bundle_changed')
    value = json.loads(raw)
    if (not isinstance(value, dict) or set(value) - {'codex_package'} != {'schema', 'files'}
            or value['schema'] != SCHEMA or not isinstance(value['files'], dict)
            or 'codex_package' in value and value['codex_package'] != 'native'
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


def _native_component(name: str) -> bool:
    return (name == 'codex-package.json' or name.startswith(('codex-resources/', 'codex-path/'))
            or name in {'bin/codex', 'bin/codex-code-mode-host', 'bin/codex-exec-server'})


def compose_native(app: Path, fingerprint: str, native: Path, output: Path) -> dict:
    """Build one public release for ordinary cold onboarding, never a live update.

    Capture the operator-selected complete native package, preserving all other
    App bytes. Its content-derived local build version uses the native installer's
    existing local-package pinning instead of following public production releases.
    No daemon, identity, credential, account or model is opened here.
    """
    from .onboarding import digest
    verify(app, fingerprint, uid=os.geteuid())
    if output.exists() or output.is_symlink() or app == native:
        raise OnboardingError('conversation_bundle_destination_required')
    being_seed._path(native)
    info = native.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        raise OnboardingError('conversation_native_package_required')
    uid = info.st_uid
    # Native managed packages use private 0700 roots; their internal files may
    # retain the owner's installation umask. Public source roots stay strict.
    private_source = not info.st_mode & 0o077
    descriptor = os.open(native / 'codex-package.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1
                or before.st_size > 65536 or before.st_mode & 0o022 and not private_source):
            raise OnboardingError('conversation_native_package_required')
        metadata_raw = stream.read(65537)
        after = os.fstat(stream.fileno())
        if (len(metadata_raw) != before.st_size or len(metadata_raw) > 65536
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise OnboardingError('conversation_bundle_changed')
    metadata = json.loads(metadata_raw)
    if (not isinstance(metadata, dict)
            or metadata.get('layoutVersion') != 1 or metadata.get('entrypoint') != 'bin/codex'
            or metadata.get('resourcesDir') != 'codex-resources'
            or metadata.get('pathDir') != 'codex-path'
            or metadata.get('execServer', 'bin/codex-exec-server') != 'bin/codex-exec-server'
            or not isinstance(metadata.get('version'), str)
            or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?', metadata['version'])):
        raise OnboardingError('conversation_native_package_required')
    deadline = time.monotonic() + 180

    def budget():
        if time.monotonic() >= deadline:
            raise OnboardingError('conversation_bundle_build_deadline')

    written_bytes = 0

    def transfer(source, target=None, *, owner, expected=None, limit=MAX_BYTES):
        nonlocal written_bytes
        budget()
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        outgoing = None
        try:
            with os.fdopen(descriptor, 'rb') as stream:
                before = os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner
                        or before.st_mode & 0o022 and not (owner == uid and private_source)
                        or before.st_nlink != 1 or before.st_size > limit):
                    raise OnboardingError('conversation_native_package_required')
                if target is not None:
                    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o555 if before.st_mode & 0o100 else 0o444)
                    outgoing = os.fdopen(fd, 'wb')
                    os.fchmod(outgoing.fileno(), 0o555 if before.st_mode & 0o100 else 0o444)
                checksum = hashlib.sha256()
                size = 0
                while chunk := stream.read(1024**2):
                    budget()
                    size += len(chunk)
                    if size > before.st_size:
                        raise OnboardingError('conversation_bundle_changed')
                    checksum.update(chunk)
                    if outgoing:
                        written_bytes += len(chunk)
                        if written_bytes > MAX_BYTES:
                            raise OnboardingError('conversation_bundle_capacity')
                        outgoing.write(chunk)
                after = os.fstat(stream.fileno())
                def identity(row):
                    return row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns
                if (identity(before) != identity(after) or size != before.st_size
                        or expected is not None and checksum.hexdigest() != expected):
                    raise OnboardingError('conversation_bundle_changed')
                return checksum.hexdigest(), size
        finally:
            if outgoing:
                outgoing.close()

    native_files = {'codex-package.json': (hashlib.sha256(metadata_raw).hexdigest(), len(metadata_raw))}
    native_bytes = len(metadata_raw)
    entries = 0
    pending = [native / name for name in ('bin', 'codex-resources', 'codex-path')]
    while pending:
        directory = pending.pop()
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
                or info.st_mode & 0o022 and not private_source):
            raise OnboardingError('conversation_native_package_required')
        with os.scandir(directory) as children:
            for child in children:
                budget()
                entries += 1
                if entries > 2 * MAX_FILES:
                    raise OnboardingError('conversation_bundle_capacity')
                path = Path(child.path)
                if child.is_dir(follow_symlinks=False):
                    pending.append(path)
                else:
                    name = path.relative_to(native).as_posix()
                    if not child.is_file(follow_symlinks=False) or not _native_component(name):
                        raise OnboardingError('conversation_native_package_required')
                    native_files[name] = transfer(path, owner=uid, limit=MAX_BYTES-native_bytes)
                    native_bytes += native_files[name][1]
    required = {'bin/codex', 'bin/codex-code-mode-host'}
    if 'execServer' in metadata:
        required.add('bin/codex-exec-server')
    if not required <= native_files.keys() or any(not (native / name).stat().st_mode & 0o100 for name in required):
        raise OnboardingError('conversation_native_package_required')
    source_digest = digest({name: value[0] for name, value in native_files.items()})
    metadata['version'] = metadata['version'].split('+', 1)[0] + '+local.' + source_digest[:16]
    local_metadata = (json.dumps(metadata, sort_keys=True) + '\n').encode()
    if len(local_metadata) > 65536:
        raise OnboardingError('conversation_native_package_required')
    app_manifest = json.loads(regular(app / MARKER, uid=os.geteuid(), limit=2 * 1024**2))
    app_files = app_manifest['files']
    selected = {name: checksum for name, checksum in app_files.items()
                if not (name.startswith('native/') if app_manifest.get('codex_package') == 'native'
                        else _native_component(name))}
    if set(selected) & {'native/' + name for name in native_files}:
        raise OnboardingError('conversation_native_package_required')
    if (len(selected) + len(native_files) > MAX_FILES
            or sum((app / name).stat().st_size for name in selected)
               + sum(size for _, size in native_files.values()) - len(metadata_raw) + len(local_metadata) > MAX_BYTES):
        raise OnboardingError('conversation_bundle_capacity')
    being_seed._path(output)
    output.mkdir(mode=0o755)
    output.chmod(0o755)
    for name, checksum in selected.items():
        transfer(app / name, output / name, owner=os.geteuid(), expected=checksum)
    for name, (checksum, _) in native_files.items():
        if name != 'codex-package.json':
            transfer(native / name, output / 'native' / name, owner=uid, expected=checksum)
            selected['native/' + name] = checksum
    target = output / 'native/codex-package.json'
    if written_bytes + len(local_metadata) > MAX_BYTES:
        raise OnboardingError('conversation_bundle_capacity')
    target.write_bytes(local_metadata)
    target.chmod(0o444)
    selected['native/codex-package.json'] = hashlib.sha256(local_metadata).hexdigest()
    for directory in output.rglob('*'):
        if directory.is_dir():
            directory.chmod(0o755)
    manifest = (json.dumps(dict(schema=SCHEMA, codex_package='native', files=selected), sort_keys=True) + '\n').encode()
    (output / MARKER).write_bytes(manifest)
    (output / MARKER).chmod(0o444)
    pin = hashlib.sha256(manifest).hexdigest()
    observed = verify(output, pin, uid=os.geteuid())
    return dict(conversation_bundle_sha256=pin, native_source_sha256=source_digest,
                native_version=metadata['version'], **observed)


def compose_listener(app: Path, fingerprint: str, listener: Path,
                     listener_digest: str, output: Path) -> dict:
    """Prepare a listener-only successor without changing a native package.

    Existing mounts/jobs are untouched. The new public tree keeps the exact
    qualified Core, Python, web and dependency bytes and package metadata.
    """
    observed = verify(app, fingerprint, uid=os.geteuid())
    source = json.loads(regular(app / MARKER, uid=os.geteuid(), limit=2 * 1024**2))
    being_seed._path(output)
    if ('bin/telecodex' not in source['files'] or output.exists()
            or app.resolve() in output.resolve().parents
            or not re.fullmatch('[0-9a-f]{64}', listener_digest)):
        raise OnboardingError('conversation_listener_selection_required')
    being_seed._path(listener)
    info = listener.lstat()
    raw = regular(listener, uid=info.st_uid, limit=128 * 1024**2)
    if not info.st_mode & 0o100 or hashlib.sha256(raw).hexdigest() != listener_digest:
        raise OnboardingError('conversation_listener_changed')
    if observed['bytes'] - (app / 'bin/telecodex').stat().st_size + len(raw) > MAX_BYTES:
        raise OnboardingError('conversation_bundle_capacity')
    deadline = time.monotonic() + 180
    output.mkdir(mode=0o755)
    output.chmod(0o755)
    for name in source['files']:
        if time.monotonic() >= deadline:
            raise OnboardingError('conversation_bundle_build_deadline')
        target = output / name
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if name == 'bin/telecodex':
            target.write_bytes(raw)
            target.chmod(0o555)
        else:
            shutil.copyfile(app / name, target, follow_symlinks=False)
            target.chmod(0o555 if (app / name).stat().st_mode & 0o100 else 0o444)
    for path in output.rglob('*'):
        if path.is_dir():
            path.chmod(0o755)
    source['files']['bin/telecodex'] = listener_digest
    manifest = (json.dumps(source, sort_keys=True) + '\n').encode()
    (output / MARKER).write_bytes(manifest)
    (output / MARKER).chmod(0o444)
    pin = hashlib.sha256(manifest).hexdigest()
    return dict(conversation_bundle_sha256=pin, listener_sha256=listener_digest,
                **verify(output, pin, uid=os.geteuid()))


def bootstrap_codex(fingerprint: str, *, root=Path('/opt/daimon-app'),
                    destination=Path('/usr/local/bin/codex'), prepare_dependencies=False,
                    state_plan=None):
    """Expose this selected public executable; never overwrite a guest login/tool."""
    verify(root, fingerprint, uid=os.geteuid())
    manifest = json.loads(regular(root / MARKER, uid=os.geteuid(), limit=2 * 1024**2))
    package_root = root / manifest.get('codex_package', '.')
    if prepare_dependencies:
        dependencies()
    if state_plan is not None:
        from .onboarding_vm_state import install
        install(*state_plan)
    source = package_root / 'bin/codex'
    # The daemon resolves its sibling package and code-mode host. A lone CLI
    # executable reports its version but cannot start the native server.
    try:
        package = json.loads(regular(package_root / 'codex-package.json', uid=os.geteuid()))
        if (package.get('layoutVersion') != 1 or package.get('entrypoint') != 'bin/codex'
                or package.get('resourcesDir') != 'codex-resources'
                or package.get('pathDir') != 'codex-path'
                or not (package_root / 'codex-resources').is_dir()
                or not (package_root / 'codex-path').is_dir()
                or not os.access(package_root / 'bin/codex-code-mode-host', os.X_OK)):
            raise ValueError
    except (OSError, ValueError, TypeError, AttributeError):
        raise OnboardingError('conversation_bundle_codex_package_required') from None
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
        and shutil.which('rsync') is not None and shutil.which('git') is not None
        and Path('/usr/bin/node').is_file())
    if ready():
        return
    facts = dict(line.split('=', 1) for line in release.read_text().splitlines() if '=' in line)
    if os.geteuid() != 0 or facts.get('ID') != 'debian' or facts.get('VERSION_ID', '').strip('"') != '13':
        raise OnboardingError('conversation_guest_dependencies_required')
    execute = run or subprocess.run
    for arguments in (['update'], ['-y', '--no-install-recommends', 'install',
                                  'python3-venv', 'rsync', 'nodejs', 'git']):
        result = execute(['/usr/bin/apt-get', '-q', '-o',
            'APT::Keep-Downloaded-Packages=false', *arguments], capture_output=True,
            timeout=90, check=False, env={'PATH': os.defpath, 'LANG': 'C.UTF-8',
                'DEBIAN_FRONTEND': 'noninteractive'})
        if result.returncode:
            raise OnboardingError('conversation_guest_dependencies_required')
    if not ready():
        raise OnboardingError('conversation_guest_dependencies_required')
