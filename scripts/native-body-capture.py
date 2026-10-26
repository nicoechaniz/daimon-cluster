#!/usr/bin/env python3
"""Capture a preseeded native body with its declared writers quiescent.

The operator supplies the reviewed writer boundary. No discovery, model requests,
backup encryption, SSH changes or automatic replay are performed here.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sys
import tempfile
import subprocess
import stat
from collections import Counter
from pathlib import Path


class CaptureError(ValueError):
    pass


def units(values: list[str], suffixes: tuple[str, ...]) -> list[str]:
    if not values or len(set(values)) != len(values):
        raise CaptureError('capture_boundary_invalid')
    if any(not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]*', x) or not x.endswith(suffixes)
           for x in values):
        raise CaptureError('capture_boundary_invalid')
    return values


def active(unit: str) -> bool:
    value = subprocess.check_output(
        ['systemctl', 'show', unit, '--property=ActiveState', '--value'], text=True, timeout=10).strip()
    if value not in {'active', 'inactive', 'failed'}:
        raise CaptureError('capture_service_transitional')
    return value == 'active'


def stopped(unit: str) -> bool:
    result = subprocess.check_output(
        ['systemctl', 'show', unit, '--property=ActiveState', '--property=Result',
         '--property=ControlGroup'], text=True, timeout=10)
    values = dict(line.split('=', 1) for line in result.splitlines() if '=' in line)
    if values.get('ActiveState') != 'inactive' or values.get('Result', 'success') != 'success':
        return False
    group = values.get('ControlGroup', '')
    events = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.events'
    return not group or not events.exists() or 'populated 0' in events.read_text()


def persist(path: Path, receipt: dict) -> None:
    descriptor, name = tempfile.mkstemp(prefix='.capture-attempt-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(receipt, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def recover(state: Path, receipt: dict | None = None) -> dict:
    path = state / 'capture-attempt.json'
    if receipt is None:
        if path.is_symlink() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077:
            raise CaptureError('capture_attempt_not_protected')
        receipt = json.loads(path.read_text())
    previous = receipt['previously_active']
    if previous:
        units(previous, ('.service', '.socket', '.timer', '.path'))
    failures = []
    # Reverse saved stop order: writers first, activation sources last.
    for unit in reversed(previous):
        try:
            result = subprocess.run(['systemctl', 'start', unit], check=False, timeout=120)
            if result.returncode or not active(unit):
                failures.append(unit)
        except (OSError, subprocess.SubprocessError, CaptureError):
            failures.append(unit)
    receipt['recovery_failures'] = failures
    receipt['availability_restored'] = not failures
    persist(path, receipt)
    return receipt


def mounts() -> list[dict]:
    result = json.loads(subprocess.check_output(
        ['findmnt', '--json', '--output', 'TARGET,FSTYPE'], text=True, timeout=15))
    rows = []
    def visit(items):
        for item in items:
            rows.append({'target': item['target'], 'fstype': item['fstype']})
            visit(item.get('children', []))
    visit(result['filesystems'])
    return sorted(rows, key=lambda item: (item['target'], item['fstype']))


def below(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def seed_boundary(destination: Path, mount_rows: list[dict]) -> dict:
    if destination.resolve() != destination or not destination.is_dir():
        raise CaptureError('capture_seed_path_invalid')
    if any(below(Path(row['target']), destination) for row in mount_rows):
        raise CaptureError('capture_seed_is_mounted')
    # A hot rsync seed may have internal hardlinks, but none may alias data
    # outside the disposable seed. Count links without following symlinks.
    counts = Counter()
    links = {}
    for directory, _, files in os.walk(destination, followlinks=False):
        for filename in files:
            info = (Path(directory) / filename).lstat()
            if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                key = (info.st_dev, info.st_ino)
                counts[key] += 1
                links[key] = info.st_nlink
    if any(counts[key] != count for key, count in links.items()):
        raise CaptureError('capture_seed_has_external_hardlinks')
    info = destination.stat()
    return {'path': str(destination), 'device': info.st_dev, 'inode': info.st_ino,
            'purpose': 'disposable-independent-backup-seed'}


def coverage(state: Path, mount_rows: list[dict], required_paths: list[Path]) -> dict:
    local_types = {'ext2', 'ext3', 'ext4', 'btrfs', 'xfs', 'zfs', 'vfat'}
    ignored = [Path(x) for x in ['/proc', '/sys', '/dev', '/run', '/tmp',
                                 '/lost+found']] + [state]
    sources = [Path('/')]
    exclusions = list(ignored)
    root_device = Path('/').stat().st_dev
    for row in sorted(mount_rows, key=lambda item: len(Path(item['target']).parts)):
        path = Path(row['target'])
        if path == Path('/') or any(below(path, parent) for parent in ignored):
            continue
        if row['fstype'] in local_types:
            # Same-device bind mounts are included by the root rsync. Separate
            # durable filesystems need their own pass, including boot/EFI.
            if path.stat().st_dev != root_device:
                sources.append(path)
        else:
            exclusions.append(path)
    for path in sources + exclusions:
        if not re.fullmatch(r'/[A-Za-z0-9_./+-]*', str(path)):
            raise CaptureError('capture_mount_pattern_unsupported')
    for path in required_paths:
        resolved = path.resolve(strict=True)
        if any(below(resolved, excluded) for excluded in exclusions):
            raise CaptureError('capture_required_store_excluded')
        if not any(below(resolved, source) and resolved.stat().st_dev == source.stat().st_dev
                   for source in sources):
            raise CaptureError('capture_required_store_uncovered')
    return {'source_roots': [str(path) for path in sources],
            'excluded_mounts_and_runtime': sorted(set(str(path) for path in exclusions)),
            'required_paths': [str(path) for path in required_paths],
            'mounts': mount_rows}


def prepare(state: Path, required_paths: list[Path]) -> dict:
    if not required_paths:
        raise CaptureError('capture_required_store_declaration_missing')
    rows = mounts()
    destination = state / 'capture/root'
    plan = {'schema': 'native-body-capture-plan/v1',
            'seed': seed_boundary(destination, rows),
            **coverage(state, rows, required_paths)}
    persist(state / 'capture-plan.json', plan)
    return plan


def load_plan(state: Path) -> dict:
    path = state / 'capture-plan.json'
    if path.is_symlink() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077:
        raise CaptureError('capture_plan_not_protected')
    plan = json.loads(path.read_text())
    if plan['schema'] != 'native-body-capture-plan/v1' or plan['mounts'] != mounts():
        raise CaptureError('capture_mount_coverage_changed')
    seed = seed_boundary(state / 'capture/root', plan['mounts'])
    if seed != plan['seed']:
        raise CaptureError('capture_seed_changed')
    current = coverage(state, plan['mounts'], [Path(x) for x in plan['required_paths']])
    if any(current[key] != plan[key] for key in current):
        raise CaptureError('capture_coverage_changed')
    return plan


def capture(state: Path, writers: list[str], activators: list[str]) -> dict:
    writers = units(writers, ('.service',))
    if activators:
        activators = units(activators, ('.timer', '.socket', '.path'))
    if (not state.is_absolute() or '..' in state.parts or state == Path('/')
            or state.is_symlink() or not state.is_dir() or state.resolve() != state
            or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(state))):
        raise CaptureError('capture_state_invalid')
    if state.stat().st_uid != os.geteuid() or state.stat().st_mode & 0o077:
        raise CaptureError('capture_state_not_private')
    destination = state / 'capture/root'
    if (destination.is_symlink() or not destination.is_dir()
            or destination.resolve() != destination):
        raise CaptureError('capture_preseed_required')
    plan = load_plan(state)
    order = activators + writers
    previously_active = [unit for unit in order if active(unit)]
    receipt = {'schema': 'native-body-capture/v1', 'previously_active': previously_active,
               'capture_consistent': False, 'availability_restored': False, 'plan': plan}
    path = state / 'capture-attempt.json'
    if path.exists():
        raise CaptureError('capture_attempt_retained')
    persist(path, receipt)
    failure = None
    try:
        # Activation sources stop before writers. systemd observes native graceful
        # shutdown; a timeout/kill is not accepted as a consistent cutoff.
        for unit in order:
            subprocess.run(['systemctl', 'stop', unit], check=True, timeout=120)
        if not all(stopped(unit) for unit in order):
            raise CaptureError('capture_quiescence_unconfirmed')
        with (state / 'capture-final.log').open('wb') as log:
            for source in plan['source_roots']:
                target = destination / source.lstrip('/')
                target.mkdir(parents=True, exist_ok=True)
                command = ['rsync', '--archive', '--acls', '--xattrs', '--hard-links',
                           '--numeric-ids', '--one-file-system', '--sparse', '--delete',
                           '--delete-excluded', '--stats']
                exclusions = list(plan['excluded_mounts_and_runtime'])
                # Protect other durable mount roots during the parent pass.
                exclusions += [x for x in plan['source_roots']
                               if x != source and below(Path(x), Path(source))]
                for exclusion in exclusions:
                    if below(Path(exclusion), Path(source)):
                        relative = str(Path(exclusion).relative_to(source))
                        command += ['--exclude', '/' + relative + '/***']
                command += [source.rstrip('/') + '/', str(target) + '/']
                subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT,
                               timeout=300)
        if not all(stopped(unit) for unit in order):
            raise CaptureError('capture_writer_reactivated')
        receipt['capture_consistent'] = True
    except Exception as error:
        failure = error
        receipt['error'] = (str(error) if isinstance(error, CaptureError)
                            else 'capture_operation_unconfirmed')
    finally:
        receipt = recover(state, receipt)
    if failure is not None or not receipt['availability_restored']:
        raise CaptureError('capture_not_accepted_inspect_retained_attempt')
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--recover-only', action='store_true')
    actions.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--required-paths', type=Path, nargs='*', default=[])
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--writers', nargs='+', default=[])
    parser.add_argument('--activators', nargs='*', default=[])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise CaptureError('capture_operator_required')
    os.umask(0o077)
    previous = signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(128 + signum))
    try:
        result = (recover(args.state) if args.recover_only else
                  prepare(args.state, args.required_paths) if args.prepare_only else
                  capture(args.state, args.writers, args.activators))
        print(json.dumps(result))
    finally:
        signal.signal(signal.SIGTERM, previous)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
