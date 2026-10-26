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
    order = activators + writers
    previously_active = [unit for unit in order if active(unit)]
    receipt = {'schema': 'native-body-capture/v1', 'previously_active': previously_active,
               'capture_consistent': False, 'availability_restored': False}
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
        exclusions = ['/proc/***', '/sys/***', '/dev/***', '/run/***', '/tmp/***',
                      '/mnt/***', '/media/***', '/lost+found/***', str(state) + '/***']
        command = ['rsync', '--archive', '--acls', '--xattrs', '--hard-links',
                   '--numeric-ids', '--one-file-system', '--sparse', '--delete',
                   '--delete-excluded', '--stats']
        for exclusion in exclusions:
            command += ['--exclude', exclusion]
        command += ['/', str(destination) + '/']
        with (state / 'capture-final.log').open('wb') as log:
            subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT, timeout=300)
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
    parser.add_argument('--recover-only', action='store_true')
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
                  capture(args.state, args.writers, args.activators))
        print(json.dumps(result))
    finally:
        signal.signal(signal.SIGTERM, previous)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
