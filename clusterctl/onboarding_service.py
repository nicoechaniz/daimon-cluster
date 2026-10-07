"""Persistent service installation in a newly provisioned onboarding guest."""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import uuid
from pathlib import Path

from . import being_seed, onboarding_release
from .onboarding import OnboardingError, validate_plan

UNIT = 'daimon-onboarding-matrix.service'


def command(code: Path, *, receive_only: bool, visibility: Path | None = None) -> list[str]:
    if receive_only == (visibility is not None):
        raise OnboardingError('onboarding_visibility_selection_required')
    launcher = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                'from clusterctl.onboarding_target import main;raise SystemExit(main())')
    public = '/home/agent/.onboarding-matrix/'
    argv = ['/usr/bin/python3', '-B', '-I', '-c', launcher, str(code), 'admitted-serve',
            '--home', '/home/agent', '--code', str(code),
            '--plan', '/home/agent/.onboarding-input/plan.json',
            '--genesis', public + 'genesis.json', '--admission-profile', public + 'admission.json']
    return argv + (['--receive-only'] if receive_only else ['--visibility-installation', str(visibility)])


def install(code: Path, *, receive_only: bool, visibility: Path | None = None,
            directory: Path = Path('/etc/systemd/system'), run=None) -> None:
    """Preserve foreign units; publication/reload/enable are independently retryable."""
    being_seed._path(directory)
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise OnboardingError('onboarding_service_directory_rejected')
    argv = command(code, receive_only=receive_only, visibility=visibility)
    # systemd's ExecStart syntax, not a shell command. Escape substitutions.
    encoded = ' '.join(json.dumps(arg.replace('%', '%%').replace('$', '$$')) for arg in argv)
    raw = ('[Unit]\nDescription=Admitted native onboarding body\nAfter=network-online.target\n'
           'Wants=network-online.target\n[Service]\nType=simple\nUser=agent\nGroup=agent\n'
           'Environment=HOME=/home/agent\nUMask=0077\nRestart=on-failure\nRestartSec=5\n'
           'KillMode=control-group\nTimeoutStopSec=30\nExecStart=' + encoded +
           '\n[Install]\nWantedBy=multi-user.target\n').encode()
    path = directory / UNIT
    if path.exists() or path.is_symlink():
        if onboarding_release.regular(path, uid=os.geteuid()) != raw:
            raise OnboardingError('existing_onboarding_service_preserved')
    else:
        temporary = directory / ('.onboarding-service-' + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            os.link(temporary, path, follow_symlinks=False)
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            temporary.unlink(missing_ok=True)
    execute = run or _run
    execute(['systemctl', 'daemon-reload'])
    execute(['systemctl', 'enable', '--now', UNIT])


def _run(argv: list[str]) -> None:
    try:
        result = subprocess.run(argv, capture_output=True, timeout=40, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise OnboardingError('onboarding_service_operation_failed') from None
    if result.returncode:
        raise OnboardingError('onboarding_service_operation_failed')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--code', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--receive-only', action='store_true')
    selection.add_argument('--visibility-installation', type=Path)
    args = parser.parse_args(argv)
    try:
        plan = validate_plan(json.loads(onboarding_release.regular(args.plan, uid=1000)))
        onboarding_release.verify(args.code, plan['release_digest'], uid=0)
        if os.geteuid() != 0 or args.code != Path('/opt/daimon-onboarding') / plan['release_digest']:
            raise OnboardingError('qualified_guest_service_required')
        install(args.code, receive_only=args.receive_only, visibility=args.visibility_installation)
        print(json.dumps(dict(installed=True)))
        return 0
    except (OSError, ValueError, OnboardingError):
        print(json.dumps(dict(installed=False, error='onboarding_service_operation_failed')))
        return 1
