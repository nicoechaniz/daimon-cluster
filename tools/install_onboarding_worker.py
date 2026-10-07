"""Install the independent worker from an operator-selected immutable release."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import uuid
from pathlib import Path

from clusterctl.onboarding import OnboardingError, private_directory
from clusterctl.onboarding_host import HostConfig
from clusterctl import being_seed, onboarding_release
from clusterctl.onboarding_service import publish

UNIT = 'daimon-onboarding-worker.service'


def install_unit(directory: Path, candidate: bytes, *, previous_sha256: str | None = None) -> bool:
    """Update only our exact owned unit, preserving its recoverable predecessor."""
    lock = private_directory(directory / '.daimon-onboarding-worker-install', create=True)
    with being_seed._locked(lock):
        return _install_unit_locked(directory, candidate, previous_sha256=previous_sha256)


def _install_unit_locked(directory: Path, candidate: bytes, *, previous_sha256: str | None) -> bool:
    path = directory / UNIT
    if previous_sha256 is None:
        publish(path, candidate)
        return False
    if not re.fullmatch(r'[0-9a-f]{64}', previous_sha256):
        raise OnboardingError('qualified_worker_predecessor_required')
    original = onboarding_release.regular(path, uid=os.geteuid())
    if path.stat().st_mode & 0o777 != 0o600:
        raise OnboardingError('existing_onboarding_service_preserved')
    if original == candidate:
        return False
    if hashlib.sha256(original).hexdigest() != previous_sha256:
        raise OnboardingError('existing_onboarding_service_preserved')
    # publish verifies ownership/mode and refuses a contradictory rollback.
    publish(directory / (UNIT + '.' + previous_sha256 + '.previous'), original)
    temporary = directory / ('.onboarding-worker-' + uuid.uuid4().hex)
    try:
        publish(temporary, candidate)
        if onboarding_release.regular(path, uid=os.geteuid()) != original:
            raise OnboardingError('existing_onboarding_service_preserved')
        os.replace(temporary, path)
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def service(release: Path, config: Path) -> bytes:
    if (release.parent != Path('/opt/daimon-cluster-releases')
            or not re.fullmatch(r'[0-9a-f]{40}', release.name)
            or not config.is_absolute() or '..' in config.parts):
        raise OnboardingError('qualified_worker_release_required')
    argv = [str(release / 'venv/bin/python'), '-m', 'clusterctl.onboarding_worker', '--config', str(config)]
    encoded = ' '.join(json.dumps(arg.replace('%', '%%').replace('$', '$$')) for arg in argv)
    return ('[Unit]\nDescription=Durable authorized Daimon onboarding worker\n'
        'After=network-online.target\nWants=network-online.target\n'
        '[Service]\nType=simple\nUser=root\nGroup=root\nUMask=0077\n'
        f'WorkingDirectory={release}\nExecStart={encoded}\n'
        'Environment=PYTHONDONTWRITEBYTECODE=1\n'
        'Restart=on-failure\nRestartSec=5\nKillMode=control-group\nTimeoutStopSec=30\n'
        'StandardOutput=null\nStandardError=null\n'
        '[Install]\nWantedBy=multi-user.target\n').encode()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--activate', action='store_true')
    parser.add_argument('--replace-unit-sha256', help='Exact installed predecessor; preserve rollback')
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise OnboardingError('host_operator_required')
        candidate = service(args.release, args.config)
        HostConfig.load(args.config)
        # Verify the selected installation, never another checkout's SDK.
        result = subprocess.run([str(args.release / 'venv/bin/python'), '-c',
            'from clusterctl.matrix_host import _matrix_api; _matrix_api()'],
            cwd=args.release, capture_output=True, timeout=30, check=False)
        if result.returncode:
            raise OnboardingError('qualified_worker_release_required')
        changed = install_unit(Path('/etc/systemd/system'), candidate,
                               previous_sha256=args.replace_unit_sha256)
        if args.activate:
            for command in (['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', UNIT]):
                result = subprocess.run(command, capture_output=True, timeout=30, check=False)
                if result.returncode:
                    raise OnboardingError('worker_service_failed')
            if changed:
                result = subprocess.run(['systemctl', 'restart', UNIT],
                    capture_output=True, timeout=40, check=False)
                if result.returncode:
                    raise OnboardingError('worker_service_failed')
        print(json.dumps(dict(installed=True, activation_requested=args.activate, software_updated=changed)))
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print(json.dumps(dict(error='onboarding_worker_install_refused')))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
