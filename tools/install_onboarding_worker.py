"""Install the independent worker from an operator-selected immutable release."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_host import HostConfig
from clusterctl.onboarding_service import publish

UNIT = 'daimon-onboarding-worker.service'


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
        publish(Path('/etc/systemd/system') / UNIT, candidate)
        if args.activate:
            for command in (['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', UNIT]):
                result = subprocess.run(command, capture_output=True, timeout=30, check=False)
                if result.returncode:
                    raise OnboardingError('worker_service_failed')
        print(json.dumps(dict(installed=True, activation_requested=args.activate)))
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print(json.dumps(dict(error='onboarding_worker_install_refused')))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
