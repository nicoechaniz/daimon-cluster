"""Retained full-OS VM maintenance through the local Incus agent.

Physical VM lifecycle remains in Cluster's journaled resource controller. This
placement reuses native OS code adoption and owner controls, without SSH
admission changes, container code mounts or a second messaging transport.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path

from . import being_seed
from .native_body import NativeBody
from .onboarding import OnboardingError, digest


class VMBody(NativeBody):
    @classmethod
    def load(cls, locator: Path, plan: dict, *, expected_digest: str | None = None) -> VMBody:
        value = being_seed._read(locator)
        if expected_digest is not None and digest(value) != expected_digest:
            raise OnboardingError('native_receiving_placement_changed')
        required = {'schema', 'plan_digest', 'project', 'instance', 'instance_uuid',
                    'host_machine_id_sha256', 'machine_id_sha256', 'bootstrap_python', 'home'}
        if (set(value) != required or value['schema'] != 'cluster-incus-vm-body-placement/v1'
                or value['plan_digest'] != digest(plan)
                or value['instance'] != 'dm-' + plan['name']
                or not isinstance(value['project'], str)
                or not being_seed.NAME.fullmatch(value['project'])
                or value['home'] != '/home/agent'
                or not isinstance(value['bootstrap_python'], str)
                or not Path(value['bootstrap_python']).is_absolute()
                or '..' in Path(value['bootstrap_python']).parts
                or any(not isinstance(value[key], str)
                    or re.fullmatch(r'[0-9a-f]{64}', value[key]) is None
                    for key in ('machine_id_sha256', 'host_machine_id_sha256'))):
            raise OnboardingError('vm_receiving_placement_required')
        try:
            if str(uuid.UUID(value['instance_uuid'])) != value['instance_uuid']:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise OnboardingError('vm_receiving_placement_required') from None
        if hashlib.sha256(Path('/etc/machine-id').read_bytes().strip()).hexdigest() != value['host_machine_id_sha256']:
            raise OnboardingError('vm_receiving_host_changed')
        return cls(value, locator)

    def _incus(self) -> list[str]:
        return ['incus', '--force-local', '--project', self.value['project']]

    def _verify_instance(self, timeout_seconds: float) -> None:
        try:
            result = subprocess.run(['incus', '--force-local', 'query', '/1.0/instances/' + self.value['instance']
                + '?project=' + self.value['project']],
                capture_output=True, text=True, timeout=min(8, timeout_seconds),
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
            if result.returncode:
                raise OnboardingError('vm_receiving_instance_unconfirmed')
            row = json.loads(result.stdout)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            raise OnboardingError('vm_receiving_instance_unconfirmed') from None
        if (not isinstance(row, dict) or row.get('type') != 'virtual-machine'
                or row.get('config', {}).get('volatile.uuid') != self.value['instance_uuid']):
            raise OnboardingError('vm_receiving_instance_changed')

    def _transport_command(self, command: list[str], *, timeout_seconds: float) -> list[str]:
        self._verify_instance(timeout_seconds)
        return [*self._incus(), 'exec', self.value['instance'], '--', *command]

    def _transfer_code(self, source: Path, stage: Path, remaining: float) -> None:
        deadline = time.monotonic_ns() + int(remaining * 1e9)
        started = time.monotonic()
        self._verify_instance(remaining)
        remaining -= time.monotonic() - started
        if remaining <= 0:
            raise OnboardingError('receiving_host_deadline_expired')
        # Source was qualified by NativeBody.prepare_code. Copy public children
        # only; Incus's agent writes the existing private staging directory.
        command = [*self._incus(), 'file', 'push', '--recursive',
                   '--', *[str(path) for path in sorted(source.iterdir())],
                   self.value['instance'] + str(stage) + '/']
        try:
            result = subprocess.run(command, capture_output=True, timeout=remaining,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
        except subprocess.TimeoutExpired:
            raise OnboardingError('receiving_host_deadline_expired') from None
        except OSError:
            raise OnboardingError('receiving_host_launch_failed') from None
        if result.returncode:
            raise OnboardingError('native_receiving_code_unconfirmed')
        # Incus refuses uid/gid overrides in recursive mode. Normalize only
        # this task's protected public-code stage, then the inherited verifier
        # checks every byte and ownership before atomic publication.
        normalize = """import os,stat,sys
from pathlib import Path
root=Path(sys.argv[1])
for p in [root,*root.rglob('*')]:
    s=p.lstat()
    if not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)) or (stat.S_ISREG(s.st_mode) and s.st_nlink!=1):
        raise SystemExit('native_receiving_code_changed')
    os.chown(p,0,0,follow_symlinks=False)
    os.chmod(p,0o755 if stat.S_ISDIR(s.st_mode) else 0o644,follow_symlinks=False)
"""
        self.execute([str(self.python), '-B', '-I', '-c', normalize, str(stage)],
                     uid=0, gid=0, deadline_ns=deadline)
