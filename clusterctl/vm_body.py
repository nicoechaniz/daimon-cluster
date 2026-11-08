"""Retained, explicitly typed Incus bodies through the existing agent.

Physical VM lifecycle remains in Cluster's journaled resource controller. This
placement reuses native OS code adoption and owner controls, without SSH
admission changes, container code mounts or a second messaging transport.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import time
import uuid
from pathlib import Path

from . import being_seed, onboarding_release
from .native_body import NativeBody, ssh_arguments
from .onboarding import OnboardingError, digest


HOST_LAUNCH = """import hashlib,json,os,sys
if hashlib.sha256(open('/etc/machine-id','rb').read().strip()).hexdigest()!=sys.argv[1]:
    raise SystemExit('vm_receiving_host_changed')
argv=json.loads(sys.argv[2])+sys.argv[3:]
os.execvpe(argv[0],argv,{'PATH':os.defpath,'LANG':'C.UTF-8'})
"""


class IncusBody(NativeBody):
    placement_schema = ''
    instance_type = ''

    @classmethod
    def load(cls, locator: Path, plan: dict, *, expected_digest: str | None = None) -> IncusBody:
        value = being_seed._read(locator)
        if expected_digest is not None and digest(value) != expected_digest:
            raise OnboardingError('native_receiving_placement_changed')
        required = {'schema', 'plan_digest', 'project', 'instance', 'instance_uuid',
                    'host_machine_id_sha256', 'machine_id_sha256', 'bootstrap_python', 'home'}
        if (set(value) - {'incus_host_ssh'} != required or value['schema'] != cls.placement_schema
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
        parent = value.get('incus_host_ssh')
        if parent is not None:
            keys = {'host', 'port', 'ssh_user', 'identity_file', 'identity_uid', 'known_hosts', 'bootstrap_python'}
            if (not isinstance(parent, dict) or set(parent) - {'sudo'} != keys
                    or 'sudo' in parent and type(parent['sudo']) is not bool
                    or not isinstance(parent['host'], str)
                    or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}', parent['host']) is None
                    or not isinstance(parent['ssh_user'], str)
                    or re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', parent['ssh_user']) is None
                    or type(parent['port']) is not int or not 1 <= parent['port'] <= 65535
                    or type(parent['identity_uid']) is not int or not 0 <= parent['identity_uid'] < 2**32
                    or any(not isinstance(parent[key], str) or not Path(parent[key]).is_absolute()
                        or '..' in Path(parent[key]).parts
                        for key in ('identity_file','known_hosts','bootstrap_python'))):
                raise OnboardingError('vm_receiving_placement_required')
        body = cls(value, locator)
        if not body._local():
            if parent is None:
                raise OnboardingError('vm_receiving_host_changed')
            for key in ('identity_file', 'known_hosts'):
                onboarding_release.regular(Path(parent[key]),
                    uid=parent['identity_uid'] if key == 'identity_file' else os.geteuid())
            if Path(parent['identity_file']).stat().st_mode & 0o077:
                raise OnboardingError('vm_receiving_placement_required')
        return body

    def _local(self) -> bool:
        return hashlib.sha256(Path('/etc/machine-id').read_bytes().strip()).hexdigest() == self.value['host_machine_id_sha256']

    def _incus(self) -> list[str]:
        return ['incus', '--force-local', '--project', self.value['project']]

    def _parent_command(self, argv: list[str]) -> list[str]:
        if self._local():
            return argv
        parent = self.value.get('incus_host_ssh')
        if parent is None:
            raise OnboardingError('vm_receiving_host_changed')
        command = [parent['bootstrap_python'], '-B', '-I', '-c', HOST_LAUNCH,
                   self.value['host_machine_id_sha256'], json.dumps(argv)]
        if parent.get('sudo', False):
            command = ['sudo', '-n', '--', *command]
        return [*ssh_arguments(parent), '--', parent['ssh_user']+'@'+parent['host'], shlex.join(command)]

    def _verify_instance(self, timeout_seconds: float) -> None:
        try:
            result = subprocess.run(self._parent_command(['incus', '--force-local', 'query', '/1.0/instances/' + self.value['instance']
                + '?project=' + self.value['project']]),
                capture_output=True, text=True, timeout=min(8, timeout_seconds),
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
            if result.returncode:
                if 'vm_receiving_host_changed' in result.stderr.splitlines():
                    raise OnboardingError('vm_receiving_host_changed')
                raise OnboardingError('vm_receiving_instance_unconfirmed')
            row = json.loads(result.stdout)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            raise OnboardingError('vm_receiving_instance_unconfirmed') from None
        if (not isinstance(row, dict) or row.get('type') != self.instance_type
                or row.get('config', {}).get('volatile.uuid') != self.value['instance_uuid']):
            raise OnboardingError('vm_receiving_instance_changed')

    def _transport_command(self, command: list[str], *, timeout_seconds: float) -> list[str]:
        self._verify_instance(timeout_seconds)
        return self._parent_command([*self._incus(), 'exec', self.value['instance'], '--', *command])

    def _transfer_code(self, source: Path, stage: Path, remaining: float) -> None:
        deadline = time.monotonic_ns() + int(remaining * 1e9)
        started = time.monotonic()
        self._verify_instance(remaining)
        remaining -= time.monotonic() - started
        if remaining <= 0:
            raise OnboardingError('receiving_host_deadline_expired')
        # Source was qualified by NativeBody.prepare_code. Copy public children
        # only; Incus's agent writes the existing private staging directory.
        if self._local():
            command = [*self._incus(), 'file', 'push', '--recursive',
                       '--', *[str(path) for path in sorted(source.iterdir())],
                       self.value['instance'] + str(stage) + '/']
        else:
            parent = self.value['incus_host_ssh']
            host = parent['host']
            if ':' in host:
                host = '[' + host + ']'
            server = [parent['bootstrap_python'], '-B', '-I', '-c', HOST_LAUNCH,
                      self.value['host_machine_id_sha256'],
                      json.dumps([*self._incus(), 'exec', self.value['instance'], '--', 'rsync'])]
            if parent.get('sudo', False):
                server = ['sudo', '-n', '--', *server]
            command = ['rsync', '--archive', '--checksum', '--protect-args', '--chmod=D755,F644',
                       '-e', shlex.join(ssh_arguments(parent)), '--rsync-path', shlex.join(server),
                       '--', str(source)+'/', parent['ssh_user']+'@'+host+':'+str(stage)+'/']
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


class VMBody(IncusBody):
    """A full OS VM; container observations never satisfy this locator."""
    placement_schema = 'cluster-incus-vm-body-placement/v1'
    instance_type = 'virtual-machine'


class ContainerBody(IncusBody):
    """A container with its own pinned instance UUID and guest machine ID."""
    placement_schema = 'cluster-incus-container-body-placement/v1'
    instance_type = 'container'


class RemoteIncusRunner:
    """Existing HostBackend execution on one explicitly selected Incus host.

    Job/custody ownership stays with the controller. Incus inventory and mounts
    describe the physical host; guest execution and framed sessions additionally
    verify the exact instance and receiving OS. Publication is supplied by the
    same protected operator, rather than silently leaving files on the controller.
    """
    def __init__(self, placements: dict[str, tuple[Path, str]], plans: dict[str, dict], *, publish):
        if not placements or set(placements) != set(plans) or not callable(publish):
            raise OnboardingError('remote_incus_host_binding_required')
        self.placements, self.plans, self.publish = dict(placements), dict(plans), publish
        bodies = [self.body_for(plan) for plan in self.plans.values()]
        self.parent = bodies[0]
        def key(body):
            return (body.value['host_machine_id_sha256'], body.value.get('incus_host_ssh'), body.value['project'])
        if self.parent._local() or any(key(body) != key(self.parent) for body in bodies):
            raise OnboardingError('remote_incus_host_binding_required')

    def body_for(self, plan: dict) -> IncusBody:
        name = plan.get('name')
        if name not in self.plans or digest(plan) != digest(self.plans[name]):
            raise OnboardingError('remote_incus_plan_changed')
        locator, pin = self.placements[name]
        body = NativeBody.load(locator, plan, expected_digest=pin)
        if not isinstance(body, IncusBody):
            raise OnboardingError('remote_incus_host_binding_required')
        return body

    def prepare_matrix_public(self, views: Path, plan: dict, documents: dict) -> None:
        self.body_for(plan)  # Recheck the protected plan and placement before publication.
        self.publish(views, plan, documents)

    def __call__(self, argv: list[str], *, timeout_seconds: float | None = None,
                 input_data: str | None = None) -> str:
        import math
        if (not argv or any(not isinstance(item, str) or '\0' in item for item in argv)
                or timeout_seconds is not None and (not math.isfinite(timeout_seconds)
                    or not 0 < timeout_seconds <= 65)
                or input_data is not None and (not isinstance(input_data, str)
                    or len(input_data.encode()) > being_seed.MAX_SELECTION)):
            raise OnboardingError('remote_incus_request_required')
        timeout = min(60, timeout_seconds) if timeout_seconds is not None else 60
        if argv[0] == 'exec':
            try:
                separator = argv.index('--', 2)
                name = next(name for name, plan in self.plans.items()
                    if argv[1] == 'dm-' + plan['name'])
            except (ValueError, StopIteration, IndexError):
                raise OnboardingError('remote_incus_plan_changed') from None
            uid = gid = 0
            env = None
            options = argv[2:separator]
            if len(options) % 2:
                raise OnboardingError('remote_incus_exec_options_required')
            seen = set()
            for flag, value in zip(options[::2], options[1::2]):
                if flag in seen or flag not in {'--user', '--group', '--env'}:
                    raise OnboardingError('remote_incus_exec_options_required')
                seen.add(flag)
                if flag == '--env':
                    if value != 'HOME=/home/agent':
                        raise OnboardingError('remote_incus_exec_options_required')
                    env = {'HOME': '/home/agent'}
                elif value not in {'0', '1000'}:
                    raise OnboardingError('remote_incus_exec_options_required')
                elif flag == '--user':
                    uid = int(value)
                else:
                    gid = int(value)
            if (uid, gid) not in {(0, 0), (1000, 1000)}:
                raise OnboardingError('remote_incus_exec_options_required')
            command = argv[separator+1:]
            deadline = None
            owner_clock = '--observation-deadline-ns' in command or '--deadline-ns' in command
            for flag in ('--observation-deadline-ns', '--deadline-ns'):
                if flag in command:
                    try:
                        deadline = int(command[command.index(flag)+1])
                    except (ValueError, IndexError):
                        raise OnboardingError('receiving_host_deadline_required') from None
            return self.body_for(self.plans[name]).execute(command, uid=uid, gid=gid, env=env,
                input_data=input_data, timeout_seconds=timeout, deadline_ns=deadline, owner_clock=owner_clock)
        # Keep the already authorized HostBackend's exact Incus operation. SSH
        # carries an argv array through the same pinned parent launcher, no shell
        # interpolation, credentials, new service or second resource registry.
        parent = self.body_for(self.plans[next(iter(self.plans))])
        try:
            result = subprocess.run(parent._parent_command(['incus', '--force-local', '--project', parent.value['project'], *argv]), input=input_data,
                capture_output=True, text=True, timeout=timeout,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
        except (OSError, subprocess.TimeoutExpired):
            raise OnboardingError('remote_incus_operation_unconfirmed') from None
        if result.returncode or len(result.stdout.encode()) > being_seed.MAX_SELECTION:
            raise OnboardingError('remote_incus_operation_unconfirmed')
        return result.stdout
