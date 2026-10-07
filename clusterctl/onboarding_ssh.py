"""Dedicated SSH configuration for a new isolated receiving guest.

The standalone listener never edits the operating system's SSH configuration.
Its key files and service belong only to the dedicated receiving account.
"""
from __future__ import annotations

import hashlib
import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from . import being_seed, onboarding_release
from .onboarding import OnboardingError, digest, private_directory, validate_plan
from .onboarding_service import publish

SCHEMA = 'cluster-onboarding-ssh/v1'
PORT = 2222
ROOT = Path('/etc/daimon-onboarding/ssh')
UNIT = 'daimon-onboarding-ssh.service'


def public_key(value: object) -> bytes:
    """Close the configuration grammar before any privileged file publication."""
    if not isinstance(value, str) or not re.fullmatch(
            r'(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]{40,1600}(?: [^\r\n\x00]{0,80})?', value):
        raise OnboardingError('onboarding_ssh_public_key_required')
    return (value + '\n').encode()


def proposal(plan: dict, key: object) -> dict:
    """Freeze the exact receiving key and standalone configuration for apply."""
    validate_plan(plan)
    raw = public_key(key)
    configuration = ('Port 2222\nListenAddress 0.0.0.0\n'
        f'HostKey {ROOT}/private/host.key\nPidFile /run/daimon-onboarding-ssh/sshd.pid\n'
        f'AuthorizedKeysFile {ROOT}/owner.pub\n'
        'AllowUsers agent\nAuthenticationMethods publickey\nPubkeyAuthentication yes\n'
        'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n'
        'UsePAM yes\nStrictModes yes\nUseDNS no\nAllowAgentForwarding no\n'
        'AllowTcpForwarding no\nAllowStreamLocalForwarding no\nPermitTunnel no\n'
        'X11Forwarding no\nSubsystem sftp internal-sftp\n').encode()
    service = ('[Unit]\nDescription=Dedicated receiving SSH listener\nAfter=network.target\n'
        '[Service]\nType=simple\nRuntimeDirectory=daimon-onboarding-ssh\n'
        'RuntimeDirectoryMode=0700\nUMask=0077\nRestart=on-failure\nRestartSec=5\n'
        f'ExecStart=/usr/sbin/sshd -D -e -f {ROOT}/sshd.conf\n'
        '[Install]\nWantedBy=multi-user.target\n').encode()
    return dict(schema=SCHEMA, plan_digest=digest(plan), port=PORT, account='agent',
                public_key_sha256=hashlib.sha256(raw).hexdigest(),
                configuration=configuration.decode(), service=service.decode(), public_key=raw.decode())


def _run(argv: list[str]) -> str:
    try:
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=600 if argv[0] == '/usr/bin/apt-get' else 40, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise OnboardingError('onboarding_ssh_operation_failed') from None
    if result.returncode:
        raise OnboardingError('onboarding_ssh_operation_failed')
    return result.stdout


def dependencies(*, run=None, sshd: Path = Path('/usr/sbin/sshd'),
                 policy: Path = Path('/usr/sbin/policy-rc.d')) -> None:
    """Install OpenSSH only in the already-validated new receiving guest."""
    execute = run or _run
    # Debian package scripts must not start a second, unconfigured listener.
    raw = b'#!/bin/sh\n# daimon-onboarding dependency installation\nexit 101\n'
    owned_policy = policy.exists() and onboarding_release.regular(policy, uid=os.geteuid()) == raw
    if sshd.is_file() and not owned_policy:
        return
    publish(policy, raw, mode=0o755)
    execute(['/usr/bin/apt-get', '-q', 'update'])
    execute(['/usr/bin/apt-get', '-q', '-y', '--no-install-recommends', 'install', 'openssh-server'])
    execute(['systemctl', 'disable', '--now', 'ssh.service'])
    # Keep our suppression marker on failure. Retry finishes package
    # configuration even if a prior attempt already published the executable.
    if onboarding_release.regular(policy, uid=os.geteuid()) == raw:
        policy.unlink()


def install(plan: dict, key: object, *, root: Path = ROOT,
            units: Path = Path('/etc/systemd/system'), run=None) -> dict:
    """Preserve host key and owner key across interrupted service installation."""
    value = proposal(plan, key)
    being_seed._path(root)
    if not root.exists():
        root.mkdir(mode=0o755, parents=True)
    info = root.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022 or not root.is_dir():
        raise OnboardingError('onboarding_ssh_directory_rejected')
    private = private_directory(root / 'private', create=True)
    execute = run or _run
    # Invalid inputs must not publish a durable binding that blocks correction.
    with tempfile.TemporaryDirectory(prefix='.validation-', dir=root) as stage:
        candidate = Path(stage) / 'owner.pub'
        publish(candidate, value['public_key'].encode())
        execute(['/usr/bin/ssh-keygen', '-l', '-f', str(candidate)])
    with being_seed._locked(private):
        binding = dict(schema=SCHEMA, plan_digest=digest(plan), public_key_sha256=value['public_key_sha256'])
        marker = private / 'binding.json'
        if marker.exists():
            if being_seed._read(marker) != binding:
                raise OnboardingError('existing_onboarding_ssh_preserved')
        elif any(path.name != 'lock' for path in private.iterdir()):
            raise OnboardingError('existing_onboarding_ssh_preserved')
        else:
            publish(marker, json.dumps(binding, sort_keys=True).encode())
        publish(root / 'owner.pub', value['public_key'].encode(), mode=0o644)
        host_key = private / 'host.key'
        descriptor = private / 'host-public.json'
        if not host_key.exists():
            if descriptor.exists():
                raise OnboardingError('existing_onboarding_ssh_preserved')
            with tempfile.TemporaryDirectory(prefix='.preparing-', dir=private) as stage:
                temporary = Path(stage) / 'host.key'
                execute(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(temporary)])
                publish(host_key, onboarding_release.regular(temporary, uid=os.geteuid()))
        onboarding_release.regular(host_key, uid=os.geteuid())
        if host_key.stat().st_mode & 0o077:
            raise OnboardingError('private_onboarding_ssh_key_required')
        host_public = execute(['/usr/bin/ssh-keygen', '-y', '-f', str(host_key)]).strip()
        public_key(host_public)
        publish(descriptor, json.dumps(dict(public_key_sha256=hashlib.sha256(host_public.encode()).hexdigest()),
                                      sort_keys=True).encode())
        # Replace only the constant proposal root for disposable fixture roots.
        configuration = value['configuration'].replace(str(ROOT) + '/private/host.key', str(private / 'host.key'))
        configuration = configuration.replace(str(ROOT) + '/owner.pub', str(root / 'owner.pub'))
        service = value['service'].replace(str(ROOT) + '/sshd.conf', str(root / 'sshd.conf'))
        publish(root / 'sshd.conf', configuration.encode())
        execute(['/usr/sbin/sshd', '-t', '-f', str(root / 'sshd.conf')])
        publish(units / UNIT, service.encode())
        execute(['systemctl', 'daemon-reload'])
        execute(['systemctl', 'enable', '--now', UNIT])
    return dict(installed=True, plan_digest=digest(plan), port=PORT)


def observe(plan: dict, key: object, *, root: Path = ROOT,
            units: Path = Path('/etc/systemd/system'), run=None) -> dict:
    """Read actual dedicated files and process state without installing anything."""
    value = proposal(plan, key)
    execute = run or _run
    being_seed._path(root)
    if not root.exists():
        return dict(installed=False, plan_digest=digest(plan), port=PORT)
    if not (root / 'private/binding.json').exists():
        return dict(installed=False, plan_digest=digest(plan), port=PORT)
    private = private_directory(root / 'private')
    expected = dict(schema=SCHEMA, plan_digest=digest(plan), public_key_sha256=value['public_key_sha256'])
    if being_seed._read(private / 'binding.json') != expected:
        raise OnboardingError('existing_onboarding_ssh_preserved')
    paths = {
        root / 'owner.pub': value['public_key'].encode(),
        root / 'sshd.conf': value['configuration'].replace(str(ROOT) + '/private/host.key', str(private / 'host.key'))
            .replace(str(ROOT) + '/owner.pub', str(root / 'owner.pub')).encode(),
        units / UNIT: value['service'].replace(str(ROOT) + '/sshd.conf', str(root / 'sshd.conf')).encode(),
    }
    for path, expected_bytes in paths.items():
        try:
            raw = onboarding_release.regular(path, uid=os.geteuid())
        except FileNotFoundError:
            return dict(installed=False, plan_digest=digest(plan), port=PORT)
        expected_mode = 0o644 if path == root / 'owner.pub' else 0o600
        if raw != expected_bytes or path.stat().st_mode & 0o777 != expected_mode:
            raise OnboardingError('existing_onboarding_ssh_preserved')
    host_key = private / 'host.key'
    try:
        onboarding_release.regular(host_key, uid=os.geteuid())
    except FileNotFoundError:
        if (private / 'host-public.json').exists():
            raise OnboardingError('existing_onboarding_ssh_preserved') from None
        return dict(installed=False, plan_digest=digest(plan), port=PORT)
    if host_key.stat().st_mode & 0o077:
        raise OnboardingError('private_onboarding_ssh_key_required')
    host_public = execute(['/usr/bin/ssh-keygen', '-y', '-f', str(host_key)]).strip()
    public_key(host_public)
    if being_seed._read(private / 'host-public.json') != dict(
            public_key_sha256=hashlib.sha256(host_public.encode()).hexdigest()):
        raise OnboardingError('existing_onboarding_ssh_preserved')
    execute(['/usr/sbin/sshd', '-t', '-f', str(root / 'sshd.conf')])
    active = execute(['systemctl', 'show', UNIT, '--property=ActiveState', '--property=MainPID'])
    fields = dict(line.split('=', 1) for line in active.splitlines() if '=' in line)
    process = fields.get('MainPID', '')
    if fields.get('ActiveState') != 'active' or not process.isdecimal() or int(process) <= 0:
        return dict(installed=False, plan_digest=digest(plan), port=PORT)
    listening = execute(['/usr/bin/ss', '-H', '-ltnp', 'sport = :2222'])
    if f'pid={process},' not in listening:
        return dict(installed=False, plan_digest=digest(plan), port=PORT)
    return dict(installed=True, plan_digest=digest(plan), port=PORT,
                host_public_key=host_public, service_verified=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'observe'))
    parser.add_argument('--code', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--public-key', required=True)
    args = parser.parse_args(argv)
    try:
        import pwd
        account = pwd.getpwnam('agent')
        if (os.geteuid() != 0 or account.pw_uid != 1000 or account.pw_gid != 1000
                or account.pw_dir != '/home/agent'
                or args.plan != Path('/home/agent/.onboarding-input/plan.json')):
            raise OnboardingError('qualified_guest_ssh_required')
        plan = validate_plan(json.loads(onboarding_release.regular(args.plan, uid=1000)))
        if args.code != Path('/opt/daimon-onboarding') / plan['release_digest']:
            raise OnboardingError('qualified_guest_ssh_required')
        onboarding_release.verify(args.code, plan['release_digest'], uid=0)
        # OpenSSH privilege separation needs this conventional runtime directory;
        # only the new guest is targeted. No existing sshd configuration is read.
        if args.action == 'install':
            dependencies()
            runtime = Path('/run/sshd')
            being_seed._path(runtime)
            runtime.mkdir(mode=0o755, exist_ok=True)
            info = runtime.stat()
            if not runtime.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
                raise OnboardingError('qualified_guest_ssh_required')
        operation = install if args.action == 'install' else observe
        print(json.dumps(operation(plan, args.public_key)))
        return 0
    except (OSError, ValueError, KeyError):
        print(json.dumps(dict(installed=False, error='native_onboarding_ssh_refused')))
        return 1
