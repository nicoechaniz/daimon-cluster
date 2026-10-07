"""Dedicated SSH ingress with durable port reservations and owner-only coordinates."""
from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import os
import re
import subprocess
import stat
import time

from . import being_seed
from .onboarding import OnboardingError, digest, private_directory
from .onboarding_progress import Progress
from .onboarding_ssh import public_key

SCHEMA = 'cluster-onboarding-access/v1'
POLICY = 'cluster-onboarding-ssh-ingress/v1'
HOST = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?')


@contextlib.contextmanager
def reservation_lock(root):
    """Serialize only the local reservation transaction, with a bounded wait."""
    descriptor = os.open(being_seed._path(root / 'lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise OnboardingError('private_onboarding_directory_required')
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise OnboardingError('onboarding_host_operation_failed') from None
                time.sleep(.02)
        yield
    finally:
        os.close(descriptor)


def validate(value: object) -> dict:
    if (not isinstance(value, dict) or set(value) != {'schema', 'name', 'owner', 'plan_digest', 'ssh'}
            or value['schema'] != SCHEMA
            or any(not isinstance(value[key], str) or not being_seed.NAME.fullmatch(value[key])
                   for key in ('name', 'owner'))
            or not isinstance(value['plan_digest'], str) or not re.fullmatch(r'[a-f0-9]{64}', value['plan_digest'])):
        raise OnboardingError('invalid_onboarding_access')
    ssh = value['ssh']
    if ssh is not None:
        if (not isinstance(ssh, dict) or set(ssh) != {'hostname', 'port', 'username', 'host_public_key', 'host_key_fingerprint'}
                or not isinstance(ssh['hostname'], str) or not HOST.fullmatch(ssh['hostname'])
                or type(ssh['port']) is not int or not 20000 <= ssh['port'] <= 50000
                or ssh['username'] != 'agent'):
            raise OnboardingError('invalid_onboarding_access')
        public_key(ssh['host_public_key'])
        if ssh['host_key_fingerprint'] != fingerprint(ssh['host_public_key']):
            raise OnboardingError('invalid_onboarding_access')
    return value


def fingerprint(key: str) -> str:
    try:
        wire = base64.b64decode(public_key(key).decode().split()[1], validate=True)
    except ValueError:
        raise OnboardingError('invalid_onboarding_access') from None
    return 'SHA256:' + base64.b64encode(hashlib.sha256(wire).digest()).decode().rstrip('=')


class Access(Progress):
    suffix = '.access.json'
    validate = staticmethod(validate)


def policy(path) -> dict:
    value = being_seed._read(path)
    if (set(value) != {'schema', 'hostname', 'listen_address', 'first_port', 'last_port', 'revoked'}
            or value['schema'] != POLICY
            or not isinstance(value['hostname'], str) or not HOST.fullmatch(value['hostname'])
            or not isinstance(value['listen_address'], str)
            or type(value['first_port']) is not int or type(value['last_port']) is not int
            or not 20000 <= value['first_port'] <= value['last_port'] <= 50000
            or value['last_port'] - value['first_port'] > 999 or type(value['revoked']) is not bool):
        raise OnboardingError('invalid_onboarding_ingress_policy')
    try:
        ipaddress.IPv4Address(value['listen_address'])
    except ipaddress.AddressValueError:
        raise OnboardingError('invalid_onboarding_ingress_policy') from None
    return value


class Ingress:
    def __init__(self, backend, *, sockets=None, probe=None):
        self.backend, self.config = backend, backend.config
        self.settings = policy(self.config.ssh_ingress)
        self.root = private_directory(self.config.jobs / '.ssh-ingress', create=True)
        self.sockets = sockets or self._sockets
        self.probe = probe or self._probe

    @staticmethod
    def _sockets() -> set[int]:
        result = subprocess.run(['ss', '-H', '-ltn'], capture_output=True, text=True, timeout=15, check=False)
        if result.returncode:
            raise OnboardingError('onboarding_host_operation_failed')
        return {int(row.split()[3].rsplit(':', 1)[1]) for row in result.stdout.splitlines()
                if len(row.split()) >= 4 and row.split()[3].rsplit(':', 1)[1].isdigit()}

    @staticmethod
    def _probe(address: str, port: int, key: str) -> bool:
        result = subprocess.run(['ssh-keyscan', '-T', '5', '-p', str(port), '-t', 'ed25519', address],
            capture_output=True, text=True, timeout=10, check=False)
        expected = public_key(key).decode().split()[:2]
        return result.returncode == 0 and any(row.split()[-2:] == expected for row in result.stdout.splitlines())

    def _reservation(self, plan: dict, guest: dict, *, create: bool) -> dict | None:
        if (guest.get('installed') is not True or guest.get('service_verified') is not True
                or guest.get('plan_digest') != digest(plan) or guest.get('port') != 2222):
            raise OnboardingError('qualified_guest_ssh_required')
        key = guest.get('host_public_key')
        if not isinstance(key, str):
            raise OnboardingError('qualified_guest_ssh_required')
        public_key(key)
        path = self.root / (digest(plan) + '.json')
        used = set()
        if create and not path.exists():
            # Network/host observations never hold the shared allocation lock.
            used = self.sockets()
            rows, _ = self.backend._inventory()
            for row in rows:
                for device in row.get('expanded_devices', {}).values():
                    listen = device.get('listen', '')
                    if device.get('type') == 'proxy' and listen.startswith('tcp:') and listen.rsplit(':', 1)[1].isdigit():
                        used.add(int(listen.rsplit(':', 1)[1]))
        with reservation_lock(self.root):
            if path.exists():
                record = being_seed._read(path)
                access = validate(record['access'])
                if (set(record) != {'policy_digest', 'access'} or record['policy_digest'] != digest(self.settings)
                        or access['name'] != plan['name'] or access['owner'] != plan['owner']
                        or access['plan_digest'] != digest(plan) or access['ssh']['host_public_key'] != key):
                    raise OnboardingError('existing_onboarding_ssh_preserved')
                return access
            if not create:
                return None
            for candidate in self.root.glob('*.json'):
                record = being_seed._read(candidate)
                used.add(validate(record['access'])['ssh']['port'])
            available = next((port for port in range(self.settings['first_port'], self.settings['last_port'] + 1)
                              if port not in used), None)
            if available is None:
                raise OnboardingError('onboarding_ssh_ports_unavailable')
            value = validate(dict(schema=SCHEMA, name=plan['name'], owner=plan['owner'], plan_digest=digest(plan),
                ssh=dict(hostname=self.settings['hostname'], port=available, username='agent',
                         host_public_key=key, host_key_fingerprint=fingerprint(key))))
            being_seed._write(path, dict(policy_digest=digest(self.settings), access=value))
            return value

    def _proxy(self, value: dict) -> dict:
        return dict(type='proxy', bind='host', listen=f"tcp:{self.settings['listen_address']}:{value['ssh']['port']}",
                    connect='tcp:127.0.0.1:2222')

    def _current(self, plan: dict, value: dict) -> bool:
        rows, _ = self.backend._inventory()
        row = next(row for row in rows if row.get('name') == self.backend.instance(plan))
        current = row.get('expanded_devices', {}).get('onboarding-ssh')
        if current is not None and current != self._proxy(value):
            raise OnboardingError('foreign_receiving_mount_preserved')
        return current is not None

    def _publish(self, plan: dict, ssh: dict | None) -> None:
        if self.config.progress is None:
            raise OnboardingError('invalid_onboarding_host_configuration')
        Access(self.config.progress, worker_uid=os.geteuid()).publish(dict(schema=SCHEMA,
            name=plan['name'], owner=plan['owner'], plan_digest=digest(plan), ssh=ssh))

    def observe(self, plan: dict, guest: dict) -> bool:
        value = None if self.settings['revoked'] else self._reservation(plan, guest, create=False)
        address = self.settings['listen_address']
        address = '127.0.0.1' if address == '0.0.0.0' else address
        ready = value is not None and self._current(plan, value) and self.probe(
            address, value['ssh']['port'], value['ssh']['host_public_key'])
        self._publish(plan, value['ssh'] if ready and value is not None else None)
        return ready

    def execute(self, plan: dict, guest: dict) -> None:
        if self.settings['revoked']:
            raise OnboardingError('host_authorization_required')
        value = self._reservation(plan, guest, create=True)
        assert value is not None
        if not self._current(plan, value):
            self.backend._dispatch(plan, ['config', 'device', 'add', self.backend.instance(plan),
                'onboarding-ssh', 'proxy', *[key + '=' + data for key, data in self._proxy(value).items() if key != 'type']])
        # A persisted proxy is not a working connection; publish only the pinned
        # host key actually observed through its dedicated listener.
        self.observe(plan, guest)
