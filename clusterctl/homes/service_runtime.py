"""Fixed receiving executor. Operator-selected transport supplies stdin, never a shell.

Run under the selected receiving system manager. Runtime code executes as the
configured non-root UID; the executor/configuration remain operator-owned.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

from .. import being_seed
from ..onboarding_conversation import atomic
from ..onboarding_release import regular
from .service_package import (HEX, NAME, MAX_ARCHIVE, canonical, closed, exact,
                              path, sha, unpack, verify_tree)


@closed
def receiver(value):
    exact(value, 'schema home owner service placement machine_sha256 profile_file profile_sha256 '
          'node node_sha256 root code data unit_dir uid gid port state_schema memory_mb cpu_percent '
          'tasks state_bytes quota_probe', 'invalid_service_receiver')
    if (value['schema'] != 'dm.home-service-receiver/v1'
            or value['placement'] not in {'native', 'kvm', 'container'}
            or not NAME.fullmatch(value['service']) or not NAME.fullmatch(value['state_schema'])
            or not isinstance(value['home'], str) or not isinstance(value['owner'], str)
            or not value['home'] or not value['owner']):
        raise ValueError('invalid_service_receiver')
    for k in ('machine_sha256', 'profile_sha256', 'node_sha256'):
        if not HEX.fullmatch(value[k]):
            raise ValueError('invalid_service_receiver')
    paths = [path(value[k]) for k in ('profile_file', 'node', 'root', 'data', 'unit_dir', 'code')]
    if len(set(paths)) != len(paths) or paths[2] == Path('/') or paths[3] == Path('/'):
        raise ValueError('invalid_service_receiver')
    for a in (paths[2], paths[3], paths[5]):
        for b in (paths[2], paths[3], paths[5]):
            if a != b and a.is_relative_to(b):
                raise ValueError('service_external_state_required')
    for k, lower, upper in (('uid', 1, 2**31-1), ('gid', 1, 2**31-1), ('port', 1024, 65535),
                            ('memory_mb', 32, 4096), ('cpu_percent', 1, 200), ('tasks', 8, 256),
                            ('state_bytes', 1024**2, 16*1024**3)):
        if type(value[k]) is not int or not lower <= value[k] <= upper:
            raise ValueError('invalid_service_receiver')
    argv = value['quota_probe']
    if (not isinstance(argv, list) or not 1 <= len(argv) <= 8
            or any(not isinstance(a, str) or not a or '\0' in a for a in argv)):
        raise ValueError('service_quota_probe_required')
    path(argv[0])
    return value


def key(config):
    return sha(canonical({k: config[k] for k in ('home', 'owner', 'service')}))[:24]


def unit(config, release, package):
    """No package-supplied argv, environment, unit directives or install scripts."""
    c = config
    return (f'[Unit]\nDescription=Own Home HTTP service {key(c)}\n'
            f'After=network.target\nRequiresMountsFor={c["data"]}\nStartLimitIntervalSec=60\nStartLimitBurst=3\n'
            f'[Service]\nUser={c["uid"]}\nGroup={c["gid"]}\nUMask=0077\n'
            f'WorkingDirectory={release}\nExecStart={c["node"]} {release / package["entry"]}\n'
            f'Environment=HOST=127.0.0.1 PORT={c["port"]} NODE_ENV=production\n'
            f'Environment=HOME={c["data"]} STATE_DIR={c["data"]}\n'
            'Restart=on-failure\nRestartSec=3\nTimeoutStopSec=10\nKillMode=control-group\n'
            'NoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateDevices=true\n'
            'PrivateTmp=true\nTemporaryFileSystem=/tmp:size=32M\n'
            'ProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\n'
            'RestrictSUIDSGID=true\nCapabilityBoundingSet=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n'
            f'ReadWritePaths={c["data"]}\nMemoryMax={c["memory_mb"]}M\n'
            f'CPUQuota={c["cpu_percent"]}%\nTasksMax={c["tasks"]}\n'
            'StandardOutput=journal\nStandardError=journal\nLogRateLimitIntervalSec=30s\n'
            'LogRateLimitBurst=100\n[Install]\nWantedBy=multi-user.target\n').encode()


class Runtime:
    def __init__(self, config):
        self.config = receiver(config)
        self.root = path(config['root'])
        self.code = path(config['code'])
        self.unit_name = 'dm-home-service-' + key(config) + '.service'
        self.unit_path = path(config['unit_dir']) / self.unit_name
        self.deadline = time.monotonic() + 90
        self.dispatched = False

    def command(self, argv):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('service_deadline')
        result = subprocess.run(argv, capture_output=True, timeout=min(15, remaining),
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
        if result.returncode or len(result.stdout) > 16384:
            raise ValueError('service_command_unconfirmed')
        return result.stdout

    def preflight(self):
        c = self.config
        if (sha(regular(Path('/etc/machine-id'), uid=0)) != c['machine_sha256']
                or sha(regular(path(c['profile_file']), uid=os.geteuid())) != c['profile_sha256']
                or sha(regular(path(c['node']), uid=0, limit=256*1024**2)) != c['node_sha256']
                or not self.command([c['node'], '--version']).startswith(b'v24.')):
            raise ValueError('service_host_profile_mismatch')
        for p in (self.root, self.code, path(c['unit_dir'])):
            being_seed._path(p)
            info = p.stat()
            if not p.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise ValueError('service_operator_directory_required')
        if self.code.stat().st_gid != c['gid'] or self.code.stat().st_mode & 0o777 != 0o750:
            raise ValueError('service_readable_code_directory_required')
        # A root-owned leaf below a writable publisher home is not custody.
        # Require every executable/configuration ancestor to remain operator-owned.
        for p in (self.root, self.code, path(c['unit_dir']), path(c['node']).parent,
                  path(c['profile_file']).parent, path(c['data']).parent):
            for ancestor in (p, *p.parents):
                info = ancestor.stat()
                if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise ValueError('service_operator_ancestry_required')
        data = being_seed._path(path(c['data']))
        info = data.stat()
        if not data.is_dir() or info.st_uid != c['uid'] or info.st_mode & 0o077:
            raise ValueError('service_private_external_state_required')
        for selected in (self.code, data, path(c['node']).parent):
            for ancestor in (selected, *selected.parents):
                info = ancestor.stat()
                bit = 0o100 if info.st_uid == c['uid'] else 0o010 if info.st_gid == c['gid'] else 0o001
                if not info.st_mode & bit:
                    raise ValueError('service_receiving_traversal_required')
        # The quota belongs to the selected storage writer, not a guessed du limit.
        regular(path(c['quota_probe'][0]), uid=0)
        quota = json.loads(self.command(c['quota_probe']))
        if quota != {'path': str(data), 'hard_bytes': c['state_bytes'], 'enforced': True}:
            raise ValueError('service_enforced_state_quota_required')

    def read(self, name):
        p = self.root / name
        return json.loads(regular(p, uid=os.geteuid(), limit=2*1024**2)) if p.exists() else None

    def save(self, name, value):
        atomic(self.root / name, canonical(value), mode=0o600)

    def prune(self, candidate):
        protected = {candidate}
        for n in ('current.json', 'previous.json'):
            retained = self.read(n)
            if retained:
                protected.add(retained['digest'])
        for release in self.code.glob('release-*'):
            digest = release.name.removeprefix('release-')
            if digest in protected:
                continue
            if not HEX.fullmatch(digest):
                raise ValueError('service_unknown_release_preserved')
            records = [self.read(p.name) for p in self.root.glob('operation-*.json')]
            known = next((r for r in records if r['digest'] == digest and r['state'] == 'ready'), None)
            if not known:
                raise ValueError('service_unknown_release_preserved')
            value = known['package']
            verify_tree(release, value, uid=os.geteuid())
            shutil.rmtree(release)  # Verified obsolete code only, never state or receipts.

    def health(self, record):
        """Observe actual loaded entry and exact loopback health bytes."""
        c = self.config
        value = self.command(['systemctl', 'show', self.unit_name, '-p', 'MainPID', '-p', 'ActiveState', '-p', 'UnitFileState'])
        props = dict(line.split('=', 1) for line in value.decode().splitlines())
        pid = int(props.get('MainPID', '0'))
        if pid <= 0 or props.get('ActiveState') != 'active' or props.get('UnitFileState') != 'enabled':
            return False
        argv = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        release = self.code / ('release-' + record['digest'])
        if argv[:2] != [c['node'].encode(), str(release / record['package']['entry']).encode()]:
            return False
        if not self.owns_listener(pid):
            return False
        if regular(self.unit_path, uid=os.geteuid()) != unit(c, release, record['package']):
            return False
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_):
                return None
        try:
            with urllib.request.build_opener(NoRedirect).open(
                    f'http://127.0.0.1:{c["port"]}' + record['package']['health']['path'], timeout=2) as response:
                body = response.read(65537)
                return (response.status == 200 and len(body) <= 65536
                        and sha(body) == record['package']['health']['sha256'])
        except OSError:
            return False

    def listeners(self):
        rows = []
        for name in ('tcp', 'tcp6'):
            for line in Path('/proc/net/' + name).read_text().splitlines()[1:]:
                fields = line.split()
                address, port = fields[1].split(':')
                if fields[3] == '0A' and int(port, 16) == self.config['port']:
                    rows.append((address, fields[9]))
        return rows

    def owns_listener(self, pid):
        rows = self.listeners()
        owned = set()
        for fd in Path(f'/proc/{pid}/fd').iterdir():
            try:
                owned.add(os.readlink(fd))
            except FileNotFoundError:
                continue
        return bool(rows) and all(address == '0100007F' and 'socket:['+inode+']' in owned
                                  for address, inode in rows)

    def listener_precondition(self, current):
        if not self.listeners():
            return
        props = dict(line.split('=', 1) for line in self.command(
            ['systemctl', 'show', self.unit_name, '-p', 'MainPID']).decode().splitlines())
        pid = int(props.get('MainPID', '0'))
        if not current or pid <= 0 or not self.owns_listener(pid):
            raise ValueError('service_existing_listener_preserved')

    @closed
    def run(self, envelope):
        exact(envelope, 'schema action capability request_id digest previous package', 'invalid_service_envelope')
        c = self.config
        if (envelope['schema'] != 'dm.home-service-executor/v1'
                or envelope['capability'] != sha(canonical(c))
                or envelope['action'] not in {'apply', 'observe'}
                or not re_id(envelope['request_id']) or not HEX.fullmatch(envelope['digest'])
                or envelope['previous'] is not None and not HEX.fullmatch(envelope['previous'])):
            raise ValueError('service_capability_denied')
        self.preflight()
        with being_seed._locked(self.root):
            name = 'operation-' + envelope['request_id'] + '.json'
            old = self.read(name)
            pins = {k: v for k, v in envelope.items() if k not in {'package', 'action'}}
            if old and old['pins'] != pins:
                raise ValueError('service_request_conflict')
            current = self.read('current.json')
            if old:
                if old['state'] == 'ready' and (not current or current['digest'] != old['digest']):
                    return {'state': 'superseded', 'digest': old['digest']}
                if old['state'] == 'dispatched':
                    self.dispatched = True
                    if self.health(old):
                        old['state'] = 'ready'
                        self.save('current.json', old)
                        self.save(name, old)
                    else:
                        return {'state': 'uncertain', 'digest': old['digest']}
                return {'state': 'ready' if self.health(old) else 'uncertain', 'digest': old['digest']}
            if envelope['action'] == 'observe':
                return {'state': 'absent', 'digest': envelope['digest']}
            if (current['digest'] if current else None) != envelope['previous']:
                raise ValueError('service_predecessor_conflict')
            if len(list(self.root.glob('operation-*.json'))) >= 128:
                raise ValueError('service_receipt_capacity')
            for pending in self.root.glob('operation-*.json'):
                if json.loads(regular(pending, uid=os.geteuid(), limit=2*1024**2))['state'] == 'dispatched':
                    raise ValueError('service_pending_operation_preserved')
            if current:
                if regular(self.unit_path, uid=os.geteuid()) != unit(c, self.code / ('release-' + current['digest']), current['package']):
                    raise ValueError('service_concurrent_unit_preserved')
            elif self.unit_path.exists():
                raise ValueError('service_existing_unit_preserved')
            self.listener_precondition(current)
            if not isinstance(envelope['package'], str) or len(envelope['package']) > MAX_ARCHIVE * 4 // 3 + 8:
                raise ValueError('service_package_capacity')
            raw = base64.b64decode(envelope['package'], validate=True)
            package, files = unpack(raw, envelope['digest'])
            if package['service'] != c['service'] or package['state_schema'] != c['state_schema']:
                raise ValueError('service_state_or_identity_mismatch')
            release = self.code / ('release-' + envelope['digest'])
            if not release.exists():
                # Bound code storage to current + predecessor + one candidate.
                self.prune(envelope['digest'])
                if len(list(self.code.glob('release-*'))) >= 3:
                    raise ValueError('service_release_retention_required')
                release.mkdir(mode=0o755)
                try:
                    for n, raw_file in files.items():
                        if n == 'service.json':
                            raw_file = canonical(package)
                        p = release / n
                        p.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                        atomic(p, raw_file, mode=0o644, max_bytes=MAX_ARCHIVE)
                        p.chmod(0o644)
                    # Private operator umasks must not hide immutable code from the service UID.
                    release.chmod(0o755)
                    for directory in release.rglob('*'):
                        if directory.is_dir():
                            directory.chmod(0o755)
                except BaseException:
                    shutil.rmtree(release)
                    raise
            verify_tree(release, package, uid=os.geteuid())
            record = dict(pins=pins, state='dispatched', digest=envelope['digest'], package=package)
            # Persist intent BEFORE changing the unit or asking the manager.
            # An interruption is reconciled by observation; never another restart.
            self.save(name, record)
            self.dispatched = True
            if current:
                self.save('previous.json', current)
            atomic(self.unit_path, unit(c, release, package), mode=0o644)
            self.command(['systemctl', 'daemon-reload'])
            self.command(['systemctl', 'enable', self.unit_name])
            self.command(['systemctl', 'restart', self.unit_name])
            while time.monotonic() < self.deadline - 2:
                if self.health(record):
                    record['state'] = 'ready'
                    self.save('current.json', record)
                    self.save(name, record)
                    return {'state': 'ready', 'digest': record['digest']}
                time.sleep(.2)
            return {'state': 'uncertain', 'digest': record['digest']}


def re_id(value):
    import re
    return isinstance(value, str) and re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    args = parser.parse_args()
    def expired(*_):
        raise TimeoutError('service_executor_deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(95)  # Includes lock acquisition and receiving transport lifetime.
    worker, envelope = None, {}
    try:
        config = json.loads(regular(args.config, uid=os.geteuid(), limit=65536))
        raw = sys.stdin.buffer.read(MAX_ARCHIVE * 2 + 65537)
        if len(raw) > MAX_ARCHIVE * 2 + 65536:
            raise ValueError('service_executor_input_capacity')
        envelope = json.loads(raw)
        worker = Runtime(config)
        print(json.dumps(worker.run(envelope)))
    except (ValueError, OSError, subprocess.SubprocessError, TimeoutError) as error:
        import re
        code = str(error)
        if not re.fullmatch(r'[a-z][a-z0-9_]{1,79}', code):
            code = 'service_executor_unconfirmed'
        digest = envelope.get('digest') if isinstance(envelope, dict) else None
        result = {'state': 'uncertain' if worker and worker.dispatched else 'refused', 'error': code}
        if isinstance(digest, str) and HEX.fullmatch(digest):
            result['digest'] = digest
        print(json.dumps(result))
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
