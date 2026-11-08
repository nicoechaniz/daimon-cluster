#!/usr/bin/env python3
"""Bounded Debian inventory and vendor advisory phase; never installs packages.

Private configuration selects one host and four children. Full maintenance also
needs the owning cleanup, application-advisory and Alerts adapters. Missing
coverage is explicit, never a zero-vulnerability certificate.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time
import urllib.request
import zlib


FEED = 'https://security-tracker.debian.org/tracker/debsecan/release/1/trixie'
MIB = 1024 * 1024
PROBE = r'''
import json,os,platform
from pathlib import Path
p=Path('/var/lib/dpkg/status')
if p.stat().st_size>4*1024*1024:raise ValueError('inventory limit')
release={}
for line in Path('/etc/os-release').read_text().splitlines():
 k,_,v=line.partition('=')
 if k in {'ID','VERSION_ID','VERSION_CODENAME'}:release[k]=v.strip('"')
memory={}
for line in Path('/proc/meminfo').read_text().splitlines():
 k,_,v=line.partition(':')
 if k in {'MemTotal','MemAvailable','SwapTotal','SwapFree'}:memory[k]=int(v.split()[0])*1024
filesystems={}
for name in ('/','/home/agent'):
 if Path(name).is_dir():
  v=os.statvfs(name);filesystems[name]={'available_bytes':v.f_bavail*v.f_frsize,'inodes_available':v.f_favail,'quota_aware':False}
cgroups={}
for name in ('memory.max','pids.max','cpu.max','cpuset.cpus.effective'):
 p=Path('/sys/fs/cgroup')/name
 if p.exists():cgroups[name]=p.read_text().strip()
print(json.dumps({'os':release,'kernel':platform.release(),'memory':memory,'filesystems':filesystems,'cgroups':cgroups,'package_status':Path('/var/lib/dpkg/status').read_text()}))
'''


class LimitError(ValueError):
    pass


def command(argv, *, seconds=20, limit=8 * MIB):
    """Drain both streams with byte/time bounds; do not retain raw stderr."""
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
    reader = selectors.DefaultSelector()
    reader.register(child.stdout, selectors.EVENT_READ, True)
    reader.register(child.stderr, selectors.EVENT_READ, False)
    output, seen, deadline = bytearray(), 0, time.monotonic() + seconds
    try:
        while reader.get_map():
            if time.monotonic() >= deadline:
                raise LimitError('command_timeout')
            for key, _ in reader.select(min(0.2, max(0, deadline-time.monotonic()))):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    reader.unregister(key.fileobj)
                    continue
                seen += len(chunk)
                if seen > limit:
                    raise LimitError('command_output_limit')
                if key.data:
                    output.extend(chunk)
        if child.wait(timeout=max(0.01, deadline-time.monotonic())):
            raise ValueError('command_failed')
        return bytes(output)
    finally:
        reader.close()
        if child.poll() is None:
            # These commands are finite reads/matching only, never dpkg writers.
            import signal
            os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        child.stdout.close()
        child.stderr.close()


def atomic(path, raw):
    temporary = path.with_name(path.name + '.next')
    if temporary.is_symlink() or path.is_symlink():
        raise ValueError('owned_regular_state_required')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def footprint(root):
    total = 0
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('state_symlink_refused')
        if path.is_file():
            total += path.stat().st_size
    return total


def fetch_feed(opener=None):
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(FEED, headers={'User-Agent': 'children-daily/1'})
    with opener.open(request, timeout=20) as response:
        if response.geturl() != FEED:
            raise ValueError('advisory_redirect_refused')
        raw = response.read(16 * MIB + 1)
    if len(raw) > 16 * MIB:
        raise LimitError('advisory_download_limit')
    decoder = zlib.decompressobj()
    plain = decoder.decompress(raw, 64 * MIB + 1)
    if len(plain) > 64 * MIB or not decoder.eof or decoder.unused_data:
        raise LimitError('advisory_expansion_limit')
    if not plain.startswith(b'VERSION 1\n'):
        raise ValueError('unsupported_vendor_feed')
    return raw


def validate(config):
    if set(config) != {'schema', 'state', 'scanner', 'scanner_sha256', 'targets'}:
        raise ValueError('explicit_daily_configuration_required')
    if config['schema'] != 'cluster-children-daily/v1':
        raise ValueError('unsupported_daily_configuration')
    targets = config['targets']
    if len(targets) != 5 or len({t['id'] for t in targets}) != 5:
        raise ValueError('one_host_and_four_children_required')
    if targets[0] != {'id': 'lordoftheflies', 'instance': None}:
        raise ValueError('selected_host_required')
    if targets[1:] != [{'id': n, 'instance': 'dm-' + n}
                       for n in ('pixin', 'calipso', 'c-137', 'noodles')]:
        raise ValueError('selected_children_required')
    scanner = Path(config['scanner'])
    if (not scanner.is_absolute() or scanner.is_symlink() or scanner.stat().st_uid != 0
            or scanner.stat().st_mode & 0o022 or scanner.stat().st_size > MIB
            or hashlib.sha256(scanner.read_bytes()).hexdigest() != config['scanner_sha256']):
        raise ValueError('qualified_vendor_scanner_required')


def collect(config):
    validate(config)
    root = Path(config['state'])
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077:
        raise ValueError('private_daily_state_required')
    with (root/'lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # No eviction of findings or pending incidents to admit another run.
        if footprint(root) > 384 * MIB:
            raise LimitError('daily_state_capacity')
        feed = root/'feed'
        feed.mkdir(mode=0o700, exist_ok=True)
        # Vendor whitelist grammar requires its version header even when empty.
        # Never inherit a host/user suppression list into these observations.
        whitelist = root/'no-suppressions'
        atomic(whitelist, b'VERSION 0\n')
        report = {'schema': 'cluster-children-daily-result/v1', 'started': int(time.time()),
                  'coverage': 'partial', 'targets': {}, 'source': {},
                  'unassessed': ['upstream-and-malicious-release-advisories',
                                 'automatic-patch-transactions', 'browser-and-cache-cleanup',
                                 'incident-delivery-and-missed-run-supervision']}
        try:
            raw = fetch_feed()
            atomic(feed/'trixie', raw)
            report['source'] = {'state': 'fresh', 'sha256': hashlib.sha256(raw).hexdigest(),
                                'bytes': len(raw), 'checked': int(time.time())}
        except (OSError, ValueError, zlib.error) as error:
            report['source'] = {'state': 'unavailable', 'reason': type(error).__name__}
        for target in config['targets']:
            name = target['id']
            directory = root/name
            directory.mkdir(mode=0o700, exist_ok=True)
            value = None
            try:
                argv = ['/usr/bin/python3', '-B', '-I', '-c', PROBE]
                if target['instance']:
                    argv = ['incus', 'exec', target['instance'], '--', *argv]
                value = json.loads(command(argv))
                if value['os'] != {'ID': 'debian', 'VERSION_ID': '13', 'VERSION_CODENAME': 'trixie'}:
                    raise ValueError('unsupported_distribution')
                status = value.pop('package_status').encode()
                if len(status) > 4*MIB:
                    raise LimitError('package_inventory_limit')
                atomic(directory/'packages.status', status)
                value.update(inventory='observed', inventory_sha256=hashlib.sha256(status).hexdigest(),
                             debian_advisories='unassessed')
                if report['source']['state'] == 'fresh':
                    found = command(['/usr/bin/python3', config['scanner'], '--suite', 'trixie',
                        '--source', feed.as_uri(), '--status', str(directory/'packages.status'),
                        '--format', 'simple', '--config', '/dev/null', '--whitelist', str(whitelist)],
                        seconds=40, limit=4*MIB)
                    # Preserve exact current findings, including unfixed vulnerabilities.
                    atomic(directory/'debian-findings.txt', found)
                    value.update(debian_advisories='matched',
                                 vulnerability_pairs=len(set(found.decode().splitlines())))
                raw = json.dumps(value, sort_keys=True).encode()
                if len(raw) > 256*1024:
                    raise LimitError('resource_receipt_limit')
                current = directory/'current.json'
                if current.exists() and json.loads(current.read_bytes()).get('debian_advisories') == 'matched':
                    atomic(directory/'previous.json', current.read_bytes())
                atomic(current, raw)
                report['targets'][name] = value
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                observed = value if value is not None and value.get('inventory') == 'observed' else {}
                report['targets'][name] = {**observed,
                    'inventory': 'observed' if observed else 'unavailable',
                    'debian_advisories': 'unassessed', 'reason': type(error).__name__}
        report['finished'] = int(time.time())
        raw = json.dumps(report, sort_keys=True).encode()
        if len(raw) > 256*1024 or footprint(root) > 512*MIB:
            raise LimitError('daily_state_capacity')
        atomic(root/'current.json', raw)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    result = collect(json.loads(args.config.read_text()))
    print(json.dumps({'coverage': result['coverage'], 'source': result['source']['state'],
                      'targets': {k: v.get('debian_advisories') for k, v in result['targets'].items()}}))
    return 0 if result['source']['state'] == 'fresh' and all(
        value.get('debian_advisories') == 'matched' for value in result['targets'].values()) else 2


if __name__ == '__main__':
    raise SystemExit(main())
