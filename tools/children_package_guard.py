#!/usr/bin/env python3
"""Read-only APT v2 pre-install guard for an already reviewed local transaction.

This is not a downloader, signature verifier, scheduler or package installer.
The owning selection step must qualify signed metadata and maintainer behavior
before writing its private manifest. Never install this hook globally.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import shlex
import sys
import urllib.parse

MAX_INPUT = 256 * 1024
MAX_ARCHIVES = 256 * 1024 * 1024
PACKAGES = frozenset({'chromium', 'chromium-common'})
BROWSERS = ('chromium', 'chrome', 'firefox', 'webbridge')


class Deferred(ValueError):
    """A bounded reason code, without process contents or private paths."""


def private_json(path, owner_uid):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
                or info.st_mode & 0o077 or info.st_size > MAX_INPUT):
            raise Deferred('manifest_custody')
        raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise Deferred('manifest_capacity')
    return json.loads(raw)


def manifest_packages(manifest):
    if (manifest.get('schema') != 'children-reviewed-apt-transaction/v1'
            or manifest.get('source') != 'verified-local-debian-security'
            or manifest.get('maintainer_reviewed') is not True):
        raise Deferred('unqualified_selection')
    packages = manifest.get('packages')
    if not isinstance(packages, dict) or set(packages) != PACKAGES:
        raise Deferred('unreviewed_packages')
    total = 0
    for item in packages.values():
        if (not isinstance(item, dict)
                or set(item) != {'old_version', 'version', 'archive', 'sha256', 'bytes'}
                or not all(isinstance(item[k], str) and item[k] and not re.search(r'\s', item[k])
                           for k in ('old_version', 'version', 'archive', 'sha256'))
                or not re.fullmatch(r'[a-f0-9]{64}', item['sha256'])
                or type(item['bytes']) is not int or item['bytes'] <= 0
                or not Path(item['archive']).is_absolute()
                or '..' in Path(item['archive']).parts):
            raise Deferred('malformed_selection')
        total += item['bytes']
    if total > MAX_ARCHIVES:
        raise Deferred('archive_capacity')
    if len({i['archive'] for i in packages.values()}) != len(packages):
        raise Deferred('duplicate_archive')
    return packages


def parse_protocol(raw, expected_hook=None):
    if len(raw) > MAX_INPUT:
        raise Deferred('input_capacity')
    lines = raw.decode('utf-8', errors='strict').splitlines()
    if not lines or lines[0] != 'VERSION 2':
        raise Deferred('unsupported_apt_protocol')
    try:
        split = lines.index('', 1)
    except ValueError:
        raise Deferred('malformed_apt_protocol') from None
    config = []
    for line in lines[1:split]:
        key, delimiter, value = line.partition('=')
        if not delimiter:
            raise Deferred('malformed_apt_config')
        config.append((urllib.parse.unquote(key), urllib.parse.unquote(value)))
    for key, value in config:
        lowered = key.lower()
        if (lowered in {'apt::get::allowunauthenticated',
                        'acquire::allowinsecurerepositories',
                        'acquire::allowdowngradetoinsecurerepositories'}
                and value.lower() not in {'false', '0', 'no'}):
            raise Deferred('insecure_apt_source')
        if (lowered.rstrip(':') == 'dpkg::pre-install-pkgs'
                and value != expected_hook):
            raise Deferred('unreviewed_apt_hook')
        if lowered.rstrip(':') in {'dpkg::pre-invoke', 'dpkg::post-invoke'}:
            raise Deferred('unreviewed_apt_hook')
        if lowered.rstrip(':') == 'dpkg::options' and value != '--force-confold':
            raise Deferred('unreviewed_dpkg_option')
    actions = [line.split() for line in lines[split + 1:] if line]
    if not 1 <= len(actions) <= 8 or any(len(a) != 5 for a in actions):
        raise Deferred('malformed_apt_actions')
    return actions


def idle_browser_scope(proc_root=Path('/proc')):
    for proc in proc_root.iterdir():
        if not proc.name.isdigit():
            continue
        try:
            name = (proc / 'comm').read_text().strip().lower()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            raise Deferred('process_observation_unavailable') from None
        if any(browser in name for browser in BROWSERS):
            raise Deferred('browser_active')


def verify_archive(item, owner_uid):
    path = Path(item['archive'])
    # APT's cache and manifest directories must exclude unprivileged writers.
    for parent in path.parents:
        info = parent.stat()
        if parent.is_symlink() or info.st_uid not in {0, owner_uid} or info.st_mode & 0o022:
            raise Deferred('archive_parent_custody')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner_uid
                or before.st_mode & 0o022 or before.st_size != item['bytes']):
            raise Deferred('archive_custody')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
        def stable(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (digest != item['sha256'] or stable(before) != stable(after)
                or stable(path.stat()) != stable(before)):
            raise Deferred('archive_changed')


def guard(raw, manifest, *, owner_uid=0, proc_root=Path('/proc'), verify=verify_archive, expected_hook=None):
    packages = manifest_packages(manifest)
    actions = parse_protocol(raw, expected_hook)
    unpacked, configured = set(), set()
    for package, old, direction, new, action in actions:
        if package not in packages:
            raise Deferred('unreviewed_packages')
        item = packages[package]
        if (old != item['old_version'] or new != item['version']
                or old == '-' or direction != '<'):
            raise Deferred('changed_package_plan')
        if action == '**CONFIGURE**':
            if package in configured:
                raise Deferred('duplicate_package_action')
            configured.add(package)
        elif action == item['archive']:
            if package in unpacked:
                raise Deferred('duplicate_package_action')
            unpacked.add(package)
        else:
            raise Deferred('changed_package_action')
    if unpacked != set(packages) or not configured <= unpacked:
        raise Deferred('incomplete_transaction')
    idle_browser_scope(proc_root)
    for item in packages.values():
        verify(item, owner_uid)
    # Repeat activity observation after hashing immediately before admission.
    idle_browser_scope(proc_root)
    return {'schema': 'children-apt-guard-result/v1', 'decision': 'admitted',
            'packages': sorted(packages), 'archives_verified': len(packages),
            'package_write_performed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise Deferred('requires_own_guest_operator')
        manifest = private_json(args.manifest, 0)
        hook = shlex.join(['/usr/bin/python3', '-B', '-I', str(Path(__file__).resolve()),
                           '--manifest', str(args.manifest.absolute())])
        result = guard(sys.stdin.buffer.read(MAX_INPUT + 1), manifest, expected_hook=hook)
        status = 0
    except (Deferred, OSError, ValueError, KeyError, TypeError, UnicodeError):
        error = sys.exception()
        result = {'schema': 'children-apt-guard-result/v1', 'decision': 'deferred',
                  'reason': str(error) if isinstance(error, Deferred) else type(error).__name__,
                  'package_write_performed': False}
        status = 1
    print(json.dumps(result, sort_keys=True))
    return status


if __name__ == '__main__':
    raise SystemExit(main())
