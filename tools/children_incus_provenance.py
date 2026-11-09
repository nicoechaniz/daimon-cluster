#!/usr/bin/env python3
"""Read-only Incus source selection from a fresh signed Debian security index.

This command never installs a package or runs archive code/maintainer scripts.
It reuses the existing APT index freshness and archive custody checks, and emits
an ordinary selected-deployment manifest for the existing daily observer.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tempfile
import time
import urllib.request

if __package__:
    from .children_daily import atomic, command
    from . import children_package_selection as selection
    from .children_package_guard import verify_archive
else:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from children_daily import atomic, command
    import children_package_selection as selection
    from children_package_guard import verify_archive

MAX_ARCHIVE = 32 * 1024 * 1024
MAX_TAR = 128 * 1024 * 1024
ROOT = 'usr/libexec/incus/'


def signed_index(targets, *, read, now):
    candidates = [v for v in selection.paragraphs(targets) if tuple(v.get(k) for k in
        ('Identifier', 'Codename', 'Label', 'Origin', 'Component', 'Architecture', 'Trusted'))
        == ('Packages', 'trixie-security', 'Debian-Security', 'Debian', 'main', 'amd64', 'yes')]
    if len(candidates) != 1:
        raise ValueError('incus_trusted_security_index_required')
    target = candidates[0]
    index = selection.release_fresh(target, now)
    suffix = target['MetaKey'].replace('/', '_')
    release = index.with_name(index.name[:-len(suffix)] + 'InRelease')
    # Read-only provenance does not widen the separate package-mutation policy's
    # legacy sources.list restriction. Authenticate this host's native mirror
    # index independently with its installed Debian archive keyring instead.
    with tempfile.TemporaryDirectory(prefix='children-incus-signature-') as temporary:
        authenticated = Path(temporary)/'authenticated'
        read(['/usr/bin/sqv', '--keyring', '/usr/share/keyrings/debian-archive-keyring.gpg',
              '--cleartext', '--output', str(authenticated), str(release)])
        if authenticated.stat().st_size > 256 * 1024:
            raise ValueError('incus_signed_release_capacity')
        body = authenticated.read_text()
    raw = read(['/usr/lib/apt/apt-helper', 'cat-file', str(index)], limit=selection.MAX_INDEX)
    rows = selection.paragraphs(body)
    digests = [line.split() for line in rows[0]['SHA256'].splitlines()]
    matched = [v for v in digests if len(v) == 3 and v[2] == target['MetaKey']]
    if (len(matched) != 1 or matched[0][:2] != [hashlib.sha256(raw).hexdigest(), str(len(raw))]):
        raise ValueError('incus_signed_index_digest_changed')
    return raw


def package_record(index, version):
    rows = [v for v in selection.paragraphs(index.decode()) if
        (v.get('Package'), v.get('Version'), v.get('Architecture')) == ('incus-base', version, 'amd64')]
    if len(rows) != 1:
        raise ValueError('incus_installed_security_package_required')
    row = rows[0]
    if (not re.fullmatch('[a-f0-9]{64}', row.get('SHA256', '')) or not row.get('Size', '').isdigit()
            or not 0 < int(row['Size']) <= MAX_ARCHIVE
            or not row.get('Filename', '').startswith('pool/updates/main/i/incus/')
            or '..' in PurePosixPath(row['Filename']).parts):
        raise ValueError('incus_security_package_shape')
    return row


def archive_files(raw):
    if len(raw) > MAX_TAR:
        raise ValueError('incus_archive_capacity')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for index, item in enumerate(archive):
            if index >= 4096:
                raise ValueError('incus_archive_entry_capacity')
            name = item.name.removeprefix('./')
            if not name.startswith(ROOT) or item.isdir():
                continue
            relative = name[len(ROOT):]
            if (not item.isfile() or not re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', relative)
                    or any(v in {'', '.', '..'} for v in relative.split('/'))
                    or not 0 <= item.size <= 64 * 1024 * 1024 or relative in files or len(files) >= 16):
                raise ValueError('incus_archive_file_shape')
            stream = archive.extractfile(item)
            if stream is None:
                raise ValueError('incus_archive_file_shape')
            with stream:
                files[relative] = hashlib.file_digest(stream, 'sha256').hexdigest()
    if 'incusd' not in files:
        raise ValueError('incus_main_image_missing')
    return files


def deployment_manifest(files, archive_sha256):
    return {'schema': 'children-selected-deployments/v1', 'units': {'incus.service': {
        'root': '/usr/libexec/incus', 'bind': 'executable',
        'source_ref': 'Debian-Security:incus-base/'+archive_sha256, 'files': files}}}


def download_archive(path, row, *, opener=None):
    """Bound a public cache download; resume retained bytes only with exact Range."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    partial = path.with_name(path.name + '.partial')
    expected = int(row['Size'])
    retained = partial.exists()
    offset = partial.stat().st_size if retained else 0
    if partial.is_symlink() or offset > expected:
        raise ValueError('incus_retained_partial_changed')
    if partial.exists():
        info = partial.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022 or info.st_nlink != 1):
            raise ValueError('incus_retained_partial_changed')
    headers = {'User-Agent': 'children-incus-provenance/1'}
    if offset:
        headers['Range'] = 'bytes='+str(offset)+'-'
    url = 'https://security.debian.org/debian-security/'+row['Filename']
    deadline = time.monotonic()+40
    if offset < expected:
        request = urllib.request.Request(url, headers=headers)
        with opener.open(request, timeout=20) as response:
            if (offset and (response.status != 206 or response.headers.get('Content-Range')
                    != f'bytes {offset}-{expected-1}/{expected}')
                    or not offset and response.status != 200):
                raise ValueError('incus_archive_range_unconfirmed')
            descriptor = os.open(partial, os.O_WRONLY | os.O_NOFOLLOW |
                (os.O_APPEND if retained else os.O_CREAT | os.O_EXCL), 0o600)
            with os.fdopen(descriptor, 'ab') as stream:
                while True:
                    chunk = response.read(min(1024*1024, expected-offset+1))
                    if not chunk:
                        break
                    if offset+len(chunk) > expected or time.monotonic() > deadline:
                        raise ValueError('incus_archive_download_capacity')
                    stream.write(chunk)
                    offset += len(chunk)
                stream.flush()
                os.fsync(stream.fileno())
    verify_archive(dict(archive=str(partial), bytes=expected, sha256=row['SHA256']), os.geteuid())
    if path.exists():
        raise ValueError('incus_archive_publication_changed')
    partial.rename(path)


def qualify(state, *, run=command, now=None):
    if os.geteuid() != 0:
        raise ValueError('incus_provenance_owner_required')
    state = Path(state)
    if not state.is_absolute() or '..' in state.parts:
        raise ValueError('incus_provenance_state_required')
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    for p in (state, *state.parents):
        info = p.lstat()
        if p.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('incus_provenance_state_required')
    fd = os.open(state/'.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError('incus_provenance_lock_custody')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return qualify_locked(state, run=run, now=now)


def qualify_locked(state, *, run, now):
    if len(list(state.iterdir())) > 8:
        raise ValueError('incus_provenance_state_capacity')
    metadata = [p for p in state.iterdir() if p.name != 'archives']
    if any(not stat.S_ISREG(p.lstat().st_mode) or p.lstat().st_uid != 0
           or p.lstat().st_mode & 0o077 for p in metadata) or sum(p.stat().st_size for p in metadata) > 512 * 1024:
        raise ValueError('incus_provenance_state_capacity')
    archives = state/'archives'
    archives.mkdir(mode=0o700, exist_ok=True)
    if (archives.is_symlink() or archives.stat().st_uid != 0
            or archives.stat().st_mode & 0o077 or len(list(archives.iterdir())) > 2):
        raise ValueError('incus_provenance_cache_capacity')
    cached = list(archives.iterdir())
    if any(not stat.S_ISREG(p.lstat().st_mode) or p.lstat().st_uid != 0
           or p.lstat().st_mode & 0o077 for p in cached) or sum(p.stat().st_size for p in cached) > MAX_ARCHIVE:
        raise ValueError('incus_provenance_cache_capacity')
    def read(args, limit=65536):
        return run(args, seconds=40, limit=limit)
    version = read(['dpkg-query', '-W', '-f=${Version}', 'incus-base']).decode().strip()
    if not re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,100}', version):
        raise ValueError('incus_installed_version_required')
    index = signed_index(read(['apt-get', 'indextargets']).decode(), read=read,
                         now=time.time() if now is None else now)
    row = package_record(index, version)
    path = archives/PurePosixPath(row['Filename']).name
    item = dict(archive=str(path), bytes=int(row['Size']), sha256=row['SHA256'])
    if not path.exists():
        if any(p != path.with_name(path.name+'.partial') for p in archives.iterdir()):
            raise ValueError('incus_retained_archive_requires_reconciliation')
        download_archive(path, row)
    verify_archive(item, 0)
    raw = read(['dpkg-deb', '--fsys-tarfile', str(path)], limit=MAX_TAR)
    files = archive_files(raw)
    if read(['dpkg-query', '-W', '-f=${Version}', 'incus-base']).decode().strip() != version:
        raise ValueError('incus_installed_version_changed')
    manifest = deployment_manifest(files, row['SHA256'])
    receipt = dict(schema='children-incus-provenance/v1', checked=int(time.time()), version=version,
        package_sha256=row['SHA256'], package_bytes=int(row['Size']),
        signed_index_sha256=hashlib.sha256(index).hexdigest(), declared_files=len(files),
        package_installation=False, package_code_execution=False, service_changes=0,
        interpretation='Signed package bytes only; loaded executable association requires the existing daily observer')
    atomic(state/'manifest.json', json.dumps(manifest, sort_keys=True).encode())
    atomic(state/'receipt.json', json.dumps(receipt, sort_keys=True).encode())
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.state), sort_keys=True))


if __name__ == '__main__':
    main()
