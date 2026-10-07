"""Serve the existing canonical Cluster admission DB as its current owner.

Load the already-configured fence signer in the root service process, verify
it against the existing database, then permanently drop to that DB's owner.
No Matrix Root key is loaded, no key is copied, no ownership is changed and
no alternate admission database is initialized.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

from . import being_seed, onboarding_release
from .admission import AdmissionAuthority, AdmissionTCPServer
from .fences import Ed25519Signer
from .onboarding import OnboardingError
from .production_fences import DATABASE_SCHEMA, ed25519_fingerprint


def preflight(path: Path) -> tuple[dict, Ed25519Signer]:
    raw = onboarding_release.regular(path, uid=0, limit=65536)
    value = json.loads(raw)
    if (os.geteuid() != 0 or path.stat().st_mode & 0o077
            or not isinstance(value, dict) or set(value) != {'schema', 'state_dir',
                'runtime_uid', 'runtime_gid', 'authority_key', 'authority_key_id', 'holder_registrars', 'port'}
            or value['schema'] != 'cluster-onboarding-admission-service/v1'
            or type(value['runtime_uid']) is not int or value['runtime_uid'] <= 0
            or type(value['runtime_gid']) is not int or value['runtime_gid'] < 0
            or type(value['port']) is not int or not 1024 <= value['port'] <= 65535
            or not isinstance(value['holder_registrars'], dict) or not value['holder_registrars']
            or any(not isinstance(value[k], str) or not Path(value[k]).is_absolute()
                   for k in ('state_dir', 'authority_key'))):
        raise OnboardingError('canonical_onboarding_authority_required')
    root = being_seed._path(Path(value['state_dir']))
    database = root / 'resource-fences.sqlite3'
    being_seed._path(database)
    for target, directory in [(root, True), (database, False)]:
        info = target.stat()
        if (info.st_uid != value['runtime_uid'] or info.st_gid != value['runtime_gid']
                or info.st_mode & 0o077 or (stat.S_ISDIR(info.st_mode) if directory else
                    stat.S_ISREG(info.st_mode) and info.st_nlink == 1) is not True):
            raise OnboardingError('canonical_onboarding_authority_required')
    signer = Ed25519Signer(value['authority_key'], value['authority_key_id'])
    for key_id, public in value['holder_registrars'].items():
        if not isinstance(key_id, str) or not key_id or not isinstance(public, str):
            raise OnboardingError('canonical_onboarding_authority_required')
        ed25519_fingerprint(public)
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as connection:
        schema = connection.execute("SELECT value FROM metadata WHERE name='schema'").fetchone()
        selected = connection.execute('SELECT public_key,state FROM signing_keys WHERE key_id=?',
                                      (signer.key_id,)).fetchone()
        registrars = dict(connection.execute("SELECT key_id,public_key FROM holder_registrars WHERE state='active'"))
    if (schema != (DATABASE_SCHEMA,) or selected != (signer.public_key, 'active')
            or registrars != value['holder_registrars']):
        raise OnboardingError('canonical_onboarding_authority_conflict')
    return value, signer


def serve(value: dict, signer: Ed25519Signer) -> None:
    os.setgroups([])
    os.setgid(value['runtime_gid'])
    os.setuid(value['runtime_uid'])
    if os.geteuid() != value['runtime_uid'] or os.getegid() != value['runtime_gid']:
        raise OnboardingError('canonical_onboarding_authority_required')
    authority = AdmissionAuthority(value['state_dir'], signer=signer,
                                   holder_registrars=value['holder_registrars'])
    server = AdmissionTCPServer(('127.0.0.1', value['port']), authority)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    try:
        value, signer = preflight(args.config)
        if args.check:
            print(json.dumps({'configured': True, 'existing_authority_verified': True}))
        else:
            serve(value, signer)
        return 0
    except Exception:
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
