#!/usr/bin/env python3
"""Export an EXISTING body's public signed identity; no enrollment or service.

Download onboarding_peer_native.py alongside this file. Run with the body's
existing Matrix Python environment. Its daemon must have released its writer
lock; this tool never stops a service, reads an inbox or creates Root custody.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import time
import types
from pathlib import Path

PEER_SHA256 = 'e5360670b1e7a17194472bfd1a84ae68e60b90d591bf4e91b06771eff1dd97b6'


def export(runtime_root: Path, password_file: Path, output: Path, *,
           visibility_installation: Path | None = None, peer_file: Path | None = None) -> None:
    from daimon_matrix.daemon import _state_root, _visibility_factory, acquire_lock
    from daimon_matrix.messaging_config import protected_read
    from daimon_matrix.native_egress import closed_visibility
    from daimon_matrix.runtime import load_runtime

    asset = peer_file or Path(__file__).with_name('onboarding_peer_native.py')
    descriptor = os.open(asset, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022 or info.st_size > 100000):
            raise ValueError('verified_native_identity_tool_required')
        raw = stream.read()
    if hashlib.sha256(raw).hexdigest() != PEER_SHA256:
        raise ValueError('verified_native_identity_tool_required')
    tool = types.ModuleType('native_public_identity_export')
    exec(compile(raw, str(asset), 'exec'), tool.__dict__)
    root = _state_root(runtime_root)
    _state_root(output.parent)
    password = protected_read(password_file)
    lock = acquire_lock(root)
    try:
        def clock():
            return time.time_ns() // 1000000
        bundle = json.loads(protected_read(root / 'runtime.json'))
        if bundle.get('schema') != 'dm.runtime.bundle/v8':
            raise ValueError('existing_v8_identity_required')
        options = ({'egress_factory': _visibility_factory(visibility_installation, clock=clock)}
                   if visibility_installation is not None else
                   {'egress': closed_visibility(clock=clock, catalog_mode='validate')})
        runtime = load_runtime(root, 'runtime.json', lambda: bytearray(password), clock=clock, **options)
        public = tool.public_identity(runtime, bundle)
        tool.verify_identity(public)
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(public, sort_keys=True).encode())
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(lock)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-root', type=Path, required=True)
    parser.add_argument('--password-file', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--visibility-installation', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        export(args.runtime_root, args.password_file, args.output,
               visibility_installation=args.visibility_installation)
    except BlockingIOError:
        print(json.dumps({'error': 'local_daemon_writer_lock_owned',
            'action': 'Use the existing owner-controlled service procedure; no competing runtime load.'}))
        return 2
    except (OSError, ValueError, RuntimeError, ImportError, TypeError, KeyError):
        print(json.dumps({'error': 'local_public_identity_export_unavailable',
            'action': 'Preserve the local installation and report unavailable through the same API.'}))
        return 2
    print(json.dumps({'public_identity_exported': True, 'share_only': 'the public identity JSON'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
