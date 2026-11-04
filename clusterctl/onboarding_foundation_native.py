"""Serve the existing granted Matrix MCP from a qualified receiving owner.

This client-only profile preserves the separately selected chat/echo adapter.
It loads the receiver's existing protected client; no custody is opened and no
runtime, identity, grant, thread, model turn or background listener is created.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import inspect
import json
import os
import re
import sys
from pathlib import Path

from . import onboarding_code_successor, onboarding_sdk
from .onboarding import OnboardingError, digest


def foundation_command(venv: Path, imports: Path, code: Path, *, code_digest: str,
                       runtime_root: Path, request_dir: Path, code_uid: int = 0) -> list[str]:
    """Render one owner-selected profile, never model-selected coordinates."""
    if (not re.fullmatch('[a-f0-9]{64}', code_digest) or type(code_uid) is not int or code_uid < 0
            or any(not p.is_absolute() or '..' in p.parts for p in (runtime_root, request_dir))):
        raise OnboardingError('qualified_foundation_profile_required')
    return onboarding_sdk.runtime_command(venv, imports, code,
        'clusterctl.onboarding_foundation_native', ['--code-digest', code_digest,
            '--code-owner', str(code_uid), '--runtime-root', str(runtime_root),
            '--request-dir', str(request_dir), 'mcp'])


def foundation_bridge(runtime_root: Path, request_dir: Path):
    """Load only this owner's existing client; enumeration sends no request."""
    from daimon_matrix.client import ClientConfig, LocalClient
    from daimon_matrix.codex_matrix_binding import read_native_capability_key
    from daimon_matrix.mcp_server import DaimonMcp
    from daimon_matrix.messaging_config import protected_read

    if 'granted_only' not in inspect.signature(DaimonMcp).parameters:
        raise OnboardingError('qualified_foundation_sdk_required')
    if any(not p.is_absolute() or '..' in p.parts for p in (runtime_root, request_dir)):
        raise OnboardingError('qualified_foundation_profile_required')
    raw = protected_read(runtime_root/'runtime.json')
    runtime = json.loads(raw)
    client_raw = protected_read(runtime_root/'client.json')
    descriptor = os.open(runtime_root/'client.key', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    key = None
    try:
        key = read_native_capability_key(descriptor)
        config = ClientConfig.load(runtime_root/'client.json', key)
    finally:
        os.close(descriptor)
        if key is not None:
            key[:] = bytes(len(key))
    socket = Path(runtime['socket'])
    if not socket.is_absolute():
        socket = runtime_root/socket
    request_dir.mkdir(mode=0o700, exist_ok=True)
    client = LocalClient(socket, config)
    bridge = DaimonMcp(client, request_dir, granted_only=True)
    if (protected_read(runtime_root/'runtime.json') != raw
            or protected_read(runtime_root/'client.json') != client_raw):
        raise OnboardingError('receiving_foundation_binding_changed')
    fingerprint = digest({'runtime_sha256': hashlib.sha256(raw).hexdigest(),
        'client_sha256': hashlib.sha256(client_raw).hexdigest()})
    return bridge, fingerprint


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--code-digest', required=True)
    parser.add_argument('--code-owner', type=int, default=0)
    parser.add_argument('--runtime-root', type=Path, required=True)
    parser.add_argument('--request-dir', type=Path, required=True)
    parser.add_argument('action', choices=['mcp'])
    args = parser.parse_args(argv)
    try:
        code = Path(__file__).resolve().parents[1]
        parameters = onboarding_code_successor.sdk_parameters(code, uid=args.code_owner)
        if not parameters:
            raise OnboardingError('qualified_foundation_sdk_required')
        startup = onboarding_sdk.qualified_startup(Path(sys.prefix), code,
            code_digest=args.code_digest, code_uid=args.code_owner, **parameters)
        bridge, fingerprint = foundation_bridge(args.runtime_root, args.request_dir)
        from .onboarding_owner_client import tooling_version
        from daimon_matrix.mcp_server import _run_stdio
        server = bridge.server()
        server.version = tooling_version(startup, fingerprint)
        asyncio.run(_run_stdio(server))
        return 0
    except Exception:
        # Exception text and local paths can contain private receiver data.
        print('foundation_native_startup_refused', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
