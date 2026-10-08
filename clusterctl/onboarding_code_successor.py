"""Qualify runtime-only code updates without rebinding a receiving seed or plan.

The original context, skills, HMK tools and provider binary remain pinned.
Ordinary successors change maintained Cluster modules only. An explicit V2
successor additionally pins the previous and qualified replacement SDK digests;
dependency generations never overwrite an existing receiving environment.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from . import onboarding_release
from .onboarding import OnboardingError, digest

SCHEMA = 'cluster-onboarding-runtime-successor/v1'
SDK_SCHEMA = 'cluster-onboarding-runtime-successor/v2'
MARKER = 'runtime-successor.json'


def verify(code: Path, fingerprint: str, base: Path, base_fingerprint: str, *, uid: int) -> dict:
    original = onboarding_release.verify(base, base_fingerprint, uid=uid)
    successor = onboarding_release.verify(code, fingerprint, uid=uid)
    marker = json.loads(onboarding_release.regular(code / MARKER, uid=uid))
    ordinary = dict(schema=SCHEMA, base_release_digest=base_fingerprint)
    sdk_change = marker.get('schema') == SDK_SCHEMA
    if sdk_change:
        from . import onboarding_sdk
        previous = onboarding_sdk.verify(base, uid=uid,
            matrix_commit=onboarding_sdk.PREVIOUS_MATRIX_COMMIT)
        current = onboarding_sdk.verify(code, uid=uid)
        expected = dict(schema=SDK_SCHEMA, base_release_digest=base_fingerprint,
            previous_sdk_digest=digest(previous), sdk_digest=digest(current))
    else:
        expected = ordinary
    if (code.absolute() == base.absolute() or fingerprint == base_fingerprint
            or marker != expected or original['profile'] != successor['profile']):
        raise OnboardingError('compatible_onboarding_runtime_successor_required')
    before = {row['path']: row['sha256'] for row in original['files']}
    after = {row['path']: row['sha256'] for row in successor['files']}
    def module(name: str) -> bool:
        return re.fullmatch(r'clusterctl/(?:__init__|[a-z][a-z0-9_]*)\.py', name) is not None
    def sdk(name: str) -> bool:
        return sdk_change and (name in {'sdk/sdk.json', 'sdk/requirements.txt'}
            or re.fullmatch(r'sdk/wheels/[A-Za-z0-9_.+-]+\.whl', name) is not None)
    if (not {name for name in before if not sdk(name)} <= set(after)
            or any(after.get(name) != checksum for name, checksum in before.items()
                   if not module(name) and not sdk(name))
            or any(name not in before and name != MARKER and not module(name) and not sdk(name) for name in after)):
        raise OnboardingError('original_onboarding_context_preserved')
    return successor


def selected(code: Path, fingerprint: str | None, base: Path, base_fingerprint: str,
             *, uid: int = 0) -> Path:
    """Both launch paths validate their declared code before loading private state."""
    if fingerprint is None:
        if code != base:
            raise OnboardingError('qualified_onboarding_runtime_required')
        onboarding_release.verify(base, base_fingerprint, uid=uid)
    else:
        verify(code, fingerprint, base, base_fingerprint, uid=uid)
    return code


def selection(code: Path | None, fingerprint: str | None, base: Path, base_fingerprint: str,
              *, uid: int = 0) -> Path:
    if (code is None) != (fingerprint is None):
        raise OnboardingError('qualified_onboarding_runtime_required')
    return selected(base if code is None else code, fingerprint, base, base_fingerprint, uid=uid)


def build(base: Path, base_fingerprint: str, source: Path, modules: tuple[str, ...], output: Path,
          *, sdk: Path | None = None) -> dict:
    """Capture a code-only successor; never read receiving home or custody."""
    from . import being_seed
    from tools.build_onboarding_code import copy_code, capture_peer_tool
    original = onboarding_release.verify(base, base_fingerprint, uid=os.geteuid())
    marker = dict(schema=SCHEMA, base_release_digest=base_fingerprint)
    if sdk is not None:
        from . import onboarding_sdk
        if sdk.name != 'sdk':
            raise OnboardingError('onboarding_sdk_directory_required')
        previous = onboarding_sdk.verify(base, uid=os.geteuid(),
            matrix_commit=onboarding_sdk.PREVIOUS_MATRIX_COMMIT)
        current = onboarding_sdk.verify(sdk.parent, uid=os.geteuid())
        marker = dict(schema=SDK_SCHEMA, base_release_digest=base_fingerprint,
            previous_sdk_digest=digest(previous), sdk_digest=digest(current))
    being_seed._path(output)
    if (output.exists() or output.is_symlink() or output.is_relative_to(base)
            or base.is_relative_to(output)):
        raise OnboardingError('receiving_code_destination_exists')
    if (not modules or len(set(modules)) != len(modules)
            or any(re.fullmatch(r'(?:__init__|[a-z][a-z0-9_]*)\.py', name) is None for name in modules)):
        raise OnboardingError('qualified_onboarding_runtime_required')
    output.mkdir(mode=0o755)
    replaced = {'clusterctl/' + name for name in modules}
    if 'onboarding_peer.py' in modules:
        replaced.add('clusterctl/onboarding_peer_native.py')
    for row in original['files']:
        if (row['path'] not in replaced and row['path'] != MARKER
                and not (sdk is not None and row['path'].startswith('sdk/'))):
            copy_code(base / row['path'], output / row['path'])
    for name in modules:
        copy_code(source / name, output / 'clusterctl' / name)
    if 'onboarding_peer.py' in modules:
        capture_peer_tool(output)
    if sdk is not None:
        for path in sorted(sdk.rglob('*')):
            if path.is_file():
                copy_code(path, output / 'sdk' / path.relative_to(sdk))
    (output / MARKER).write_text(json.dumps(marker, sort_keys=True))
    (output / MARKER).chmod(0o644)
    for directory in output.rglob('*'):
        if directory.is_dir():
            directory.chmod(0o755)
    fingerprint = onboarding_release.seal(output, original['profile'])
    verify(output, fingerprint, base, base_fingerprint, uid=os.geteuid())
    return dict(runtime_digest=fingerprint, base_release_digest=base_fingerprint)
