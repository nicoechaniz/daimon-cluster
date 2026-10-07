"""Qualify runtime-only code updates without rebinding a receiving seed or plan.

The original context, skills, HMK tools, provider binary and Matrix wheelhouse
remain pinned. The operator selects a separately sealed runtime artifact whose
only changed executable files are the maintained Cluster Python modules.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from . import onboarding_release
from .onboarding import OnboardingError

SCHEMA = 'cluster-onboarding-runtime-successor/v1'
MARKER = 'runtime-successor.json'


def verify(code: Path, fingerprint: str, base: Path, base_fingerprint: str, *, uid: int) -> dict:
    original = onboarding_release.verify(base, base_fingerprint, uid=uid)
    successor = onboarding_release.verify(code, fingerprint, uid=uid)
    marker = json.loads(onboarding_release.regular(code / MARKER, uid=uid))
    if (code.absolute() == base.absolute() or fingerprint == base_fingerprint
            or marker != dict(schema=SCHEMA, base_release_digest=base_fingerprint)
            or original['profile'] != successor['profile']):
        raise OnboardingError('compatible_onboarding_runtime_successor_required')
    before = {row['path']: row['sha256'] for row in original['files']}
    after = {row['path']: row['sha256'] for row in successor['files']}
    def module(name: str) -> bool:
        return re.fullmatch(r'clusterctl/(?:__init__|[a-z][a-z0-9_]*)\.py', name) is not None
    if (not set(before) <= set(after)
            or any(after.get(name) != checksum for name, checksum in before.items() if not module(name))
            or any(name not in before and name != MARKER and not module(name) for name in after)):
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


def build(base: Path, base_fingerprint: str, source: Path, modules: tuple[str, ...], output: Path) -> dict:
    """Capture a code-only successor; never read receiving home or custody."""
    from . import being_seed
    from tools.build_onboarding_code import copy_code, capture_peer_tool
    original = onboarding_release.verify(base, base_fingerprint, uid=os.geteuid())
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
        if row['path'] not in replaced and row['path'] != MARKER:
            copy_code(base / row['path'], output / row['path'])
    for name in modules:
        copy_code(source / name, output / 'clusterctl' / name)
    if 'onboarding_peer.py' in modules:
        capture_peer_tool(output)
    (output / MARKER).write_text(json.dumps(dict(schema=SCHEMA, base_release_digest=base_fingerprint), sort_keys=True))
    (output / MARKER).chmod(0o644)
    for directory in output.rglob('*'):
        if directory.is_dir():
            directory.chmod(0o755)
    fingerprint = onboarding_release.seal(output, original['profile'])
    verify(output, fingerprint, base, base_fingerprint, uid=os.geteuid())
    return dict(runtime_digest=fingerprint, base_release_digest=base_fingerprint)
