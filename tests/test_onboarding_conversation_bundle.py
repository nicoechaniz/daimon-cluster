"""Cold guests receive pinned public App bytes without another private home."""
import hashlib
import json
import os
from types import SimpleNamespace
from dataclasses import replace

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl import onboarding_conversation_bundle as bundle
from clusterctl.onboarding_host import HostBackend
from tests.test_onboarding_host import configured


def artifact(root):
    root.mkdir()
    root.chmod(0o755)
    (root / 'telecodex').write_bytes(b'public executable')
    (root / 'telecodex').chmod(0o644)
    raw = json.dumps({'schema': bundle.SCHEMA, 'files': {
        'telecodex': hashlib.sha256(b'public executable').hexdigest()}}).encode()
    (root / bundle.MARKER).write_bytes(raw)
    (root / bundle.MARKER).chmod(0o444)
    return hashlib.sha256(raw).hexdigest()


def test_cold_context_mount_is_pinned_read_only_and_original_job_stays_compatible(tmp_path):
    root = tmp_path / 'app'
    pin = artifact(root)
    config, plan, _, original = configured(tmp_path)
    assert original._conversation_bundle_mount(plan) == {}
    config = replace(config, conversation_bundle_by_name={plan['name']: (root, pin)})
    backend = HostBackend(config)
    assert backend._conversation_bundle_mount(plan) == {'onboarding-app': {
        'type': 'disk', 'source': str(root), 'path': '/opt/daimon-app',
        'readonly': 'true', 'shift': 'true'}}
    (root / 'telecodex').write_bytes(b'different bytes')
    with pytest.raises(OnboardingError, match='conversation_bundle_changed'):
        backend._environment(plan)  # Refuse before any Incus allocation/query.


@pytest.mark.parametrize('fault', ['link', 'extra', 'missing', 'writable', 'digest', 'private-directory'])
def test_bundle_refuses_unsafe_or_different_public_tree(tmp_path, fault):
    root = tmp_path / 'app'
    pin = artifact(root)
    assert bundle.verify(root, pin, uid=os.geteuid())['files'] == 1
    if fault == 'link':
        (root / 'link').symlink_to(root / 'telecodex')
    elif fault == 'extra':
        (root / 'private.json').write_bytes(b'never mount unlisted state')
    elif fault == 'missing':
        (root / 'telecodex').unlink()
    elif fault == 'writable':
        (root / 'telecodex').chmod(0o666)
    elif fault == 'private-directory':
        root.chmod(0o700)
    else:
        pin = '0' * 64
    with pytest.raises(OnboardingError):
        bundle.verify(root, pin, uid=os.geteuid())


def test_own_codex_is_exposed_idempotently_and_foreign_guest_executable_survives(tmp_path):
    root = tmp_path / 'app'
    root.mkdir()
    root.chmod(0o755)
    (root / 'bin').mkdir()
    (root / 'bin').chmod(0o755)
    binary = root / 'bin/codex'
    binary.write_bytes(b'qualified binary')
    binary.chmod(0o555)
    (root / 'codex-resources').mkdir(mode=0o755)
    (root / 'codex-path').mkdir(mode=0o755)
    for directory in root.iterdir():
        if directory.is_dir():
            directory.chmod(0o755)
    host = root / 'bin/codex-code-mode-host'
    host.write_bytes(b'qualified host')
    host.chmod(0o555)
    package = root / 'codex-package.json'
    package.write_text(json.dumps(dict(layoutVersion=1, entrypoint='bin/codex',
        resourcesDir='codex-resources', pathDir='codex-path')))
    package.chmod(0o444)
    raw = json.dumps({'schema': bundle.SCHEMA, 'files': {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (binary, host, package)}}).encode()
    (root / bundle.MARKER).write_bytes(raw)
    (root / bundle.MARKER).chmod(0o444)
    pin = hashlib.sha256(raw).hexdigest()
    destination = tmp_path / 'codex'
    destination.write_bytes(b'existing guest executable')
    with pytest.raises(OnboardingError, match='existing_guest_codex_preserved'):
        bundle.bootstrap_codex(pin, root=root, destination=destination)
    assert destination.read_bytes() == b'existing guest executable'
    destination.unlink()
    bundle.bootstrap_codex(pin, root=root, destination=destination)
    bundle.bootstrap_codex(pin, root=root, destination=destination)
    assert destination.readlink() == binary


def test_missing_guest_dependencies_have_one_finite_standard_package_install(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle.os, 'geteuid', lambda: 0)
    release = tmp_path / 'os-release'
    release.write_text('ID=debian\nVERSION_ID="13"\n')
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        assert kwargs['timeout'] == 90 and kwargs['env']['DEBIAN_FRONTEND'] == 'noninteractive'
        return SimpleNamespace(returncode=0)
    bundle.dependencies(ready=lambda: len(calls) == 2, run=run, release=release)
    assert len(calls) == 2
    assert calls[-1][-4:] == ['python3-venv', 'rsync', 'nodejs', 'git']
    bundle.dependencies(ready=lambda: True, run=run, release=release)
    assert len(calls) == 2
    release.write_text('ID=other\nVERSION_ID="13"\n')
    with pytest.raises(OnboardingError):
        bundle.dependencies(ready=lambda: False, run=run, release=release)
    assert len(calls) == 2


def test_lone_codex_binary_cannot_claim_native_daemon_delivery(tmp_path):
    root = tmp_path / 'app'
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    (root / 'bin').mkdir(mode=0o755)
    (root / 'bin').chmod(0o755)
    binary = root / 'bin/codex'
    binary.write_bytes(b'CLI version works, daemon needs its package')
    binary.chmod(0o555)
    raw = json.dumps({'schema': bundle.SCHEMA, 'files': {
        'bin/codex': hashlib.sha256(binary.read_bytes()).hexdigest()}}).encode()
    (root / bundle.MARKER).write_bytes(raw)
    (root / bundle.MARKER).chmod(0o444)
    with pytest.raises(OnboardingError, match='conversation_bundle_codex_package_required'):
        bundle.bootstrap_codex(hashlib.sha256(raw).hexdigest(), root=root,
            destination=tmp_path / 'codex')
    assert not (tmp_path / 'codex').exists()
