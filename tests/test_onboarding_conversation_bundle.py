"""Cold guests receive pinned public App bytes without another private home."""
import hashlib
import json
import os
from dataclasses import replace

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl import onboarding_conversation_bundle as bundle
from clusterctl.onboarding_host import HostBackend
from tests.test_onboarding_host import configured


def artifact(root):
    root.mkdir()
    (root / 'telecodex').write_bytes(b'public executable')
    raw = json.dumps({'schema': bundle.SCHEMA, 'files': {
        'telecodex': hashlib.sha256(b'public executable').hexdigest()}}).encode()
    (root / bundle.MARKER).write_bytes(raw)
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


@pytest.mark.parametrize('fault', ['link', 'extra', 'missing', 'writable', 'digest'])
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
    else:
        pin = '0' * 64
    with pytest.raises(OnboardingError):
        bundle.verify(root, pin, uid=os.geteuid())


def test_own_codex_is_exposed_idempotently_and_foreign_guest_executable_survives(tmp_path):
    root = tmp_path / 'app'
    root.mkdir()
    (root / 'bin').mkdir()
    binary = root / 'bin/codex'
    binary.write_bytes(b'qualified binary')
    binary.chmod(0o555)
    raw = json.dumps({'schema': bundle.SCHEMA, 'files': {
        'bin/codex': hashlib.sha256(binary.read_bytes()).hexdigest()}}).encode()
    (root / bundle.MARKER).write_bytes(raw)
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
