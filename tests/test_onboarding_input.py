"""Freeze actual receiving output, keeping the source and rejecting drift."""
import json
import os

import pytest

from clusterctl import being_seed, onboarding_input
from clusterctl.onboarding import OnboardingError
from tests import test_being_seed as seed_fixtures

packet = seed_fixtures.packet
staging_volume = seed_fixtures.staging_volume


def cache_input(tmp_path):
    root = tmp_path / 'frozen'
    root.mkdir(mode=0o700)
    received = root / 'received'
    received.mkdir(mode=0o700)
    path = received / 'history'
    path.write_bytes(b'preserved history')
    path.chmod(0o600)
    manifest = dict(schema=onboarding_input.SCHEMA,
                    files=onboarding_input.inventory(received, uid=os.geteuid()),
                    archive_sha256='a' * 64)
    being_seed._write(root / 'manifest.json', manifest)
    return root, onboarding_input.digest(manifest), path


def test_cache_reuses_bytes_and_keeps_caller_mutations_private(tmp_path, monkeypatch):
    root, expected, _ = cache_input(tmp_path)
    original = onboarding_input.owned_digest
    reads = []
    def counted(path, **kwargs):
        reads.append(path)
        return original(path, **kwargs)
    monkeypatch.setattr(onboarding_input, 'owned_digest', counted)
    cache = onboarding_input.VerificationCache()
    first = cache.verify(root, expected)
    assert len(reads) == 1
    first['files'].clear()
    assert len(cache.verify(root, expected)['files']) == 1
    assert len(reads) == 1
    with pytest.raises(OnboardingError, match='digest_mismatch'):
        cache.verify(root, 'b' * 64)
    assert len(reads) == 1


@pytest.mark.parametrize('change', ['edit', 'replace', 'add', 'remove', 'permissions',
                                    'symlink', 'manifest'])
def test_cached_input_still_rejects_drift(tmp_path, change):
    root, expected, path = cache_input(tmp_path)
    cache = onboarding_input.VerificationCache()
    cache.verify(root, expected)
    previous = path.stat()
    if change == 'edit':
        path.write_bytes(b'changed history!!')
        # Restoring mtime cannot conceal the new ctime.
        os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns))
    elif change == 'replace':
        replacement = path.with_name('replacement')
        replacement.write_bytes(b'changed history!!')
        replacement.chmod(0o600)
        os.replace(replacement, path)
    elif change == 'add':
        added = path.with_name('extra')
        added.write_bytes(b'extra history')
        added.chmod(0o600)
    elif change == 'remove':
        path.unlink()
    elif change == 'permissions':
        path.chmod(0o644)
    elif change == 'symlink':
        path.unlink()
        path.symlink_to(root / 'manifest.json')
    else:
        (root / 'manifest.json').write_text('{}')
    with pytest.raises((OnboardingError, being_seed.SeedError, KeyError)):
        cache.verify(root, expected)


def test_cache_rehashes_identical_replacement_and_detects_mid_verification_change(tmp_path, monkeypatch):
    root, expected, path = cache_input(tmp_path)
    original = onboarding_input.verify
    cache = onboarding_input.VerificationCache()
    cache.verify(root, expected)
    replacement = path.with_name('replacement')
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(0o600)
    os.replace(replacement, path)
    calls = []
    def verified_then_changed(root, expected, **kwargs):
        calls.append(root)
        result = original(root, expected, **kwargs)
        path.write_bytes(b'changed after verification')
        return result
    monkeypatch.setattr(onboarding_input, 'verify', verified_then_changed)
    with pytest.raises(OnboardingError, match='input_changed'):
        cache.verify(root, expected)
    assert calls == [root]
    monkeypatch.setattr(onboarding_input, 'verify', original)
    with pytest.raises(OnboardingError, match='digest_mismatch'):
        cache.verify(root, expected)


def prepared(tmp_path, packet):
    state = tmp_path / "intake"
    selection = seed_fixtures.imported(state, packet, name="fixture")
    being_seed.prepare(state, "fixture", selection, owner="ani")
    captures = tmp_path / "captures"
    captures.mkdir(mode=0o700)
    return state / "being-seeds/fixture/received", captures / "fixture"


def test_actual_prepared_input_is_frozen_and_all_selected_memory_preserved(tmp_path, packet):
    source, destination = prepared(tmp_path, packet)
    before = onboarding_input.inventory(source, uid=os.geteuid())
    result = onboarding_input.capture(source, destination, source_uid=os.geteuid())
    manifest = onboarding_input.verify(destination, result["seed_digest"])
    assert manifest["files"] == before == onboarding_input.inventory(source, uid=os.geteuid())
    assert any(row["path"] == "memory/store-001/library.db" for row in manifest["files"])
    with pytest.raises(OnboardingError, match="destination_exists"):
        onboarding_input.capture(source, destination, source_uid=os.geteuid())
    path = destination / "received/context/SOUL.md"
    path.write_text("A different identity")
    with pytest.raises(OnboardingError, match="digest_mismatch"):
        onboarding_input.verify(destination, result["seed_digest"])
    assert json.loads((destination / "manifest.json").read_text()) == manifest


def test_source_link_or_drift_never_publishes_a_capture_marker(tmp_path, packet, monkeypatch):
    source, destination = prepared(tmp_path, packet)
    original = onboarding_input.owned_digest
    changed = False
    def mutate(path, *, uid, copy=None):
        nonlocal changed
        result = original(path, uid=uid, copy=copy)
        if copy and not changed:
            changed = True
            (source / "context/SOUL.md").write_text("Source changed during capture")
        return result
    monkeypatch.setattr(onboarding_input, "owned_digest", mutate)
    with pytest.raises(OnboardingError, match="input_changed"):
        onboarding_input.capture(source, destination, source_uid=os.geteuid())
    assert not (destination / "manifest.json").exists()
    assert (destination / "received").exists()
    alias = source / "context/linked"
    alias.symlink_to(source / "context/SOUL.md")
    with pytest.raises(being_seed.SeedError, match="symlink"):
        onboarding_input.capture(source, destination.parent / "second", source_uid=os.geteuid())


def test_interrupted_copy_resumes_exact_input_without_publishing_partial_files(tmp_path, packet, monkeypatch):
    source, destination = prepared(tmp_path, packet)
    original = onboarding_input.owned_digest
    interrupted = False
    def copy(path, *, uid, copy=None):
        nonlocal interrupted
        if copy is not None and not interrupted:
            interrupted = True
            copy.write_bytes(b'partial interrupted copy')
            copy.chmod(0o600)
            raise OSError('fixture process interruption')
        return original(path, uid=uid, copy=copy)
    monkeypatch.setattr(onboarding_input, 'owned_digest', copy)
    with pytest.raises(OSError):
        onboarding_input.capture(source, destination, source_uid=os.geteuid(), resume=True)
    assert not (destination / 'manifest.json').exists()
    assert not any(path.is_file() for path in (destination / 'received').rglob('*'))
    monkeypatch.setattr(onboarding_input, 'owned_digest', original)
    result = onboarding_input.capture(source, destination, source_uid=os.geteuid(), resume=True)
    assert onboarding_input.verify(destination, result['seed_digest'])['files'] == onboarding_input.inventory(source, uid=os.geteuid())
    assert onboarding_input.capture(source, destination, source_uid=os.geteuid(), resume=True) == result
    assert list((destination / '.capture-staging').iterdir())  # Preserved interruption evidence.
