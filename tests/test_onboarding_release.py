"""Code-only bundles use pinned HMK and explicit shared skill selection."""
import io
import json
import os
import tarfile
from types import SimpleNamespace

import pytest

from clusterctl import onboarding_release
from clusterctl.onboarding import OnboardingError
from tools import build_onboarding_code as builder


def test_qualified_ordinary_context_remains_valid_after_host_transfer_upgrade(tmp_path):
    from tests.test_onboarding_code_successor import fixture
    base, _, _, selected = fixture(tmp_path)
    (base / 'release.json').unlink()
    (base / 'support/being-seed-tools/tools/protected_being.py').unlink()
    frozen = onboarding_release.seal(base, selected)
    original = {p.relative_to(base).as_posix(): p.read_bytes()
                for p in base.rglob('*') if p.is_file()}
    assert onboarding_release.verify(base, frozen, uid=os.geteuid())['profile'] == selected
    assert {p.relative_to(base).as_posix(): p.read_bytes()
            for p in base.rglob('*') if p.is_file()} == original
    # A context that actually captures the new transfer implementation must
    # carry its exact protected helper too, even when separately resealed.
    transfer = base / 'clusterctl/onboarding_transfer.py'
    transfer.write_text('# Synthetic transfer fixture.\n')
    transfer.chmod(0o644)
    (base / 'release.json').unlink()
    upgraded = onboarding_release.seal(base, selected)
    with pytest.raises(OnboardingError, match='receiving_release_incomplete'):
        onboarding_release.verify(base, upgraded, uid=os.geteuid())


def test_builder_captures_mutable_code_but_publishes_qualified_read_only_artifact(tmp_path, monkeypatch):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as stream:
        for name in ('memoryctl.py', 'native_records.py'):
            entry = tarfile.TarInfo('scripts/' + name)
            raw = b'# Pinned synthetic code-only fixture.\n'
            entry.size = len(raw)
            stream.addfile(entry, io.BytesIO(raw))
    calls = []
    def git(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout=archive.getvalue())
    monkeypatch.setattr(builder.subprocess, 'run', git)
    commons = tmp_path / 'commons'
    approved = commons / 'approved'
    approved.mkdir(parents=True)
    (approved / 'SKILL.md').write_text('Approved code\n')
    historical = commons / 'unselected-history'
    historical.mkdir()
    (historical / 'SKILL.md').write_text('Historical behavior\n')
    output = tmp_path / 'output'
    tmp_path.chmod(0o700)
    selected = dict(schema=onboarding_release.PROFILE, model='gpt-6.1', reasoning='medium',
                    approval='never', sandbox='danger-full-access', skills=['approved'], primary_store=None)
    result = builder.build(tmp_path / 'unused-checkout', commons, selected, output)
    assert calls[0][5] == builder.HMK_COMMIT
    release = onboarding_release.verify(output, result['release_digest'], uid=os.geteuid())
    assert release['profile'] == selected
    assert not (output / 'skills/unselected-history').exists()
    assert not any(path.stat().st_mode & 0o022 for path in (output, *output.rglob('*')))
    assert json.loads((output / 'provenance.json').read_text())['hmk_commit'] == builder.HMK_COMMIT
    with pytest.raises(OnboardingError, match='destination_exists'):
        builder.build(tmp_path, commons, selected, output)
    (output / 'inheritance.md').write_text('Changed after qualification')
    with pytest.raises(OnboardingError, match='digest_mismatch'):
        onboarding_release.verify(output, result['release_digest'], uid=os.geteuid())


def test_builder_refuses_symlink_and_preserves_partial_without_release(tmp_path, monkeypatch):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as stream:
        entry = tarfile.TarInfo('scripts/memoryctl.py')
        entry.type = tarfile.SYMTYPE
        entry.linkname = '/outside/private-file'
        stream.addfile(entry)
    monkeypatch.setattr(builder.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0, stdout=archive.getvalue()))
    tmp_path.chmod(0o700)
    selected = dict(schema=onboarding_release.PROFILE, model='gpt-6.1', reasoning='medium',
                    approval='never', sandbox='danger-full-access', skills=[], primary_store=None)
    with pytest.raises(OnboardingError, match='invalid_pinned_hmk_archive'):
        builder.build(tmp_path, tmp_path, selected, tmp_path / 'output')
    assert not (tmp_path / 'output/release.json').exists()
    assert (tmp_path / 'output').exists()
