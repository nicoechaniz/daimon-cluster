"""Freeze actual receiving output, keeping the source and rejecting drift."""
import json
import os

import pytest

from clusterctl import being_seed, onboarding_input
from clusterctl.onboarding import OnboardingError
from tests import test_being_seed as seed_fixtures

packet = seed_fixtures.packet
staging_volume = seed_fixtures.staging_volume


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
