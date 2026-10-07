"""Canonical owner adapters preserve registry history and root fence custody."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from clusterctl.admission import AdmissionAuthority, AdmissionEndpoint
from clusterctl.embodiments import Registry
from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_authority import preflight
from clusterctl.onboarding_registry import OwnerRegistry
from tests.test_admission import _key, _client, _coordinates, _enroll

ROOT = Path(__file__).resolve().parents[1]


def test_registry_replay_preserves_other_bodies_and_rejects_changed_owner(tmp_path):
    registry = tmp_path / 'registry'
    registry.mkdir(mode=0o700)
    source = dict(body_ref='codex:source', embodiment_id='embodiment:source', incarnation_id='incarnation:source')
    Registry(registry).adopt_running(**source)
    owner = OwnerRegistry(registry)
    before = owner.load()['embodiments']['embodiment:source']
    receiving = dict(body_ref='codex:fixture', embodiment_id='embodiment:fixture', incarnation_id='incarnation:fixture')
    owner.adopt_running(**receiving)
    raw = owner.path.read_bytes()
    owner.adopt_running(**receiving)
    assert owner.path.read_bytes() == raw
    assert owner.load()['embodiments']['embodiment:source'] == before
    registry.rename(tmp_path / 'old-registry')
    registry.mkdir(mode=0o700)
    with pytest.raises(OnboardingError, match='registry_changed'):
        owner.load()


def test_registry_refuses_public_directory_and_symlink(tmp_path):
    root = tmp_path / 'registry'
    root.mkdir(mode=0o755)
    with pytest.raises(OnboardingError):
        OwnerRegistry(root)
    root.chmod(0o700)
    alias = tmp_path / 'alias'
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError):
        OwnerRegistry(alias)


@pytest.mark.skipif(os.geteuid() != 0, reason='real root/service owner separation requires root')
def test_root_worker_uses_real_registry_owner_without_chowning_existing_state():
    with tempfile.TemporaryDirectory(prefix='dm-registry-owner-') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        registry = root / 'registry'
        registry.mkdir(mode=0o700)
        os.chown(registry, 65534, 65534)
        owner = OwnerRegistry(registry)
        receiving = dict(body_ref='codex:fixture', embodiment_id='embodiment:fixture', incarnation_id='incarnation:fixture')
        owner.adopt_running(**receiving)
        before = owner.path.read_bytes()
        owner.adopt_running(**receiving)
        assert owner.path.read_bytes() == before
        assert owner.load()['embodiments']['embodiment:fixture']['body_ref'] == receiving['body_ref']
        for path in [registry, owner.path, registry / 'embodiments.lock']:
            assert (path.stat().st_uid, path.stat().st_gid) == (65534, 65534)


@pytest.mark.skipif(os.geteuid() != 0, reason='real root/service owner separation requires root')
def test_existing_authority_serves_as_db_owner_and_preserves_root_key():
    with tempfile.TemporaryDirectory(prefix='dm-admission-owner-') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        signer = _key(root / 'keys/authority.pem', 'fixture-authority')
        registrar = _key(root / 'keys/registrar.pem', 'fixture-registrar')
        holder = _key(root / 'keys/holder.pem', 'fixture-holder')
        authority = root / 'canonical'
        AdmissionAuthority(authority, signer=signer, holder_registrars={registrar.key_id: registrar.public_key})
        for path in [authority, *authority.iterdir()]:
            os.chown(path, 65534, 65534)
        with socket.socket() as reserving:
            reserving.bind(('127.0.0.1', 0))
            port = reserving.getsockname()[1]
        config = root / 'config.json'
        value = dict(schema='cluster-onboarding-admission-service/v1', state_dir=str(authority),
            runtime_uid=65534, runtime_gid=65534, authority_key=str(root / 'keys/authority.pem'),
            authority_key_id=signer.key_id, holder_registrars={registrar.key_id: registrar.public_key}, port=port)
        config.write_text(json.dumps(value))
        config.chmod(0o600)
        assert preflight(config)[0] == value
        original_key = (root / 'keys/authority.pem').read_bytes()
        # Wrong configured identity must fail before it mutates the canonical DB.
        before = (authority / 'resource-fences.sqlite3').read_bytes()
        value['authority_key_id'] = 'different-authority'
        config.write_text(json.dumps(value))
        with pytest.raises(OnboardingError, match='authority_conflict'):
            preflight(config)
        assert (authority / 'resource-fences.sqlite3').read_bytes() == before
        value['authority_key_id'] = signer.key_id
        config.write_text(json.dumps(value))
        launcher = 'import sys;sys.path.insert(0,sys.argv.pop(1));from clusterctl.onboarding_authority import main;raise SystemExit(main())'
        process = subprocess.Popen([sys.executable, '-B', '-I', '-c', launcher, str(ROOT), '--config', str(config)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    pytest.fail('canonical authority process stopped before listening')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                pytest.fail('canonical authority did not start')
            credentials = next(line for line in Path('/proc', str(process.pid), 'status').read_text().splitlines()
                               if line.startswith('Uid:'))
            assert set(credentials.split()[1:]) == {'65534'}
            coordinates = _coordinates('owner-fixture')
            client = _client(AdmissionEndpoint.network('127.0.0.1', port), holder, signer, coordinates)
            _enroll(client, registrar, holder, coordinates, int(time.time() * 1000))
            session = client.acquire()
            assert session is not None
            client.release()
            assert (authority / 'resource-fences.sqlite3').stat().st_uid == 65534
            assert (root / 'keys/authority.pem').read_bytes() == original_key
            assert (root / 'keys/authority.pem').stat().st_uid == 0
        finally:
            process.terminate()
            process.wait(timeout=10)
