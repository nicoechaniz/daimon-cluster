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


@pytest.mark.skipif(os.geteuid() != 0, reason='root-created execution input requires actual UID separation')
def test_root_worker_passes_sealed_execution_input_without_host_journal_access(tmp_path, monkeypatch):
    import fcntl
    from clusterctl import onboarding_group_recovery as recovery
    from tests.test_onboarding_group_recovery import remaining_fixture
    journal, parent, request, clock = remaining_fixture(tmp_path, monkeypatch)
    selected = recovery.remaining_reference(recovery.remaining_plan(journal, request, audit_identity={}))
    recovery.remaining_attach(journal, parent['operation_id'], selected)
    parent = journal.get(parent['operation_id'])
    command = parent['runtime_observation']['group_publication']['requests']['entrant']['application']['command']
    bindings = dict(effect='publication', owner_name='entrant', command=command,
        expected_context_sha256='a'*64, helper_code_digest='e'*64, helper_code_uid=0, now_ms=clock[0])
    program = '''import fcntl,json,os,sys
from clusterctl.onboarding_group_recovery import read_remaining_projection_fd
from clusterctl.onboarding import OnboardingError
fd,unsealed=int(sys.argv[1]),int(sys.argv[2])
bindings=json.loads(sys.argv[3])
assert os.geteuid()==1000
assert not os.access(sys.argv[4],os.R_OK)
value=read_remaining_projection_fd(fd,**bindings)
try:os.write(fd,b'changed')
except PermissionError:pass
else:raise AssertionError('owner changed root-sealed public input')
forged=os.memfd_create('owner-forged',os.MFD_ALLOW_SEALING)
os.write(forged,json.dumps(value).encode())
os.fchmod(forged,0o400)
fcntl.fcntl(forged,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
for bad in (forged,unsealed):
 try:read_remaining_projection_fd(bad,**bindings)
 except OnboardingError:pass
 else:raise AssertionError('untrusted mutable or owner-forged input accepted')
os.close(forged)
print(json.dumps(value))
'''
    unsealed = os.memfd_create('unsealed-root-context', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with recovery.remaining_reader(journal, parent, 'publication', owner_name='entrant', command=command,
                expected_context_sha256='a'*64) as reader, recovery.sealed_remaining_input(reader) as (descriptor, pin):
            bindings['expected_sha256'] = pin
            os.write(unsealed, json.dumps(reader()).encode())
            os.fchmod(unsealed, 0o400)
            result = subprocess.run([sys.executable, '-B', '-c', program, str(descriptor), str(unsealed),
                json.dumps(bindings), str(journal.path)], pass_fds=(descriptor,unsealed),
                user=1000, group=1000, extra_groups=(), cwd=ROOT, capture_output=True, text=True,
                env={'PATH':os.defpath,'LANG':'C.UTF-8'}, timeout=15)
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout) == reader()
            assert fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE
    finally:
        os.close(unsealed)


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
    root.chmod(0o755)
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
