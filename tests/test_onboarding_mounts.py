"""Host view isolation and typed guest-stage integration through the same engine."""
import copy
import json
import os
from dataclasses import replace

import pytest

from clusterctl import being_seed, onboarding_consent, onboarding_input, onboarding_mounts
from clusterctl.onboarding import JobStore, OnboardingError, digest
from clusterctl.onboarding_host import HostBackend
from tests import test_onboarding_guest as guest_fixtures
from tests import test_onboarding_host as host_fixtures

packet = guest_fixtures.packet
staging_volume = guest_fixtures.staging_volume


@pytest.fixture(autouse=True)
def fixture_guest_ids(monkeypatch):
    # Synthetic host fixtures need no privilege or a particular CI runner UID.
    monkeypatch.setattr(onboarding_mounts, 'GUEST_UID', os.geteuid())
    monkeypatch.setattr(onboarding_mounts, 'GUEST_GID', os.getegid())


def test_view_retry_preserves_all_input_and_refuses_changed_existing_bytes(tmp_path, packet):
    receiver = guest_fixtures.receiving(tmp_path, packet)
    views = tmp_path / 'views'
    views.mkdir(mode=0o700)
    view = onboarding_mounts.prepare_view(receiver.incoming, views, receiver.plan)
    assert onboarding_input.verify(view, receiver.plan['seed_digest'], uid=onboarding_mounts.GUEST_UID)['files'] == receiver.manifest['files']
    assert json.loads((view / 'plan.json').read_bytes()) == receiver.plan
    assert view.parent.stat().st_uid == os.geteuid() and view.parent.stat().st_mode & 0o077 == 0
    assert onboarding_mounts.prepare_view(receiver.incoming, views, receiver.plan) == view
    original = (receiver.incoming / 'received/context/SOUL.md').read_bytes()
    (view / 'received/context/SOUL.md').write_bytes(b'Changed existing view')
    with pytest.raises(OnboardingError, match='existing_onboarding_view_preserved'):
        onboarding_mounts.prepare_view(receiver.incoming, views, receiver.plan)
    assert (receiver.incoming / 'received/context/SOUL.md').read_bytes() == original
    assert (view / 'received/context/SOUL.md').read_bytes() == b'Changed existing view'


class GuestIncus(host_fixtures.IncusFixture):
    def __init__(self):
        super().__init__()
        self.guest_effects = set()
        self.guest_calls = []

    def __call__(self, argv):
        if argv[:3] == ['config', 'device', 'add'] and argv[4] != 'home':
            self.calls.append(argv)
            row = next(row for row in self.instances if row['name'] == argv[3])
            row['expanded_devices'][argv[4]] = dict(type='disk', **dict(value.split('=', 1) for value in argv[6:]))
            return ''
        if argv[0] == 'exec':
            self.guest_calls.append(argv)
            if 'bootstrap_home' in ' '.join(argv):
                return ''
            stage = argv[argv.index('--home') - 1]
            action = argv[argv.index('--home') - 2]
            if action == 'execute':
                self.guest_effects.add(stage)
                return '{}'
            if stage in self.guest_effects:
                facts = {'verified': True, 'context_verified': True, 'skills': 1} if stage == 'context' else {
                    'verified': True, 'memory_stores': 1, 'memory_chapters': 2}
                return json.dumps(dict(state='complete', facts=facts, reason=None, safe_to_execute=False))
            return json.dumps(dict(state='absent', facts={}, reason=None, safe_to_execute=True))
        return super().__call__(argv)


def test_engine_installs_guest_context_and_memory_through_read_only_devices(tmp_path, packet):
    receiver = guest_fixtures.receiving(tmp_path, packet)
    config, _, _, _ = host_fixtures.configured(tmp_path)
    inputs, views = tmp_path / 'inputs', tmp_path / 'views'
    inputs.mkdir(mode=0o700)
    views.mkdir(mode=0o700)
    # Fixture input has exactly the same owner/name/digest selected in its plan.
    receiver.incoming.rename(inputs / 'fixture')
    config = replace(config, inputs=inputs, views=views, code=receiver.code, release_digest=receiver.plan['release_digest'])
    state, progress = tmp_path / 'intake', tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    state.chmod(0o700)
    reviews = onboarding_consent.Reviews(progress, worker_uid=os.geteuid())
    proposal = onboarding_consent.review(receiver.plan, (receiver.code / 'inheritance.md').read_text())
    reviews.publish(proposal)
    onboarding_consent.submit(state, 'fixture', dict(review_digest=proposal['review_digest'],
        inheritance_approved=True, matrix_identity_mode='first'), owner=receiver.plan['owner'], reviews=reviews)
    config = replace(config, progress=progress, consent_state=state, consent_uid=os.geteuid())
    being_seed._write(config.grants / 'fixture.json', dict(schema='cluster-onboarding-host-grant/v1', plan=receiver.plan, revoked=False))
    incus = GuestIncus()
    backend = HostBackend(config, run=incus)
    store = JobStore(config.jobs)
    store.submit(receiver.plan, backend)
    for _ in range(4):
        result = store.tick('fixture', backend)
    assert result['completed_steps'] == ['environment', 'context', 'memory']
    assert result['stage'] == 'matrix' and result['active'] is False
    devices = incus.instances[0]['expanded_devices']
    assert devices['onboarding-input']['readonly'] == devices['onboarding-code']['readonly'] == 'true'
    assert devices['onboarding-input']['shift'] == devices['onboarding-code']['shift'] == 'true'
    assert devices['onboarding-input']['source'].endswith(digest(receiver.plan) + '/input')
    assert sum('execute' in call for call in incus.guest_calls) == 2
    before = copy.deepcopy(incus.calls)
    store.tick('fixture', backend)
    assert incus.calls == before
    assert not any('sh' in call or 'bash' in call for call in incus.guest_calls)
    devices['onboarding-code']['source'] = '/unselected-code'
    with pytest.raises(OnboardingError, match='foreign_receiving_mount_preserved'):
        backend.observe(receiver.plan, 'context', 'unused')
    assert incus.calls == before


def test_bootstrap_creates_only_the_dedicated_guest_account_and_empty_home(tmp_path, monkeypatch):
    import grp
    import pwd
    import subprocess
    from pathlib import Path
    from types import SimpleNamespace
    home = tmp_path / 'empty-home'
    home.mkdir(mode=0o700)
    account = SimpleNamespace(pw_uid=onboarding_mounts.GUEST_UID, pw_gid=onboarding_mounts.GUEST_GID, pw_dir=str(home))
    created, calls = [], []
    def lookup(name):
        assert name == 'agent'
        if not created:
            raise KeyError(name)
        return account
    def missing(identifier):
        raise KeyError(identifier)
    def create(argv, **kwargs):
        calls.append(argv)
        created.append(True)
        return SimpleNamespace(returncode=0)
    original_stat = Path.stat
    assigned = []
    def stat(path, **kwargs):
        value = original_stat(path, **kwargs)
        if path == home:
            fields = list(value)
            fields[4] = onboarding_mounts.GUEST_UID if assigned else 0
            return os.stat_result(fields)
        return value
    monkeypatch.setattr(pwd, 'getpwnam', lookup)
    monkeypatch.setattr(pwd, 'getpwuid', missing)
    monkeypatch.setattr(grp, 'getgrgid', missing)
    monkeypatch.setattr(subprocess, 'run', create)
    monkeypatch.setattr(Path, 'stat', stat)
    monkeypatch.setattr(onboarding_mounts.os, 'chown', lambda *args, **kwargs: assigned.append(args))
    onboarding_mounts.bootstrap_home(home)
    onboarding_mounts.bootstrap_home(home)
    assert len(calls) == len(assigned) == 1
    assert calls[0][0] == 'useradd' and calls[0][-1] == 'agent'
    assert '--no-create-home' in calls[0] and '--user-group' in calls[0]
    assert home.stat().st_mode & 0o077 == 0
    # Existing populated homes cannot authorize a missing-user creation.
    created.clear()
    assigned.clear()
    (home / 'old-file').write_text('preserved')
    with pytest.raises(OnboardingError, match='existing_guest_home_preserved'):
        onboarding_mounts.bootstrap_home(home)
    assert len(calls) == 1 and (home / 'old-file').read_text() == 'preserved'


def test_public_matrix_publisher_adds_authorization_without_replacing_genesis(tmp_path):
    from tests.test_onboarding import plan
    views = tmp_path / 'views'
    views.mkdir(mode=0o700)
    value = plan()
    target = onboarding_mounts.prepare_matrix_public(views, value, {'genesis.json': {'public': 'genesis'}})
    before = (target / 'genesis.json').read_bytes()
    assert target.stat().st_mode & 0o077 == 0o055
    assert onboarding_mounts.prepare_matrix_public(views, value, {'activation.json': {'public': 'activation'}}) == target
    assert (target / 'genesis.json').read_bytes() == before
    with pytest.raises(OnboardingError, match='existing_onboarding_public_matrix_preserved'):
        onboarding_mounts.prepare_matrix_public(views, value, {'genesis.json': {'public': 'replacement'}})
    assert (target / 'genesis.json').read_bytes() == before


@pytest.mark.skipif(os.geteuid() != 0, reason='actual publisher/consumer UID separation requires root')
def test_root_publisher_does_not_use_consumer_owned_private_staging(tmp_path, monkeypatch):
    monkeypatch.setattr(onboarding_mounts, 'GUEST_UID', 1000)
    monkeypatch.setattr(onboarding_mounts, 'GUEST_GID', 1000)
    test_public_matrix_publisher_adds_authorization_without_replacing_genesis(tmp_path)
    target = next((tmp_path/'views').glob('*/matrix-public'))
    assert target.stat().st_uid == 0
    assert {path.stat().st_uid for path in target.iterdir()} == {1000}


def test_private_connections_retry_preserves_original_and_refuses_changed_bot(tmp_path):
    from tests.test_onboarding import plan
    views = tmp_path / 'views'
    views.mkdir(mode=0o700)
    value = plan()
    (views / digest(value)).mkdir(mode=0o700)
    supplied = dict(telegram_bot_token='123456789:' + 'x' * 40, telegram_chat_id=1234)
    target = onboarding_mounts.prepare_connections(views, value, supplied)
    before = (target / 'connections.json').read_bytes()
    assert onboarding_mounts.prepare_connections(views, value, supplied) == target
    with pytest.raises(OnboardingError, match='existing_onboarding_connections_preserved'):
        onboarding_mounts.prepare_connections(views, value, {**supplied, 'telegram_chat_id': 5678})
    assert (target / 'connections.json').read_bytes() == before
    assert (target / 'connections.json').stat().st_mode & 0o077 == 0
    assert target.stat().st_mode & 0o077 == 0
    with pytest.raises(OnboardingError, match='connection_data_required'):
        onboarding_mounts.prepare_connections(views, value, {**supplied, 'ssh_public_key': 'excluded'})
