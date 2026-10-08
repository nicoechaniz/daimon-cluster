"""Disposable new-seed journey; external substrate/identity effects are fixtures.

The actual exporter, receiver, frozen input, native context, SQLite memory,
intake, consent and durable worker run here. This is no live enrollment or
provider/Telegram acceptance claim.
"""
import json
import os
import sqlite3
from contextlib import closing
from dataclasses import replace

import pytest

from clusterctl import being_seed, onboarding_consent, onboarding_input, onboarding_intake, onboarding_release
from clusterctl.onboarding import JobStore, OnboardingError, digest
from clusterctl.onboarding_guest import Receiver, mkdir_chain
from clusterctl.onboarding_host import HostBackend
from clusterctl.onboarding_worker import Worker
from tests.test_being_seed import KEY
from tests.test_onboarding import FixtureBackend
from tests.test_onboarding_guest import NATIVE, artifact
from tests.test_onboarding_host import configured

EMPTY_NATIVE = NATIVE.replace("if sys.argv[1] == 'stats':", """if sys.argv[1] == 'init':
    db.execute('CREATE TABLE IF NOT EXISTS chapters(id INTEGER PRIMARY KEY,title TEXT,raw TEXT,access_count INTEGER DEFAULT 0)')
    db.commit()
    value = {'ok': True, 'db_path': path}
elif sys.argv[1] == 'stats':""")


def new_seed(tmp_path, primary='store-001'):
    state = tmp_path / 'intake'
    state.mkdir(mode=0o700)
    name = 'qualify-new-being'
    spec = dict(name=name, label='Disposable New Being', mode='new', soul='Own new identity; no previous memories.')
    being_seed.create(state, spec, owner='family', key=KEY)
    being_seed.queue_prepare(state, name, None, owner='family')
    config, _, _, _ = configured(tmp_path)
    inputs, progress, code = tmp_path / 'inputs', tmp_path / 'progress', tmp_path / 'code'
    inputs.mkdir(mode=0o700)
    progress.mkdir(mode=0o750)
    release = artifact(code, script=EMPTY_NATIVE)
    if primary is None:
        profile = onboarding_release.verify(code, release, uid=os.geteuid())['profile']
        (code / 'release.json').unlink()
        release = onboarding_release.seal(code, {**profile, 'primary_store': None})
    policy = tmp_path / 'intake-policy.json'
    being_seed._write(policy, dict(schema=onboarding_intake.POLICY, release_digest=release,
        beings={name:dict(owner='family', account_profile='shared', browser=False)}, revoked=False))
    config = replace(config, inputs=inputs, code=code, release_digest=release, progress=progress,
        consent_state=state, consent_uid=os.geteuid(), intake_policy=policy)
    plan, = config.approved_plans()
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    incoming = home / 'incoming'
    captured = onboarding_input.capture(state / 'being-seeds' / name / 'received', incoming,
        source_uid=os.geteuid(), seed_mode='new')
    assert captured['seed_digest'] == plan['seed_digest']
    return config, plan, Receiver(home, incoming, code, plan, code_uid=os.geteuid())


@pytest.mark.parametrize('primary', ['store-001', None])
def test_new_seed_creates_own_native_pool_and_preserves_frozen_empty_history_on_retry(tmp_path, monkeypatch, primary):
    config, plan, receiver = new_seed(tmp_path, primary)
    before = onboarding_input.inventory(receiver.incoming / 'received', uid=os.geteuid())
    assert receiver.preparation['selection']['memory'] == []
    assert receiver.primary == 'store-001'
    native = receiver._native
    failed = False
    def lose_ack(store, args):
        nonlocal failed
        result = native(store, args)
        if args == ['init'] and not failed:
            failed = True
            raise OSError('lost completed native initialization acknowledgement')
        return result
    monkeypatch.setattr(receiver, '_native', lose_ack)
    with pytest.raises(OSError, match='lost completed native'):
        receiver.install_context()
    pool = receiver.received / 'memory/store-001/library.db'
    assert pool.stat().st_mode & 0o077 == 0
    with closing(sqlite3.connect(pool)) as database:
        assert database.execute('SELECT COUNT(*) FROM chapters').fetchone()[0] == 0
        database.execute("INSERT INTO chapters VALUES(1,'Own receiving memory','Created after initial empty pool',0)")
        database.commit()
    resumed = Receiver(receiver.home, receiver.incoming, receiver.code, plan, code_uid=os.geteuid())
    resumed.install_context()
    resumed.verify_memory()
    assert resumed.observe_memory().facts['memory_chapters'] == 1
    assert (resumed.home / '.local/bin/hmk').exists()
    assert before == onboarding_input.inventory(receiver.incoming / 'received', uid=os.geteuid())
    assert config.approved_plans() == [plan]
    assert being_seed.status(config.consent_state, plan['name'], owner='family')['memory_coverage'] == 'empty-new'
    assert resumed.preparation['selection']['memory'] == []


def test_unbound_database_is_preserved_and_new_mode_cannot_relabel_imported_history(tmp_path):
    _, plan, receiver = new_seed(tmp_path)
    pool = receiver.received / 'memory/store-001'
    mkdir_chain(receiver.home, pool)
    database = pool / 'library.db'
    database.write_bytes(b'unrelated existing bytes')
    database.chmod(0o600)
    with pytest.raises(OnboardingError, match='existing_receiving_file_preserved'):
        receiver.install_context()
    assert database.read_bytes() == b'unrelated existing bytes'
    assert receiver._marker('new-memory') is None
    with pytest.raises(OnboardingError, match='new_seed_must_have_empty_history'):
        onboarding_input.new_memory_store({'seed_mode':'new'}, ['existing-store'], 'store-001')
    assert onboarding_input.new_memory_store({}, [], 'store-001') is None


def test_disposable_new_seed_restarts_same_worker_and_completes_all_engine_stages(tmp_path):
    config, plan, receiver = new_seed(tmp_path)
    host, effects = HostBackend(config), FixtureBackend()
    original_observe, original_execute = effects.observe, effects.execute
    def observe(value, stage, operation):
        assert host.authorize(value, digest(value))
        if stage == 'context' and host._decision(value) is None:
            from clusterctl.onboarding import Observation
            return Observation('waiting', reason='identity_authorization_required')
        if stage == 'context':
            return receiver.observe_context()
        if stage == 'memory':
            return receiver.observe_memory()
        return original_observe(value, stage, operation)
    def execute(value, stage, operation):
        if stage == 'context':
            receiver.install_context()
        elif stage == 'memory':
            receiver.verify_memory()
        else:
            original_execute(value, stage, operation)
    effects.authorize = host.authorize
    effects.observe, effects.execute = observe, execute
    store = JobStore(config.jobs)
    worker = Worker(store, lambda:effects, plans=config.approved_plans)
    assert worker.once()[0]['completed_steps'] == ['environment']
    assert worker.once()[0]['reason'] == 'identity_authorization_required'
    review = onboarding_consent.Reviews(config.progress, worker_uid=os.geteuid()).read(plan['name'],owner='family')
    onboarding_consent.submit(config.consent_state, plan['name'], dict(review_digest=review['review_digest'],
        inheritance_approved=True,matrix_identity_mode='first'), owner='family',
        reviews=onboarding_consent.Reviews(config.progress,worker_uid=os.geteuid()))
    worker = Worker(JobStore(config.jobs), lambda:effects, plans=config.approved_plans)
    for _ in range(7):
        result, = worker.once()
    assert result['active'] is True
    assert store._load(plan['name'])['steps']['memory']['facts']['memory_chapters'] == 0
    assert store._load(plan['name'])['steps']['memory']['facts']['memory_stores'] == 1
    calls = list(effects.calls)
    assert worker.once()[0]['active'] is True and effects.calls == calls
    with pytest.raises(OnboardingError, match='onboarding_job_not_found'):
        store.status(plan['name'], owner='another-family')
    assert not (receiver.home / '.codex/auth.json').exists()
    assert (receiver.received / 'context/SOUL.md').read_text() == 'Own new identity; no previous memories.'
    assert json.loads((config.inputs / plan['name'] / 'manifest.json').read_text())['seed_mode'] == 'new'
