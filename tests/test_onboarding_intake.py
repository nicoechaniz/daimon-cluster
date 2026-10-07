"""Prepared intake progresses through exact owner consent without manual grants."""
import os
from dataclasses import replace

from clusterctl import being_seed, onboarding_consent, onboarding_intake, onboarding_release
from clusterctl.onboarding_host import HostBackend
from clusterctl.onboarding_progress import Progress
from tests import test_onboarding_guest as guest_fixtures
from tests import test_onboarding_host as host_fixtures

packet = guest_fixtures.packet
staging_volume = guest_fixtures.staging_volume


def configured(tmp_path, packet):
    source, _ = guest_fixtures.prepared(tmp_path, packet)
    source.parents[2].chmod(0o700)
    config, _, _, _ = host_fixtures.configured(tmp_path)
    inputs, progress = tmp_path / 'inputs', tmp_path / 'progress'
    inputs.mkdir(mode=0o700)
    progress.mkdir(mode=0o750)
    code = tmp_path / 'code'
    fingerprint = guest_fixtures.artifact(code)
    selection = dict(owner='ani', account_profile='shared', browser=False)
    path = tmp_path / 'policy.json'
    being_seed._write(path, dict(schema=onboarding_intake.POLICY, release_digest=fingerprint,
                               beings=dict(fixture=selection), revoked=False))
    return replace(config, inputs=inputs, code=code, release_digest=fingerprint,
                   progress=progress, consent_state=source.parents[2], consent_uid=os.geteuid(), intake_policy=path)


def test_worker_discovers_prepared_seed_and_resumes_same_plan_after_portal_consent(tmp_path, packet):
    config = configured(tmp_path, packet)
    assert config.approved_plans() == []
    reviews = onboarding_consent.Reviews(config.progress, worker_uid=os.geteuid())
    proposal = reviews.read('fixture', owner='ani')
    assert Progress(config.progress, worker_uid=os.geteuid()).read('fixture', owner='ani')['active'] is False
    original = (config.inputs / 'fixture/received/context/SOUL.md').read_bytes()
    onboarding_consent.submit(config.consent_state, 'fixture', dict(review_digest=proposal['review_digest'],
        inheritance_approved=True, matrix_identity_mode='first'), owner='ani', reviews=reviews)
    plans = config.approved_plans()
    assert plans == [proposal['plan']]
    assert HostBackend(config).authorize(plans[0], onboarding_intake.digest(plans[0]))
    assert config.approved_plans() == plans
    assert (config.inputs / 'fixture/received/context/SOUL.md').read_bytes() == original
    # No custody or body creation follows from an intake/consent publication.
    assert config.custody is None and config.custody_grants is None
    assert not any(path.name.startswith('dm-') for path in tmp_path.iterdir())


def test_wrong_owner_and_policy_revocation_cannot_issue_or_reuse_resource_grant(tmp_path, packet):
    config = configured(tmp_path, packet)
    value = being_seed._read(config.intake_policy)
    wrong = {**value, 'beings': {'fixture': {**value['beings']['fixture'], 'owner': 'sai'}}}
    being_seed._write(config.intake_policy, wrong)
    assert config.approved_plans() == []
    assert not (config.grants / 'fixture.json').exists()
    being_seed._write(config.intake_policy, value)
    config.approved_plans()
    reviews = onboarding_consent.Reviews(config.progress, worker_uid=os.geteuid())
    proposal = reviews.read('fixture', owner='ani')
    onboarding_consent.submit(config.consent_state, 'fixture', dict(review_digest=proposal['review_digest'],
        inheritance_approved=True, matrix_identity_mode='existing'), owner='ani', reviews=reviews)
    assert config.approved_plans() == [proposal['plan']]
    being_seed._write(config.intake_policy, {**value, 'revoked': True})
    assert config.approved_plans() == []
    assert not HostBackend(config).authorize(proposal['plan'], onboarding_intake.digest(proposal['plan']))
    onboarding_release.verify(config.code, config.release_digest, uid=os.geteuid())


def test_bad_intake_does_not_block_another_prepared_pair(tmp_path, packet):
    config = configured(tmp_path, packet)
    value = being_seed._read(config.intake_policy)
    selection = value['beings']['fixture']
    being_seed._write(config.intake_policy, {**value, 'beings': {'broken': selection, **value['beings']}})
    directory = config.consent_state / 'being-seeds/broken'
    directory.mkdir(mode=0o700)
    being_seed._write(directory / 'record.json', dict(schema=being_seed.SCHEMA, name='broken',
                                                    created_by='wrong-owner', phase='prepared'))
    assert config.approved_plans() == []
    assert onboarding_consent.Reviews(config.progress, worker_uid=os.geteuid()).read('fixture', owner='ani')
    assert not (config.inputs / 'broken').exists()


def test_same_worker_enqueues_only_after_owner_decision_and_without_a_codex_turn(tmp_path, packet):
    from clusterctl.onboarding import JobStore
    from clusterctl.onboarding_worker import Worker
    from tests.test_onboarding import FixtureBackend
    config = configured(tmp_path, packet)
    backend = FixtureBackend()
    store = JobStore(config.jobs)
    worker = Worker(store, lambda: backend, plans=config.approved_plans)
    assert worker.once() == []
    reviews = onboarding_consent.Reviews(config.progress, worker_uid=os.geteuid())
    proposal = reviews.read('fixture', owner='ani')
    onboarding_consent.submit(config.consent_state, 'fixture', dict(review_digest=proposal['review_digest'],
        inheritance_approved=True, matrix_identity_mode='first'), owner='ani', reviews=reviews)
    assert worker.once()[0]['completed_steps'] == ['environment']
    assert worker.once()[0]['completed_steps'] == ['environment', 'context']
    assert store.status('fixture', owner='ani')['active'] is False
