"""Delegated approval preserves the actual author and the exact reviewed terms."""
import dataclasses
import os
from types import SimpleNamespace

import pytest

from clusterctl import being_seed, onboarding_consent
from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_approvals import Approvals, SCHEMA, Status, decision
from tests.test_onboarding import plan
from tests.test_being_seed import KEY, http_server
from tests import test_onboarding_guest as guest_fixtures

packet = guest_fixtures.packet
staging_volume = guest_fixtures.staging_volume


def setup(tmp_path):
    root = tmp_path / 'private'
    root.mkdir(mode=0o700)
    state = root / 'intake'
    being_seed.create(state, dict(name='eko', label='Eko', mode='import'), owner='sai', key=KEY)
    state.chmod(0o700)
    progress = root / 'progress'
    progress.mkdir(mode=0o750)
    grants = root / 'grants'
    grants.mkdir(mode=0o700)
    proposal = onboarding_consent.review(plan(), 'Approved Source context.\n',
        custody=dict(policy_digest='a' * 64, notice=onboarding_consent.CUSTODY_NOTICE))
    onboarding_consent.Reviews(progress, worker_uid=os.geteuid()).publish(proposal)
    value = dict(schema=SCHEMA, source_digest=proposal['source_digest'],
        custody_policy_digest='a' * 64, human_instruction_digest='b' * 64,
        recorded_by='nicolas', pairs=dict(eko=dict(owner='sai', matrix_identity_mode='first')),
        revoked=False)
    path = root / 'approvals.json'
    being_seed._write(path, value)
    config = SimpleNamespace(consent_state=state, consent_uid=os.geteuid(),
        owner_approval_policy=path, grants=grants, progress=progress)
    return config, proposal, value


def test_delegated_decision_is_durable_without_forging_participant_intake(tmp_path):
    config, proposal, value = setup(tmp_path)
    approved = decision(config, proposal)
    assert approved['matrix_identity_mode'] == 'first'
    assert approved == decision(config, proposal)
    assert not list(config.consent_state.rglob('consent-*.json'))
    records = list((config.grants / 'delegated-owner-approvals').glob('*.json'))
    assert len(records) == 1
    record = being_seed._read(records[0])
    assert record['recorded_by'] == 'nicolas'
    assert record['human_instruction_digest'] == value['human_instruction_digest']
    assert record['decision'] == approved
    projected = Status(config.progress, worker_uid=os.geteuid()).read('eko', owner='sai')
    assert projected['recorded'] and projected['recorded_by'] == 'nicolas'
    with pytest.raises(OnboardingError, match='onboarding_job_not_found'):
        Status(config.progress, worker_uid=os.geteuid()).read('eko', owner='ani')


@pytest.mark.parametrize('change', ['source', 'custody', 'owner', 'being', 'revoked'])
def test_approval_does_not_follow_changed_terms_or_another_pair(tmp_path, change):
    config, proposal, value = setup(tmp_path)
    if change == 'source':
        proposal = onboarding_consent.review(plan(), 'Changed Source text.', custody=proposal['matrix_custody'])
    elif change == 'custody':
        proposal = onboarding_consent.review(plan(), proposal['source_text'],
            custody={**proposal['matrix_custody'], 'policy_digest': 'c' * 64})
    elif change in {'owner', 'being'}:
        changed = {**proposal['plan'], ('owner' if change == 'owner' else 'name'): 'ani'}
        proposal = onboarding_consent.review(changed, proposal['source_text'], custody=proposal['matrix_custody'])
    else:
        being_seed._write(config.owner_approval_policy, {**value, 'revoked': True})
    assert Approvals(config.owner_approval_policy).decision(proposal, config.grants) is None
    assert not list(config.grants.rglob('*.json'))


def test_participant_choice_precedes_delegation_and_remains_exact(tmp_path):
    config, proposal, _ = setup(tmp_path)
    reviews = onboarding_consent.Reviews(config.progress, worker_uid=os.geteuid())
    onboarding_consent.submit(config.consent_state, 'eko', dict(review_digest=proposal['review_digest'],
        inheritance_approved=True, matrix_identity_mode='existing'), owner='sai', reviews=reviews)
    assert decision(config, proposal)['matrix_identity_mode'] == 'existing'
    assert Status(config.progress, worker_uid=os.geteuid()).read('eko', owner='sai')['recorded_by'] == 'sai'
    assert not list(config.grants.rglob('*.json'))


def test_reconciling_another_existing_identity_preserves_original_pair_approval(tmp_path):
    config, proposal, value = setup(tmp_path)
    approved = decision(config, proposal)
    record = next((config.grants / 'delegated-owner-approvals').glob('*.json'))
    original = record.read_bytes()
    successor = {**value, 'pairs': {**value['pairs'],
        'oliva': dict(owner='ani', matrix_identity_mode='existing')}}
    being_seed._write(config.owner_approval_policy, successor)
    assert decision(config, proposal) == approved
    assert record.read_bytes() == original
    other = onboarding_consent.review(plan(name='oliva', owner='ani'), proposal['source_text'],
                                      custody=proposal['matrix_custody'])
    assert Approvals(config.owner_approval_policy).decision(other, config.grants)['matrix_identity_mode'] == 'existing'
    changed = {**successor, 'pairs': {**successor['pairs'],
        'eko': dict(owner='sai', matrix_identity_mode='existing')}}
    being_seed._write(config.owner_approval_policy, changed)
    with pytest.raises(OnboardingError, match='existing_onboarding_approval_preserved'):
        decision(config, proposal)
    assert record.read_bytes() == original


def test_http_reports_delegated_approval_only_for_current_review_and_owner(tmp_path):
    config, proposal, _ = setup(tmp_path)
    decision(config, proposal)
    with http_server(config.consent_state) as (server, request):
        server.deps = dataclasses.replace(server.deps, seed_only=True,
            onboarding_progress=str(config.progress), onboarding_worker_uid=os.geteuid())
        endpoint = '/v1/seeds/eko/onboarding/review'
        assert request(endpoint, owner='ani')[0] == 404
        status, _, response = request(endpoint, owner='sai')
        assert status == 200 and response['recorded'] is True
        assert response['recorded_by'] == 'nicolas'
        assert response['matrix_identity_mode'] == 'first'
        onboarding_consent.Reviews(config.progress, worker_uid=os.geteuid()).publish(
            onboarding_consent.review(plan(), 'Unapproved successor.', custody=proposal['matrix_custody']))
        assert request(endpoint, owner='sai')[2]['recorded'] is False


def test_operator_configuration_resumes_same_prepared_job_and_issues_separate_custody_grant(tmp_path, packet):
    from clusterctl.onboarding_approvals import configure
    from clusterctl.onboarding_custody import POLICY_SCHEMA, ROLES
    from clusterctl.onboarding_host import HostBackend
    from tests.test_onboarding_intake import configured
    config = configured(tmp_path, packet)
    paths = {}
    for name in ['custody', 'custody-grants']:
        paths[name] = tmp_path / name
        paths[name].mkdir(mode=0o700)
    custody_policy = tmp_path / 'custody-policy.json'
    being_seed._write(custody_policy, dict(schema=POLICY_SCHEMA, execution_uid=os.geteuid(),
        source_binding_digest='a' * 64, operator_instruction_digest='b' * 64, roles=ROLES, revoked=False))
    config = dataclasses.replace(config, custody=paths['custody'], custody_grants=paths['custody-grants'],
        custody_policy=custody_policy)
    before = config.approved_plans()
    assert HostBackend(config)._decision(before[0]) is None
    instruction = tmp_path / 'human-instruction'
    instruction.write_text('The local human confirms complete pair approval for this receiving procedure.')
    instruction.chmod(0o600)
    path = tmp_path / 'owner-approvals.json'
    pairs = {'fixture': dict(owner='ani', matrix_identity_mode='first')}
    assert configure(config, path, pairs, instruction=instruction, instruction_uid=os.geteuid(),
        recorded_by='nicolas')['configured'] is True
    config = dataclasses.replace(config, owner_approval_policy=path)
    assert config.approved_plans() == before
    assert HostBackend(config)._decision(before[0])['matrix_identity_mode'] == 'first'
    assert being_seed._read(config.custody_grants / 'fixture.json')['roles'] == ROLES
    assert not list(config.custody.rglob('*'))
    assert not list(config.consent_state.rglob('consent-*.json'))
