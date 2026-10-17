"""Linked approval preserves original operations and never replaces native effects."""
import copy
import os
import time
import uuid
from types import SimpleNamespace

import pytest

from clusterctl import onboarding_group_recovery as recovery
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_code_successor import plan_update
from clusterctl.operation_journal import JournalConflict, OperationJournal


def fixture(tmp_path, monkeypatch):
    from daimon_matrix.canonical import b64url
    from daimon_matrix.relationships import INVITATION_SCHEMA, invitation_id, tribe_ref
    now = time.time_ns()//1_000_000
    monkeypatch.setattr(recovery, 'time', SimpleNamespace(time_ns=lambda: now*1_000_000,monotonic_ns=time.monotonic_ns))
    founder, entrant = ['dm:being:v1:'+b64url(bytes([index])*32) for index in (1, 2)]
    tribe = tribe_ref(dict(created_at_ms=now-100_000, founder_principal_id=founder,
        nonce=b64url(b'0'*32), policy_ref='dm:tribe-policy:v1:continuation-test'))
    def invite(issued, expires, nonce):
        return dict(schema=INVITATION_SCHEMA, tribe_ref=tribe, founder_epoch=0,
            founder_being_ref=founder, invitee_being_ref=entrant, nonce=nonce,
            invitation_id=invitation_id(tribe=tribe, founder_epoch=0, invitee_being_ref=entrant, nonce=nonce),
            issued_at_ms=issued, expires_at_ms=expires)
    old = invite(now-90_000, now-1000, b64url(b'1'*32))
    social = dict(operation_id=str(uuid.uuid4()), founder_owner='founder', entrant_owner='entrant', invitation=old)
    admission = dict(tribe_ref=tribe, activation={'expires_at_ms': now-1000}, receivers={
        name: {'being_ref': ref, 'candidate': {'code_uid': os.geteuid()}}
        for name, ref in (('founder', founder), ('entrant', entrant))}, entrant={'being_ref': entrant})
    journal = OperationJournal(tmp_path/'journal')
    row = plan_update(journal, manifest_digest='a'*64, target='receiving:'+tribe,
        expected_precondition=dict(senders=[{'name': 'founder', 'being_ref': founder}]),
        intended_transition=dict(cohort_admission=admission, portal_admission=dict(
            schema='cluster-portal-group-admission/v2', social=social), admission_preparations={'founder': {}},
            admission_publications={'owners': {name: {'steps': {'application': 'application'}}
                for name in ('founder', 'entrant')}}),
        audit_identity={'actor': 'synthetic-test'})
    command = dict(operation_id=social['operation_id'], step='membership-invite', method='tribe.invite', params={'payload': old})
    observations = dict(portal_admission={'execution_intent': {}, 'preserved-founder': {'result_sha256': 'b'*64}},
        admission_lifecycles={'founder': {'lifecycle_operation_id': 'operation:'+str(uuid.uuid4()), 'link_sha256': 'c'*64}},
        sender_revocations={'founder': {'gate': {'phase': 'revoke', 'readers': []}}},
        membership_admission=dict(recipe_sha256=digest(social), requests={'founder': {
            'membership-invite': dict(command=command, result=None)}}))
    row = journal.advance(row['operation_id'], 'runtime-dispatching', runtime_observation=observations)
    inspection = dict(schema='cluster-group-invitation-inspection/v1', operation_id=social['operation_id'],
        command_sha256=digest(command), ledger_sha256='d'*64, request_retained=False, rpc_state='not-dispatched',
        request_sha256=None, response_sha256=None, invitations=[], acceptances=[],
        membership=dict(tribe_state='active', active_members=[founder], entrant_state=None),
        observed_at_ms=now, requests_dispatched=0, receiving_readiness='unobserved')
    request = dict(schema=recovery.REQUEST_SCHEMA, authorization_id=str(uuid.uuid4()),
        parent_operation_id=row['operation_id'], parent_intent_sha256=row['intent_hash'],
        frontier_sha256=digest(observations), expires_at_ms=now+3_600_000,
        invitation=invite(now, now+3_600_000, b64url(b'2'*32)), inspection=inspection,
        maintenance={name:dict(code='/qualified/helper', code_digest='e'*64, code_uid=os.geteuid())
            for name in ('founder', 'entrant')})
    return journal, row, request, now


def test_linked_grant_cas_preserves_original_vectors_and_survives_exact_retry(tmp_path, monkeypatch):
    journal, parent, request, now = fixture(tmp_path, monkeypatch)
    original = copy.deepcopy(parent)
    approved = recovery.plan(journal, request, audit_identity={'actor': 'synthetic-test'})
    assert journal.get(parent['operation_id']) == original
    assert approved['operation'] == 'admission-continuation' and approved['target'] != parent['target']
    assert journal.open_for_target(parent['target'])['operation_id'] == parent['operation_id']
    selected = recovery.reference(approved)
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.require_effect(journal, parent, selected, 'membership', now_ms=now)
    grant = recovery.attach(journal, parent['operation_id'], selected)
    current = journal.get(parent['operation_id'])
    assert recovery.attached(journal,current)==grant
    assert recovery.bounds(journal,current)=={**original['intended_transition']['cohort_admission']['activation'],
        'expires_at_ms':grant['expires_at_ms']}
    deadline=time.monotonic_ns()+1_000_000_000
    assert recovery.effect_deadline(journal,current,'membership',deadline)==deadline
    for field in ('intent', 'intent_hash', 'expected_precondition', 'intended_transition'):
        assert current[field] == original[field]
    assert current['runtime_observation']['membership_admission'] == original['runtime_observation']['membership_admission']
    assert recovery.require_effect(journal, current, selected, 'membership', now_ms=now) == grant
    changed = copy.deepcopy(current['runtime_observation'])
    changed['new_actual_progress'] = {'retained': True}
    journal.advance(parent['operation_id'], parent['state'], runtime_observation=changed,
        expected_runtime_observation=current['runtime_observation'])
    assert recovery.attach(journal, parent['operation_id'], selected) == grant
    monkeypatch.setattr(recovery, 'time', SimpleNamespace(time_ns=lambda: (grant['expires_at_ms']+1)*1_000_000))
    assert recovery.plan(journal, request, audit_identity={'actor': 'retry'})['operation_id'] == approved['operation_id']
    assert recovery.resolve(journal, journal.get(parent['operation_id']), selected) == grant
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.require_effect(journal, journal.get(parent['operation_id']), selected,
            'membership', now_ms=grant['expires_at_ms'])
    with pytest.raises(JournalConflict, match='exact request'):
        recovery.plan(journal, {**request, 'expires_at_ms': request['expires_at_ms']+1}, audit_identity={})


def test_protected_coordinator_selection_reads_same_grant_and_cannot_drop_attachment(tmp_path,monkeypatch):
    from clusterctl.onboarding_group_coordinator import GroupCoordinator
    journal,parent,request,_=fixture(tmp_path,monkeypatch)
    approved=recovery.plan(journal,request,audit_identity={})
    coordinator=object.__new__(GroupCoordinator)
    coordinator.settings={'continuations':{parent['operation_id']:recovery.reference(approved)}}
    grant=coordinator._continuation(journal,parent)
    assert grant==approved['intended_transition'] and recovery.attached(journal,parent) is None
    recovery.attach(journal,parent['operation_id'],recovery.reference(approved))
    current=journal.get(parent['operation_id'])
    assert coordinator._continuation(journal,current)==grant
    coordinator.settings={}
    with pytest.raises(OnboardingError,match='reference_required'):
        coordinator._continuation(journal,current)


@pytest.mark.parametrize('fault', ['pending', 'completed', 'events', 'wrong-request', 'old-invitation',
    'active-entrant', 'foreign-helper', 'publication', 'initial', 'activation', 'different-frontier'])
def test_narrow_recovery_refuses_uncertainty_foreign_binding_or_later_effect(tmp_path, monkeypatch, fault):
    journal, parent, request, now = fixture(tmp_path, monkeypatch)
    if fault in {'pending', 'completed'}:
        request['inspection']['rpc_state'] = fault
    elif fault == 'events':
        request['inspection']['invitations'] = [{'event_id': 'existing'}]
    elif fault == 'wrong-request':
        request['inspection']['command_sha256'] = 'f'*64
    elif fault == 'old-invitation':
        request['invitation'] = parent['intended_transition']['portal_admission']['social']['invitation']
    elif fault == 'active-entrant':
        request['inspection']['membership']['entrant_state'] = 'active'
    elif fault == 'foreign-helper':
        request['maintenance']['other'] = request['maintenance']['founder']
    elif fault == 'different-frontier':
        request['frontier_sha256'] = 'f'*64
    else:
        key = {'publication': 'group_publication', 'initial': 'initial_managed', 'activation': 'admission_activation_plan'}[fault]
        observations = {**parent['runtime_observation'], key: {}}
        parent = journal.advance(parent['operation_id'], parent['state'], runtime_observation=observations,
            expected_runtime_observation=parent['runtime_observation'])
        request['frontier_sha256'] = digest(observations)
    with pytest.raises(OnboardingError):
        recovery.plan(journal, request, audit_identity={})
    assert len(journal.list_all()) == 1


def test_attachment_refuses_changed_frontier_without_overwriting_or_compensating(tmp_path, monkeypatch):
    journal, parent, request, now = fixture(tmp_path, monkeypatch)
    approved = recovery.plan(journal, request, audit_identity={})
    observations = {**parent['runtime_observation'], 'concurrent_progress': True}
    journal.advance(parent['operation_id'], parent['state'], runtime_observation=observations,
        expected_runtime_observation=parent['runtime_observation'])
    with pytest.raises(OnboardingError, match='frontier_changed'):
        recovery.attach(journal, parent['operation_id'], recovery.reference(approved))
    assert journal.get(parent['operation_id'])['runtime_observation'] == observations
    assert journal.get(parent['operation_id'])['state'] == 'runtime-dispatching'
    assert journal.get(approved['operation_id'])['state'] == 'planned'


def test_lost_attachment_reply_recovers_same_grant_without_fresh_expired_permission(tmp_path, monkeypatch):
    journal, parent, request, now = fixture(tmp_path, monkeypatch)
    approved = recovery.plan(journal, request, audit_identity={})
    selected = recovery.reference(approved)
    advance = journal.advance
    def fail_authorization_ack(operation, *args, **options):
        if operation == approved['operation_id']:
            raise OSError('synthetic attachment reply lost')
        return advance(operation, *args, **options)
    monkeypatch.setattr(journal, 'advance', fail_authorization_ack)
    with pytest.raises(OSError, match='reply lost'):
        recovery.attach(journal, parent['operation_id'], selected)
    attached = journal.get(parent['operation_id'])['runtime_observation']['admission_continuation']
    assert attached['reference'] == selected
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.require_effect(journal, journal.get(parent['operation_id']), selected, 'membership', now_ms=now)
    monkeypatch.setattr(journal, 'advance', advance)
    monkeypatch.setattr(recovery, 'time', SimpleNamespace(time_ns=lambda: (request['expires_at_ms']+1)*1_000_000))
    recovery.attach(journal, parent['operation_id'], selected)
    assert journal.get(parent['operation_id'])['runtime_observation']['admission_continuation'] == attached
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.require_effect(journal, journal.get(parent['operation_id']), selected, 'membership',
            now_ms=request['expires_at_ms']+1)


@pytest.mark.parametrize('terminal', ['degraded', 'compensated'])
def test_stale_parent_cannot_authorize_after_current_parent_stops(tmp_path, monkeypatch, terminal):
    journal, parent, request, now = fixture(tmp_path, monkeypatch)
    selected = recovery.reference(recovery.plan(journal, request, audit_identity={}))
    recovery.attach(journal, parent['operation_id'], selected)
    stale = journal.get(parent['operation_id'])
    journal.advance(parent['operation_id'], terminal)
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.require_effect(journal, stale, selected, 'membership', now_ms=now)


def test_virtual_attachment_and_changed_intent_are_never_effect_authority(tmp_path, monkeypatch):
    journal, parent, request, now = fixture(tmp_path, monkeypatch)
    selected = recovery.reference(recovery.plan(journal, request, audit_identity={}))
    recovery.attach(journal, parent['operation_id'], selected)
    stale = journal.get(parent['operation_id'])
    journal.advance(parent['operation_id'], parent['state'], runtime_observation=parent['runtime_observation'],
        expected_runtime_observation=stale['runtime_observation'])
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.require_effect(journal, stale, selected, 'membership', now_ms=now)
    recovery.attach(journal, parent['operation_id'], selected)
    virtual = journal.get(parent['operation_id'])
    virtual['intended_transition']['cohort_admission']['receivers']['entrant']['candidate']['code_uid'] += 1
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.require_effect(journal, virtual, selected, 'membership', now_ms=now)


def test_inactive_grant_cannot_execute_even_before_its_horizon(tmp_path, monkeypatch):
    journal, parent, request, now = fixture(tmp_path, monkeypatch)
    selected = recovery.reference(recovery.plan(journal, request, audit_identity={}))
    grant = recovery.attach(journal, parent['operation_id'], selected)
    current = journal.get(parent['operation_id'])
    assert recovery.require_execution(journal, current, selected, 'old-selection-start') == grant
    journal.advance(selected['operation_id'], 'completed')
    # History remains readable; execution must not turn it into fresh permission.
    assert recovery.attached(journal, current) == grant
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.require_execution(journal, current, selected, 'old-selection-start')
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.require_effect(journal, current, selected, 'old-selection-start', now_ms=now)


def remaining_fixture(tmp_path, monkeypatch):
    """Isolate protected journal semantics; native signed reducers are tested separately."""
    from clusterctl import onboarding_group_admission
    from daimon_matrix.messaging_config import APPLICATION_SCHEMA_V3
    journal, parent, request, now = fixture(tmp_path, monkeypatch)
    selected = recovery.reference(recovery.plan(journal, request, audit_identity={}))
    social_grant = recovery.attach(journal, parent['operation_id'], selected)
    # Only the signature-bearing recipe validator is a seam here. Keep the
    # actual social resolver/attachment and original intent digests in use.
    monkeypatch.setattr(onboarding_group_admission, 'membership_recipe',
        lambda value, *_args, **_kwargs: copy.deepcopy(value))
    current = journal.get(parent['operation_id'])
    admission = current['intended_transition']['cohort_admission']
    social, key, _prefix, provenance = recovery.membership(journal, current, admission)
    acceptance = {'event_id': str(uuid.uuid4())}
    members = [dict(principal_id=row['being_ref'], state='active',
        membership_ref=acceptance['event_id']) for row in admission['receivers'].values()]
    result = dict(schema='cluster-native-membership-admission/v1', operation_id=social['operation_id'],
        invitation={}, acceptance=acceptance, receiving_readiness='unobserved',
        snapshots={name:dict(tribe_ref=admission['tribe_ref'], members=members)
            for name in admission['receivers']})
    observed = copy.deepcopy(current['runtime_observation'])
    observed[key] = dict(recipe_sha256=digest(social), result=result, result_sha256=digest(result),
        requests={}, **provenance)
    publication = dict(operation_id=social['operation_id'], step='application', action='application',
        params=dict(expected_application_sha256=None, specification={'schema': APPLICATION_SCHEMA_V3},
            additions=None, admitted_being_refs=[], secret_sources={}))
    observed['group_publication'] = dict(membership_sha256=digest(result),
        recipe_sha256=digest(current['intended_transition']['admission_publications']),
        requests={'entrant': {'application': dict(command=publication, result=None)}}, **provenance)
    current = journal.advance(parent['operation_id'], parent['state'], runtime_observation=observed,
        expected_runtime_observation=current['runtime_observation'])
    now = social_grant['expires_at_ms']+1
    clock = [now]
    monkeypatch.setattr(recovery, 'time', SimpleNamespace(time_ns=lambda: clock[0]*1_000_000))
    supplemental = dict(schema=recovery.REMAINING_REQUEST_SCHEMA, authorization_id=str(uuid.uuid4()),
        parent_operation_id=parent['operation_id'], parent_intent_sha256=parent['intent_hash'],
        frontier_sha256=digest(observed), expires_at_ms=now+60_000, maintenance=request['maintenance'])
    return journal, current, supplemental, clock


def test_remaining_approval_preserves_social_history_and_original_pending_request(tmp_path, monkeypatch):
    journal, parent, request, clock = remaining_fixture(tmp_path, monkeypatch)
    original = copy.deepcopy(parent)
    approved = recovery.remaining_plan(journal, request, audit_identity={})
    selected = recovery.remaining_reference(approved)
    assert journal.get(parent['operation_id']) == original
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.remaining_require_effect(journal, parent, selected, 'publication', now_ms=clock[0])
    grant = recovery.remaining_attach(journal, parent['operation_id'], selected)
    current = journal.get(parent['operation_id'])
    for field in ('intent', 'intent_hash', 'expected_precondition', 'intended_transition'):
        assert current[field] == original[field]
    for field in original['runtime_observation']:
        assert current['runtime_observation'][field] == original['runtime_observation'][field]
    assert grant['social_grant_sha256'] == digest(recovery.attached(journal, current))
    assert recovery.remaining_require_effect(journal, current, selected, 'publication', now_ms=clock[0]) == grant
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.remaining_require_effect(journal, current, selected, 'membership', now_ms=clock[0])
    clock[0] = grant['expires_at_ms']
    assert recovery.remaining_plan(journal, request, audit_identity={}) == journal.get(approved['operation_id'])
    assert recovery.remaining_attach(journal, parent['operation_id'], selected) == grant
    assert recovery.remaining_resolve(journal, current, selected) == grant
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.remaining_require_effect(journal, current, selected, 'publication', now_ms=clock[0])
    with pytest.raises(JournalConflict, match='exact request'):
        recovery.remaining_plan(journal, {**request, 'expires_at_ms': clock[0]+1}, audit_identity={})


@pytest.mark.parametrize('fault', ['initial', 'loaded', 'activation', 'communication', 'membership', 'completed-publication'])
def test_remaining_planner_refuses_later_or_incomplete_frontiers(tmp_path, monkeypatch, fault):
    journal, parent, request, _clock = remaining_fixture(tmp_path, monkeypatch)
    observed = copy.deepcopy(parent['runtime_observation'])
    if fault in {'loaded', 'communication'}:
        observed['portal_admission'][{'loaded': 'loaded-entrant', 'communication': 'communication-intent-send'}[fault]] = {}
    elif fault in {'initial', 'activation'}:
        observed[{'initial': 'initial_managed', 'activation': 'admission_activation_plan'}[fault]] = {}
    elif fault == 'membership':
        observed['membership_continuation']['result'] = None
    else:
        observed['group_publication']['result'] = {}
    parent = journal.advance(parent['operation_id'], parent['state'], runtime_observation=observed,
        expected_runtime_observation=parent['runtime_observation'])
    request['frontier_sha256'] = digest(observed)
    with pytest.raises(OnboardingError):
        recovery.remaining_plan(journal, request, audit_identity={})
    assert len(journal.list_all()) == 2


def test_remaining_retry_accepts_results_but_never_changed_original_commands(tmp_path, monkeypatch):
    journal, parent, request, clock = remaining_fixture(tmp_path, monkeypatch)
    selected = recovery.remaining_reference(recovery.remaining_plan(journal, request, audit_identity={}))
    grant = recovery.remaining_attach(journal, parent['operation_id'], selected)
    current = journal.get(parent['operation_id'])
    observed = copy.deepcopy(current['runtime_observation'])
    observed['group_publication']['requests']['entrant']['application']['result'] = {'retained': 'result'}
    current = journal.advance(parent['operation_id'], parent['state'], runtime_observation=observed,
        expected_runtime_observation=current['runtime_observation'])
    assert recovery.remaining_require_effect(journal, current, selected, 'tooling', now_ms=clock[0]) == grant
    observed = copy.deepcopy(current['runtime_observation'])
    observed['group_publication']['requests']['entrant']['application']['command']['step'] = 'replacement'
    current = journal.advance(parent['operation_id'], parent['state'], runtime_observation=observed,
        expected_runtime_observation=current['runtime_observation'])
    with pytest.raises(OnboardingError, match='reference_required'):
        recovery.remaining_resolve(journal, current, selected)


@pytest.mark.parametrize('target', ['parent', 'approval'])
def test_remaining_stale_snapshot_cannot_execute_after_live_journal_terminal_state(tmp_path, monkeypatch, target):
    journal, parent, request, clock = remaining_fixture(tmp_path, monkeypatch)
    selected = recovery.remaining_reference(recovery.remaining_plan(journal, request, audit_identity={}))
    recovery.remaining_attach(journal, parent['operation_id'], selected)
    stale = journal.get(parent['operation_id'])
    journal.advance(parent['operation_id'] if target == 'parent' else selected['operation_id'], 'completed')
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.remaining_require_effect(journal, stale, selected, 'publication', now_ms=clock[0])


def test_remaining_lost_attachment_ack_recovers_without_renewing_its_expired_bound(tmp_path, monkeypatch):
    journal, parent, request, clock = remaining_fixture(tmp_path, monkeypatch)
    approved = recovery.remaining_plan(journal, request, audit_identity={})
    selected = recovery.remaining_reference(approved)
    advance = journal.advance
    def lost(operation_id, *args, **kwargs):
        if operation_id == approved['operation_id']:
            raise OSError('lost remaining attachment acknowledgment')
        return advance(operation_id, *args, **kwargs)
    monkeypatch.setattr(journal, 'advance', lost)
    with pytest.raises(OSError, match='lost remaining'):
        recovery.remaining_attach(journal, parent['operation_id'], selected)
    current = journal.get(parent['operation_id'])
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.remaining_require_effect(journal, current, selected, 'publication', now_ms=clock[0])
    clock[0] = request['expires_at_ms']+1
    monkeypatch.setattr(journal, 'advance', advance)
    grant = recovery.remaining_attach(journal, parent['operation_id'], selected)
    assert grant['expires_at_ms'] == request['expires_at_ms']
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.remaining_require_effect(journal, current, selected, 'publication', now_ms=clock[0])


def test_remaining_inactive_approval_cannot_attach_to_unchanged_parent(tmp_path, monkeypatch):
    journal, parent, request, _clock = remaining_fixture(tmp_path, monkeypatch)
    selected = recovery.remaining_reference(recovery.remaining_plan(journal, request, audit_identity={}))
    journal.advance(selected['operation_id'], 'completed')
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.remaining_attach(journal, parent['operation_id'], selected)
    assert journal.get(parent['operation_id']) == parent


def test_remaining_attachment_cas_refuses_intervening_publication_progress(tmp_path, monkeypatch):
    journal, parent, request, _clock = remaining_fixture(tmp_path, monkeypatch)
    selected = recovery.remaining_reference(recovery.remaining_plan(journal, request, audit_identity={}))
    observed = copy.deepcopy(parent['runtime_observation'])
    observed['group_publication']['requests']['entrant']['application']['result'] = {'retained': 'result'}
    parent = journal.advance(parent['operation_id'], parent['state'], runtime_observation=observed,
        expected_runtime_observation=parent['runtime_observation'])
    with pytest.raises(OnboardingError, match='frontier_changed'):
        recovery.remaining_attach(journal, parent['operation_id'], selected)
    assert journal.get(parent['operation_id']) == parent
