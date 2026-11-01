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
    social = dict(operation_id=str(uuid.uuid4()), founder_owner='founder', entrant_owner='entrant', invitation=old,
        owner_contexts={name:'a'*64 for name in ('founder', 'entrant')})
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


def remaining_fixture(tmp_path, monkeypatch, *, preparation=False):
    """Isolate protected journal semantics; native signed reducers are tested separately."""
    from clusterctl import onboarding_group_admission
    from daimon_matrix.messaging_config import APPLICATION_SCHEMA_V3
    factory = preparation_fixture if preparation else fixture
    journal, parent, request, now = factory(tmp_path, monkeypatch)
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
    if preparation:
        observed['admission_lifecycles'] = {'founder': dict(
            lifecycle_operation_id='operation:'+str(uuid.uuid4()), link_sha256='c'*64)}
        observed['sender_revocations'] = {'founder': {'gate': {'phase': 'revoke', 'readers': []}}}
        observed['portal_admission']['preserved-founder'] = {'result_sha256': 'b'*64}
    observed[key] = dict(recipe_sha256=digest(social), result=result, result_sha256=digest(result),
        requests={}, **provenance)
    publication = dict(operation_id=social['operation_id'], step='application', action='application',
        params=dict(expected_application_sha256=None, specification={'schema': APPLICATION_SCHEMA_V3},
            additions=None, admitted_being_refs=[], secret_sources={}))
    observed['group_publication'] = dict(membership_sha256=digest(result),
        recipe_sha256=digest(current['intended_transition']['admission_publications']),
        requests={'entrant': {'application': dict(command=publication, result=None)}}, **provenance)
    current = journal.advance(parent['operation_id'], 'runtime-dispatching', runtime_observation=observed,
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


@pytest.mark.parametrize('fault', ['initial', 'replacement', 'loaded', 'activation', 'communication', 'membership', 'completed-publication'])
def test_remaining_planner_refuses_later_or_incomplete_frontiers(tmp_path, monkeypatch, fault):
    journal, parent, request, _clock = remaining_fixture(tmp_path, monkeypatch)
    observed = copy.deepcopy(parent['runtime_observation'])
    if fault in {'loaded', 'communication'}:
        observed['portal_admission'][{'loaded': 'loaded-entrant', 'communication': 'communication-intent-send'}[fault]] = {}
    elif fault in {'initial', 'replacement', 'activation'}:
        observed[{'initial': 'initial_managed', 'replacement': 'sender_replacements',
            'activation': 'admission_activation_plan'}[fault]] = {}
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


@pytest.mark.parametrize('key', ['membership_sha256', 'recipe_sha256', 'continuation_sha256', 'original_recipe_sha256'])
@pytest.mark.parametrize('remove', [False, True])
def test_remaining_execution_refuses_publication_identity_drift(tmp_path, monkeypatch, key, remove):
    journal, parent, request, clock = remaining_fixture(tmp_path, monkeypatch)
    selected = recovery.remaining_reference(recovery.remaining_plan(journal, request, audit_identity={}))
    recovery.remaining_attach(journal, parent['operation_id'], selected)
    current = journal.get(parent['operation_id'])
    observed = copy.deepcopy(current['runtime_observation'])
    publication = observed['group_publication']
    if remove:
        publication.pop(key)
    else:
        publication[key] = 'f'*64
    current = journal.advance(parent['operation_id'], parent['state'], runtime_observation=observed,
        expected_runtime_observation=current['runtime_observation'])
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.remaining_require_effect(journal, current, selected, 'tooling', now_ms=clock[0])


def test_execution_resolver_selects_remaining_bound_without_changing_social_history(tmp_path, monkeypatch):
    journal, parent, request, clock = remaining_fixture(tmp_path, monkeypatch)
    social = recovery.attached(journal, parent)
    approved = recovery.remaining_plan(journal, request, audit_identity={})
    grant = recovery.remaining_attach(journal, parent['operation_id'], recovery.remaining_reference(approved))
    current = journal.get(parent['operation_id'])
    assert recovery.attached(journal, current) == social
    assert recovery.execution(journal, current, effect='publication') == grant
    assert recovery.execution(journal, current, effect='steady-handoff') == grant
    assert recovery.bounds(journal, current)['expires_at_ms'] == request['expires_at_ms']
    assert recovery.membership(journal, current, current['intended_transition']['cohort_admission'])[1] == 'membership_continuation'
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.execution(journal, current, effect='membership')
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.execution(journal, current)
    clock[0] = request['expires_at_ms']
    assert recovery.execution(journal, current, historical=True) == grant
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.execution(journal, current, effect='publication')
    journal.advance(approved['operation_id'], 'completed')
    assert recovery.execution(journal, current, historical=True) == grant
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.execution(journal, current, effect='activation')


def test_initial_effect_scope_uses_real_remaining_approval_and_both_kernel_fences(tmp_path,monkeypatch):
    journal,parent,request,clock=remaining_fixture(tmp_path,monkeypatch)
    selected=recovery.remaining_reference(recovery.remaining_plan(journal,request,audit_identity={}))
    grant=recovery.remaining_attach(journal,parent['operation_id'],selected)
    current=journal.get(parent['operation_id'])
    competitor=OperationJournal.existing(journal.path.parent)
    with recovery.effect_scope(journal,current,'initial-start',
            deadline_ns=time.monotonic_ns()+1_000_000_000) as actual:
        assert actual==grant
        for key in (parent['operation_id'],selected['operation_id']):
            with pytest.raises(JournalConflict):
                with competitor.mutation_lock(key):
                    pass
    clock[0]=request['expires_at_ms']
    with pytest.raises(OnboardingError,match='effect_not_authorized'):
        with recovery.effect_scope(journal,current,'initial-start',
                deadline_ns=time.monotonic_ns()+1_000_000_000):
            pytest.fail('expired remaining approval dispatched a first start')
    for key in (parent['operation_id'],selected['operation_id']):
        with competitor.mutation_lock(key):
            pass


def test_remaining_projection_keeps_parent_and_approval_kernel_locks_through_dispatch(tmp_path, monkeypatch):
    import fcntl
    import hashlib
    journal, parent, request, clock = remaining_fixture(tmp_path, monkeypatch)
    selected = recovery.remaining_reference(recovery.remaining_plan(journal, request, audit_identity={}))
    grant = recovery.remaining_attach(journal, parent['operation_id'], selected)
    parent = journal.get(parent['operation_id'])
    command = parent['runtime_observation']['group_publication']['requests']['entrant']['application']['command']
    paths = [journal.path.parent/('.operation-'+hashlib.sha256(identifier.encode()).hexdigest()+'.lock')
        for identifier in (parent['operation_id'], selected['operation_id'])]
    with recovery.remaining_projection(journal, parent, 'publication', owner_name='entrant',
            command=command, expected_context_sha256='a'*64) as projection:
        assert projection['authorization_sha256'] == digest(grant)
        assert projection['command_sha256'] == digest(command)
        assert projection['not_after_ms'] == grant['expires_at_ms']
        assert 'active' not in projection and 'maintenance' not in projection
        for path in paths:
            with path.open('rb') as stream:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    for path in paths:
        with path.open('rb') as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    journal.advance(selected['operation_id'], 'completed')
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        with recovery.remaining_projection(journal, parent, 'publication', owner_name='entrant',
                command=command, expected_context_sha256='a'*64):
            pytest.fail('inactive approval yielded a fresh owner projection')


@pytest.mark.parametrize('owner,context', [('foreign','a'*64), ('entrant','f'*64)])
def test_remaining_projection_refuses_foreign_owner_or_context(tmp_path, monkeypatch, owner, context):
    journal, parent, request, _clock = remaining_fixture(tmp_path, monkeypatch)
    selected = recovery.remaining_reference(recovery.remaining_plan(journal, request, audit_identity={}))
    recovery.remaining_attach(journal, parent['operation_id'], selected)
    parent = journal.get(parent['operation_id'])
    with pytest.raises(OnboardingError, match='owner_context_required'):
        with recovery.remaining_projection(journal, parent, 'publication', owner_name=owner,
                command={}, expected_context_sha256=context):
            pytest.fail('foreign owner/context yielded a projection')


@pytest.mark.parametrize('fault', [None, 'writable-input', 'changed-body', 'foreign-owner',
    'foreign-command', 'expired', 'membership'])
def test_owner_projection_requires_exact_readonly_input_and_native_binding(tmp_path, monkeypatch, fault):
    from clusterctl import being_seed, onboarding_mounts
    journal, parent, request, clock = remaining_fixture(tmp_path, monkeypatch)
    selected = recovery.remaining_reference(recovery.remaining_plan(journal, request, audit_identity={}))
    recovery.remaining_attach(journal, parent['operation_id'], selected)
    parent = journal.get(parent['operation_id'])
    command = parent['runtime_observation']['group_publication']['requests']['entrant']['application']['command']
    views = tmp_path/'views'
    views.mkdir(mode=0o700)
    # This test qualifies file/binding semantics only, not a real Incus mount.
    monkeypatch.setattr(onboarding_mounts, 'GUEST_UID', os.geteuid())
    monkeypatch.setattr(onboarding_mounts, 'GUEST_GID', os.getegid())
    with recovery.remaining_projection(journal, parent, 'publication', owner_name='entrant',
            command=command, expected_context_sha256='a'*64) as context:
        pin = digest(context)
        name = 'execution-'+pin+'.json'
        root = onboarding_mounts.prepare_matrix_public(views, {'one': 'receiver'}, {name: context})
        arguments = dict(input_root=root, expected_sha256=pin, effect='publication', owner_name='entrant',
            command=command, expected_context_sha256='a'*64, helper_code_digest='e'*64,
            helper_code_uid=os.geteuid(), now_ms=clock[0])
        monkeypatch.setattr(os, 'statvfs', lambda _path: SimpleNamespace(
            f_flag=0 if fault == 'writable-input' else os.ST_RDONLY))
        if fault == 'changed-body':
            being_seed._write(root/name, {**context, 'owner_name': 'foreign'})
        if fault == 'foreign-owner':
            arguments['owner_name'] = 'foreign'
        if fault == 'foreign-command':
            arguments['command'] = {**command, 'step': 'different'}
        if fault == 'expired':
            arguments['now_ms'] = context['not_after_ms']
        if fault == 'membership':
            arguments['effect'] = 'membership'
        if fault is None:
            assert recovery.read_remaining_projection(root/name, **arguments) == context
        else:
            with pytest.raises(OnboardingError, match='owner_input_required'):
                recovery.read_remaining_projection(root/name, **arguments)


def test_remaining_host_reader_does_not_let_a_cached_result_outlive_execution_scope(tmp_path, monkeypatch):
    journal, parent, request, clock = remaining_fixture(tmp_path, monkeypatch)
    selected = recovery.remaining_reference(recovery.remaining_plan(journal, request, audit_identity={}))
    recovery.remaining_attach(journal, parent['operation_id'], selected)
    parent = journal.get(parent['operation_id'])
    command = parent['runtime_observation']['group_publication']['requests']['entrant']['application']['command']
    with recovery.remaining_reader(journal, parent, 'publication', owner_name='entrant',
            command=command, expected_context_sha256='a'*64) as reader:
        first = reader()
        first['owner_name'] = 'changed-copy'
        assert reader()['owner_name'] == 'entrant'
        clock[0] = request['expires_at_ms']
        with pytest.raises(OnboardingError, match='effect_not_authorized'):
            reader()
    clock[0] -= 1
    with pytest.raises(OnboardingError, match='execution_scope_required'):
        reader()


@pytest.mark.parametrize('owner_name', ['founder', 'entrant'])
def test_publication_dispatch_carries_remaining_scope_without_rewriting_original(tmp_path, monkeypatch, owner_name):
    """Real protected journal/locks; owner transport and signed reducer are seams."""
    from clusterctl.onboarding_group_admission import _dispatch_publication
    journal, parent, request, clock = remaining_fixture(tmp_path, monkeypatch)
    approved = recovery.remaining_plan(journal, request, audit_identity={})
    recovery.remaining_attach(journal, parent['operation_id'], recovery.remaining_reference(approved))
    current = journal.get(parent['operation_id'])
    original = copy.deepcopy(current['runtime_observation']['group_publication'])
    social, _key, _prefix, provenance = recovery.membership(journal, current,
        current['intended_transition']['cohort_admission'])
    assert clock[0] > social['acceptance_not_after_ms']
    command = original['requests']['entrant']['application']['command']
    captured = {}
    def publication(value, **options):
        assert value == command
        assert options['effect_not_after_ms'] == social['acceptance_not_after_ms']
        reader = options['remaining_execution']
        context = reader()
        assert context['owner_name'] == owner_name
        assert context['not_after_ms'] == request['expires_at_ms']
        assert context['command_sha256'] == digest(command)
        captured['reader'] = reader
        return {'status': 'recorded'}
    cohort = SimpleNamespace(journal=journal,
        owners={owner_name: SimpleNamespace(group_publication=publication,
            deadline_ns=time.monotonic_ns()+500_000_000)})
    assert _dispatch_publication(cohort, current, owner_name, command,
        context_sha256='a'*64, authorities={}, social=social,
        provenance=provenance) == {'status': 'recorded'}
    assert journal.get(parent['operation_id'])['runtime_observation']['group_publication'] == original
    with pytest.raises(OnboardingError, match='execution_scope_required'):
        captured['reader']()
    clock[0] = request['expires_at_ms']
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        _dispatch_publication(cohort, current, owner_name, command,
            context_sha256='a'*64, authorities={}, social=social, provenance=provenance)


def test_publication_dispatch_does_not_accept_result_after_remaining_expiry(tmp_path, monkeypatch):
    from clusterctl.onboarding_group_admission import _dispatch_publication
    journal, parent, request, clock = remaining_fixture(tmp_path, monkeypatch)
    approved = recovery.remaining_plan(journal, request, audit_identity={})
    recovery.remaining_attach(journal, parent['operation_id'], recovery.remaining_reference(approved))
    current = journal.get(parent['operation_id'])
    social, _key, _prefix, provenance = recovery.membership(journal, current,
        current['intended_transition']['cohort_admission'])
    command = current['runtime_observation']['group_publication']['requests']['entrant']['application']['command']
    def publication(value, **options):
        options['remaining_execution']()
        clock[0] = request['expires_at_ms']
        return {'status': 'recorded'}
    cohort = SimpleNamespace(journal=journal,
        owners={'entrant': SimpleNamespace(group_publication=publication,
            deadline_ns=time.monotonic_ns()+500_000_000)})
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        _dispatch_publication(cohort, current, 'entrant', command,
            context_sha256='a'*64, authorities={}, social=social, provenance=provenance)
    assert journal.get(parent['operation_id'])['runtime_observation']['group_publication']['requests']['entrant']['application']['result'] is None


def preparation_fixture(tmp_path, monkeypatch):
    _journal, original, request, now = fixture(tmp_path, monkeypatch)
    after = copy.deepcopy(original['intended_transition'])
    after['portal_admission'].update(plan_digest='1'*64, owners_sha256='2'*64)
    journal = OperationJournal(tmp_path/'preparation-journal')
    parent = plan_update(journal, manifest_digest='a'*64, target=original['target'],
        expected_precondition=original['expected_precondition'], intended_transition=after,
        audit_identity={'actor':'synthetic-test'})
    phases = dict(native_intent=dict(plan_digest='1'*64, cohort_intent_sha256=parent['intent_hash'],
        owners_sha256='2'*64), native_dispatch={'plan_digest':'1'*64}, target_ready={})
    parent = journal.advance(parent['operation_id'], 'planned', runtime_observation={'portal_admission':phases})
    request.update(schema=recovery.PREPARATION_REQUEST_SCHEMA, parent_operation_id=parent['operation_id'],
        parent_intent_sha256=parent['intent_hash'], frontier_sha256=digest(parent['runtime_observation']),
        native_readiness={name:dict(schema='cluster-native-endpoint-readiness/v1', native_process={'pid':123},
            endpoint_sha256='3'*64, acceptance='native-endpoint-only', model_turns_started=0, messages_sent=0)
            for name in after['cohort_admission']['receivers']})
    return journal, parent, request, now


def test_pre_native_grant_keeps_original_parent_and_first_preparation_bound(tmp_path, monkeypatch):
    journal, parent, request, now = preparation_fixture(tmp_path, monkeypatch)
    original = copy.deepcopy(parent)
    approved = recovery.plan(journal, request, audit_identity={'actor':'synthetic-test'})
    assert journal.get(parent['operation_id']) == original
    reference = recovery.reference(approved)
    grant = recovery.attach(journal, parent['operation_id'], reference)
    assert grant['schema'] == recovery.PREPARATION_SCHEMA and grant['children'] == {}
    assert grant['preparations_sha256'] == digest(parent['intended_transition']['admission_preparations'])
    assert recovery.attach(journal, parent['operation_id'], reference) == grant
    current = journal.get(parent['operation_id'])
    assert recovery.require_effect(journal, current, reference, 'preparation', now_ms=now) == grant
    # Exercise the real keeper with both actual journal locks held.
    with recovery.execution_scope(journal, current, 'preparation'):
        with recovery.retain_execution_locks(journal, current, deadline_ns=time.monotonic_ns()+1_000_000_000):
            assert recovery.execution(journal, current, effect='preparation') == grant
    assert recovery.bounds(journal, current)['expires_at_ms'] == request['expires_at_ms']
    # No pre-existing child is falsely presented as preserved or renewed.
    assert recovery.lifecycle(journal, current, 'founder', fresh=False) is None
    with pytest.raises(OnboardingError, match='effect_not_authorized'):
        recovery.require_effect(journal, current, reference, 'preparation', now_ms=request['expires_at_ms'])
    assert journal.get(parent['operation_id'])['intended_transition'] == original['intended_transition']


@pytest.mark.parametrize('key', ['execution_intent','physical_intent','controller_intent','communication_intent',
    'lifecycle_intent-founder','preserved-founder','loaded-founder'])
def test_pre_native_approval_refuses_later_or_uncertain_preparation(tmp_path, monkeypatch, key):
    journal, parent, request, now = preparation_fixture(tmp_path, monkeypatch)
    observed = copy.deepcopy(parent['runtime_observation'])
    observed['portal_admission'][key] = {}
    parent = journal.advance(parent['operation_id'], 'planned', runtime_observation=observed)
    request['frontier_sha256'] = digest(observed)
    with pytest.raises(OnboardingError, match='frontier_required'):
        recovery.authorization(parent, request, now_ms=now)


@pytest.mark.parametrize('change', ['membership','children','unresolved_native','missing_native','changed_plan','dispatched_social'])
def test_pre_native_approval_requires_reconciled_original_frontier(tmp_path, monkeypatch, change):
    journal, parent, request, now = preparation_fixture(tmp_path, monkeypatch)
    if change == 'membership':
        parent['runtime_observation']['membership_admission'] = {}
    elif change == 'children':
        parent['runtime_observation']['admission_lifecycles'] = {}
    elif change == 'unresolved_native':
        request['native_readiness']['entrant']['model_turns_started'] = 1
    elif change == 'missing_native':
        del request['native_readiness']['entrant']
    elif change == 'changed_plan':
        parent['runtime_observation']['portal_admission']['native_dispatch']['plan_digest'] = '4'*64
    else:
        request['inspection'].update(rpc_state='pending',requests_dispatched=1)
    request['frontier_sha256'] = digest(parent['runtime_observation'])
    with pytest.raises(OnboardingError):
        recovery.authorization(parent, request, now_ms=now)


def process_rebind_fixture(tmp_path, monkeypatch):
    _journal, parent, request, now = preparation_fixture(tmp_path, monkeypatch)
    before = copy.deepcopy(parent['expected_precondition'])
    original = before['senders'][0]
    process = dict(uid=os.geteuid(), pid=100, start_ticks=3, boot_id=str(uuid.uuid4()))
    instance = str(uuid.uuid4())
    gate = dict(schema='dm.receiving.reader-selection/v2',channel_id='tribe',context_sha256='a'*64,
        controlled=True,phase='unselected',readers=[],operation_id=None,release_digest=None,request_sha256=None,
        process_id=100,process_instance_id=instance,head=digest([instance,'tribe','a'*64,True]))
    original.update(process=process,gate=gate,root='/owner/root',socket='/owner/root/tribe.sock',
        server={'embodiment_id':'embodiment:original'})
    before['receiver_selections'] = {'founder':{'receiving_code':'a'*64},'entrant':None}
    journal = OperationJournal(tmp_path/'rebind-journal')
    row = plan_update(journal,manifest_digest='a'*64,target=parent['target'],expected_precondition=before,
        intended_transition=parent['intended_transition'],audit_identity={'actor':'synthetic-host'})
    observed = copy.deepcopy(parent['runtime_observation'])
    observed['portal_admission']['native_intent']['cohort_intent_sha256'] = row['intent_hash']
    row = journal.advance(row['operation_id'],'planned',runtime_observation=observed)
    current = copy.deepcopy(original)
    current['process'].update(pid=101,start_ticks=4)
    current['gate'].update(process_id=101,process_instance_id=str(uuid.uuid4()))
    g = current['gate']
    g['head'] = digest([g['process_instance_id'],g['channel_id'],g['context_sha256'],g['controlled']])
    request.update(parent_operation_id=row['operation_id'],parent_intent_sha256=row['intent_hash'],
        frontier_sha256=digest(observed),sender_rebind=dict(senders=[current],
            receiver_selections={'founder':copy.deepcopy(before['receiver_selections']['founder'])}))
    return journal, row, request, now


def test_explicit_preparation_process_rebind_preserves_original_identity_and_vectors(tmp_path, monkeypatch):
    journal, parent, request, now = process_rebind_fixture(tmp_path, monkeypatch)
    original = copy.deepcopy(parent)
    assert recovery.senders(journal,parent) == parent['expected_precondition']['senders']
    approved = recovery.plan(journal,request,audit_identity={'actor':'synthetic-host'})
    recovery.attach(journal,parent['operation_id'],recovery.reference(approved))
    current = journal.get(parent['operation_id'])
    assert recovery.senders(journal,current) == request['sender_rebind']['senders']
    assert current['expected_precondition'] == original['expected_precondition']
    assert current['intent'] == original['intent']
    assert recovery.plan(journal,request,audit_identity={'actor':'synthetic-host'}) == journal.get(approved['operation_id'])


@pytest.mark.parametrize('field',['identity','server','root','socket','code','context','selected','head','pid','uid'])
def test_process_rebind_refuses_identity_software_gate_or_process_substitution(tmp_path, monkeypatch, field):
    journal, parent, request, now = process_rebind_fixture(tmp_path, monkeypatch)
    row = request['sender_rebind']['senders'][0]
    if field == 'identity':
        row['being_ref'] = 'other'
    elif field == 'server':
        row['server']['embodiment_id'] = 'other'
    elif field in {'root','socket'}:
        row[field] = '/other'
    elif field == 'code':
        request['sender_rebind']['receiver_selections']['founder']['receiving_code'] = 'b'*64
    elif field == 'context':
        row['gate']['context_sha256'] = 'b'*64
    elif field == 'selected':
        row['gate']['phase'] = 'select'
    elif field == 'head':
        row['gate']['head'] = 'b'*64
    elif field == 'uid':
        row['process']['uid'] += 1
    else:
        row['gate']['process_id'] = 999
    with pytest.raises(OnboardingError,match='preparation_predecessor_required'):
        recovery.authorization(parent,request,now_ms=now)


@pytest.mark.parametrize('original_child', [False, True])
def test_lifecycle_association_uses_explicit_rebind_without_changing_parent(tmp_path, monkeypatch, original_child):
    from clusterctl.onboarding_receiving_update import CohortController
    journal, parent, request, now = process_rebind_fixture(tmp_path, monkeypatch)
    approved = recovery.plan(journal,request,audit_identity={'actor':'synthetic-host'})
    recovery.attach(journal,parent['operation_id'],recovery.reference(approved))
    current = journal.get(parent['operation_id'])
    selected = (parent['expected_precondition']['senders'][0] if original_child
        else request['sender_rebind']['senders'][0])
    admission = copy.deepcopy(parent['intended_transition']['cohort_admission'])
    receiver = admission['receivers']['founder']
    receiver.update(embodiment_id='embodiment:original',recipe={'profile':'guest'})
    recipe = {'profile':'guest'}
    lifecycle = {'expected_precondition':{'guest_bootstraps':{'founder':{'owner':{
        'predecessor':{'process':selected['process']},'origin':selected['server']}}}}}
    proof = dict(schema='cluster-admission-lifecycle-projection/v1',cohort_operation_id=parent['operation_id'],
        cohort_intent_sha256=digest(parent['intent']),tribe_ref=admission['tribe_ref'],
        owner={'being_ref':receiver['being_ref'],'embodiment_id':receiver['embodiment_id']},
        link_sha256='b'*64,manifest_digest=parent['intent']['runtime_call']['manifest_digest'],
        snapshot_request_sha256='c'*64,owner_context_sha256='d'*64,publication_operation_id='retained-publication',derived=None)
    controller = CohortController(journal,parent['operation_id'],{})
    if original_child:
        with pytest.raises(OnboardingError,match='association_changed'):
            controller._admission_lifecycle_association(current,admission,'founder',recipe,lifecycle,proof,require_group=False)
    else:
        controller._admission_lifecycle_association(current,admission,'founder',recipe,lifecycle,proof,require_group=False)
    assert journal.get(parent['operation_id'])['expected_precondition'] == parent['expected_precondition']



def remaining_started_fixture(tmp_path, monkeypatch, *, preparation=False):
    journal, parent, request, clock = remaining_fixture(tmp_path, monkeypatch, preparation=preparation)
    observed = copy.deepcopy(parent['runtime_observation'])
    publication = observed['group_publication']
    command = publication['requests']['entrant']['application']['command']
    for name in parent['intended_transition']['cohort_admission']['receivers']:
        publication['requests'][name] = {'application': {'command': copy.deepcopy(command), 'result': {'retained': True}}}
    identity = {key: value for key, value in publication.items() if key != 'requests'}
    result = dict(schema='cluster-admission-group-publications/v1', operation_id=command['operation_id'],
        **identity, snapshots={name:{} for name in publication['requests']}, receiving_readiness='unobserved')
    publication.update(result=result, result_sha256=digest(result))
    observed['portal_admission']['loaded-founder'] = {'retained': True}
    observed['sender_replacements'] = {'founder': {'retained': True}}
    observed['initial_managed'] = {'entrant': dict(
        intent=dict(request={'schema': 'cluster-guest-service-initial/v1'}, unit_sha256='f'*64),
        validated={}, selected={'selected_sha256': 'f'*64},
        started=dict(schema='cluster-guest-service-initial-start/v1', service={'unit_sha256': 'f'*64}))}
    parent = journal.advance(parent['operation_id'], parent['state'], runtime_observation=observed,
        expected_runtime_observation=parent['runtime_observation'])
    request['frontier_sha256'] = digest(observed)
    return journal, parent, request, clock


@pytest.mark.parametrize('preparation', [False, True])
def test_remaining_started_frontier_preserves_completed_publication_and_first_start(tmp_path, monkeypatch, preparation):
    journal, parent, request, clock = remaining_started_fixture(tmp_path, monkeypatch, preparation=preparation)
    original = copy.deepcopy(parent)
    approved = recovery.remaining_plan(journal, request, audit_identity={})
    selected = recovery.remaining_reference(approved)
    grant = recovery.remaining_attach(journal, parent['operation_id'], selected)
    current = journal.get(parent['operation_id'])
    assert grant['started_frontier']['publication_result_sha256'] == digest(
        parent['runtime_observation']['group_publication']['result'])
    assert set(grant['children']) == {'founder'}
    assert recovery.remaining_require_effect(journal, current, selected, 'initial-start', now_ms=clock[0]) == grant
    prior = recovery.attached(journal, current)
    historical = recovery.lifecycle(journal, current, 'founder', fresh=False)
    if preparation:
        assert historical is None
    else:
        assert historical['continuation_sha256'] == digest(prior)
        assert historical['not_after_ms'] == prior['expires_at_ms']
    assert recovery.lifecycle(journal, current, 'founder')['not_after_ms'] == grant['expires_at_ms']
    assert all(current[key] == original[key] for key in ('intent','intent_hash','expected_precondition','intended_transition'))
    observed = copy.deepcopy(current['runtime_observation'])
    observed['initial_managed']['entrant']['start_recovery_request'] = {'new': 'separate retained observation'}
    journal.advance(parent['operation_id'], parent['state'], runtime_observation=observed)
    assert recovery.remaining_resolve(journal, journal.get(parent['operation_id']), selected) == grant
    observed['initial_managed']['entrant']['started']['service']['unit_sha256'] = '0'*64
    journal.advance(parent['operation_id'], parent['state'], runtime_observation=observed)
    with pytest.raises(OnboardingError, match='remaining_reference_required'):
        recovery.remaining_resolve(journal, journal.get(parent['operation_id']), selected)


@pytest.mark.parametrize('change', ['publication-hash','pending-request','completed-load','activation','communication','initial-unit'])
def test_remaining_started_frontier_refuses_unproved_or_later_stage(tmp_path, monkeypatch, change):
    journal, parent, request, _ = remaining_started_fixture(tmp_path, monkeypatch)
    observed = copy.deepcopy(parent['runtime_observation'])
    if change == 'publication-hash':
        observed['group_publication']['result_sha256'] = '0'*64
    elif change == 'pending-request':
        observed['group_publication']['requests']['founder']['application']['result'] = None
    elif change == 'completed-load':
        observed['initial_managed']['entrant']['controlled_loaded'] = {}
    elif change == 'activation':
        observed['admission_activation_plan'] = {}
    elif change == 'communication':
        observed['portal_admission']['communication-intent-send'] = {}
    else:
        observed['initial_managed']['entrant']['started']['service']['unit_sha256'] = '0'*64
    parent = journal.advance(parent['operation_id'], parent['state'], runtime_observation=observed)
    request['frontier_sha256'] = digest(observed)
    with pytest.raises(OnboardingError):
        recovery.remaining_plan(journal, request, audit_identity={})
