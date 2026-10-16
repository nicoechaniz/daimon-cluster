"""Immutable, linked authorization for the reconciled pre-membership frontier.

Planning records approval in the existing owner journal; it performs no social,
service, credential or receiving effect. Consumers must attach this grant under
the original parent lock, validate current owners and record its provenance.
"""
from __future__ import annotations

import copy
import re
import time
import uuid
from pathlib import Path

from .onboarding import OnboardingError, digest

SCHEMA = 'cluster-admission-continuation/v1'
REQUEST_SCHEMA = 'cluster-admission-continuation-request/v1'
REFERENCE_SCHEMA = 'cluster-admission-continuation-reference/v1'
EFFECTS = ['membership', 'publication', 'old-selection-start', 'initial-start', 'activation', 'communication']


def _sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _frontier(row: dict) -> tuple[dict, dict, dict, dict]:
    """Recognize only the reviewed frontier, not an arbitrary partial admission."""
    from .onboarding_group_admission import command
    try:
        before, after, observed = row['expected_precondition'], row['intended_transition'], row['runtime_observation']
        admission, social = after['cohort_admission'], after['portal_admission']['social']
        phases = observed['portal_admission']
        old = {item['name'] for item in before['senders']}
        children = observed['admission_lifecycles']
        membership = observed['membership_admission']
        pending = membership['requests']
        invite = pending[social['founder_owner']]['membership-invite']
        expected = command(dict(operation_id=social['operation_id'], step='membership-invite',
            method='tribe.invite', params={'payload': social['invitation']}))
        if (row['operation'] != 'receiving-update' or row['state'] != 'runtime-dispatching'
                or row['target'] != 'receiving:'+admission['tribe_ref']
                or row['intent_hash'] != digest(row['intent'])
                or row['intent']['runtime_call']['precondition_digest'] != digest(before)
                or row['intent']['runtime_call']['transition_digest'] != digest(after)
                or after['portal_admission']['schema'] != 'cluster-portal-group-admission/v2'
                or 'execution_intent' not in phases or not old or set(children) != old
                or set(observed['sender_revocations']) != old
                or set(after['admission_preparations']) != old
                or set(pending) != {social['founder_owner']}
                or set(pending[social['founder_owner']]) != {'membership-invite'}
                or set(invite) != {'command', 'result'} or invite['command'] != expected or invite['result'] is not None
                or membership.get('recipe_sha256') != digest(social) or membership.get('result') is not None
                or any(key in observed for key in ('group_publication', 'initial_managed', 'admission_activation_plan',
                    'cohort_activation', 'sender_initials', 'sender_selections', 'admission_continuation'))
                or any(key.startswith(('loaded-', 'communication-', 'communication-intent-')) for key in phases)):
            raise ValueError
        preserved = {}
        for name in sorted(old):
            child, proof = children[name], phases['preserved-'+name]
            if (set(child) != {'lifecycle_operation_id', 'link_sha256'}
                    or not isinstance(child['lifecycle_operation_id'], str) or not child['lifecycle_operation_id']
                    or not _sha(child['link_sha256']) or set(proof) != {'result_sha256'}
                    or not _sha(proof['result_sha256'])
                    or observed['sender_revocations'][name]['gate']['phase'] != 'revoke'
                    or observed['sender_revocations'][name]['gate']['readers'] != []):
                raise ValueError
            preserved[name] = dict(child=child, preservation_sha256=proof['result_sha256'])
        return admission, social, expected, preserved
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_continuation_frontier_required') from None


def authorization(parent: dict, request: dict, *, now_ms: int) -> dict:
    """Validate a closed operator request against the unchanged original intent.

    An inspection supplied by a protected operator is evidence, not native
    authority. Actual owner consumers must revalidate it before fresh authoring.
    """
    from daimon_matrix.relationships import validate_relationship_event_payload
    try:
        fields = {'schema', 'authorization_id', 'parent_operation_id', 'parent_intent_sha256',
            'frontier_sha256', 'expires_at_ms', 'invitation', 'inspection', 'maintenance'}
        if (not isinstance(request, dict) or set(request) != fields or request['schema'] != REQUEST_SCHEMA
                or str(uuid.UUID(request['authorization_id'])) != request['authorization_id']
                or request['parent_operation_id'] != parent['operation_id']
                or request['parent_intent_sha256'] != parent['intent_hash']
                or request['frontier_sha256'] != digest(parent['runtime_observation'])
                or type(now_ms) is not int or type(request['expires_at_ms']) is not int
                or not 0 < now_ms < request['expires_at_ms'] < 2**53):
            raise ValueError
        admission, social, original, children = _frontier(parent)
        if now_ms < admission['activation']['expires_at_ms']:
            raise ValueError
        replacement = validate_relationship_event_payload('matrix/tribe-invitation', request['invitation'],
            author_being_ref=social['invitation']['founder_being_ref'], causal_parents=[])
        changing = {'issued_at_ms', 'expires_at_ms', 'nonce', 'invitation_id'}
        if (any(replacement[key] != value for key, value in social['invitation'].items() if key not in changing)
                or replacement['nonce'] == social['invitation']['nonce']
                or replacement['invitation_id'] == social['invitation']['invitation_id']
                or not admission['activation']['expires_at_ms'] <= replacement['issued_at_ms'] <= now_ms
                or replacement['expires_at_ms'] != request['expires_at_ms']):
            raise ValueError
        inspection = request['inspection']
        inspection_fields = {'schema', 'operation_id', 'command_sha256', 'ledger_sha256', 'request_retained',
            'rpc_state', 'request_sha256', 'response_sha256', 'invitations', 'acceptances', 'membership',
            'observed_at_ms', 'requests_dispatched', 'receiving_readiness'}
        if (not isinstance(inspection, dict) or set(inspection) != inspection_fields
                or inspection['schema'] != 'cluster-group-invitation-inspection/v1'
                or inspection['operation_id'] != social['operation_id']
                or inspection['command_sha256'] != digest(original) or not _sha(inspection['ledger_sha256'])
                or inspection['rpc_state'] not in {'absent', 'not-dispatched'}
                or type(inspection['request_retained']) is not bool
                or inspection['request_retained'] != (inspection['rpc_state'] == 'absent')
                or (not _sha(inspection['request_sha256']) if inspection['request_retained']
                    else inspection['request_sha256'] is not None)
                or inspection['response_sha256'] is not None or inspection['invitations'] != []
                or inspection['acceptances'] != [] or type(inspection['requests_dispatched']) is not int
                or inspection['requests_dispatched'] != 0 or inspection['receiving_readiness'] != 'unobserved'
                or type(inspection['observed_at_ms']) is not int or not 0 < inspection['observed_at_ms'] <= now_ms
                or inspection['membership'] != dict(tribe_state='active',
                    active_members=sorted(item['being_ref'] for item in parent['expected_precondition']['senders']),
                    entrant_state=inspection['membership'].get('entrant_state'))
                or inspection['membership']['entrant_state'] not in {None, 'left', 'expelled'}):
            raise ValueError
        helpers = request['maintenance']
        if not isinstance(helpers, dict) or set(helpers) != set(admission['receivers']):
            raise ValueError
        for name, helper in helpers.items():
            if (set(helper) != {'code', 'code_digest', 'code_uid'} or not isinstance(helper['code'], str)
                    or not Path(helper['code']).is_absolute() or '..' in Path(helper['code']).parts
                    or not _sha(helper['code_digest']) or type(helper['code_uid']) is not int
                    or helper['code_uid'] != admission['receivers'][name]['candidate']['code_uid']):
                raise ValueError
        return dict(schema=SCHEMA, authorization_id=request['authorization_id'],
            parent_operation_id=parent['operation_id'], parent_intent_sha256=parent['intent_hash'],
            original_vectors_sha256=digest(dict(before=parent['expected_precondition'], after=parent['intended_transition'])),
            frontier_sha256=request['frontier_sha256'], children=copy.deepcopy(children),
            manifest_digest=parent['intent']['runtime_call']['manifest_digest'],
            original_recipe_sha256=digest(social), original_invitation_command_sha256=digest(original),
            expires_at_ms=request['expires_at_ms'], invitation=copy.deepcopy(replacement),
            inspection=copy.deepcopy(inspection), maintenance=copy.deepcopy(helpers), effects=EFFECTS.copy())
    except OnboardingError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_continuation_authorization_required') from None


def plan(journal, request: dict, *, audit_identity: dict) -> dict:
    """Retain one approval, not another receiving operation or activation."""
    from .operation_journal import JournalConflict
    with journal.mutation_lock(request['parent_operation_id']):
        parent = journal.get(request['parent_operation_id'])
        if parent is None:
            raise OnboardingError('onboarding_group_continuation_frontier_required')
        key = 'admission-authorization:'+request['authorization_id']
        previous = journal.latest_for_idempotency_key(key)
        if previous is not None:
            if previous['intent'].get('runtime_call', {}).get('request_sha256') != digest(request):
                raise JournalConflict('continuation approval is bound to different exact request bytes')
            resolve(journal, parent, reference(previous))
            return previous
        grant = authorization(parent, request, now_ms=time.time_ns()//1_000_000)
        return journal.plan(operation='admission-continuation', target='admission-authorization:'+parent['operation_id'],
            idempotency_key=key,
            intent=dict(operation='admission-continuation', target='admission-authorization:'+parent['operation_id'],
                runtime_call=dict(parent_intent_sha256=parent['intent_hash'], authorization_sha256=digest(grant),
                    request_sha256=digest(request))),
            expected_precondition=dict(parent_operation_id=parent['operation_id'], parent_intent_sha256=parent['intent_hash'],
                frontier_sha256=grant['frontier_sha256']),
            intended_transition=grant, audit_identity=audit_identity)


def reference(row: dict) -> dict:
    return dict(schema=REFERENCE_SCHEMA, operation_id=row['operation_id'], intent_sha256=row['intent_hash'])


def resolve(journal, parent: dict, selected: dict) -> dict:
    """Read explicit provenance without rewriting an intent or requiring a fresh clock."""
    try:
        if (not isinstance(selected, dict) or set(selected) != {'schema', 'operation_id', 'intent_sha256'}
                or selected['schema'] != REFERENCE_SCHEMA):
            raise ValueError
        row = journal.get(selected['operation_id'])
        if row is None:
            raise ValueError
        grant = row['intended_transition']
        if (row['operation'] != 'admission-continuation' or row['state'] in {'degraded', 'compensated'}
                or row['target'] != 'admission-authorization:'+parent['operation_id']
                or row['intent_hash'] != selected['intent_sha256'] or row['intent_hash'] != digest(row['intent'])
                or row['intent']['runtime_call'] != dict(parent_intent_sha256=parent['intent_hash'],
                    authorization_sha256=digest(grant), request_sha256=row['intent']['runtime_call'].get('request_sha256'))
                or not _sha(row['intent']['runtime_call']['request_sha256'])
                or grant['schema'] != SCHEMA or grant['parent_operation_id'] != parent['operation_id']
                or grant['parent_intent_sha256'] != parent['intent_hash'] or grant['effects'] != EFFECTS
                or grant['original_vectors_sha256'] != digest(dict(before=parent['expected_precondition'],
                    after=parent['intended_transition']))
                or grant['manifest_digest'] != parent['intent']['runtime_call']['manifest_digest']
                or grant['original_recipe_sha256'] != digest(parent['intended_transition']['portal_admission']['social'])
                or row['expected_precondition'] != dict(parent_operation_id=parent['operation_id'],
                    parent_intent_sha256=parent['intent_hash'], frontier_sha256=grant['frontier_sha256'])):
            raise ValueError
        for name, binding in grant['children'].items():
            observed = parent['runtime_observation']
            if (observed['admission_lifecycles'][name] != binding['child']
                    or observed['portal_admission']['preserved-'+name] != {
                        'result_sha256': binding['preservation_sha256']}):
                raise ValueError
        return copy.deepcopy(grant)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_continuation_reference_required') from None


def attach(journal, parent_operation_id: str, selected: dict) -> dict:
    """CAS the approved frontier once; later legitimate progress stays resumable.

    Attachment is journal metadata, not permission to bypass any fresh owner,
    helper, membership, preservation or effect-boundary checks.
    """
    with journal.mutation_lock(parent_operation_id):
        parent = journal.get(parent_operation_id)
        grant = resolve(journal, parent, selected)
        retained = dict(schema='cluster-admission-continuation-attachment/v1', reference=selected,
            authorization_sha256=digest(grant), frontier_sha256=grant['frontier_sha256'])
        observations = copy.deepcopy(parent['runtime_observation'] or {})
        previous = observations.get('admission_continuation')
        if previous is not None:
            if previous != retained:
                raise OnboardingError('onboarding_group_continuation_reference_required')
        else:
            _frontier(parent)
            if (digest(observations) != grant['frontier_sha256']
                    or time.time_ns()//1_000_000 >= grant['expires_at_ms']):
                raise OnboardingError('onboarding_group_continuation_frontier_changed')
            observations['admission_continuation'] = retained
            journal.advance(parent_operation_id, parent['state'], runtime_observation=observations,
                expected_runtime_observation=parent['runtime_observation'])
        approved = journal.get(selected['operation_id'])
        effect = dict(parent_operation_id=parent_operation_id, authorization_sha256=digest(grant))
        if approved['runtime_observation'] is None:
            journal.advance(approved['operation_id'], 'runtime-dispatching', runtime_observation={'attachment': effect},
                expected_runtime_observation=None)
        elif approved['runtime_observation'] != {'attachment': effect}:
            raise OnboardingError('onboarding_group_continuation_reference_required')
        return grant


def require_effect(journal, parent: dict, selected: dict, effect: str, *, now_ms: int) -> dict:
    """Check the journal's current parent; a supplied snapshot is only an expectation.

    Consumers must hold the same reentrant parent mutation lock through dispatch.
    An expired grant remains inspectable, but never authorizes a fresh effect.
    """
    with journal.mutation_lock(parent['operation_id']):
        current = journal.get(parent['operation_id'])
        try:
            if (current is None or current['operation'] != 'receiving-update'
                    or current['state'] != 'runtime-dispatching'
                    or any(current[key] != parent[key] for key in
                        ('intent', 'intent_hash', 'expected_precondition', 'intended_transition'))
                    or current['intent_hash'] != digest(current['intent'])
                    or current['intent']['runtime_call']['precondition_digest'] != digest(current['expected_precondition'])
                    or current['intent']['runtime_call']['transition_digest'] != digest(current['intended_transition'])):
                raise ValueError
            grant = resolve(journal, current, selected)
            expected = dict(schema='cluster-admission-continuation-attachment/v1', reference=selected,
                authorization_sha256=digest(grant), frontier_sha256=grant['frontier_sha256'])
            approved = journal.get(selected['operation_id'])
            if (effect not in grant['effects']
                    or (current['runtime_observation'] or {}).get('admission_continuation') != expected
                    or approved['state'] != 'runtime-dispatching'
                    or approved['runtime_observation'] != {'attachment': dict(parent_operation_id=current['operation_id'],
                        authorization_sha256=digest(grant))}
                    or type(now_ms) is not int or not 0 < now_ms < grant['expires_at_ms']):
                raise ValueError
            return grant
        except (KeyError, TypeError, ValueError, AttributeError):
            raise OnboardingError('onboarding_group_continuation_effect_not_authorized') from None
