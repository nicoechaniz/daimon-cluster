"""Immutable, linked authorization for the reconciled pre-membership frontier.

Planning records approval in the existing owner journal; it performs no social,
service, credential or receiving effect. Consumers must attach this grant under
the original parent lock, validate current owners and record its provenance.
"""
from __future__ import annotations

import copy
import os
import re
import stat
import threading
import time
import uuid
from contextlib import contextmanager, nullcontext
from pathlib import Path

from .onboarding import OnboardingError, digest

SCHEMA = 'cluster-admission-continuation/v1'
REQUEST_SCHEMA = 'cluster-admission-continuation-request/v1'
REFERENCE_SCHEMA = 'cluster-admission-continuation-reference/v1'
EFFECTS = ['membership', 'publication', 'old-selection-start', 'initial-start', 'activation', 'communication']
REMAINING_SCHEMA = 'cluster-admission-remaining-effects/v1'
REMAINING_REQUEST_SCHEMA = 'cluster-admission-remaining-effects-request/v1'
REMAINING_REFERENCE_SCHEMA = 'cluster-admission-remaining-effects-reference/v1'
REMAINING_EFFECTS = ['publication', 'old-selection-start', 'initial-start', 'tooling',
                     'activation', 'steady-handoff', 'communication']


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


def require_execution(journal, parent: dict, selected: dict, effect: str) -> dict:
    """Check the journal's current parent; a supplied snapshot is only an expectation.

    Consumers must hold the same reentrant parent mutation lock through dispatch.
    Expiry permits historical reconciliation, but inactive grants cannot execute.
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
                        authorization_sha256=digest(grant))}):
                raise ValueError
            return grant
        except (KeyError, TypeError, ValueError, AttributeError):
            raise OnboardingError('onboarding_group_continuation_effect_not_authorized') from None


def require_effect(journal, parent: dict, selected: dict, effect: str, *, now_ms: int) -> dict:
    """Require an active attachment and its fixed bound for a fresh effect."""
    grant = require_execution(journal, parent, selected, effect)
    if type(now_ms) is not int or not 0 < now_ms < grant['expires_at_ms']:
        raise OnboardingError('onboarding_group_continuation_effect_not_authorized')
    return grant


def attached(journal, parent: dict, *, effect: str | None = None) -> dict | None:
    """Resolve the real attached approval, preserving ordinary admission behavior.

    Fresh effects require the caller to retain the parent lock through dispatch.
    Historical readers omit effect and never acquire fresh permission.
    """
    current = journal.get(parent['operation_id'])
    if current is None or any(current[key] != parent[key] for key in
            ('intent', 'intent_hash', 'expected_precondition', 'intended_transition')):
        raise OnboardingError('onboarding_group_continuation_reference_required')
    attachment = (current['runtime_observation'] or {}).get('admission_continuation')
    if attachment is None:
        return None
    grant = resolve(journal, current, attachment['reference'])
    expected = dict(schema='cluster-admission-continuation-attachment/v1', reference=attachment['reference'],
        authorization_sha256=digest(grant), frontier_sha256=grant['frontier_sha256'])
    if attachment != expected:
        raise OnboardingError('onboarding_group_continuation_reference_required')
    return grant if effect is None else require_effect(journal, current, attachment['reference'], effect,
        now_ms=time.time_ns()//1_000_000)


def membership(journal, parent: dict, admission: dict) -> tuple[dict, str, str, dict]:
    """Derive a correlated social attempt without rewriting the original recipe."""
    from .onboarding_group_admission import membership_recipe
    original = membership_recipe(parent['intended_transition']['portal_admission']['social'], admission,
        parent['expected_precondition']['senders'])
    grant = attached(journal, parent)
    if grant is None:
        return original, 'membership_admission', '', {}
    social = copy.deepcopy(original)
    social.update(invitation=grant['invitation'], acceptance_not_after_ms=grant['expires_at_ms'])
    recipe = membership_recipe(social, admission, parent['expected_precondition']['senders'],
        expires_at_ms=grant['expires_at_ms'])
    provenance = dict(continuation_sha256=digest(grant), original_recipe_sha256=digest(original))
    return recipe, 'membership_continuation', 'c-'+grant['authorization_id'].replace('-', '')+'-', provenance


def effect_deadline(journal, parent: dict, effect: str, deadline_ns: int) -> int:
    """Propagate the fixed linked bound to the actual owner, never renew a budget."""
    grant = execution(journal, parent, effect=effect, historical=True)
    if grant is None or time.time_ns()//1_000_000 >= grant['expires_at_ms']:
        # An expired invocation can only reconcile exact committed owner effects.
        # The fixed effect bound is carried separately to those actual consumers.
        return deadline_ns
    execution(journal,parent,effect=effect)
    return min(deadline_ns,time.monotonic_ns()+(
        grant['expires_at_ms']-time.time_ns()//1_000_000)*1_000_000)


def bounds(journal, parent: dict) -> dict:
    """Derive the remaining bound explicitly; original activation stays frozen."""
    result = copy.deepcopy(parent['intended_transition']['cohort_admission']['activation'])
    grant = execution(journal, parent, historical=True)
    if grant is not None:
        result['expires_at_ms'] = grant['expires_at_ms']
    return result


def lifecycle(journal, parent: dict, name: str, *, fresh: bool = True) -> dict | None:
    """Project only the approved remaining start to the existing owner CLI."""
    grant = execution(journal, parent, effect='old-selection-start', historical=not fresh)
    if grant is None:
        return None
    try:
        child = grant['children'][name]
        return dict(schema='cluster-admission-lifecycle-continuation/v1', continuation_sha256=digest(grant),
            cohort_operation_id=parent['operation_id'], cohort_intent_sha256=parent['intent_hash'],
            lifecycle_operation_id=child['child']['lifecycle_operation_id'], link_sha256=child['child']['link_sha256'],
            preservation_sha256=child['preservation_sha256'], not_after_ms=grant['expires_at_ms'])
    except (KeyError, TypeError):
        raise OnboardingError('onboarding_group_continuation_lifecycle_required') from None


def validate_lifecycle(child: dict, candidate: dict, value: dict, *, preservation_sha256: str) -> int:
    """Owner-local association check, independent of private host journal access.

    The protected owner CLI accepts this explicit operator request, just as its
    existing initial/bootstrap requests. It does not accept a peer's authority.
    Actual store, capability validity, stopped service and fresh bounds remain
    the controller's checks at selection/start. Historical projection omits time.
    """
    try:
        link = candidate['admission_link']
        if (set(value) != {'schema','continuation_sha256','cohort_operation_id','cohort_intent_sha256',
                'lifecycle_operation_id','link_sha256','preservation_sha256','not_after_ms'}
                or value['schema'] != 'cluster-admission-lifecycle-continuation/v1'
                or not _sha(value['continuation_sha256'])
                or value['lifecycle_operation_id'] != child['operation_id']
                or value['cohort_operation_id'] != link['cohort_operation_id']
                or value['cohort_intent_sha256'] != link['cohort_intent_sha256']
                or value['link_sha256'] != digest(link)
                or value['preservation_sha256'] != preservation_sha256
                or type(value['not_after_ms']) is not int or not 0 < value['not_after_ms'] < 2**53):
            raise ValueError
        return value['not_after_ms']
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_continuation_lifecycle_required') from None


def _remaining_frontier(journal, parent: dict) -> dict:
    """Pin accepted membership and incomplete publication, never renew social intent."""
    try:
        observed = parent['runtime_observation']
        admission = parent['intended_transition']['cohort_admission']
        social, state_key, _prefix, provenance = membership(journal, parent, admission)
        prior = attached(journal, parent)
        joined = observed[state_key]
        result = joined['result']
        publication = observed['group_publication']
        phases = observed['portal_admission']
        old = {item['name'] for item in parent['expected_precondition']['senders']}
        if (parent['operation'] != 'receiving-update' or parent['state'] != 'runtime-dispatching'
                or parent['intent_hash'] != digest(parent['intent'])
                or parent['target'] != 'receiving:'+admission['tribe_ref']
                or parent['intent']['runtime_call']['precondition_digest'] != digest(parent['expected_precondition'])
                or parent['intent']['runtime_call']['transition_digest'] != digest(parent['intended_transition'])
                or prior is None or joined['recipe_sha256'] != digest(social)
                or joined['result_sha256'] != digest(result)
                or result['schema'] != 'cluster-native-membership-admission/v1'
                or result['operation_id'] != social['operation_id']
                or result['receiving_readiness'] != 'unobserved'
                or set(result['snapshots']) != set(admission['receivers'])
                or any(joined.get(key) != value or publication.get(key) != value
                       for key, value in provenance.items())
                or publication['membership_sha256'] != digest(result)
                or publication['recipe_sha256'] != digest(parent['intended_transition']['admission_publications'])
                or publication.get('result') is not None
                or not publication['requests'] or not set(publication['requests']) <= set(admission['receivers'])
                or set(observed['admission_lifecycles']) != old
                or set(observed['sender_revocations']) != old
                or any(key in observed for key in ('initial_managed', 'admission_activation_plan',
                    'cohort_activation', 'sender_initials', 'sender_selections', 'sender_replacements', 'initial_steady',
                    'admission_remaining_effects'))
                or any(key.startswith(('loaded-', 'communication-', 'communication-intent-')) for key in phases)):
            raise ValueError
        expected_refs = {item['being_ref'] for item in admission['receivers'].values()}
        for snapshot in result['snapshots'].values():
            if (snapshot['tribe_ref'] != admission['tribe_ref']
                    or {item['principal_id'] for item in snapshot['members'] if item['state'] == 'active'}
                        != expected_refs
                    or not any(item['principal_id'] == admission['entrant']['being_ref']
                        and item['membership_ref'] == result['acceptance']['event_id']
                        for item in snapshot['members'])):
                raise ValueError
        retained_requests: dict[str, dict[str, dict[str, str | None]]] = {}
        for name, requests in publication['requests'].items():
            steps = parent['intended_transition']['admission_publications']['owners'][name]['steps']
            if not requests or not set(requests) <= set(steps):
                raise ValueError
            for key, entry in requests.items():
                from .onboarding_group_admission import publication_command
                command = publication_command(entry['command'])
                if (set(entry) != {'command', 'result'} or command['operation_id'] != social['operation_id']
                        or command['step'] != steps[key]
                        or command['action'] != {'application': 'application', 'disclosure': 'visibility-disclosure',
                            'acceptance': 'visibility-accept', 'visibility': 'visibility-publish',
                            'selection': 'selection', 'snapshot': 'snapshot'}[key]):
                    raise ValueError
                retained_requests.setdefault(name, {})[key] = dict(command_sha256=digest(command),
                    result_sha256=None if entry['result'] is None else digest(entry['result']))
        for name, child in prior['children'].items():
            if (observed['admission_lifecycles'][name] != child['child']
                    or phases['preserved-'+name] != {'result_sha256': child['preservation_sha256']}
                    or observed['sender_revocations'][name]['gate']['phase'] != 'revoke'
                    or observed['sender_revocations'][name]['gate']['readers'] != []):
                raise ValueError
        return dict(social_grant_sha256=digest(prior), membership_state_key=state_key,
            membership_sha256=digest(joined), publication_sha256=digest(publication),
            publication_identity=dict(recipe_sha256=publication['recipe_sha256'],
                membership_sha256=publication['membership_sha256'], **provenance),
            publication_requests=retained_requests,
            children=copy.deepcopy(prior['children']))
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_remaining_frontier_required') from None


def remaining_plan(journal, request: dict, *, audit_identity: dict) -> dict:
    """Approve remaining effects separately; keep the social attachment immutable."""
    from .operation_journal import JournalConflict
    with journal.mutation_lock(request['parent_operation_id']):
        parent = journal.get(request['parent_operation_id'])
        key = 'admission-remaining:'+request['authorization_id']
        previous = journal.latest_for_idempotency_key(key)
        if previous is not None:
            if previous['intent']['runtime_call']['request_sha256'] != digest(request):
                raise JournalConflict('remaining effects approval has different exact request bytes')
            remaining_resolve(journal, parent, remaining_reference(previous))
            return previous
        try:
            if (set(request) != {'schema', 'authorization_id', 'parent_operation_id',
                    'parent_intent_sha256', 'frontier_sha256', 'expires_at_ms', 'maintenance'}
                    or request['schema'] != REMAINING_REQUEST_SCHEMA
                    or str(uuid.UUID(request['authorization_id'])) != request['authorization_id']
                    or request['parent_intent_sha256'] != parent['intent_hash']
                    or request['frontier_sha256'] != digest(parent['runtime_observation'])
                    or type(request['expires_at_ms']) is not int
                    or not 0 < time.time_ns()//1_000_000 < request['expires_at_ms'] < 2**53):
                raise ValueError
            frontier = _remaining_frontier(journal, parent)
            admission = parent['intended_transition']['cohort_admission']
            helpers = request['maintenance']
            prior = attached(journal, parent)
            if (prior is None or time.time_ns()//1_000_000 < prior['expires_at_ms']
                    or not isinstance(helpers, dict) or set(helpers) != set(admission['receivers'])):
                raise ValueError
            for name, helper in helpers.items():
                if (set(helper) != {'code', 'code_digest', 'code_uid'}
                        or not isinstance(helper['code'], str) or not Path(helper['code']).is_absolute()
                        or '..' in Path(helper['code']).parts or not _sha(helper['code_digest'])
                        or type(helper['code_uid']) is not int
                        or helper['code_uid'] != admission['receivers'][name]['candidate']['code_uid']):
                    raise ValueError
        except (KeyError, TypeError, ValueError, AttributeError):
            raise OnboardingError('onboarding_group_remaining_authorization_required') from None
        grant = dict(schema=REMAINING_SCHEMA, authorization_id=request['authorization_id'],
            parent_operation_id=parent['operation_id'], parent_intent_sha256=parent['intent_hash'],
            original_vectors_sha256=digest(dict(before=parent['expected_precondition'],
                after=parent['intended_transition'])), manifest_digest=parent['intent']['runtime_call']['manifest_digest'],
            frontier_sha256=request['frontier_sha256'], **frontier, effects=REMAINING_EFFECTS.copy(),
            expires_at_ms=request['expires_at_ms'], maintenance=copy.deepcopy(helpers))
        target = 'admission-remaining:'+parent['operation_id']
        return journal.plan(operation='admission-remaining-effects', target=target, idempotency_key=key,
            intent=dict(operation='admission-remaining-effects', target=target, runtime_call=dict(
                parent_intent_sha256=parent['intent_hash'], authorization_sha256=digest(grant),
                request_sha256=digest(request))), expected_precondition=dict(parent_operation_id=parent['operation_id'],
                parent_intent_sha256=parent['intent_hash'], frontier_sha256=grant['frontier_sha256']),
            intended_transition=grant, audit_identity=audit_identity)


def remaining_reference(row: dict) -> dict:
    return dict(schema=REMAINING_REFERENCE_SCHEMA, operation_id=row['operation_id'], intent_sha256=row['intent_hash'])


def remaining_resolve(journal, parent: dict, selected: dict) -> dict:
    """Historical provenance does not activate or extend remaining permission."""
    try:
        if (set(selected) != {'schema', 'operation_id', 'intent_sha256'}
                or selected['schema'] != REMAINING_REFERENCE_SCHEMA):
            raise ValueError
        row = journal.get(selected['operation_id'])
        grant = row['intended_transition']
        prior = attached(journal, parent)
        if (row['operation'] != 'admission-remaining-effects'
                or row['state'] in {'degraded', 'compensated'}
                or row['intent_hash'] != selected['intent_sha256'] or row['intent_hash'] != digest(row['intent'])
                or row['target'] != 'admission-remaining:'+parent['operation_id']
                or grant['schema'] != REMAINING_SCHEMA
                or grant['parent_operation_id'] != parent['operation_id']
                or grant['parent_intent_sha256'] != parent['intent_hash']
                or grant['original_vectors_sha256'] != digest(dict(before=parent['expected_precondition'],
                    after=parent['intended_transition']))
                or grant['manifest_digest'] != parent['intent']['runtime_call']['manifest_digest']
                or parent['intent_hash'] != digest(parent['intent'])
                or parent['intent']['runtime_call']['precondition_digest'] != digest(parent['expected_precondition'])
                or parent['intent']['runtime_call']['transition_digest'] != digest(parent['intended_transition'])
                or grant['effects'] != REMAINING_EFFECTS
                or prior is None or grant['social_grant_sha256'] != digest(prior)
                or row['intent']['runtime_call'] != dict(parent_intent_sha256=parent['intent_hash'],
                    authorization_sha256=digest(grant), request_sha256=row['intent']['runtime_call']['request_sha256'])
                or not _sha(row['intent']['runtime_call']['request_sha256'])
                or row['expected_precondition'] != dict(parent_operation_id=parent['operation_id'],
                    parent_intent_sha256=parent['intent_hash'], frontier_sha256=grant['frontier_sha256'])
                or digest(parent['runtime_observation'][grant['membership_state_key']]) != grant['membership_sha256']):
            raise ValueError
        for name, child in grant['children'].items():
            if (parent['runtime_observation']['admission_lifecycles'][name] != child['child']
                    or parent['runtime_observation']['portal_admission']['preserved-'+name]
                        != {'result_sha256': child['preservation_sha256']}):
                raise ValueError
        publication = parent['runtime_observation']['group_publication']
        if any(publication.get(key) != value for key, value in grant['publication_identity'].items()):
            raise ValueError
        for name, requests in grant['publication_requests'].items():
            for key, evidence in requests.items():
                entry = publication['requests'][name][key]
                if (digest(entry['command']) != evidence['command_sha256']
                        or evidence['result_sha256'] is not None
                        and digest(entry['result']) != evidence['result_sha256']):
                    raise ValueError
        return copy.deepcopy(grant)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_remaining_reference_required') from None


def remaining_attach(journal, parent_operation_id: str, selected: dict) -> dict:
    """CAS one approved publication frontier, preserving every previous attachment."""
    with journal.mutation_lock(parent_operation_id):
        parent = journal.get(parent_operation_id)
        grant = remaining_resolve(journal, parent, selected)
        retained = dict(schema='cluster-admission-remaining-effects-attachment/v1', reference=selected,
            authorization_sha256=digest(grant), frontier_sha256=grant['frontier_sha256'])
        observed = copy.deepcopy(parent['runtime_observation'])
        previous = observed.get('admission_remaining_effects')
        if previous is None:
            if journal.get(selected['operation_id'])['state'] != 'planned':
                raise OnboardingError('onboarding_group_remaining_effect_not_authorized')
            _remaining_frontier(journal, parent)
            if (digest(observed) != grant['frontier_sha256']
                    or time.time_ns()//1_000_000 >= grant['expires_at_ms']):
                raise OnboardingError('onboarding_group_remaining_frontier_changed')
            observed['admission_remaining_effects'] = retained
            journal.advance(parent_operation_id, parent['state'], runtime_observation=observed,
                expected_runtime_observation=parent['runtime_observation'])
        elif previous != retained:
            raise OnboardingError('onboarding_group_remaining_reference_required')
        approved = journal.get(selected['operation_id'])
        effect = {'attachment': dict(parent_operation_id=parent_operation_id, authorization_sha256=digest(grant))}
        if approved['runtime_observation'] is None:
            journal.advance(approved['operation_id'], 'runtime-dispatching', runtime_observation=effect,
                expected_runtime_observation=None)
        elif approved['runtime_observation'] != effect:
            raise OnboardingError('onboarding_group_remaining_reference_required')
        return grant


def remaining_require_effect(journal, parent: dict, selected: dict, effect: str, *, now_ms: int) -> dict:
    """Use the current protected parent and active grant through actual dispatch."""
    with journal.mutation_lock(parent['operation_id']):
        try:
            current = journal.get(parent['operation_id'])
            if (current['state'] != 'runtime-dispatching' or current['operation'] != 'receiving-update'
                    or any(current[key] != parent[key] for key in
                        ('intent', 'intent_hash', 'expected_precondition', 'intended_transition'))):
                raise ValueError
            grant = remaining_resolve(journal, current, selected)
            retained = dict(schema='cluster-admission-remaining-effects-attachment/v1', reference=selected,
                authorization_sha256=digest(grant), frontier_sha256=grant['frontier_sha256'])
            approved = journal.get(selected['operation_id'])
            if (current['runtime_observation'].get('admission_remaining_effects') != retained
                    or approved['state'] != 'runtime-dispatching'
                    or approved['runtime_observation'] != {'attachment': dict(parent_operation_id=current['operation_id'],
                        authorization_sha256=digest(grant))}
                    or effect not in grant['effects'] or type(now_ms) is not int
                    or not 0 < now_ms < grant['expires_at_ms']):
                raise ValueError
            return grant
        except (KeyError, TypeError, ValueError, AttributeError):
            raise OnboardingError('onboarding_group_remaining_effect_not_authorized') from None


def execution(journal, parent: dict, *, effect: str | None = None, historical: bool = False) -> dict | None:
    """Resolve execution separately from the immutable social recipe/history.

    A remaining-effects attachment takes precedence for its own effects only;
    it cannot extend membership or fall back to an expired social approval.
    Fresh callers retain the parent mutation lock through their actual dispatch.
    Historical readers gain no permission by resolving a longer horizon.
    """
    with journal.mutation_lock(parent['operation_id']):
        current = journal.get(parent['operation_id'])
        if current is None or any(current[key] != parent[key] for key in
                ('intent', 'intent_hash', 'expected_precondition', 'intended_transition')):
            raise OnboardingError('onboarding_group_remaining_reference_required')
        attachment = (current['runtime_observation'] or {}).get('admission_remaining_effects')
        if attachment is None or effect == 'membership':
            return attached(journal, current, **({'effect': effect} if not historical and effect is not None else {}))
        grant = remaining_resolve(journal, current, attachment['reference'])
        expected = dict(schema='cluster-admission-remaining-effects-attachment/v1',
            reference=attachment['reference'], authorization_sha256=digest(grant),
            frontier_sha256=grant['frontier_sha256'])
        if attachment != expected or effect is not None and effect not in grant['effects']:
            raise OnboardingError('onboarding_group_remaining_reference_required')
        if historical:
            return grant
        if effect is None:
            raise OnboardingError('onboarding_group_remaining_effect_not_authorized')
        return remaining_require_effect(journal, current, attachment['reference'], effect,
            now_ms=time.time_ns()//1_000_000)


@contextmanager
def execution_scope(journal, parent: dict, effect: str):
    """Keep both current operation and approval stable through owner dispatch.

    Lock order is parent then approval, matching attachment. The receiving owner
    must still enforce the fixed horizon at each original effect boundary.
    Resolving a copied projection outside this scope is never permission.
    """
    with journal.mutation_lock(parent['operation_id']):
        current = journal.get(parent['operation_id'])
        execution(journal, parent, effect=effect, historical=True)
        observed = current['runtime_observation'] or {}
        attachment = observed.get('admission_remaining_effects') if effect != 'membership' else None
        attachment = attachment or observed.get('admission_continuation')
        lock = (journal.mutation_lock(attachment['reference']['operation_id'])
            if attachment is not None else nullcontext())
        with lock:
            yield execution(journal, parent, effect=effect)


@contextmanager
def remaining_projection(journal, parent: dict, effect: str, *, owner_name: str,
                         command: dict, expected_context_sha256: str):
    """Render public owner-binding evidence under actual execution ownership.

    Consumers publish this through their verified read-only owner-input route,
    then dispatch and observe the finite owner while this scope remains open.
    This document is not an independent grant or a cached active-state token.
    """
    from .onboarding_group_admission import admission_owner_contexts
    with execution_scope(journal, parent, effect) as grant:
        try:
            current = journal.get(parent['operation_id'])
            admission = current['intended_transition']['cohort_admission']
            social, _key, _prefix, _provenance = membership(journal, current, admission)
            contexts = admission_owner_contexts(current, social)
            if (grant is None or grant['schema'] != REMAINING_SCHEMA
                    or owner_name not in admission['receivers']
                    or expected_context_sha256 != contexts[owner_name]):
                raise ValueError
            attachment = current['runtime_observation']['admission_remaining_effects']
            helper = grant['maintenance'][owner_name]
            value = dict(schema='cluster-admission-execution-context/v1',
                reference=attachment['reference'], authorization_sha256=digest(grant),
                parent_operation_id=current['operation_id'], parent_intent_sha256=current['intent_hash'],
                original_vectors_sha256=grant['original_vectors_sha256'],
                social_operation_id=social['operation_id'], social_grant_sha256=grant['social_grant_sha256'],
                membership_sha256=grant['membership_sha256'], publication_identity_sha256=digest(grant['publication_identity']),
                effect=effect, owner_name=owner_name, owner_context_sha256=expected_context_sha256,
                command_sha256=digest(command), helper_code_digest=helper['code_digest'],
                helper_code_uid=helper['code_uid'], not_after_ms=grant['expires_at_ms'])
        except (KeyError, TypeError, ValueError, AttributeError):
            raise OnboardingError('onboarding_group_remaining_owner_context_required') from None
        yield value


@contextmanager
def remaining_reader(journal, parent: dict, effect: str, *, owner_name: str,
                     command: dict, expected_context_sha256: str):
    """Supply current evidence only within this host's actual dispatch scope.

    Host adapters call this reader immediately before publishing protected
    input/dispatching. Retaining its return value never retains its permission.
    """
    with remaining_projection(journal, parent, effect, owner_name=owner_name,
            command=command, expected_context_sha256=expected_context_sha256) as projection:
        active, process_id, thread_id = True, os.getpid(), threading.get_ident()
        def read():
            if not active or (os.getpid(), threading.get_ident()) != (process_id, thread_id):
                raise OnboardingError('onboarding_group_remaining_execution_scope_required')
            grant = execution(journal, parent, effect=effect)
            if grant is None or digest(grant) != projection['authorization_sha256']:
                raise OnboardingError('onboarding_group_remaining_execution_scope_required')
            return copy.deepcopy(projection)
        try:
            yield read
        finally:
            active = False


@contextmanager
def retain_execution_locks(journal, parent: dict, *, deadline_ns: int):
    """Retain parent/approval serialization until the actual owner horizon.

    Enter inside remaining_reader, after both current locks are acquired.
    The helper inherits duplicates only; the owner input remains public proof.
    """
    from .owner_process import lock_custody
    descriptors = []
    try:
        current = journal.get(parent['operation_id'])
        approval = current['runtime_observation']['admission_remaining_effects']['reference']['operation_id']
        for operation_id in (parent['operation_id'], approval):
            descriptors.append(journal.duplicate_mutation_lock(operation_id))
        with lock_custody(tuple(descriptors), deadline_ns=deadline_ns):
            yield
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def read_remaining_projection(path: Path, *, input_root: Path, expected_sha256: str,
                              effect: str, owner_name: str, command: dict,
                              expected_context_sha256: str, helper_code_digest: str,
                              helper_code_uid: int, now_ms: int) -> dict:
    """Bind a finite owner invocation to its verified read-only host input.

    The host must retain execution_scope through the invocation; this file is
    binding evidence, not a replacement for current protected journal authority.
    Receiving CLIs supply their fixed input root and independently qualified
    helper identity, never paths or helper pins supplied in the request body.
    """
    from .onboarding_release import regular
    try:
        if (not _sha(expected_sha256) or not path.is_absolute() or '..' in path.parts
                or path.parent != input_root or path.name != 'execution-'+expected_sha256+'.json'
                or not os.statvfs(input_root).f_flag & os.ST_RDONLY):
            raise ValueError
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ValueError
        return _projection_value(regular(path, uid=os.geteuid(), limit=65536),
            expected_sha256=expected_sha256, effect=effect, owner_name=owner_name, command=command,
            expected_context_sha256=expected_context_sha256, helper_code_digest=helper_code_digest,
            helper_code_uid=helper_code_uid, now_ms=now_ms)
    except (OSError, KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_remaining_owner_input_required') from None


def _projection_value(raw: bytes, *, expected_sha256: str, effect: str, owner_name: str,
                      command: dict, expected_context_sha256: str, helper_code_digest: str,
                      helper_code_uid: int, now_ms: int) -> dict:
    import json
    try:
        value = json.loads(raw)
        fields = {'schema', 'reference', 'authorization_sha256', 'parent_operation_id',
            'parent_intent_sha256', 'original_vectors_sha256', 'social_operation_id',
            'social_grant_sha256', 'membership_sha256', 'publication_identity_sha256',
            'effect', 'owner_name', 'owner_context_sha256', 'command_sha256',
            'helper_code_digest', 'helper_code_uid', 'not_after_ms'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['schema'] != 'cluster-admission-execution-context/v1'
                or digest(value) != expected_sha256 or effect not in REMAINING_EFFECTS
                or value['effect'] != effect or value['owner_name'] != owner_name
                or value['owner_context_sha256'] != expected_context_sha256
                or value['command_sha256'] != digest(command)
                or value['helper_code_digest'] != helper_code_digest
                or type(value['helper_code_uid']) is not int or value['helper_code_uid'] != helper_code_uid
                or type(value['not_after_ms']) is not int or not 0 < value['not_after_ms'] < 2**53
                or type(now_ms) is not int or not 0 < now_ms < value['not_after_ms']
                or any(not _sha(value[field]) for field in fields if field.endswith('_sha256')
                    or field == 'helper_code_digest')
                or set(value['reference']) != {'schema', 'operation_id', 'intent_sha256'}
                or value['reference']['schema'] != REMAINING_REFERENCE_SCHEMA
                or not _sha(value['reference']['intent_sha256'])
                or str(uuid.UUID(value['social_operation_id'])) != value['social_operation_id']
                or any('operation:'+str(uuid.UUID(identifier.removeprefix('operation:'))) != identifier
                    for identifier in (value['parent_operation_id'], value['reference']['operation_id']))):
            raise ValueError
        return value
    except (OSError, KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_remaining_owner_input_required') from None


@contextmanager
def sealed_remaining_input(reader):
    """Pass public evidence to a local receiving UID without sharing host state.

    Only the host root can produce this kernel-sealed input. Source retains its
    own SDK/custody and receives no host journal, credential or writable file.
    The caller keeps the current remaining_reader scope through the child call.
    """
    import fcntl
    import json
    if os.geteuid() != 0 or not callable(reader):
        raise OnboardingError('onboarding_group_remaining_owner_input_required')
    value = reader()
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    if not 0 < len(raw) <= 65536:
        raise OnboardingError('onboarding_group_remaining_owner_input_required')
    descriptor = os.memfd_create('cluster-owner-execution', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        pending = raw
        while pending:
            pending = pending[os.write(descriptor, pending):]
        os.fchmod(descriptor, 0o400)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        if reader() != value:
            raise OnboardingError('onboarding_group_remaining_owner_input_required')
        yield descriptor, digest(value)
    finally:
        os.close(descriptor)


def read_remaining_projection_fd(descriptor: int, **bindings) -> dict:
    """Accept only a root-created sealed public input inherited by local Source."""
    import fcntl
    try:
        if type(descriptor) is not int or descriptor < 3:
            raise ValueError
        info = os.fstat(descriptor)
        required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 0
                or not 0 < info.st_size <= 65536 or info.st_mode & 0o077
                or fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & required != required):
            raise ValueError
        raw = os.pread(descriptor, 65537, 0)
        if len(raw) != info.st_size:
            raise ValueError
        return _projection_value(raw, **bindings)
    except (OSError, KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_remaining_owner_input_required') from None
