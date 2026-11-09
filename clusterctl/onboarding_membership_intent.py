"""Compile fixed signed-membership inputs into the existing original-job intent.

This is preparation only. The caller retains the invitation and current public
observations; compilation never creates a nonce, changes a deadline, signs an
event, opens custody, dispatches a request or selects a running group.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re

from . import being_seed
from .onboarding import JobStore, OnboardingError, digest, validate_plan


def compile_request(*, plan: dict, owners: dict, admission: dict, senders: list,
                    governance: list, authority_closure: dict, owner_contexts: dict,
                    invitation: dict, operation_id: str, founder_owner: str,
                    source: str, acceptance_not_after_ms: int) -> dict:
    """Use verified native governance, not names or a publication prerequisite.

    Inputs are owner-selected preparation evidence, not intake authorization.
    The existing coordinator still requires the original job/custody grants and
    the native writer's current authoring precondition before actual effects.
    Historical inputs compile unchanged, including expired invitations; they
    cannot acquire a fresh authoring window by calling this function again.
    """
    from daimon_matrix.relationship_store import RelationshipView
    from .onboarding_group_admission import membership_recipe
    from .onboarding_group_coordinator import SOCIAL_CALLER_SCHEMA
    from .onboarding_receiving_update import CohortController

    try:
        plan = validate_plan(plan)
        name = plan['name']
        receivers = admission['receivers']
        old = [row['name'] for row in senders]
        if (not isinstance(owners, dict) or not isinstance(receivers, dict)
                or not 2 <= len(receivers) <= 256
                or not set(receivers) <= set(owners)
                or old != sorted(set(old)) or set(receivers) - set(old) != {name}
                or founder_owner not in old
                or owners[name]['profile'] != 'guest' or owners[name]['plan'] != plan
                or admission['schema'] != 'cluster-receiving-admission/v1'
                or not isinstance(source, str) or re.fullmatch('[a-zA-Z0-9._-]{1,80}', source) is None
                or not isinstance(governance, list) or not 1 <= len(governance) <= 256):
            raise ValueError
        identities = set()
        for owner_name, receiver in receivers.items():
            selected = owners[owner_name]
            profile = selected['profile']
            candidate = (dict(code=selected['code'], digest=selected['code_digest'])
                         if profile == 'source' else selected['candidate'])
            identity = (receiver['being_ref'], receiver['embodiment_id'])
            if (profile not in {'source', 'guest'} or identity in identities
                    or receiver['root'] != selected['root']
                    or receiver['candidate']['code'] != candidate['code']
                    or receiver['recipe']['profile'] != profile
                    or receiver['recipe']['prepared']['code_digest'] != candidate['digest']
                    or any(receiver['recipe']['prepared'][key] != receiver[key]
                           for key in ('being_ref', 'embodiment_id'))
                    or receiver['recipe']['tooling'] != {'profile': 'matrix-only'}):
                raise ValueError
            identities.add(identity)
        entrant = receivers[name]
        if admission['entrant'] != dict(being_ref=entrant['being_ref'],
                                        embodiment_ids=[entrant['embodiment_id']]):
            raise ValueError
        for sender in senders:
            receiver = receivers[sender['name']]
            if (set(sender) != {'name', 'root', 'socket', 'being_ref', 'server', 'process', 'gate'}
                    or any(sender[key] != receiver[key] for key in ('root', 'socket', 'being_ref'))
                    or sender['server']['embodiment_id'] != receiver['embodiment_id']):
                raise ValueError
        # Derive episode coordinates from the same native reducer used by the
        # final signature/closure validator below; never invent episode zero.
        view = RelationshipView(governance, at_ms=invitation['issued_at_ms'], card_verifier=None)
        tribe = view.tribes[admission['tribe_ref']]
        previous = tribe['memberships'].get(entrant['being_ref'])
        episodes = [] if previous is None else previous['episodes']
        terminal = None if not episodes else episodes[-1].get('terminal_event')
        social = dict(schema='cluster-membership-admission/v1', operation_id=operation_id,
            founder_owner=founder_owner, entrant_owner=name, authority_closure=authority_closure,
            governance=governance, invitation=invitation, membership_sequence=len(episodes),
            previous_membership_terminal_ref=None if terminal is None else dict(
                event_id=terminal['event_id'], event_hash=terminal['content_hash']),
            acceptance_not_after_ms=acceptance_not_after_ms, owner_contexts=owner_contexts)
        social = membership_recipe(social, admission, senders)
        before = dict(tribe_ref=admission['tribe_ref'], senders=senders,
                      receiver_selections={owner_name: None for owner_name in receivers})
        after = dict(cohort_admission=admission, portal_admission=dict(
            schema=SOCIAL_CALLER_SCHEMA, plan_digest=digest(plan),
            matrix_operation_id=JobStore.operation_id(digest(plan), 'matrix'),
            owners_sha256=digest({owner_name: owners[owner_name] for owner_name in receivers}),
            social=social), membership_only={'schema': 'cluster-native-membership-only/v1'})
        result = dict(schema='cluster-native-membership-only-request/v1', source=source,
                      name=name, original_plan_digest=digest(plan), before=before, after=after)
        locations = {owner_name: dict(root=owners[owner_name]['root'],
            socket=owners[owner_name]['socket_path'] if owners[owner_name]['profile'] == 'source'
            else str(Path(owners[owner_name]['root'])/'tribe.sock')) for owner_name in receivers}
        CohortController.validate_admission(dict(target='receiving:'+admission['tribe_ref'],
            expected_precondition=before, intended_transition=after), locations, senders)
        if len(json.dumps(result).encode()) > being_seed.MAX_SELECTION:
            raise ValueError
        digest(result)
    except (KeyError, TypeError, ValueError, AttributeError, OnboardingError):
        raise OnboardingError('onboarding_group_membership_compilation_required') from None
    return copy.deepcopy(result)
