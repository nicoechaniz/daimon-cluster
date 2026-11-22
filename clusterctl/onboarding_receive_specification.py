"""Compile own receive application inputs from retained native signed membership.

Pure preparation: no resource key generation, file/custody access, native RPC,
publication, service selection or model. Existing owner writers apply the result.
"""
from __future__ import annotations

import copy
import json
from pathlib import PurePosixPath

from .onboarding import OnboardingError, digest


def compile_specification(*, runtime: dict, runtime_root: str, authorities: dict,
                          governance: list, tribe_ref: str, policy: dict, listen: dict,
                          intake: dict, roster: list, stores: dict, at_ms: int,
                          authority_order: list[str] | None = None) -> dict:
    """Retain explicit own store/routing choices, deriving no adult private state.

    The caller supplies an owner-authorized public authority closure and actual
    runtime bundle. Native signatures/reducer prove membership, not permission
    to install. No expiry is extended, no Telegram/outbound proof is required.
    """
    from daimon_matrix.messaging_config import APPLICATION_SCHEMA_V3, validate_shape
    from daimon_matrix.operator_messaging import public_authority_history
    from daimon_matrix.relationship_store import RelationshipView
    from daimon_matrix.weave import verify_event
    try:
        if (not isinstance(runtime_root, str) or not PurePosixPath(runtime_root).is_absolute()
                or '..' in PurePosixPath(runtime_root).parts
                or type(at_ms) is not int or at_ms <= 0
                or not isinstance(authorities, dict) or not 1 <= len(authorities) <= 64
                or not isinstance(governance, list) or not 1 <= len(governance) <= 256
                or len(json.dumps(governance).encode()) > 1024**2
                or not isinstance(roster, list) or not 1 <= len(roster) <= 64
                or not isinstance(policy, dict) or set(policy) != {'classification', 'max_ttl_ms'}
                or policy['classification'] != 'shareable'):
            raise ValueError
        order = sorted(authorities) if authority_order is None else authority_order
        if (not isinstance(order, list) or len(order) != len(authorities)
                or any(not isinstance(ref, str) for ref in order)
                or len(set(order)) != len(order) or set(order) != set(authorities)):
            raise ValueError
        public, resolved = [], {}
        for ref in order:
            value = authorities[ref]
            if not isinstance(value, dict) or set(value) != {'authority', 'history'}:
                raise ValueError
            authority = public_authority_history(value['authority'], value['history'])
            if authority.active.manifest.being_ref != ref:
                raise ValueError
            resolved[ref] = authority
            public.append(copy.deepcopy(value['authority']))
        own_ref = runtime['manifest']['being_ref']
        own = resolved[own_ref]
        origin = runtime['local_origin']
        own.active.validate_origin(origin, require_active=True)
        # A different self-consistent public manifest must not substitute for
        # this actual runtime's current signed identity.
        from .onboarding_group_admission import public_authorities
        own_context = {key:value for key,value in authorities.items() if key != own_ref}
        public_authorities(runtime, own_context)
        from daimon_matrix.operator_rebirth import authority_from_runtime_bundle
        actual = authority_from_runtime_bundle(runtime)
        if (actual.manifest.digest != own.active.manifest.digest
                or actual.state.head != own.active.state.head
                or actual.credentials != own.active.credentials
                or actual.incarnations != own.active.incarnations
                or digest(authorities[own_ref]['history']) != digest(runtime['authority_history'])):
            raise ValueError
        seen = set()
        for event in governance:
            if (not isinstance(event, dict) or event.get('sensitivity') != 'shareable'
                    or event['payload']['tribe_ref'] != tribe_ref or event['event_id'] in seen):
                raise ValueError
            seen.add(event['event_id'])
            verify_event(event, resolved[event['being_ref']])
        view = RelationshipView(governance, at_ms=at_ms, card_verifier=None)
        if len(view.complete) != len(governance):
            raise ValueError
        members = view.tribes[tribe_ref]['memberships']
        membership = members[own_ref]
        if membership['state'] != 'active':
            raise ValueError
        bodies, own_rows = set(), []
        for row in roster:
            ref = row['being_ref']
            if members.get(ref, {}).get('state') != 'active':
                raise ValueError
            body = (ref, row['embodiment_id'])
            if body in bodies:
                raise ValueError
            bodies.add(body)
            # Validate actual active coordinates against this being's own public
            # authority; ancestry/shared account can never stand in for identity.
            authorized = resolved[ref].active
            origins = [value for value in authorized.manifest.value['embodiments']
                if value['embodiment_id'] == row['embodiment_id']
                and value['body_ref'] == row['body_ref'] and value['status'] == 'active']
            if not origins:
                raise ValueError
            if ref == own_ref and row['embodiment_id'] == origin['embodiment_id']:
                if row['body_ref'] != origin['body_ref']:
                    raise ValueError
                own_rows.append(row)
        if len(own_rows) != 1:
            raise ValueError
        if any(intake[key] != own_rows[0]['route'][key] for key in (
                'provider_ref', 'route_ref', 'key_ref', 'secret_file', 'secret_sha256')):
            raise ValueError
        result = dict(schema=APPLICATION_SCHEMA_V3, listen=copy.deepcopy(listen),
            authorities=public, relationship_events=copy.deepcopy(governance),
            relationship_mode=dict(mode='shared', runtime_id=runtime['runtime_id'], state_root=runtime_root,
                store_filename=runtime['relationships']['store_filename']),
            tribe=dict(channel_id='tribe', policy=dict(tribe_ref=tribe_ref,
                membership_ref=membership['membership_event']['event_id'], **policy)),
            intake=copy.deepcopy(intake), roster=copy.deepcopy(roster), stores=copy.deepcopy(stores))
        validate_shape(result, specification=True)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('receive_specification_signed_membership_required') from None
    return result


def compile_controller_manifest(*, template: dict, target: dict, authority_closure: dict,
                                baseline: dict, snapshot: dict, code_digest: str) -> dict:
    """Derive public controller pins from the original retained receive result.

    The owner selects the code/contract template. Actual signed authorities and
    the six current selection pins come from this admitted job, not a copied
    companion descriptor. This compiles data only; native preflight still checks
    the qualified candidate before any service or custody operation.
    """
    import re
    from daimon_matrix.operator_messaging import public_authority_history
    from daimon_matrix.release_compatibility import validate_release
    from daimon_matrix.operator_rebirth import RebirthError
    try:
        if (not isinstance(template, dict) or len(json.dumps(template).encode()) > 2*1024**2
                or not isinstance(authority_closure, dict) or not 1 <= len(authority_closure) <= 64
                or set(target) != {'being_ref', 'embodiment_id'}
                or set(baseline) != {'receiving_code', 'matrix_sdk', 'runtime_bundle_sha256'}
                or snapshot.get('outbound_release') is not False
                or not isinstance(code_digest, str) or re.fullmatch('[0-9a-f]{64}', code_digest) is None):
            raise ValueError
        # Validate the selected template as supplied before deriving any fields.
        value = validate_release(template, expected_digest=digest(template))
        if (set(value['artifacts']) != {'matrix_sdk'}
                or value['artifacts']['matrix_sdk'] != baseline['matrix_sdk']):
            raise ValueError
        rows = []
        for ref in sorted(authority_closure):
            entry = authority_closure[ref]
            authority = public_authority_history(entry['authority'], entry['history']).active
            if authority.manifest.being_ref != ref:
                raise ValueError
            if ref == target['being_ref'] and not any(
                    body['embodiment_id'] == target['embodiment_id'] and body['status'] == 'active'
                    for body in authority.manifest.value['embodiments']):
                raise ValueError
            rows.append(dict(being_ref=ref, manifest_hash=authority.manifest.digest,
                             control_head=authority.state.head))
        if target['being_ref'] not in authority_closure:
            raise ValueError
        group = snapshot['group']
        selection = dict(baseline, application_sha256=group['application_sha256'],
            publication_sha256=group['publication_sha256'], visibility_installation_sha256=None)
        if any(not isinstance(v, str) or re.fullmatch('[0-9a-f]{64}', v) is None
               for k,v in selection.items() if k != 'visibility_installation_sha256'):
            raise ValueError
        value['authorities'] = dict(current=copy.deepcopy(rows), candidate=copy.deepcopy(rows))
        value['required_receivers'] = [dict(target, expected_selection_sha256=digest(selection),
            artifacts=dict(receiving_code=code_digest))]
        return validate_release(value, expected_digest=digest(value))
    except (KeyError, TypeError, ValueError, AttributeError, RebirthError):
        raise OnboardingError('companion_controller_signed_preparation_required') from None
