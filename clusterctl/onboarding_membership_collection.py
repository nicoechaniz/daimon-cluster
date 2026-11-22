"""Retained model-free preparation through the existing owner clients."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import time
import uuid

from . import being_seed
from .onboarding import OnboardingError, digest, private_directory
from .onboarding_custody import document


def configuration(value):
    if (not isinstance(value, dict)
            or set(value) != {'state', 'participants', 'founder_owner', 'authoring_seconds'}
            or not isinstance(value['state'], str) or not Path(value['state']).is_absolute()
            or '..' in Path(value['state']).parts
            or not isinstance(value['participants'], list) or not 2 <= len(value['participants']) <= 16
            or any(not isinstance(name, str) or not being_seed.NAME.fullmatch(name)
                   for name in value['participants'])
            or value['participants'] != sorted(set(value['participants']))
            or value['founder_owner'] not in value['participants']
            or type(value['authoring_seconds']) is not int
            or not 60 <= value['authoring_seconds'] <= 3600):
        raise OnboardingError('onboarding_group_membership_compilation_required')
    return value


def collect(*, plan, selected, template, owners, identity, tribe_ref, deadline_ns, authorize):
    """Freeze once after actual identity, then resume only missing public reads.

    No participant signature, journal admission or native writer is created here.
    The original job's caller binds the resulting exact request separately.
    """
    from daimon_matrix.canonical import b64url
    from daimon_matrix.operator_messaging import public_authority_history
    from daimon_matrix.relationship_store import RelationshipView
    from daimon_matrix.relationships import INVITATION_SCHEMA, invitation_id
    from .onboarding_membership_intent import compile_request
    configuration(template)
    names = template['participants']
    if (plan['name'] not in names or template['founder_owner'] == plan['name']
            or set(owners) != set(names) or not set(names) <= set(selected)):
        raise OnboardingError('onboarding_group_membership_compilation_required')
    pins = digest(dict(plan=plan, owners={name: selected[name] for name in names},
        template=template, identity=identity, tribe_ref=tribe_ref))
    root = private_directory(Path(template['state']), create=True)

    def budget():
        if time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_host_deadline_expired')

    def save(path, value):
        budget()
        entries = list(root.iterdir())
        if (len(entries) > 8 or any(p.is_symlink() or not p.is_file() for p in entries)
                or sum(p.stat().st_size for p in entries if p != path)
                    + len(json.dumps(value).encode()) > 8*1024*1024):
            raise OnboardingError('onboarding_group_preparation_unavailable')
        being_seed._write(path, value, limit=8*1024*1024)

    def call(owner, command, closure):
        budget()
        previous = owner.deadline_ns
        owner.deadline_ns = min(previous, deadline_ns) if previous is not None else deadline_ns
        try:
            result = owner.group_publication(command, authority_closure=closure)
            budget()
            return result
        finally:
            owner.deadline_ns = previous

    with being_seed._locked(root):
        budget()
        if not authorize():
            raise OnboardingError('host_authorization_required')
        intent_path = root/'intent.json'
        if intent_path.exists():
            intent = document(intent_path)
            if (intent.get('schema') != 'cluster-membership-preparation-intent/v1'
                    or intent.get('pins') != pins):
                raise OnboardingError('onboarding_group_membership_compilation_required')
        else:
            intent = dict(schema='cluster-membership-preparation-intent/v1', pins=pins,
                operation_id=str(uuid.uuid5(uuid.NAMESPACE_URL, 'companion-membership:'+pins)),
                created_at_ms=time.time_ns()//1_000_000,
                nonce=b64url(os.urandom(32)))
            save(intent_path, intent)
        public_path, contexts_path, request_path = (root/name for name in
            ('public.json', 'contexts.json', 'request.json'))
        public = document(public_path) if public_path.exists() else {}
        contexts = document(contexts_path) if contexts_path.exists() else {}
        if not set(public) <= set(names) or not set(contexts) <= set(names):
            raise OnboardingError('onboarding_group_membership_compilation_required')
        for name in names:
            if name not in public:
                public[name] = call(owners[name], dict(operation_id=intent['operation_id'],
                    step='membership-preparation-preview', action='preparation-preview',
                    params=dict(tribe_ref=tribe_ref)), {})
                save(public_path, public)
        closure, receivers = {}, {}
        for name in names:
            value, row, owner = public[name], selected[name], owners[name]
            if (value.get('schema') != 'cluster-membership-preparation-preview/v1'
                    or value.get('operation_id') != intent['operation_id'] or value.get('tribe_ref') != tribe_ref
                    or value.get('receiving_readiness') != 'unobserved'
                    or value.get('governance_verified') is not False):
                raise OnboardingError('onboarding_group_membership_compilation_required')
            authority = public_authority_history(value['public']['authority'], value['public']['history'])
            ref = authority.active.manifest.being_ref
            authority.active.validate_origin(value['origin'], require_active=True)
            candidate = (dict(code=row['code'], digest=row['code_digest'])
                         if row['profile'] == 'source' else row['candidate'])
            startup = value.get('qualified_startup')
            if (ref != value.get('being_ref') or ref in closure or not isinstance(startup, dict)
                    or set(startup) != {'code_digest', 'matrix_wheel_sha256'}
                    or startup['code_digest'] != candidate['digest']
                    or not isinstance(startup['matrix_wheel_sha256'], str)
                    or re.fullmatch('[0-9a-f]{64}', startup['matrix_wheel_sha256']) is None):
                raise OnboardingError('onboarding_group_membership_compilation_required')
            closure[ref] = value['public']
            receivers[name] = dict(being_ref=ref, embodiment_id=value['origin']['embodiment_id'],
                root=str(owner.root), socket=str(owner.socket), candidate=dict(code=candidate['code'],
                    code_uid=row['code_uid'] if row['profile'] == 'source' else 0),
                recipe=dict(profile=row['profile'], prepared=dict(being_ref=ref,
                    embodiment_id=value['origin']['embodiment_id'], code_digest=candidate['digest'],
                    matrix_wheel_sha256=startup['matrix_wheel_sha256']), tooling={'profile': 'matrix-only'}))
        entrant = receivers[plan['name']]
        if any(entrant[key] != identity[key] for key in ('being_ref', 'embodiment_id')):
            raise OnboardingError('onboarding_group_membership_compilation_required')
        for name in names:
            if name not in contexts:
                result = call(owners[name], dict(operation_id=intent['operation_id'],
                    step='membership-context-preview', action='context-preview', params={}),
                    {ref: row for ref, row in closure.items() if ref != receivers[name]['being_ref']})
                if (result.get('operation_id') != intent['operation_id']
                        or result.get('runtime_bundle_sha256') != public[name]['runtime_bundle_sha256']
                        or not isinstance(result.get('owner_context_sha256'), str)
                        or re.fullmatch('[0-9a-f]{64}', result['owner_context_sha256']) is None):
                    raise OnboardingError('onboarding_group_membership_compilation_required')
                contexts[name] = result['owner_context_sha256']
                save(contexts_path, contexts)
        if 'issued_at_ms' not in intent:
            issued = time.time_ns()//1_000_000
            intent.update(issued_at_ms=issued, expires_at_ms=issued+template['authoring_seconds']*1000)
            save(intent_path, intent)
        founder = template['founder_owner']
        governance = public[founder]['governance']
        view = RelationshipView(governance, at_ms=intent['issued_at_ms'], card_verifier=None)
        tribe = view.tribes[tribe_ref]
        payload = dict(schema=INVITATION_SCHEMA, tribe_ref=tribe_ref,
            founder_epoch=tribe['founder_epoch'], founder_being_ref=receivers[founder]['being_ref'],
            invitee_being_ref=entrant['being_ref'], nonce=intent['nonce'],
            invitation_id=invitation_id(tribe=tribe_ref, founder_epoch=tribe['founder_epoch'],
                invitee_being_ref=entrant['being_ref'], nonce=intent['nonce']),
            issued_at_ms=intent['issued_at_ms'], expires_at_ms=intent['expires_at_ms'])
        senders = [dict(name=name, root=str(owners[name].root), socket=str(owners[name].socket),
            being_ref=receivers[name]['being_ref'], server=public[name]['origin'], process={}, gate=None)
            for name in names if name != plan['name']]
        admission = dict(schema='cluster-receiving-admission/v1', tribe_ref=tribe_ref,
            entrant=dict(being_ref=entrant['being_ref'], embodiment_ids=[entrant['embodiment_id']]),
            receivers=receivers, activation=dict(manifest_path=str(request_path), manifest_uid=os.geteuid(),
                expires_at_ms=intent['expires_at_ms'], observation_window_ms=60000))
        result = compile_request(plan=plan, owners=selected, admission=admission, senders=senders,
            governance=governance, authority_closure=closure, owner_contexts=contexts, invitation=payload,
            operation_id=intent['operation_id'], founder_owner=founder,
            source='maintained-membership-preparation-v1', acceptance_not_after_ms=intent['expires_at_ms'])
        if not authorize():
            raise OnboardingError('host_authorization_required')
        if request_path.exists():
            if document(request_path) != result:
                raise OnboardingError('onboarding_group_membership_compilation_required')
        else:
            save(request_path, result)
        return dict(path=str(request_path), sha256=digest(result))
