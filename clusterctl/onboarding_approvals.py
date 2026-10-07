"""Preserve delegated pair approvals recorded by the local human operator.

The operator policy is separate from resources and from participant intake.
It pins the reviewed Source text and custody notice, identifies each pair and
retains human-instruction attribution. HTTP or archive content cannot issue it.
"""
from __future__ import annotations

import os
import re
import hashlib
import json
from pathlib import Path

from . import being_seed, onboarding_consent
from .onboarding import OnboardingError, digest, private_directory
from .onboarding_custody import document
from .onboarding_progress import Progress
from .onboarding_service import publish
from . import onboarding_release

SCHEMA = 'cluster-onboarding-owner-approval-policy/v1'


def configure(config, path: Path, pairs: dict, *, instruction: Path,
              instruction_uid: int, recorded_by: str) -> dict:
    """Publish the local human's already-approved terms, without intake writes."""
    from .onboarding_custody import CustodyPolicy
    from .onboarding_intake import policy
    if config.custody_policy is None or config.intake_policy is None or config.code is None:
        raise OnboardingError('invalid_onboarding_owner_approval_policy')
    raw = onboarding_release.regular(instruction, uid=instruction_uid, limit=65536)
    if not raw.strip() or instruction.stat().st_mode & 0o077:
        raise OnboardingError('private_onboarding_instruction_required')
    permitted = policy(config.intake_policy, config.release_digest)['beings']
    if (not isinstance(pairs, dict) or not pairs or any(name not in permitted
            or not isinstance(entry, dict) or entry.get('owner') != permitted[name]['owner']
            for name, entry in pairs.items())):
        raise OnboardingError('invalid_onboarding_owner_approval_policy')
    custody = CustodyPolicy(config.custody_policy)
    if custody.value['revoked']:
        raise OnboardingError('identity_authorization_required')
    selected = dict(schema=SCHEMA, source_digest=hashlib.sha256(
        (config.code / 'inheritance.md').read_bytes()).hexdigest(),
        custody_policy_digest=custody.review()['policy_digest'],
        human_instruction_digest=hashlib.sha256(raw).hexdigest(), recorded_by=recorded_by,
        pairs=pairs, revoked=False)
    # Validate before publication with the same grammar as the worker.
    validate_policy(selected)
    publish(path, json.dumps(selected, sort_keys=True).encode())
    return dict(configured=True, pairs=sorted(pairs), recorded_by=recorded_by)


def validate_policy(value: object) -> dict:
    if (not isinstance(value, dict) or set(value) != {'schema', 'source_digest', 'custody_policy_digest',
                      'human_instruction_digest', 'recorded_by', 'pairs', 'revoked'}
            or value['schema'] != SCHEMA or type(value['revoked']) is not bool
            or not isinstance(value['recorded_by'], str)
            or not being_seed.NAME.fullmatch(value['recorded_by'])
            or any(not isinstance(value[k], str) or not re.fullmatch(r'[0-9a-f]{64}', value[k])
                   for k in ('source_digest', 'custody_policy_digest', 'human_instruction_digest'))
            or not isinstance(value['pairs'], dict) or len(value['pairs']) > 100):
        raise OnboardingError('invalid_onboarding_owner_approval_policy')
    for name, entry in value['pairs'].items():
        if (not isinstance(name, str) or not being_seed.NAME.fullmatch(name)
                or not isinstance(entry, dict) or set(entry) != {'owner', 'matrix_identity_mode'}
                or not isinstance(entry['owner'], str) or not being_seed.NAME.fullmatch(entry['owner'])
                or not isinstance(entry['matrix_identity_mode'], str)
                or entry['matrix_identity_mode'] not in {'first', 'existing'}):
            raise OnboardingError('invalid_onboarding_owner_approval_policy')
    return value


def validate_status(value: object) -> dict:
    if (not isinstance(value, dict) or set(value) != {'schema', 'name', 'owner', 'review_digest',
            'recorded', 'matrix_identity_mode', 'recorded_by'}
            or value['schema'] != 'cluster-onboarding-approval-status/v1'
            or any(not isinstance(value[k], str) or not being_seed.NAME.fullmatch(value[k])
                   for k in ('name', 'owner'))
            or not isinstance(value['review_digest'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', value['review_digest'])
            or type(value['recorded']) is not bool):
        raise OnboardingError('invalid_onboarding_approval_status')
    if value['recorded']:
        if (not isinstance(value['matrix_identity_mode'], str)
                or value['matrix_identity_mode'] not in {'first', 'existing'}
                or not isinstance(value['recorded_by'], str)
                or not being_seed.NAME.fullmatch(value['recorded_by'])):
            raise OnboardingError('invalid_onboarding_approval_status')
    elif value['matrix_identity_mode'] is not None or value['recorded_by'] is not None:
        raise OnboardingError('invalid_onboarding_approval_status')
    return value


class Status(Progress):
    suffix = '.approval.json'
    validate = staticmethod(validate_status)


class Approvals:
    def __init__(self, path: Path):
        self.path = path
        self.value = validate_policy(document(path))

    def decision(self, proposal: dict, state: Path) -> dict | None:
        proposal = onboarding_consent.validate_review(proposal)
        value = self.value
        entry = value['pairs'].get(proposal['name'])
        if value['revoked'] or entry is None or entry['owner'] != proposal['owner']:
            return None
        if (proposal['source_digest'] != value['source_digest']
                or proposal.get('matrix_custody', {}).get('policy_digest') != value['custody_policy_digest']):
            return None
        decision = onboarding_consent._expected(proposal, dict(
            review_digest=proposal['review_digest'], inheritance_approved=True,
            matrix_identity_mode=entry['matrix_identity_mode']))
        record = dict(schema='cluster-onboarding-delegated-owner-approval/v1',
                      execution_uid=os.geteuid(), recorded_by=value['recorded_by'],
                      human_instruction_digest=value['human_instruction_digest'],
                      approval_policy_digest=digest(value), decision=decision)
        directory = private_directory(state / 'delegated-owner-approvals', create=True)
        path = directory / (proposal['review_digest'] + '.json')
        with being_seed._locked(directory):
            if path.exists():
                previous = document(path)
                # A successor may reconcile another pair's existing identity.
                # Preserve this pair's original attribution and policy digest
                # when its exact approved decision and human instruction match.
                if (set(previous) != set(record)
                        or any(previous[key] != item for key, item in record.items()
                               if key != 'approval_policy_digest')
                        or not isinstance(previous['approval_policy_digest'], str)
                        or not re.fullmatch(r'[0-9a-f]{64}', previous['approval_policy_digest'])):
                    raise OnboardingError('existing_onboarding_approval_preserved')
            else:
                being_seed._write(path, record)
        return decision


def decision(config, proposal: dict) -> dict | None:
    """Prefer the participant's decision; retain the real delegated author."""
    value = onboarding_consent.read(config.consent_state, proposal, intake_uid=config.consent_uid)
    recorded_by = proposal['owner'] if value is not None else None
    path = getattr(config, 'owner_approval_policy', None)
    if value is None and path is not None:
        approvals = Approvals(path)
        value = approvals.decision(proposal, config.grants)
        recorded_by = approvals.value['recorded_by'] if value is not None else None
    if getattr(config, 'progress', None) is not None:
        status = dict(schema='cluster-onboarding-approval-status/v1', name=proposal['name'],
                      owner=proposal['owner'], review_digest=proposal['review_digest'],
                      recorded=value is not None, recorded_by=recorded_by,
                      matrix_identity_mode=value['matrix_identity_mode'] if value else None)
        projection = Status(config.progress, worker_uid=os.geteuid())
        try:
            previous = projection.read(proposal['name'], owner=proposal['owner'])
        except FileNotFoundError:
            previous = None
        if previous != status:
            projection.publish(status)
    return value
