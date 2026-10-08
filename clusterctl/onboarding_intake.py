"""Turn prepared intake into exact plans under an explicit host policy.

The HTTP principal cannot choose resources or issue custody. Pair decisions
use the existing portal; a worker restart resumes the same frozen input.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import being_seed, onboarding_consent, onboarding_input, onboarding_release
from .onboarding import PLAN_SCHEMA, OnboardingError, digest, private_directory, validate_plan
from .onboarding_progress import Progress

POLICY = 'cluster-onboarding-intake-policy/v1'


def policy(path: Path, release_digest: str) -> dict:
    value = being_seed._read(path)
    if (set(value) != {'schema', 'release_digest', 'beings', 'revoked'}
            or value['schema'] != POLICY or value['release_digest'] != release_digest
            or type(value['revoked']) is not bool or not isinstance(value['beings'], dict)
            or len(value['beings']) > 100):
        raise OnboardingError('invalid_onboarding_intake_policy')
    for name, selection in value['beings'].items():
        if (not isinstance(name, str) or not being_seed.NAME.fullmatch(name)
                or not isinstance(selection, dict) or set(selection) != {'owner', 'account_profile', 'browser'}
                or any(not isinstance(selection[key], str) or not being_seed.NAME.fullmatch(selection[key])
                       for key in ('owner', 'account_profile')) or type(selection['browser']) is not bool):
            raise OnboardingError('invalid_onboarding_intake_policy')
    return value


def allows(config, plan: dict) -> bool:
    selected = policy(config.intake_policy, config.release_digest)
    entry = selected['beings'].get(plan['name'])
    return (selected['revoked'] is False and entry is not None
            and all(plan[key] == entry[key] for key in ('owner', 'account_profile', 'browser')))


class Intake:
    def __init__(self, config):
        self.config = config

    def once(self) -> None:
        config = self.config
        selected = policy(config.intake_policy, config.release_digest)
        if selected['revoked']:
            return
        if (config.inputs is None or config.code is None or config.progress is None
                or config.consent_state is None or config.consent_uid is None):
            raise OnboardingError('invalid_onboarding_host_configuration')
        release = onboarding_release.verify(config.code, config.release_digest, uid=os.geteuid())
        assert release['profile']
        private_directory(config.inputs)
        for name, entry in selected['beings'].items():
            try:
                self.prepare(name, entry)
            except FileNotFoundError:
                # A sleeping pair or an unfinished upload needs no intervention.
                continue
            except (OnboardingError, being_seed.SeedError, OSError, ValueError, KeyError, TypeError):
                # One malformed or interrupted intake must not starve another.
                progress = Progress(config.progress, worker_uid=os.geteuid())
                try:
                    previous = progress.read(name, owner=entry['owner'])
                except (OSError, ValueError):
                    continue
                if not previous['active']:
                    progress.publish({**previous, 'state': 'attention-required',
                        'reason': 'verification_failed', 'updated_ms': int(time.time() * 1000)})

    def prepare(self, name: str, entry: dict) -> dict | None:
        config = self.config
        directory = being_seed._directory(config.consent_state, name)
        for path in (config.consent_state, directory.parent, directory):
            being_seed._path(path)
            info = path.stat()
            if not path.is_dir() or info.st_uid != config.consent_uid or info.st_mode & 0o077:
                raise OnboardingError('private_onboarding_consent_required')
        record_path = directory / 'record.json'
        raw = onboarding_release.regular(record_path, uid=config.consent_uid, limit=65536)
        if record_path.stat().st_mode & 0o077:
            raise OnboardingError('private_onboarding_consent_required')
        record = json.loads(raw)
        if (record.get('schema') != being_seed.SCHEMA or record.get('name') != name
                or record.get('created_by') != entry['owner']):
            raise OnboardingError('onboarding_job_not_found')
        resume_marker = (record.get('phase') in {'preparing', 'attention-required'}
            and (record.get('preparation_queued') is True
                or (directory / 'received/preparation.json').exists()))
        if ((record.get('phase') == 'uploaded' or resume_marker)
                and (directory / 'preparation-request.json').exists()):
            # Root never decrypts or installs participant context as the intake
            # owner. Drop privileges for the maintained receiving tool, then
            # independently capture/verify the resulting frozen input below.
            permissions = {}
            if config.consent_uid != os.geteuid():
                if os.geteuid() != 0:
                    raise OnboardingError('private_onboarding_consent_required')
                permissions = dict(user=config.consent_uid,
                    group=config.consent_state.stat().st_gid, extra_groups=(), umask=0o077)
            launcher = ('import sys; sys.path.insert(0,sys.argv[1]); '
                'from clusterctl.being_seed import process_preparation; '
                'process_preparation(sys.argv[2],sys.argv[3],owner=sys.argv[4])')
            try:
                result = subprocess.run([sys.executable, '-B', '-I', '-c', launcher,
                    str(Path(__file__).resolve().parents[1]), str(config.consent_state),
                    name, entry['owner']], capture_output=True, timeout=being_seed.PREPARATION_TIMEOUT + 60, **permissions)
            except subprocess.TimeoutExpired:
                raise OnboardingError('onboarding_host_operation_failed') from None
            if result.returncode:
                raise OnboardingError('onboarding_host_operation_failed')
            record = json.loads(onboarding_release.regular(record_path,
                uid=config.consent_uid, limit=65536))
        if record.get('phase') != 'prepared':
            return None
        # Serialize intake-to-plan publication separately from job dispatch.
        with being_seed._locked(config.inputs):
            destination = config.inputs / name
            if (destination / 'manifest.json').exists():
                manifest = json.loads(onboarding_release.regular(destination / 'manifest.json',
                    uid=os.geteuid(), limit=onboarding_input.MAX_MANIFEST))
                fingerprint = digest(manifest)
                onboarding_input.verify(destination, fingerprint)
            else:
                fingerprint = onboarding_input.capture(directory / 'received', destination,
                    source_uid=config.consent_uid, resume=True)['seed_digest']
            plan = validate_plan(dict(schema=PLAN_SCHEMA, name=name, **entry,
                seed_digest=fingerprint, release_digest=config.release_digest))
            from .onboarding_custody import CustodyPolicy
            custody = CustodyPolicy(config.custody_policy) if config.custody_policy is not None else None
            if custody is not None and custody.value['revoked']:
                raise OnboardingError('identity_authorization_required')
            proposal = onboarding_consent.review(plan, (config.code / 'inheritance.md').read_text(),
                custody=custody.review() if custody is not None else None)
            reviews = onboarding_consent.Reviews(config.progress, worker_uid=os.geteuid())
            reviews.publish(proposal)
            from .onboarding_approvals import decision as owner_decision
            decision = owner_decision(config, proposal)
            if custody is not None and decision is not None:
                if config.custody_grants is None:
                    raise OnboardingError('identity_authorization_required')
                custody.issue(plan, proposal, decision, config.custody_grants)
            grant_path = config.grants / (name + '.json')
            grant = dict(schema='cluster-onboarding-host-grant/v1', plan=plan, revoked=False)
            if grant_path.exists():
                if being_seed._read(grant_path) != grant:
                    raise OnboardingError('existing_onboarding_grant_preserved')
            else:
                # The operator already authorized this seed's 30 GiB resources.
                # Preparing its empty environment need not wait for inheritance
                # review. Context and Matrix dispatch still require the exact
                # pair decision; a resource grant never creates native custody.
                if not allows(config, plan):
                    raise OnboardingError('host_authorization_required')
                being_seed._write(grant_path, grant)
            return plan
