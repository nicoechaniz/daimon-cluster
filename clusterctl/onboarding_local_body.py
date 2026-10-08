"""Finite owner-scoped checks of an existing local Codex body.

Requests are host-owned. Participant reports preserve evidence and never issue
Root custody, a new identity, account permission or hosted acceptance.
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from . import being_seed, onboarding_peer
from .onboarding import OnboardingError, digest, private_directory
from .onboarding_progress import Progress

SCHEMA = 'cluster-onboarding-local-body-request/v1'
REPORT = 'cluster-onboarding-local-body-report/v1'
DIAGNOSTIC = 'cluster-onboarding-local-body-diagnostic/v1'
DIAGNOSTIC_LIMIT = 60000
_CREDENTIAL = re.compile(r'-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY)|\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|[0-9]{6,15}:[A-Za-z0-9_-]{30,})\b')
CHECKS = {
    'identity_context': 'Verify Codex loads your own SOUL and being identity, preserving the original history.',
    'memory': 'Retrieve one older and one recent own memory through the configured local HMK binding.',
    'cli_resume': 'Verify your existing local Codex conversation can be resumed.',
    'matrix_owner_client': 'Check the existing authenticated owner client status for your local body. Do not read an inbox.',
}
RESULTS = {'passed', 'missing', 'failed', 'not-checked'}


def validate(value: object) -> dict:
    if (not isinstance(value, dict) or set(value) != {'schema', 'name', 'owner', 'request_id',
            'expected_being_ref', 'updated_ms'} or value['schema'] != SCHEMA
            or any(not isinstance(value[key], str) or not being_seed.NAME.fullmatch(value[key])
                   for key in ('name', 'owner'))
            or not isinstance(value['request_id'], str)
            or type(value['updated_ms']) is not int or value['updated_ms'] < 0
            or value['expected_being_ref'] is not None and (not isinstance(value['expected_being_ref'], str)
                or not re.fullmatch(r'dm:being:v1:[A-Za-z0-9_-]{43}', value['expected_being_ref']))):
        raise OnboardingError('invalid_local_body_request')
    try:
        if str(uuid.UUID(value['request_id'])) != value['request_id']:
            raise ValueError
    except ValueError as exc:
        raise OnboardingError('invalid_local_body_request') from exc
    return value


class Requests(Progress):
    suffix = '.local-body.json'
    validate = staticmethod(validate)


class Guidance(Progress):
    """Host-owned participant steps, separate from reports and authority."""
    suffix = '.local-body-guidance.json'

    @staticmethod
    def validate(value: object) -> dict:
        if (not isinstance(value, dict) or set(value) != {
                'schema', 'name', 'owner', 'request_id', 'updated_ms', 'steps'}
                or value['schema'] != 'cluster-onboarding-local-guidance/v1'
                or any(not isinstance(value[k], str) or not being_seed.NAME.fullmatch(value[k])
                       for k in ('name', 'owner'))
                or not isinstance(value['request_id'], str)
                or type(value['updated_ms']) is not int or value['updated_ms'] < 0
                or not isinstance(value['steps'], list) or not 1 <= len(value['steps']) <= 12
                or any(not isinstance(step, str) or not 1 <= len(step) <= 4000
                       for step in value['steps'])):
            raise OnboardingError('invalid_local_body_guidance')
        try:
            if str(uuid.UUID(value['request_id'])) != value['request_id']:
                raise ValueError
        except ValueError as exc:
            raise OnboardingError('invalid_local_body_guidance') from exc
        return value


def guidance(progress: Path, request: dict, *, worker_uid: int) -> dict | None:
    try:
        value = Guidance(progress, worker_uid=worker_uid).read(request['name'], owner=request['owner'])
        return value if value['request_id'] == request['request_id'] else None
    except FileNotFoundError:
        return None


def _directory(state: Path, request: dict, *, create: bool = False) -> Path:
    parent = state / 'local-body-reports'
    if create:
        private_directory(parent, create=True)
    root = parent / request['name']
    if create:
        private_directory(root, create=True)
    return being_seed._path(root)


def _summary(report: dict) -> dict:
    identity = report['matrix_identity']
    origin = identity['document']['origin'] if identity is not None else None
    return dict(request_id=report['request_id'], checked_at_ms=report['checked_at_ms'],
        checks=report['checks'], matrix_state=report['matrix_state'],
        identity_verified=identity is not None,
        being_ref=identity['document']['authority']['manifest']['being_ref'] if identity is not None else None,
        body_ref=origin['body_ref'] if origin is not None else None,
        codex_matrix_body_verified=origin is not None and origin['body_ref'].startswith('codex:'),
        evidence_scope='participant-local report; signed identity independently verified; local checks self-reported',
        hosted_acceptance=False)


def read(state: Path, request: dict) -> dict:
    request = validate(request)
    root = _directory(state, request)
    try:
        pointer = being_seed._read(root / 'latest.json')
        fingerprint = pointer['report_digest']
        if not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint):
            raise OnboardingError('invalid_local_body_report')
        report = being_seed._read(root / (fingerprint + '.json'))
        if digest(report) != fingerprint:
            raise OnboardingError('invalid_local_body_report')
        summary = _summary(report) if report['request_id'] == request['request_id'] else None
    except FileNotFoundError:
        summary = None
    try:
        seed = being_seed.status(state, request['name'], owner=request['owner'])
        received = dict(context_prepared=seed['phase'] == 'prepared', archive_received=seed['archive_sha256'] is not None,
            receiving_selection_received=seed['phase'] == 'prepared' or seed.get('preparation_queued') is True,
            ssh_key_received=seed['ssh'].startswith('key supplied'),
            telegram_data_received=seed['telegram'].startswith('data supplied'))
    except being_seed.SeedError as exc:
        if exc.status != 404:
            raise
        received = dict(context_prepared=False, archive_received=False, receiving_selection_received=False,
            ssh_key_received=False, telegram_data_received=False)
    pending = []
    if not received['archive_received']:
        pending.append('archive')
    if not received['receiving_selection_received']:
        pending.append('receiving_selection_and_preparation')
    if not received['telegram_data_received']:
        pending.append('telegram_bot_and_destination')
    if not received['ssh_key_received']:
        pending.append('ssh_public_key')
    source = state / 'existing-enrollment' / request['name'] / 'source.json'
    if request['expected_being_ref'] is not None and not source.exists():
        pending.append('signed_existing_matrix_source')
    return {**request, 'checks': CHECKS, 'report': summary, 'received': received,
        'pending_inputs': pending,
        'host_tasks': ['context_preparation'] if received['receiving_selection_received'] and not received['context_prepared'] else [],
        'pending_actions': {key: value for key, value in {
            'receiving_selection_and_preparation': dict(method='POST', path='/v1/seeds/' + request['name'] + '/prepare',
                meaning='Submit the active own SOUL and authorized memory selection with defer:true. Historical skills stay preserved; select no working copies unless reviewed.'),
            'telegram_bot_and_destination': dict(method='POST', path='/v1/seeds/' + request['name'] + '/connections',
                fields=['telegram_bot_token', 'telegram_chat_id'], meaning='Send this hosted body dedicated bot token and destination through authenticated private HTTPS. Do not consume another body bot.'),
            'ssh_public_key': dict(method='POST', path='/v1/seeds/' + request['name'] + '/connections', fields=['ssh_public_key']),
            'signed_existing_matrix_source': dict(method='POST', path='/v1/onboarding/local-body/' + request['name'] + '/enrollment',
                fields=['schema', 'request_id', 'identity', 'routes'], meaning='Public signed identity and explicit existing-body routes only; keep Root custody and passwords local.'),
        }.items() if key in pending},
        'diagnostic': diagnostic_summary(state, request),
        'diagnostic_path': '/v1/onboarding/local-body/' + request['name'] + '/diagnostic',
        'enrollment_path': '/v1/onboarding/local-body/' + request['name'] + '/enrollment',
        'instructions': [
            'Continue your existing local Codex installation and this workspace; do not reinstall or re-export received context.',
            'Keep the already selected shared account and recorded human approvals.',
            'Reuse the public signed identity already verified in your local report; the enrollment endpoint returns it as source_identity. Do not repeat its export. Only missing identities need the existing-body public exporter.',
            'For an owner messaging application, pass its existing directory as --messaging-application together with its --visibility-installation. The signed owner installation binds the application, not the bare runtime.',
            'Use its existing authority. A Hermes identity proves that being, but does not prove a local Codex embodiment exists.',
            'An existing Hermes being can receive a hosted Codex body without first enrolling another local Codex body. Preserve local checks separately from hosted acceptance.',
            'Respect the local daemon writer lock. Keep Matrix custody, private keys, passwords and provider credentials local. Send only the hosted body dedicated bot token through the authenticated private connections endpoint, never in a diagnostic, public source packet or command argument.',
            'If no identity can be found, report not-found; do not create another Root to satisfy this check.',
            'If an exporter or local check is blocked, send its nonsecret reproducible JSON report through diagnostic_path. Do not repeat an archive already received. Preserve originals and credential-bearing history while the host resolves the blocker.',
            'Submit results through the response_path. A missing check is useful evidence, not a request for Nicolas to relay technical details.',
        ], 'response_path': '/v1/onboarding/local-body/' + request['name'],
        'export_tools': {'exporter': '/v1/onboarding/local-body/tools/export_local_matrix_identity.py',
            'native_peer': '/v1/onboarding/local-body/tools/onboarding_peer_native.py',
            'native_peer_sha256': onboarding_peer.TOOL_SHA256,
            'usage': 'Use the qualified Matrix Python for the existing body. exporter --runtime-root LOCAL_ROOT --password-file LOCAL_PASSWORD --output PRIVATE_PUBLIC_JSON [--visibility-installation EXISTING_INSTALLATION [--messaging-application EXISTING_APPLICATION]]. Keep local paths and custody local; restore an owner-controlled daemon after any finite offline export.'}}


def submit(state: Path, request: dict, value: object, *, code: Path | None = None, code_uid: int | None = None) -> dict:
    request = validate(request)
    if (not isinstance(value, dict) or set(value) != {'schema', 'request_id', 'checked_at_ms',
            'checks', 'matrix_state', 'matrix_identity'} or value['schema'] != REPORT
            or value['request_id'] != request['request_id']
            or type(value['checked_at_ms']) is not int or value['checked_at_ms'] < request['updated_ms']
            or not isinstance(value['checks'], dict) or set(value['checks']) != set(CHECKS)
            or any(not isinstance(result, str) or result not in RESULTS for result in value['checks'].values())
            or value['matrix_state'] not in {'signed-identity', 'not-found', 'unavailable'}
            or (value['matrix_state'] == 'signed-identity') != isinstance(value['matrix_identity'], dict)
            or value['matrix_state'] != 'signed-identity' and value['matrix_identity'] is not None):
        raise being_seed.SeedError('invalid_local_body_report')
    if len(json.dumps(value).encode()) > being_seed.MAX_RECORD:
        raise being_seed.SeedError('local_body_report_too_large')
    if value['matrix_identity'] is not None:
        tool = onboarding_peer.native(code or Path(__file__).resolve().parents[1],
            uid=Path(__file__).stat().st_uid if code_uid is None else code_uid)
        try:
            authority = tool.verify_identity(value['matrix_identity'])
            expected = request['expected_being_ref']
            if expected is not None and authority.state.being_ref != expected:
                raise ValueError
        except (ValueError, KeyError, TypeError) as exc:
            raise being_seed.SeedError('local_body_signed_identity_required') from exc
    root = _directory(state, request, create=True)
    with being_seed._locked(root):
        previous = read(state, request)['report']
        if (previous is not None and previous['identity_verified'] and (value['matrix_identity'] is None
                or previous['being_ref'] != value['matrix_identity']['document']['authority']['manifest']['being_ref'])):
            raise being_seed.SeedError('existing_local_body_identity_preserved', 409)
        fingerprint = digest(value)
        destination = root / (fingerprint + '.json')
        if destination.exists():
            if being_seed._read(destination) != value:
                raise being_seed.SeedError('existing_local_body_report_preserved', 409)
        else:
            being_seed._write(destination, value)
        if previous is not None and value['checked_at_ms'] < previous['checked_at_ms']:
            # A delayed retry preserves its evidence without rewinding the
            # current participant report or hiding subsequent local checks.
            return read(state, request)
        being_seed._write(root / 'latest.json', {'report_digest': fingerprint})
    return read(state, request)


def diagnostic_summary(state: Path, request: dict) -> dict | None:
    root = _directory(state, request) / 'diagnostics'
    try:
        pointer = being_seed._read(root / 'latest.json')
        fingerprint = pointer['diagnostic_digest']
        if not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint):
            raise OnboardingError('invalid_local_body_diagnostic')
        value = being_seed._read(root / (fingerprint + '.json'))
        if digest(value) != fingerprint:
            raise OnboardingError('invalid_local_body_diagnostic')
        if value['request_id'] != request['request_id']:
            return None
        return dict(diagnostic_digest=fingerprint, reported_at_ms=value['reported_at_ms'],
                    component=value['component'], received=True, resolution='host-review-pending',
                    evidence_scope='untrusted participant diagnostic; no execution or hosted acceptance')
    except FileNotFoundError:
        return None


def submit_diagnostic(state: Path, request: dict, value: object) -> dict:
    request = validate(request)
    if (not isinstance(value, dict) or set(value) != {'schema', 'request_id', 'reported_at_ms',
            'component', 'no_credentials', 'report'} or value['schema'] != DIAGNOSTIC
            or value['request_id'] != request['request_id']
            or type(value['reported_at_ms']) is not int or value['reported_at_ms'] < request['updated_ms']
            or not isinstance(value['component'], str)
            or value['component'] not in {'context-exporter', 'local-codex', 'matrix-identity'}
            or value['no_credentials'] is not True or not isinstance(value['report'], dict)
            or not value['report']):
        raise being_seed.SeedError('invalid_local_body_diagnostic')
    raw = json.dumps(value)
    if len(raw.encode()) > DIAGNOSTIC_LIMIT:
        raise being_seed.SeedError('local_body_diagnostic_too_large')
    if _CREDENTIAL.search(raw):
        raise being_seed.SeedError('diagnostic_requires_nonsecret_report')
    root = _directory(state, request, create=True) / 'diagnostics'
    private_directory(root, create=True)
    with being_seed._locked(root):
        fingerprint = digest(value)
        destination = root / (fingerprint + '.json')
        if destination.exists():
            if being_seed._read(destination) != value:
                raise being_seed.SeedError('existing_local_body_diagnostic_preserved', 409)
        else:
            if len(list(root.glob('*.json'))) >= 33:
                raise being_seed.SeedError('local_body_diagnostic_limit', 409)
            being_seed._write(destination, value)
        previous = diagnostic_summary(state, request)
        if previous is None or value['reported_at_ms'] >= previous['reported_at_ms']:
            being_seed._write(root / 'latest.json', {'diagnostic_digest': fingerprint})
    return read(state, request)


def worker_identity(state: Path, request: dict, *, intake_uid: int) -> dict | None:
    """Read participant-owned public authority without changing its ownership.

    The root worker independently checks the signed packet. Local claims remain
    data; this returns no authority to mint or replace a hosted being.
    """
    from .onboarding_release import regular
    request = validate(request)
    root = _directory(state, request)
    if not root.exists():
        return None
    for parent in (state, root.parent, root):
        being_seed._path(parent)
        info = parent.stat()
        if not parent.is_dir() or info.st_uid != intake_uid or info.st_mode & 0o077:
            raise OnboardingError('private_local_body_report_required')
    def read_private(path):
        raw = regular(path, uid=intake_uid, limit=being_seed.MAX_RECORD)
        if path.stat().st_mode & 0o077:
            raise OnboardingError('private_local_body_report_required')
        return json.loads(raw)
    try:
        pointer = read_private(root / 'latest.json')
    except FileNotFoundError:
        return None
    fingerprint = pointer.get('report_digest')
    if not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint):
        raise OnboardingError('invalid_local_body_report')
    report = read_private(root / (fingerprint + '.json'))
    if digest(report) != fingerprint or report.get('request_id') != request['request_id']:
        raise OnboardingError('invalid_local_body_report')
    identity = report.get('matrix_identity')
    if identity is not None:
        authority = onboarding_peer.native(Path(__file__).resolve().parents[1],
            uid=Path(__file__).stat().st_uid).verify_identity(identity)
        if request['expected_being_ref'] is not None and authority.state.being_ref != request['expected_being_ref']:
            raise OnboardingError('existing_local_body_identity_preserved')
    return identity
