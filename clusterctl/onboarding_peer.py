"""Receiving adapter for the exact maintained native two-party peer ceremony.

Only public signed identities, encrypted offers and signed responses cross the
host boundary. Body custody and decrypted route material remain in the receiver.
The upstream tool is retained unchanged with explicit repository provenance.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import time
import types
from contextlib import closing
from pathlib import Path

from . import onboarding_release
from .onboarding import OnboardingError, digest, private_directory

TOOL_SHA256 = 'e5360670b1e7a17194472bfd1a84ae68e60b90d591bf4e91b06771eff1dd97b6'
TOOL_MODULE = 'onboarding_peer_native.py'
TOOL_COMMIT = 'ca1570aae24cadd2b9fee42bee65be5a4c06e664'


def native(code: Path, *, uid: int = 0):
    import importlib.metadata
    import sys
    from .onboarding_sdk import MATRIX_COMMIT
    # Entry points verify every installed wheel byte before importing Matrix.
    # The offline body has a pinned installation receipt, not VCS direct_url.
    # Host/source invocation instead retains the exact installed VCS guard.
    manifest = code / 'sdk/sdk.json'
    if manifest.exists():
        sdk = json.loads(onboarding_release.regular(manifest, uid=uid))
        prefix = Path(sys.prefix)
        receipt = json.loads(onboarding_release.regular(prefix.parent / 'installation.json', uid=os.geteuid()))
        expected = dict(schema='cluster-onboarding-sdk-installation/v1', sdk_digest=digest(sdk),
            matrix_commit=MATRIX_COMMIT, wheel_count=len(sdk['wheels']))
        if (sdk['matrix_commit'] != MATRIX_COMMIT or prefix.name != 'venv'
                or prefix.parent.name != digest(sdk) or receipt != expected):
            raise OnboardingError('qualified_native_peer_sdk_required')
    else:
        installed = json.loads(importlib.metadata.distribution('daimon-matrix').read_text('direct_url.json') or '{}')
        if installed.get('vcs_info', {}).get('commit_id') != MATRIX_COMMIT:
            raise OnboardingError('qualified_native_peer_sdk_required')
    path = code / 'clusterctl' / TOOL_MODULE
    raw = onboarding_release.regular(path, uid=uid)
    if hashlib.sha256(raw).hexdigest() != TOOL_SHA256:
        raise OnboardingError('qualified_native_peer_tool_required')
    module = types.ModuleType('qualified_onboarding_peer_native')
    module.__file__ = str(path)
    # Execute the verified bytes, never reopen a mutable path for importing.
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def root(target) -> Path:
    return target.root / 'peer'


def loaded(target):
    from daimon_matrix import runtime, native_egress
    def clock():
        return time.time_ns() // 1_000_000
    return runtime.load_runtime(target.package / 'runtime', 'runtime.json', target._reader,
        clock=clock, egress=native_egress.closed_visibility(clock=clock, catalog_mode='migrate'))


def identity(target) -> dict:
    tool = native(target.code, uid=target.code_uid)
    with target._runtime_writer():
        if target.observe()['phase'] != 'v8':
            raise OnboardingError('current_onboarding_target_required')
        return tool.public_identity(loaded(target), target.document_bundle())


def accept(target, packet: dict, *, expected_being: str) -> dict:
    tool = native(target.code, uid=target.code_uid)
    sender = tool.verify_identity(packet['sender_identity'])
    if sender.state.being_ref != expected_being or expected_being == target.document_bundle()['manifest']['being_ref']:
        raise OnboardingError('approved_onboarding_peer_required')
    directory = private_directory(root(target), create=True)
    with target._runtime_writer():
        if target.observe()['phase'] not in {'v8', 'peer-published'}:
            raise OnboardingError('current_onboarding_target_required')
        # The native receiver verifies both Body signatures and the shared graph
        # before publishing. Its persisted proposals recover every lost ACK.
        response = tool.accept(loaded(target), target.package / 'runtime',
                               bytes(target._reader()), packet, directory, additional_link=True)
        observed = target.observe()
        if observed['phase'] != 'v8':
            raise OnboardingError('native_onboarding_peer_incomplete')
        return json.loads(onboarding_release.regular(response, uid=os.geteuid()))


def augmented(target, original: dict, bundle: dict) -> tuple[dict, bool]:
    """Verify only the exact native additive peer change, not a new identity.

    Current identity observation is separate from historical credential receipt.
    Read relationship evidence through SQLite's read-only URI. Observation does
    not acquire the runtime writer lock, initialize stores, or read an inbox.
    """
    tool = native(target.code, uid=target.code_uid)
    payload = json.loads(onboarding_release.regular(root(target) / 'accepted-private.json', uid=os.geteuid()))
    plan = payload['plan']
    identities = plan['identities']
    authorities = [tool.verify_identity(value) for value in identities]
    own, peer = identities[1]['document'], identities[0]['document']
    if (own['runtime_id'] != original['runtime_id'] or own['origin'] != original['local_origin']
            or own['authority']['manifest'] != original['manifest']
            or own['authority']['credentials'] != original['credentials']
            or own['authority']['incarnations'] != original['incarnations']
            or own['authority']['control_artifacts'] != original['control_artifacts']
            or own['authority']['control_head'] != original['control_head']
            or own['authority_history'] != original['authority_history']
            or authorities[0].state.being_ref == authorities[1].state.being_ref):
        raise OnboardingError('existing_onboarding_target_preserved')
    expected = copy.deepcopy(original)
    known = {key: value for key, value in peer['authority'].items() if key != 'schema'}
    # uuid validation prevents a peer plan from choosing a private path.
    import uuid
    uuid.UUID(plan['link_id'])
    known.update(authority_history=peer['authority_history'], ledger_filename='peer-' + plan['link_id'] + '.sqlite')
    if expected['sources'] is None:
        expected['sources'] = dict(cas_filename='sources.sqlite3', known_beings=[])
    peers = expected['sources']['known_beings']
    matching = [row for row in peers if row['manifest']['being_ref'] == authorities[0].state.being_ref]
    if matching and matching != [known]:
        raise OnboardingError('existing_onboarding_target_preserved')
    if not matching:
        peers.append(known)
    if expected['relationships'] is None:
        expected['relationships'] = dict(store_filename='relationships.sqlite3', known_being_refs=[])
    refs = expected['relationships']['known_being_refs']
    if authorities[0].state.being_ref not in refs:
        refs.append(authorities[0].state.being_ref)
        refs.sort()
    if bundle != expected:
        raise OnboardingError('existing_onboarding_target_preserved')
    from daimon_matrix.weave import verify_event
    from daimon_matrix.relationship_store import RelationshipView
    from daimon_matrix.runtime import verify_relationship_card_authority
    by_being = {authority.state.being_ref: authority for authority in authorities}
    events = payload['signed_events']
    if (len(events) != len(plan['events']) or any(
            {k: v for k, v in event.items() if k != 'signature'} !=
            {k: v for k, v in draft.items() if k != 'signature'}
            for event, draft in zip(events, plan['events'], strict=True))):
        raise OnboardingError('native_onboarding_peer_plan_conflict')
    signed = [*plan['prior_cards'], *events]
    for event in signed:
        verify_event(event, by_being[event['being_ref']])
    historical = RelationshipView(signed, at_ms=payload['signed_at_ms'],
        card_verifier=lambda card, at: verify_relationship_card_authority(card,
            by_being[card['being_ref']], at_ms=at))
    snapshot = historical.snapshot(plan['tribe_ref'])
    if len(snapshot.value['members']) != 2 or len(snapshot.value['grants']) != 2:
        raise OnboardingError('native_onboarding_peer_plan_conflict')
    complete = False
    store = target.package / 'runtime' / expected['relationships']['store_filename']
    if store.exists() and (root(target) / 'ready.json').exists():
        onboarding_release.regular(store, uid=os.geteuid())
        with closing(sqlite3.connect(store.as_uri() + '?mode=ro', uri=True)) as database:
            retained = [json.loads(row[0]) for row in database.execute('SELECT event_json FROM events')]
        complete = all(event in retained for event in signed)
        ready = json.loads(onboarding_release.regular(root(target) / 'ready.json', uid=os.geteuid()))
        application = root(target) / 'application'
        visibility = root(target) / 'visibility/installation.json'
        if (ready['link_id'] != plan['link_id'] or ready['app_directory'] != str(application)
                or ready['runtime_root'] != str(target.package / 'runtime')
                or ready['visibility_installation'] != str(visibility)):
            raise OnboardingError('native_onboarding_peer_plan_conflict')
        app = json.loads(onboarding_release.regular(application / 'application.json', uid=os.geteuid()))
        binding = json.loads(onboarding_release.regular(application / 'binding.json', uid=os.geteuid()))
        tool.verify_document(identities[1], app, binding)
        if digest(app) != ready['application_sha256']:
            raise OnboardingError('native_onboarding_peer_plan_conflict')
        from urllib.parse import urlsplit
        endpoint = urlsplit(plan['endpoints'][1])
        rules = tool.policies(plan)
        if (app['listen'] != dict(host=endpoint.hostname, port=endpoint.port)
                or app['authorities'] != [value['document']['authority'] for value in identities]
                or app['relationship_events'] != signed
                or app['relationship_mode'] != dict(mode='shared', runtime_id=original['runtime_id'],
                    state_root=str(target.package / 'runtime'), store_filename=store.name)):
            raise OnboardingError('native_onboarding_peer_plan_conflict')
        for direction, actor, recipient in (('incoming', 0, 1), ('outgoing', 1, 0)):
            channel = app[direction]
            if (channel['channel_id'] != ('peer-in' if direction == 'incoming' else 'peer-out')
                    or channel['recipient_being_ref'] != authorities[recipient].state.being_ref
                    or channel['recipient_credential_id'] != rules[recipient]['peer_credential_id']
                    or channel['policy'] != rules[actor]):
                raise OnboardingError('native_onboarding_peer_plan_conflict')
            for phase in ('evidence', 'message'):
                route = channel['routes'][phase]
                name = f'{recipient}-{phase}.key'
                secret = tool.unb64url(payload['route_keys'][name], length=32)
                if route != dict(provider_ref=f"provider:link:{plan['link_id']}:{recipient}:{phase}",
                        route_ref=f"route:link:{plan['link_id']}:{recipient}:{phase}",
                        key_ref=f"key:link:{plan['link_id']}:{recipient}:{phase}", secret_file=name,
                        secret_sha256=hashlib.sha256(secret).hexdigest(),
                        endpoint=plan['endpoints'][recipient] + '/dm-messaging/v1/' + phase):
                    raise OnboardingError('native_onboarding_peer_plan_conflict')
        installed = json.loads(onboarding_release.regular(visibility, uid=os.geteuid()))
        document = installed['document']
        tool.verify_document(identities[1], document, installed['binding'])
        disclosure = tool.disclosures(plan)[1]
        beings = [authority.state.being_ref for authority in authorities]
        acceptance = dict(schema='dm.messaging.visibility-acceptance-set/v1',
            disclosure_sha256=digest(disclosure), bindings=[payload['visibility_bindings'][beings.index(being)][1]
                for being in sorted(beings)])
        if (document['runtime_id'] != original['runtime_id'] or document['application_sha256'] != digest(app)
                or document['disclosure'] != disclosure or document['acceptance_set'] != acceptance
                or document['telegram_qualification'] != payload['telegram_qualification']
                or any(document['policy'][key] != value for key, value in plan['destination'].items())
                or document['policy']['acceptance_digest'] != digest(acceptance)):
            raise OnboardingError('native_onboarding_peer_plan_conflict')
        for actor in (0, 1):
            tool.verify_document(identities[actor], disclosure, payload['visibility_bindings'][actor][1])
        secrets = document['secrets']
        if secrets['telegram_token_file'] != 'telegram.token' or secrets['proof_key_file'] != 'proof.key':
            raise OnboardingError('native_onboarding_peer_plan_conflict')
        token = onboarding_release.regular(visibility.parent / 'telegram.token', uid=os.geteuid())
        proof = onboarding_release.regular(visibility.parent / 'proof.key', uid=os.geteuid())
        if (token != tool.unb64url(payload['telegram_token'])
                or hashlib.sha256(token).hexdigest() != secrets['telegram_token_sha256']
                or len(proof) != 32 or document['policy']['proof_key_id'] != 'sha256:' + hashlib.sha256(proof).hexdigest()):
            raise OnboardingError('native_onboarding_peer_plan_conflict')
    receipt = dict(schema='cluster-onboarding-peer-runtime-observation/v1', plan_digest=digest(target.plan),
        origin=bundle['local_origin'], runtime_sha256=digest(bundle),
        credential_runtime_sha256=digest(original), link_id=plan['link_id'],
        peer_being_ref=authorities[0].state.being_ref)
    return receipt, complete
