"""Owner-signed group Root closure is independent of bilateral enrollment."""
import hashlib
import os
import time
import uuid

import pytest

from clusterctl import being_seed
from clusterctl.onboarding_source import Source
from tests.test_onboarding_target import receiving


@pytest.fixture
def group_source(tmp_path):
    from daimon_matrix import native_egress, operator_messaging, runtime
    from daimon_matrix.canonical import b64url
    from daimon_matrix.messaging_config import (
        APPLICATION_SCHEMA_V3, GROUP_STORE_NAMES, config_digest, create_binding,
        read_publication,
    )
    from daimon_matrix.operator_rebirth import AUTHORITY_SCHEMA, authority_from_runtime_bundle
    from daimon_matrix.relationships import DECLARATION_SCHEMA, relationship_event_subject, tribe_ref

    targets = []
    for name in ('owner', 'candidate'):
        location = tmp_path / name
        location.mkdir(mode=0o700)
        ceremony, plan, target = receiving(location)
        target.activate(ceremony.authorize_target(plan, target.prepare()))
        target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
        targets.append(target)
    target, peer = targets
    bundle, peer_bundle = target.document_bundle(), peer.document_bundle()
    peer_authority = authority_from_runtime_bundle(peer_bundle)
    peer_ref = peer_authority.manifest.being_ref
    def clock():
        return time.time_ns() // 1_000_000
    # Explicit fixture-owner construction uses the maintained trusted-host seam;
    # subsequent Source loading must recover it from its signed group itself.
    base = runtime.load_runtime(target.package / 'runtime', 'runtime.json', target._reader,
        clock=clock, relationship_authorities={peer_ref: peer_authority},
        egress=native_egress.closed_visibility(clock=clock, catalog_mode='migrate'))
    base.service.communication.upgrade_receipts_v2()
    base.service.communication.upgrade_legs_v3()
    core = dict(created_at_ms=clock(), founder_principal_id=bundle['manifest']['being_ref'],
        nonce=b64url(os.urandom(32)), policy_ref='dm:tribe-policy:v1:group-root-test')
    reference = tribe_ref(core)
    payload = dict(schema=DECLARATION_SCHEMA, tribe_ref=reference, declaration=core)
    declaration = base.service.ledger.append_local(kind='matrix/tribe-declaration',
        subject=relationship_event_subject('matrix/tribe-declaration', payload), payload=payload,
        signer=base.service.signer, sensitivity='shareable', occurred_at_ms=core['created_at_ms'],
        event_id=str(uuid.uuid4()))
    base.service.relationships.store.ingest(declaration)
    outputs = target.home / 'source-outputs'
    outputs.mkdir(mode=0o700)
    tribe = outputs / 'tribe'
    tribe.mkdir(mode=0o700)
    key = outputs / 'route.key'
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    route = dict(provider_ref='self', route_ref='self', key_ref='self',
        endpoint='http://127.0.0.1:48675/dm-messaging/v1/message', secret_file=key.name,
        secret_sha256=hashlib.sha256(key.read_bytes()).hexdigest())
    def public(document):
        return dict(schema=AUTHORITY_SCHEMA, **{name: document[name] for name in
            ('control_artifacts', 'control_head', 'credentials', 'incarnations', 'manifest')})
    spec = dict(schema=APPLICATION_SCHEMA_V3, listen=dict(host='127.0.0.1', port=48675),
        authorities=[public(bundle), public(peer_bundle)], relationship_events=[declaration],
        relationship_mode=dict(mode='shared', runtime_id=bundle['runtime_id'],
            state_root=str(base.state_root), store_filename=bundle['relationships']['store_filename']),
        tribe=dict(channel_id='tribe', policy=dict(tribe_ref=reference, membership_ref=declaration['event_id'],
            classification='shareable', max_ttl_ms=60000)), intake=route,
        roster=[dict(being_ref=bundle['manifest']['being_ref'], embodiment_id=bundle['local_origin']['embodiment_id'],
            body_ref=bundle['local_origin']['body_ref'], route=route)],
        stores={name: name+'.sqlite' for name in GROUP_STORE_NAMES})
    app = tribe / 'application'
    operator_messaging.prepare(base, app, spec, secret_sources={key.name:key})
    document, _ = read_publication(base, app)
    selection = dict(schema='cluster-onboarding-group-selection/v1', tribe_ref=reference,
        directory=str(app), visibility=str(tribe / 'visibility/installation.json'),
        socket='tribe.sock', application_sha256=config_digest(document))
    being_seed._write(tribe / 'selection.json', dict(document=selection, binding=create_binding(base, selection)))
    source = Source(dict(schema='cluster-onboarding-source/v1', runtime_root=str(base.state_root),
        password_file=str(target.root / 'body.unlock'), native_visibility=str(outputs / 'unused-visibility.json'),
        outputs=str(outputs), applications=[]))
    return source, target, peer_authority


def test_source_resolves_group_authority_without_native_pair_enrollment(group_source):
    source, target, peer = group_source
    before = {name:(source.root/name).read_bytes() for name in ('runtime.json','custody.json')}
    assert target.document_bundle()['sources']['known_beings'] == []
    loaded = source._load(signed=False)
    assert loaded.service.relationships.authority_resolver(peer.manifest.being_ref) == peer
    assert {name:(source.root/name).read_bytes() for name in before} == before


def test_unselected_group_does_not_extend_native_authority(group_source):
    source, _target, peer = group_source
    (source.outputs / 'tribe/selection.json').unlink()
    loaded = source._load(signed=False)
    with pytest.raises(KeyError):
        loaded.service.relationships.authority_resolver(peer.manifest.being_ref)


def test_tampered_group_is_refused_before_private_custody(group_source, monkeypatch):
    source, _target, _peer = group_source
    selection = source.outputs / 'tribe/selection.json'
    value = being_seed._read(selection)
    value['document']['tribe_ref'] += 'tampered'
    being_seed._write(selection, value)
    monkeypatch.setattr(source, '_reader', lambda: pytest.fail('tampered group opened private custody'))
    with pytest.raises(Exception, match='binding|group'):
        source._load(signed=False)


def advance_group_owner(source, target, peer):
    """Enroll a genuine synthetic sibling; retain the published selector."""
    from daimon_matrix import native_egress, runtime
    from daimon_matrix.canonical import canonical_bytes
    from daimon_matrix.keystore import EncryptedKeystore
    from daimon_matrix.operator_messaging import republish
    from daimon_matrix.operator_rebirth import (
        apply_activation_to_runtime_bundle, authority_from_runtime_bundle,
        authorize_enrollment_request, create_enrollment_request,
    )
    from clusterctl.onboarding import digest
    bundle = target.document_bundle()
    base = authority_from_runtime_bundle(bundle)
    custody = target.home.parent / 'custody' / digest(target.plan)
    contents = EncryptedKeystore(custody / 'root/holder.json').open(
        lambda: bytearray((custody / 'root.unlock').read_bytes()))
    now = time.time_ns() // 1_000_000
    request = create_enrollment_request(base, signing_seed=os.urandom(32),
        encryption_private=os.urandom(32), transport_seed=os.urandom(32),
        body_ref='codex:test:sibling', embodiment_id='embodiment:' + str(uuid.uuid4()),
        incarnation_id='incarnation:' + str(uuid.uuid4()), principal_id='sibling@test',
        created_at_ms=now, expires_at_ms=now+60000, nonce=os.urandom(32))
    activation = authorize_enrollment_request(request, base,
        root_seeds=tuple(contents.secrets.values()), issued_at_ms=now)
    successor = apply_activation_to_runtime_bundle(bundle, activation, base,
        target_endpoint='http://127.0.0.1:45999/dm-peer/v1')
    (source.root / 'runtime.json').write_bytes(canonical_bytes(successor))
    def clock():
        return time.time_ns() // 1_000_000
    current = runtime.load_runtime(source.root, 'runtime.json', target._reader,
        clock=clock, relationship_authorities={peer.manifest.being_ref: peer},
        egress=native_egress.closed_visibility(clock=clock, catalog_mode='migrate'))
    republish(current, source.outputs / 'tribe/application')
    return current


@pytest.mark.parametrize('lost_reply', [False, True])
def test_group_selector_follows_real_authority_advance_and_recovers_exactly(group_source, monkeypatch, lost_reply):
    from clusterctl.onboarding import digest
    from clusterctl.onboarding_peer import approved_group_application, republish_group_selection
    source, target, peer = group_source
    selected = source.outputs / 'tribe/selection.json'
    predecessor = being_seed._read(selected)
    current = advance_group_owner(source, target, peer)
    with pytest.raises(Exception, match='binding'):
        approved_group_application(current, selected.parent)
    arguments = dict(operation_id=str(uuid.uuid4()), expected_selection_sha256=digest(predecessor))
    original = being_seed._write
    def interrupted(path, value, **options):
        original(path, value, **options)
        if path == selected:
            raise OSError('synthetic lost selector reply')
    if lost_reply:
        monkeypatch.setattr(being_seed, '_write', interrupted)
        with pytest.raises(OSError, match='synthetic lost'):
            republish_group_selection(current, selected.parent, **arguments)
        monkeypatch.setattr(being_seed, '_write', original)
    result = republish_group_selection(current, selected.parent, **arguments)
    retained = selected.read_bytes()
    assert republish_group_selection(current, selected.parent, **arguments) == result
    assert selected.read_bytes() == retained
    assert approved_group_application(current, selected.parent)['application_sha256'] == result['application_sha256']
    assert source._load(signed=False).service.relationships.authority_resolver(peer.manifest.being_ref) == peer
    operation = being_seed._read(selected.parent / 'selection-operations' / (arguments['operation_id'] + '.json'))
    assert operation['before'] == predecessor


def test_group_selector_republication_rejects_forged_predecessor(group_source):
    from clusterctl.onboarding import digest
    from clusterctl.onboarding_peer import republish_group_selection
    source, target, peer = group_source
    selected = source.outputs / 'tribe/selection.json'
    current = advance_group_owner(source, target, peer)
    forged = being_seed._read(selected)
    forged['document']['tribe_ref'] += '-forged'
    being_seed._write(selected, forged)
    original = selected.read_bytes()
    with pytest.raises(Exception, match='binding'):
        republish_group_selection(current, selected.parent, operation_id=str(uuid.uuid4()),
            expected_selection_sha256=digest(forged))
    assert selected.read_bytes() == original
    assert not (selected.parent / 'selection-operations').exists()
