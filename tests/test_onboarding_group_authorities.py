"""Owner-signed group Root closure is independent of bilateral enrollment."""
import copy
import hashlib
import json
import os
import time
import uuid

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import digest
from clusterctl.onboarding_source import Source
from tests.test_onboarding_target import receiving


@pytest.fixture
def group_source(tmp_path):
    from daimon_matrix import native_egress, operator_messaging, runtime
    from daimon_matrix.canonical import b64url
    from daimon_matrix.messaging_config import (
        APPLICATION_SCHEMA_V3, GROUP_STORE_NAMES, create_binding,
        read_publication,
    )
    from daimon_matrix.operator_rebirth import AUTHORITY_SCHEMA, authority_from_runtime_bundle
    from daimon_matrix.relationships import DECLARATION_SCHEMA, relationship_event_subject, tribe_ref

    targets = []
    old_peer_event = None
    for name in ('owner', 'candidate'):
        location = tmp_path / name
        location.mkdir(mode=0o700)
        ceremony, plan, target = receiving(location)
        target.activate(ceremony.authorize_target(plan, target.prepare()))
        if name == 'candidate':
            from clusterctl.onboarding_peer import loaded
            previous = loaded(target)
            old_peer_event = previous.service.ledger.append_local(kind='experience.observed',
                subject='public group-history qualification', payload={'summary': 'public historical proof'},
                signer=previous.service.signer, sensitivity='shareable', occurred_at_ms=time.time_ns() // 1000000)
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
        socket='tribe.sock', application_sha256=digest(document))
    being_seed._write(tribe / 'selection.json', dict(document=selection, binding=create_binding(base, selection)))
    source = Source(dict(schema='cluster-onboarding-source/v1', runtime_root=str(base.state_root),
        password_file=str(target.root / 'body.unlock'), native_visibility=str(outputs / 'unused-visibility.json'),
        outputs=str(outputs), applications=[]))
    return source, target, peer_authority, peer_bundle, old_peer_event


def test_source_resolves_group_authority_without_native_pair_enrollment(group_source):
    source, target, peer, *_ = group_source
    before = {name:(source.root/name).read_bytes() for name in ('runtime.json','custody.json')}
    assert target.document_bundle()['sources']['known_beings'] == []
    loaded = source._load(signed=False)
    assert loaded.service.relationships.authority_resolver(peer.manifest.being_ref) == peer
    assert {name:(source.root/name).read_bytes() for name in before} == before


def test_unselected_group_does_not_extend_native_authority(group_source):
    source, _target, peer, *_ = group_source
    (source.outputs / 'tribe/selection.json').unlink()
    loaded = source._load(signed=False)
    with pytest.raises(KeyError):
        loaded.service.relationships.authority_resolver(peer.manifest.being_ref)


def test_tampered_group_is_refused_before_private_custody(group_source, monkeypatch):
    source, _target, _peer, *_ = group_source
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
    source, target, peer, *_ = group_source
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
    source, target, peer, *_ = group_source
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


def test_retained_membership_context_survives_owner_authority_advance(group_source):
    from clusterctl.onboarding_peer import approved_membership_authorities, retain_membership_authorities
    from daimon_matrix.messaging_config import MessagingConfigError
    from daimon_matrix.operator_rebirth import AUTHORITY_SCHEMA

    source, target, peer, peer_bundle, _ = group_source
    selected, base, document, _ = history_selection(source, peer_bundle)
    group = selected.parent
    ref = peer.manifest.being_ref
    authority = dict(schema=AUTHORITY_SCHEMA, **{key: peer_bundle[key] for key in (
        'manifest', 'control_artifacts', 'control_head', 'credentials', 'incarnations')})
    args = dict(operation_id=str(uuid.uuid4()), tribe_ref=document['tribe_ref'],
        authority_closure={ref: dict(authority=authority, history=peer_bundle['authority_history'])},
        expected_selection_sha256=None)
    first = retain_membership_authorities(base, group, **args)
    path = group / 'membership-authorities.json'
    original = path.read_bytes()

    updated = advance_group_owner(source, target, peer)
    bundle = target.document_bundle()
    assert approved_membership_authorities(group, bundle)[ref].active == peer
    assert retain_membership_authorities(updated, group, **args) == first
    assert path.read_bytes() == original

    tampered = being_seed._read(path)
    tampered['document']['tribe_ref'] += '-changed'
    being_seed._write(path, tampered)
    with pytest.raises(MessagingConfigError, match='messaging_binding_rejected'):
        approved_membership_authorities(group, bundle)


def history_selection(source, peer_bundle):
    from daimon_matrix.messaging_config import create_binding
    selected = source.outputs / 'tribe/selection.json'
    base = source._load(signed=False)
    document = being_seed._read(selected)['document']
    document.update(schema='cluster-onboarding-group-selection/v2', authority_history={
        peer_bundle['manifest']['being_ref']: copy.deepcopy(peer_bundle['authority_history'])})
    return selected, base, document, create_binding


def selection_operation(source, peer_bundle):
    from clusterctl.onboarding import digest
    from clusterctl.onboarding_peer import publish_group_selection
    selected, base, _document, _sign = history_selection(source, peer_bundle)
    before = being_seed._read(selected)
    arguments = dict(operation_id=str(uuid.uuid4()), expected_selection_sha256=digest(before),
        authority_history={peer_bundle['manifest']['being_ref']: peer_bundle['authority_history']})
    return selected, base, before, arguments, publish_group_selection


def test_selection_publication_recovers_lost_reply_without_replacing_again(group_source, monkeypatch):
    from clusterctl.onboarding import digest
    source, target, _peer, peer_bundle, _old = group_source
    selected, base, before, arguments, publish = selection_operation(source, peer_bundle)
    original = being_seed._write
    native = {name: (source.root / name).read_bytes() for name in ('runtime.json', 'custody.json')}

    def lost_reply(path, value, **options):
        original(path, value, **options)
        if path == selected:
            raise OSError('synthetic lost selector publication reply')

    monkeypatch.setattr(being_seed, '_write', lost_reply)
    with pytest.raises(OSError, match='synthetic lost'):
        publish(base, selected.parent, **arguments)
    candidate = selected.read_bytes()

    def no_replacement(*args, **kwargs):
        pytest.fail('exact retry replaced an already selected document')

    monkeypatch.setattr(being_seed, '_write', no_replacement)
    result = publish(base, selected.parent, **arguments)
    assert result['status'] == 'selected' and result['receiving_readiness'] == 'unobserved'
    assert result['selection_sha256'] == digest(being_seed._read(selected)) != digest(before)
    assert selected.read_bytes() == candidate
    recovered = source._load(signed=False)
    assert recovered.service.relationships.authority_resolver(peer_bundle['manifest']['being_ref'])
    assert {name: (source.root / name).read_bytes() for name in native} == native
    assert target.document_bundle()['sources']['known_beings'] == []


def test_selection_retry_finishes_parent_durability_before_publication(group_source, monkeypatch):
    source, _target, _peer, peer_bundle, _old = group_source
    selected, base, before, arguments, publish = selection_operation(source, peer_bundle)
    original = os.fsync
    operations = selected.parent / 'selection-operations'
    observed = []

    def failed_directory_sync(descriptor):
        path = os.readlink('/proc/self/fd/' + str(descriptor))
        if path == str(operations):
            observed.append(path)
            raise OSError('synthetic operation directory sync failure')
        original(descriptor)

    monkeypatch.setattr(os, 'fsync', failed_directory_sync)
    for _ in range(2):
        with pytest.raises(OSError, match='synthetic operation directory'):
            publish(base, selected.parent, **arguments)
        assert being_seed._read(selected) == before
        assert (operations / (arguments['operation_id'] + '.json')).exists()
    assert len(observed) == 2
    monkeypatch.setattr(os, 'fsync', original)
    assert publish(base, selected.parent, **arguments)['status'] == 'selected'


def test_selection_retry_preserves_a_later_signed_winner(group_source, monkeypatch):
    from clusterctl.onboarding import OnboardingError
    from clusterctl.onboarding_peer import approved_group_application
    from daimon_matrix.messaging_config import create_binding
    source, _target, peer, peer_bundle, _old = group_source
    selected, base, before, arguments, publish = selection_operation(source, peer_bundle)
    original = being_seed._write

    def before_selection(path, value, **options):
        if path == selected:
            raise OSError('synthetic interruption before selector')
        original(path, value, **options)

    monkeypatch.setattr(being_seed, '_write', before_selection)
    with pytest.raises(OSError, match='synthetic interruption'):
        publish(base, selected.parent, **arguments)
    monkeypatch.setattr(being_seed, '_write', original)
    winner = {**before['document'], 'schema': 'cluster-onboarding-group-selection/v2',
              'authority_history': {peer.manifest.being_ref: []}}
    original(selected, dict(document=winner, binding=create_binding(base, winner)))
    assert approved_group_application(base, selected.parent) == winner
    exact = selected.read_bytes()
    with pytest.raises(OnboardingError, match='onboarding_group_selection_changed'):
        publish(base, selected.parent, **arguments)
    assert selected.read_bytes() == exact


def test_invalid_selection_history_is_not_retained(group_source):
    from clusterctl.onboarding import OnboardingError
    source, _target, _peer, peer_bundle, _old = group_source
    selected, base, before, arguments, publish = selection_operation(source, peer_bundle)
    arguments['authority_history'] = {}
    with pytest.raises(OnboardingError, match='approved_onboarding_group_history_required'):
        publish(base, selected.parent, **arguments)
    assert being_seed._read(selected) == before
    assert not (selected.parent / 'selection-operations').exists()


def test_first_selection_and_winner_during_publication_are_preserved(group_source, monkeypatch):
    from clusterctl.onboarding import OnboardingError
    from clusterctl.onboarding_peer import approved_group_application
    from daimon_matrix.messaging_config import create_binding
    source, _target, peer, peer_bundle, _old = group_source
    selected, base, before, arguments, publish = selection_operation(source, peer_bundle)
    selected.unlink()
    arguments['expected_selection_sha256'] = None
    winner = {**before['document'], 'schema': 'cluster-onboarding-group-selection/v2',
              'authority_history': {peer.manifest.being_ref: []}}
    packet = dict(document=winner, binding=create_binding(base, winner))
    original = os.fsync
    inserted = False

    def concurrent_winner(descriptor):
        nonlocal inserted
        if not inserted and os.readlink('/proc/self/fd/' + str(descriptor)) == str(selected.parent):
            inserted = True
            being_seed._write(selected, packet)
        original(descriptor)

    monkeypatch.setattr(os, 'fsync', concurrent_winner)
    with pytest.raises(OnboardingError, match='onboarding_group_selection_changed'):
        publish(base, selected.parent, **arguments)
    assert inserted and approved_group_application(base, selected.parent) == winner
    monkeypatch.setattr(os, 'fsync', original)
    # A distinct genuine first-selection operation accepts only an absent pin.
    selected.unlink()
    arguments['operation_id'] = str(uuid.uuid4())
    result = publish(base, selected.parent, **arguments)
    exact = selected.read_bytes()
    assert result['status'] == 'selected'
    assert publish(base, selected.parent, **arguments) == result
    assert selected.read_bytes() == exact


def test_oversized_signed_selection_is_rejected_before_retention(group_source, monkeypatch):
    from clusterctl.onboarding import OnboardingError
    source, _target, _peer, peer_bundle, _old = group_source
    selected, base, before, arguments, publish = selection_operation(source, peer_bundle)
    _, _, document, sign = history_selection(source, peer_bundle)
    candidate = dict(document=document, binding=sign(base, document))
    # Exercise the real encoding boundary with a genuine signed history, without
    # generating hundreds of unrelated epochs merely to consume the byte limit.
    monkeypatch.setattr(being_seed, 'MAX_SELECTION', len(json.dumps(candidate, sort_keys=True).encode()) - 1)
    with pytest.raises(OnboardingError, match='onboarding_group_selection_too_large'):
        publish(base, selected.parent, **arguments)
    assert json.loads(selected.read_bytes()) == before
    assert not (selected.parent / 'selection-operations').exists()


def test_signed_history_selector_loads_historical_proof_without_pair_or_foreign_store(group_source):
    from daimon_matrix.authority_epochs import RootHistoryAuthority
    from daimon_matrix.weave import verify_event
    from clusterctl.onboarding_peer import _group_selection_from_bundle

    source, target, peer, peer_bundle, old_event = group_source
    assert peer_bundle['authority_history']
    with pytest.raises(ValueError):
        verify_event(old_event, peer)
    before = {name: (source.root / name).read_bytes() for name in ('runtime.json', 'custody.json')}
    old_peer_files = set(source.root.glob('peer-*.sqlite'))
    selected, base, document, sign = history_selection(source, peer_bundle)
    being_seed._write(selected, dict(document=document, binding=sign(base, document)))
    recovered = source._load(signed=False)
    history = recovered.service.relationships.store.authority_resolver(peer.manifest.being_ref)
    assert isinstance(history, RootHistoryAuthority) and history.active == peer
    verify_event(old_event, history)
    assert _group_selection_from_bundle(source.outputs / 'tribe', target.document_bundle()) == document
    assert target.document_bundle()['sources']['known_beings'] == []
    assert {name: (source.root / name).read_bytes() for name in before} == before
    assert set(source.root.glob('peer-*.sqlite')) == old_peer_files


@pytest.mark.parametrize(('native_publication', 'direct_peer'), [(False, False), (True, False), (True, True)])
def test_group_peer_update_recovers_selector_and_keeps_membership_history(
        group_source, monkeypatch, native_publication, direct_peer):
    from inspect import signature
    from clusterctl.onboarding import OnboardingError
    from clusterctl.onboarding_peer import (
        approved_membership_authorities, republish_group_peer, republish_group_selection,
        retain_membership_authorities,
    )
    from daimon_matrix.canonical import canonical_bytes
    from daimon_matrix.keystore import EncryptedKeystore
    from daimon_matrix.messaging_config import config_digest, read_publication
    from daimon_matrix.operator_messaging import _publication, _write, republish
    from daimon_matrix.operator_rebirth import (
        AUTHORITY_SCHEMA, apply_activation_to_runtime_bundle, authorize_enrollment_request,
        create_enrollment_request,
    )
    from daimon_matrix.weave import verify_event

    if native_publication and 'group_peer_successor' not in signature(republish).parameters:
        pytest.skip('Group peer publication requires the qualified Matrix successor SDK')
    source, target, peer, peer_bundle, old_event = group_source
    selected, base, document, sign = history_selection(source, peer_bundle)
    being_seed._write(selected, dict(document=document, binding=sign(base, document)))
    # Existing large selectors are valid JSON and pin an authenticated history.
    with selected.open('ab') as stream:
        stream.write(b' ' * being_seed.MAX_RECORD)
    assert selected.stat().st_size > being_seed.MAX_RECORD
    base = source._load(signed=False)
    ref = peer.manifest.being_ref
    public_fields = ('manifest', 'control_artifacts', 'control_head', 'credentials', 'incarnations')
    before_authority = dict(schema=AUTHORITY_SCHEMA, **{k: peer_bundle[k] for k in public_fields})
    if direct_peer:
        bundle = target.document_bundle()
        bundle['sources']['known_beings'] = [dict(
            **{key: peer_bundle[key] for key in public_fields},
            authority_history=peer_bundle['authority_history'], ledger_filename='known-peer.sqlite')]
        (source.root / 'runtime.json').write_bytes(canonical_bytes(bundle))
        base = source._load(signed=False)
    retain_membership_authorities(base, selected.parent, operation_id=str(uuid.uuid4()),
        tribe_ref=document['tribe_ref'], authority_closure={
            ref: dict(authority=before_authority, history=peer_bundle['authority_history'])},
        expected_selection_sha256=None)
    membership = selected.parent / 'membership-authorities.json'
    retained_membership = membership.read_bytes()
    predecessor = being_seed._read(selected, limit=being_seed.MAX_SELECTION)
    peer_custody, = (target.home.parent.parent / 'candidate' / 'custody').glob('*/root/holder.json')
    roots = EncryptedKeystore(peer_custody).open(
        lambda: bytearray((peer_custody.parents[1] / 'root.unlock').read_bytes()))
    now = time.time_ns() // 1_000_000
    request = create_enrollment_request(peer, signing_seed=os.urandom(32),
        encryption_private=os.urandom(32), transport_seed=os.urandom(32),
        body_ref='claude:test:peer', embodiment_id='embodiment:' + str(uuid.uuid4()),
        incarnation_id='incarnation:' + str(uuid.uuid4()), principal_id='peer@test',
        created_at_ms=now, expires_at_ms=now + 60_000, nonce=os.urandom(32))
    activation = authorize_enrollment_request(request, peer,
        root_seeds=tuple(roots.secrets.values()), issued_at_ms=now)
    successor = apply_activation_to_runtime_bundle(peer_bundle, activation, peer,
        target_endpoint='http://127.0.0.1:45999/dm-peer/v1')
    public = dict(schema=AUTHORITY_SCHEMA, **{k: successor[k] for k in public_fields})
    # The same retained closure can follow a directly trusted peer's verified
    # successor without a fresh local signature or any change to membership.
    direct = target.document_bundle()
    direct['sources']['known_beings'] = [dict(
        **{key: successor[key] for key in public_fields}, authority_history=successor['authority_history'])]
    direct_authority = approved_membership_authorities(selected.parent, direct)[ref]
    assert direct_authority.active.manifest.value == successor['manifest']
    verify_event(old_event, direct_authority)
    assert membership.read_bytes() == retained_membership
    # The Matrix writer has its own regression. Model its completed publication
    # with the same signed metadata, so this test also runs against the pinned SDK.
    if not native_publication:
        app = selected.parent / 'application'
        prior_app, metadata = read_publication(base, app)
        new_app = copy.deepcopy(prior_app)
        new_app['authorities'] = [public if row['manifest']['being_ref'] == ref else row
                                  for row in prior_app['authorities']]
        generation = app / ('generation-' + uuid.uuid4().hex)
        generation.mkdir(mode=0o700)
        _write(generation, 'application.json', canonical_bytes(new_app))
        _write(generation, 'binding.json', canonical_bytes(sign(base, new_app)))
        _write(generation, 'client.json', (metadata / 'client.json').read_bytes())
        (app / 'publication.json').write_bytes(
            _publication(base, new_app, generation.name, config_digest(prior_app)))
    arguments = dict(operation_id=str(uuid.uuid4()), expected_selection_sha256=digest(predecessor))
    def update(history):
        read, write = being_seed._read, being_seed._write

        def read_selection(path, *, limit=being_seed.MAX_RECORD):
            if path == selected:
                assert limit == being_seed.MAX_SELECTION
            return read(path, limit=limit)

        def write_selection(path, value, *, limit=being_seed.MAX_RECORD):
            if path == selected:
                assert limit == being_seed.MAX_SELECTION
            return write(path, value, limit=limit)

        with monkeypatch.context() as selected_limits:
            # The signed production group selection can exceed the small
            # generic record bound. All selection reads and writes use its own.
            selected_limits.setattr(being_seed, '_read', read_selection)
            selected_limits.setattr(being_seed, '_write', write_selection)
            if native_publication:
                return republish_group_peer(source.root, selected.parent, source._reader,
                    authority=public, history=history, **arguments)
            return republish_group_selection(base, selected.parent, peer_history=(ref, history), **arguments)
    with pytest.raises(OnboardingError, match='approved_onboarding_group_history_conflict'):
        update(successor['authority_history'][1:])
    assert being_seed._read(selected, limit=being_seed.MAX_SELECTION) == predecessor

    if direct_peer:
        from daimon_matrix import operator_messaging

        adopt = operator_messaging.adopt_peer_authority

        def lost_native_reply(*args, **kwargs):
            adopt(*args, **kwargs)
            raise OSError('lost native adoption reply')

        monkeypatch.setattr(operator_messaging, 'adopt_peer_authority', lost_native_reply)
        with pytest.raises(OSError, match='lost native adoption reply'):
            update(successor['authority_history'])
        monkeypatch.setattr(operator_messaging, 'adopt_peer_authority', adopt)
        assert being_seed._read(selected) == predecessor
        native, = target.document_bundle()['sources']['known_beings']
        assert native['manifest'] == successor['manifest']

    original = being_seed._write
    def lost_reply(path, value, **options):
        original(path, value, **options)
        if path == selected:
            raise OSError('lost group selection reply')
    monkeypatch.setattr(being_seed, '_write', lost_reply)
    with pytest.raises(OSError, match='lost group selection reply'):
        update(successor['authority_history'])
    after = selected.read_bytes()
    monkeypatch.setattr(being_seed, '_write', original)
    assert update(successor['authority_history'])['status'] == 'selected'
    assert selected.read_bytes() == after and membership.read_bytes() == retained_membership
    history = source._load(signed=False).service.relationships.store.authority_resolver(ref)
    assert history.active.manifest.value == successor['manifest']
    verify_event(old_event, history)
    known = target.document_bundle()['sources']['known_beings']
    assert [row['manifest'] for row in known] == ([successor['manifest']] if direct_peer else [])

    if native_publication:
        from daimon_matrix.operator_rebirth import authority_from_runtime_bundle

        # A second update used to reject the still-valid membership proof
        # because its peer authority was now one epoch behind the publication.
        enrolled = authority_from_runtime_bundle(successor)
        second_request = create_enrollment_request(enrolled, signing_seed=os.urandom(32),
            encryption_private=os.urandom(32), transport_seed=os.urandom(32),
            body_ref='rust:test:peer', embodiment_id='embodiment:' + str(uuid.uuid4()),
            incarnation_id='incarnation:' + str(uuid.uuid4()), principal_id='rust@test',
            created_at_ms=now, expires_at_ms=now + 60_000, nonce=os.urandom(32))
        second_activation = authorize_enrollment_request(second_request, enrolled,
            root_seeds=tuple(roots.secrets.values()), issued_at_ms=now)
        second = apply_activation_to_runtime_bundle(successor, second_activation, enrolled,
            target_endpoint='http://127.0.0.1:45998/dm-peer/v1')
        result = republish_group_peer(source.root, selected.parent, source._reader,
            authority=dict(schema=AUTHORITY_SCHEMA, **{key: second[key] for key in public_fields}),
            history=second['authority_history'], operation_id=str(uuid.uuid4()),
            expected_selection_sha256=digest(being_seed._read(selected)))
        assert result['peer_manifest_revision'] == second['manifest']['revision']
        assert membership.read_bytes() == retained_membership
        history = source._load(signed=False).service.relationships.store.authority_resolver(ref)
        verify_event(old_event, history)


def test_invalid_history_selector_is_refused_before_private_custody(group_source, monkeypatch):
    source, target, _peer, peer_bundle, _old_event = group_source
    selected, base, document, sign = history_selection(source, peer_bundle)
    peer_ref = peer_bundle['manifest']['being_ref']
    cases = []
    missing = copy.deepcopy(document)
    missing['authority_history'] = {}
    cases.append(missing)
    own = copy.deepcopy(document)
    own['authority_history'][target.document_bundle()['manifest']['being_ref']] = []
    cases.append(own)
    forged = copy.deepcopy(document)
    forged['authority_history'][peer_ref][0]['successor']['acceptance']['value'] = 'A' * 86
    cases.append(forged)
    wrong_app = copy.deepcopy(document)
    wrong_app['application_sha256'] = 'a' * 64
    cases.append(wrong_app)
    legacy = copy.deepcopy(document)
    legacy['schema'] = 'cluster-onboarding-group-selection/v1'
    cases.append(legacy)
    monkeypatch.setattr(source, '_reader', lambda: pytest.fail('invalid public history opened private custody'))
    for candidate in cases:
        being_seed._write(selected, dict(document=candidate, binding=sign(base, candidate)))
        with pytest.raises(Exception, match='binding|group'):
            source._load(signed=False)
    from daimon_matrix import operator_messaging
    being_seed._write(selected, dict(document=document, binding=sign(base, document)))
    monkeypatch.setattr(operator_messaging, 'public_authority_history', None)
    with pytest.raises(Exception, match='onboarding_group_history_sdk_required'):
        source._load(signed=False)


def test_history_reader_preserves_the_provided_native_chain_and_rejects_truncation(group_source):
    from clusterctl.onboarding import OnboardingError
    from clusterctl.onboarding_peer import approved_group_authorities

    source, target, peer, peer_bundle, _old_event = group_source
    selected, base, document, sign = history_selection(source, peer_bundle)
    being_seed._write(selected, dict(document=document, binding=sign(base, document)))
    # Exercise the public native-bundle guard with the genuine peer epochs.
    # No foreign ledger or augmented runtime is created by this reader test.
    native = target.document_bundle()
    native['sources']['known_beings'] = [{**{key: peer_bundle[key] for key in (
        'manifest', 'control_artifacts', 'control_head', 'credentials', 'incarnations', 'authority_history')},
        'ledger_filename': 'historical-peer.sqlite'}]
    before = (source.root / 'runtime.json').read_bytes()
    accepted = approved_group_authorities(source.root, source.outputs / 'tribe', native)
    assert len(accepted[peer.manifest.being_ref].historical) == len(peer_bundle['authority_history'])
    document['authority_history'][peer.manifest.being_ref] = []
    being_seed._write(selected, dict(document=document, binding=sign(base, document)))
    with pytest.raises(OnboardingError, match='approved_onboarding_group_history_conflict'):
        approved_group_authorities(source.root, source.outputs / 'tribe', native)
    assert (source.root / 'runtime.json').read_bytes() == before
    assert not (source.root / 'historical-peer.sqlite').exists()


def test_receive_only_group_reads_verified_application_without_visibility(group_source):
    """Actual SDK publication/client/egress; no native or model child is started."""
    from daimon_matrix import daemon
    from daimon_matrix.client import ClientConfig, LocalClient
    from daimon_matrix.messaging_config import protected_read, read_publication
    from clusterctl.onboarding_runtime import receive_only_application_view

    source, *_ = group_source
    application = source.outputs / 'tribe/application'
    visibility = source.outputs / 'tribe/visibility/installation.json'
    assert not visibility.exists()
    base = source._load(signed=False)
    view = receive_only_application_view(base, application)
    view.egress.validate_registry(daemon._enabled_egress_paths(view))
    _document, metadata = read_publication(base, application)
    config = ClientConfig.load(metadata / 'client.json', bytearray(protected_read(application / 'client.key')))
    client = LocalClient(base.state_root / 'tribe.sock', config)
    inbox = view.service.handle(client.prepare('messaging.inbox', dict(channel_id='tribe', after=0, limit=10)))
    assert inbox['ok'] is True
    assert inbox['result']['items'] == []
    outgoing = view.service.handle(client.prepare('messaging.send', dict(channel_id='tribe',
        send_id=str(uuid.uuid4()), thread_id=str(uuid.uuid4()), text='Closed native fixture')))
    assert outgoing['ok'] is False, outgoing
    assert not visibility.exists()
