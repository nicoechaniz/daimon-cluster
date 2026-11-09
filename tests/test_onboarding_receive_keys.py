"""Original own key intent survives lost replies without reminting or disclosure."""
import copy
import hashlib
import json
import os
from pathlib import Path
import uuid
from types import SimpleNamespace

import pytest

from clusterctl import being_seed, onboarding_receive_keys as keys
from clusterctl.onboarding import OnboardingError, private_directory
from tests.test_onboarding_group_publication import initial_publication
from tests import test_onboarding_group_authorities as fixtures
from tests.test_onboarding_group_admission import closure

group_source = fixtures.group_source


def command():
    return dict(operation_id=str(uuid.uuid4()), step='own-key', action='receive-key', params=dict(
        provider_ref='native', route_ref='companion', key_ref='own-resource-key',
        endpoint='http://127.0.0.1:48675/dm-messaging/v1/message', secret_file='intake.key'))


@pytest.mark.parametrize('profile', ['source', 'guest'])
@pytest.mark.parametrize('boundary', ['intent', 'key', 'result'])
def test_original_key_recovers_and_native_publication_consumes_it(group_source, monkeypatch, profile, boundary):
    owner, group, journal, request, _base = initial_publication(group_source, profile)
    source, _target, _peer, peer_bundle, _old = group_source
    cmd = command()
    cmd['operation_id'] = request['operation_id']
    op = journal / cmd['operation_id']
    intent, key, result = (op/'receive-key/intent.json', op/'receive-key/intake.key',
                           op/'publications/own-key.json')
    write, atomic = being_seed._write, keys.atomic
    def lose_write(path, value, **options):
        write(path, value, **options)
        if (boundary == 'intent' and path == intent
                or boundary == 'result' and path == result and value.get('result') is not None):
            raise OSError('lost key preparation reply')
    def lose_key(*args, **options):
        atomic(*args, **options)
        raise OSError('lost key preparation reply')
    with monkeypatch.context() as fault:
        fault.setattr(being_seed, '_write', lose_write)
        if boundary == 'key':
            fault.setattr(keys, 'atomic', lose_key)
        with pytest.raises(OSError, match='lost key preparation'):
            owner.group_publication(cmd, authority_closure=closure(peer_bundle))
    private = being_seed._read(intent)
    raw = bytes.fromhex(private['key_hex'])
    monkeypatch.setattr(keys, 'token_bytes', lambda n: pytest.fail('retry reminted a key'))
    observed = owner.group_publication(cmd, authority_closure=closure(peer_bundle))
    assert observed['route']['secret_sha256'] == hashlib.sha256(raw).hexdigest()
    assert key.read_bytes() == raw
    assert not key.stat().st_mode & 0o077
    assert raw.hex() not in json.dumps(observed)
    assert str(key) not in json.dumps(observed)
    from daimon_matrix.messaging_config import read_publication
    app, _ = read_publication(source._load(signed=False), source.outputs/'tribe/application')
    route = observed['route']
    own = owner.document_bundle()['local_origin'] if profile == 'guest' else source._load(signed=False).service.origin
    roster = copy.deepcopy(app['roster'])
    for row in roster:
        if row['embodiment_id'] == own['embodiment_id']:
            row['route'] = route
    pub = dict(operation_id=cmd['operation_id'], step='application', action='receive-application', params=dict(
        tribe_ref=app['tribe']['policy']['tribe_ref'],
        policy={k:app['tribe']['policy'][k] for k in ('classification', 'max_ttl_ms')},
        listen=app['listen'], intake=route, roster=roster, stores=app['stores'],
        authority_order=[r['manifest']['being_ref'] for r in app['authorities']],
        secret_sources={route['secret_file']:str(key)}))
    native = owner.group_publication(pub, authority_closure=closure(peer_bundle))
    assert native['application_sha256']
    persisted, _ = read_publication(source._load(signed=False), group/'application')
    assert persisted['intake'] == route
    assert owner.group_publication(cmd, authority_closure=closure(peer_bundle)) == observed
    assert private == being_seed._read(intent)
    assert not (group/'visibility/installation.json').exists()


@pytest.fixture
def local_key(tmp_path):
    runtime, group, operation = [private_directory(tmp_path/n, create=True) for n in ('runtime', 'group', 'operation')]
    being_seed._write(runtime/'runtime.json', {'own': 'fixture-runtime'})
    return SimpleNamespace(state_root=runtime), group, operation, command()


@pytest.mark.parametrize('artifact', ['application', 'selection.json'])
def test_existing_application_refuses_new_key_intent(local_key, artifact):
    hosted, group, operation, cmd = local_key
    (group/artifact).write_text('preserved')
    with pytest.raises(OnboardingError, match='existing_application_preserved'):
        keys.prepare(hosted, group, operation, cmd)
    assert not (operation/'receive-key/intent.json').exists()


@pytest.mark.parametrize('change', ['bytes', 'permissions', 'hardlink', 'symlink'])
def test_different_or_exposed_private_key_is_preserved_and_refused(local_key, change):
    hosted, group, operation, cmd = local_key
    keys.prepare(hosted, group, operation, cmd)
    path = operation/'receive-key/intake.key'
    if change == 'bytes':
        path.write_bytes(b'x'*32)
    elif change == 'permissions':
        path.chmod(0o644)
    elif change == 'hardlink':
        os.link(path, operation/'other.key')
    else:
        path.rename(operation/'other.key')
        path.symlink_to(operation/'other.key')
    before = path.read_bytes()
    with pytest.raises((OnboardingError, being_seed.SeedError), match='receive_key_|symlink'):
        keys.prepare(hosted, group, operation, cmd)
    assert path.read_bytes() == before


def test_changed_command_and_capacity_never_extend_key_state(local_key):
    hosted, group, operation, cmd = local_key
    keys.prepare(hosted, group, operation, cmd)
    changed = copy.deepcopy(cmd)
    changed['params']['route_ref'] += '-changed'
    with pytest.raises(OnboardingError, match='intent_conflict'):
        keys.prepare(hosted, group, operation, changed)
    directory = operation/'receive-key'
    for i in range(7):
        (directory/str(i)).write_bytes(b'x')
    before = {p.name:p.read_bytes() for p in directory.iterdir()}
    with pytest.raises(OnboardingError, match='capacity'):
        keys.prepare(hosted, group, operation, cmd)
    assert {p.name:p.read_bytes() for p in directory.iterdir()} == before


def test_key_intent_total_bound_keeps_exact_existing_recovery(local_key):
    hosted, group, operation, cmd = local_key
    first = keys.prepare(hosted, group, operation, cmd)
    for i in range(16):
        sibling = private_directory(operation.parent/('prior-'+str(i))/'receive-key', create=True)
        being_seed._write(sibling/'intent.json', {'retained': True})
    assert keys.prepare(hosted, group, operation, cmd) == first
    new = private_directory(operation.parent/'new-operation', create=True)
    with pytest.raises(OnboardingError, match='capacity'):
        keys.prepare(hosted, group, new, command())
    assert not (new/'receive-key/intent.json').exists()


@pytest.mark.parametrize('field,value', [
    ('secret_file', '../outside.key'), ('secret_file', 'client.key'),
    ('secret_file', 'intent.json'), ('secret_file', '/absolute.key'),
    ('endpoint', 'https://127.0.0.1:48675/dm-messaging/v1/message'),
    ('endpoint', 'http://user:password@127.0.0.1:48675/dm-messaging/v1/message'),
    ('endpoint', 'http://localhost:48675/dm-messaging/v1/message'),
    ('endpoint', 'http://127.0.0.1/dm-messaging/v1/message'),
    ('endpoint', 'http://127.0.0.1:48675/other'),
])
def test_invalid_public_parameters_refuse_before_private_state(local_key, field, value):
    hosted, group, operation, cmd = local_key
    cmd['params'][field] = value
    with pytest.raises(OnboardingError, match='parameters_required'):
        keys.prepare(hosted, group, operation, cmd)
    assert not (operation/'receive-key').exists()


def test_missing_materialization_uses_original_private_intent(local_key, monkeypatch):
    hosted, group, operation, cmd = local_key
    original = keys.prepare(hosted, group, operation, cmd)
    path = operation/'receive-key/intake.key'
    raw = path.read_bytes()
    path.unlink()
    monkeypatch.setattr(keys, 'token_bytes', lambda n: pytest.fail('missing file reminted the intent'))
    assert keys.prepare(hosted, group, operation, cmd) == original
    assert path.read_bytes() == raw


@pytest.fixture
def resource_import(tmp_path):
    from clusterctl.onboarding import digest
    runtime, group, journal = [private_directory(tmp_path/n, create=True) for n in ('own-runtime', 'own-group', 'own-journal')]
    operation = private_directory(journal/str(uuid.uuid4()), create=True)
    private_directory(operation/'owner', create=True)
    bundle = {'own': 'recipient-runtime'}
    being_seed._write(runtime/'runtime.json', bundle)
    context = {'identity': dict(runtime_root=str(runtime), group_root=str(group), runtime_bundle_sha256=digest(bundle))}
    being_seed._write(operation/'owner/context.json', context)
    raw = b'k'*32
    route = dict(command()['params'], secret_sha256=hashlib.sha256(raw).hexdigest())
    source = dict(schema='cluster-private-receive-resource-export/v1', route=route,
        provenance=dict(runtime_bundle_sha256='a'*64, source_sha256='b'*64), key_hex=raw.hex())
    packet = dict(schema='cluster-private-receive-resource/v1', action='import', operation_id=operation.name,
        owner_context_sha256=digest(context), route=route, source=source)
    return runtime, group, journal, operation, packet


def transfer(fixture):
    import time
    runtime, group, journal, _operation, packet = fixture
    return keys.private_transfer(runtime, group, journal, packet,
        deadline_ns=time.monotonic_ns()+5_000_000_000)


@pytest.mark.parametrize('boundary', ['intent', 'key', 'result'])
def test_private_import_recovers_original_bytes_without_secrets_in_receipts(resource_import, monkeypatch, boundary):
    *_, operation, packet = resource_import
    original_write, original_atomic = being_seed._write, keys.atomic
    def write(path, *args, **kwargs):
        original_write(path, *args, **kwargs)
        if path.parent.name == 'receive-imports':
            raise OSError('lost import intent acknowledgment')
    def atomic(*args, **kwargs):
        original_atomic(*args, **kwargs)
        raise OSError('lost import key acknowledgment')
    with monkeypatch.context() as patch:
        if boundary == 'intent':
            patch.setattr(being_seed, '_write', write)
        if boundary == 'key':
            patch.setattr(keys, 'atomic', atomic)
        if boundary == 'result':
            first = transfer(resource_import)
        else:
            with pytest.raises(OSError):
                transfer(resource_import)
    result = transfer(resource_import)
    assert packet['source']['key_hex'] not in json.dumps(result)
    assert str(operation) not in json.dumps(result)
    assert result['receiving_readiness'] == 'unobserved'
    assert (operation/result['secret_source']).read_bytes() == b'k'*32
    if boundary == 'result':
        assert first == result
    original = {p.name:p.read_bytes() for p in (operation/'receive-imports').iterdir()}
    monkeypatch.setattr(keys, 'atomic', lambda *a,**kw:pytest.fail('retained key rewritten'))
    assert transfer(resource_import) == result
    assert {p.name:p.read_bytes() for p in (operation/'receive-imports').iterdir()} == original


@pytest.mark.parametrize('change', ['context', 'bundle', 'digest', 'route', 'packet', 'oversize'])
def test_private_import_rejects_wrong_body_changed_input_or_unbound_key_before_materialization(resource_import, change):
    runtime, group, journal, operation, packet = resource_import
    if change == 'context':
        packet['owner_context_sha256'] = '0'*64
    elif change == 'bundle':
        being_seed._write(runtime/'runtime.json', {'foreign':'runtime'})
    elif change == 'digest':
        packet['source']['key_hex'] = '00'*32
    elif change == 'route':
        packet['source']['route'] = dict(packet['route'], endpoint='http://127.0.0.2:1234/dm-messaging/v1/message')
    elif change == 'packet':
        packet['source']['extra'] = 'unselected'
    else:
        packet['source']['unbounded'] = 'x'*16384
    with pytest.raises(OnboardingError):
        transfer(resource_import)
    assert not (operation/'receive-imports').exists()


@pytest.mark.parametrize('change', ['bytes', 'permissions', 'symlink', 'hardlink', 'provenance'])
def test_changed_import_preserved_without_replacement(resource_import, tmp_path, change):
    *_, operation, packet = resource_import
    result = transfer(resource_import)
    path = operation/result['secret_source']
    if change == 'bytes':
        path.write_bytes(b'z'*32)
    elif change == 'permissions':
        path.chmod(0o644)
    elif change == 'symlink':
        path.unlink()
        path.symlink_to(tmp_path/'foreign-key')
    elif change == 'hardlink':
        os.link(path, tmp_path/'linked-key')
    else:
        packet['source']['provenance']['source_sha256'] = 'c'*64
    before = path.lstat()
    with pytest.raises(OnboardingError):
        transfer(resource_import)
    assert path.lstat() == before


def test_import_capacity_preserves_exact_recovery_and_refuses_new_route(resource_import):
    *_, operation, packet = resource_import
    original = copy.deepcopy(packet)
    for index in range(16):
        packet['route'] = dict(packet['route'], secret_file=f'route-{index}.key')
        packet['source']['route'] = copy.deepcopy(packet['route'])
        transfer(resource_import)
        if index == 0:
            first = copy.deepcopy(packet)
    packet['route'] = dict(packet['route'], secret_file='overflow.key')
    packet['source']['route'] = copy.deepcopy(packet['route'])
    with pytest.raises(OnboardingError, match='capacity'):
        transfer(resource_import)
    assert len(list((operation/'receive-imports').glob('*.json'))) == 16
    packet.clear()
    packet.update(first)
    assert transfer(resource_import)['secret_source']
    assert original['operation_id'] == packet['operation_id']


@pytest.mark.parametrize('profile', ['source', 'guest'])
@pytest.mark.parametrize('kind', ['prepared', 'application'])
def test_existing_owner_private_pipe_exports_only_actual_own_resource_key(group_source, profile, kind):
    import time
    from clusterctl.onboarding import digest
    owner, group, journal, pub, _base = initial_publication(group_source, profile)
    _source, _target, _peer, peer_bundle, _old = group_source
    if kind == 'prepared':
        cmd = command()
        cmd['operation_id'] = pub['operation_id']
        result = owner.group_publication(cmd, authority_closure=closure(peer_bundle))
        route = result['route']
        source = dict(kind='prepared', command=cmd)
    else:
        result = owner.group_publication(pub, authority_closure=closure(peer_bundle))
        # The export itself verifies the actual signed application before reading.
        route = pub['params']['specification']['intake']
        source = dict(kind='application', application_sha256=result['application_sha256'],
            publication_sha256=result['publication_sha256'])
        preview = owner.group_publication(dict(operation_id=pub['operation_id'],
            step='route-preview',action='receive-route-preview',params={}),authority_closure={},
            deadline_ns=time.monotonic_ns()+5_000_000_000)
        assert preview['route'] == route
        assert preview['source'] == source
        assert 'key_hex' not in preview
    context = being_seed._read(journal/pub['operation_id']/'owner/context.json')
    packet = dict(schema='cluster-private-receive-resource/v1', action='export',
        operation_id=pub['operation_id'], owner_context_sha256=digest(context), route=route, source=source)
    exported = owner.private_resource(packet, deadline_ns=time.monotonic_ns()+5_000_000_000)
    assert hashlib.sha256(bytes.fromhex(exported['key_hex'])).hexdigest() == route['secret_sha256']
    assert exported['route'] == route
    if kind == 'prepared':
        # The existing native publisher consumes the transferred source without
        # another key, identity, application client or model turn.
        owner.private_resource(dict(packet, action='import', source=exported),
            deadline_ns=time.monotonic_ns()+5_000_000_000)
        from daimon_matrix.messaging_config import read_publication
        original = _source._load(signed=False)
        app, _ = read_publication(original, _source.outputs/'tribe/application')
        own = being_seed._read(Path(context['identity']['runtime_root'])/'runtime.json')['local_origin']
        roster = copy.deepcopy(app['roster'])
        for row in roster:
            if row['embodiment_id'] == own['embodiment_id']:
                row['route'] = route
        published = dict(operation_id=pub['operation_id'], step='transferred-application',
            action='receive-application', params=dict(tribe_ref=app['tribe']['policy']['tribe_ref'],
                policy={k:app['tribe']['policy'][k] for k in ('classification', 'max_ttl_ms')},
                listen=app['listen'], intake=route, roster=roster, stores=app['stores'],
                authority_order=[row['manifest']['being_ref'] for row in app['authorities']],
                secret_sources={route['secret_file']:dict(receive_import=digest(route))}))
        actual = owner.group_publication(published, authority_closure=closure(peer_bundle))
        assert actual['application_sha256']
        assert owner.group_publication(published, authority_closure=closure(peer_bundle)) == actual
        assert owner.private_resource(packet, deadline_ns=time.monotonic_ns()+5_000_000_000) == exported
        assert not (group/'visibility/installation.json').exists()

    assert (journal/pub['operation_id']/'receive-imports').exists() == (kind == 'prepared')
    packet['route'] = dict(route, secret_sha256='a'*64)
    with pytest.raises(OnboardingError):
        owner.private_resource(packet, deadline_ns=time.monotonic_ns()+5_000_000_000)


@pytest.mark.parametrize('revoke', [None, 'after-export', 'after-import'])
def test_private_relay_revalidates_each_effect_and_returns_only_public_receipt(resource_import, revoke):
    runtime, group, journal, operation, packet = resource_import
    incoming = copy.deepcopy(packet)
    exported = incoming['source']
    incoming['source'] = {}
    outgoing = dict(incoming, action='export', source={'kind':'application'})
    events = []
    class Source:
        def private_resource(self, value):
            assert value == outgoing
            events.append('export')
            return copy.deepcopy(exported)
    class Recipient:
        def private_resource(self, value):
            assert value == packet
            events.append('import')
            return transfer((runtime, group, journal, operation, value))
    def valid():
        if (revoke == 'after-export' and events == ['export']
                or revoke == 'after-import' and events == ['export', 'import']):
            raise OnboardingError('original grant revoked')
    if revoke is not None:
        with pytest.raises(OnboardingError, match='grant revoked'):
            keys.relay(Source(), Recipient(), outgoing, incoming, validate=valid)
        assert (operation/'receive-imports').exists() == (revoke == 'after-import')
    else:
        result = keys.relay(Source(), Recipient(), outgoing, incoming, validate=valid)
        assert exported['key_hex'] not in json.dumps(result)
        assert incoming['source'] == {}
        assert keys.relay(Source(), Recipient(), outgoing, incoming, validate=valid) == result


@pytest.mark.parametrize('error', [OnboardingError('receive_resource_capacity'),
    ValueError('secret should not be serialized'), PermissionError('private path or credential')])
def test_private_wire_diagnostics_remain_precise_but_never_serialize_exception_contents(error):
    def fail():
        raise error
    response = keys.private_response(fail)
    assert set(response) == {'schema', 'error'}
    assert 'secret should' not in json.dumps(response)
    assert 'private path' not in json.dumps(response)
    with pytest.raises(OnboardingError, match=response['error']):
        keys.private_result(response)
    if isinstance(error, OnboardingError):
        assert response['error'] == str(error)


@pytest.mark.parametrize('retained', [False, True])
def test_journal_import_limit_stops_new_operations_without_breaking_retained_recovery(resource_import, retained):
    _runtime, _group, journal, operation, _packet = resource_import
    if retained:
        original = transfer(resource_import)
    for _index in range(16):
        sibling = private_directory(journal/str(uuid.uuid4()), create=True)
        private_directory(sibling/'receive-imports', create=True)
    if retained:
        assert transfer(resource_import) == original
    else:
        with pytest.raises(OnboardingError, match='capacity'):
            transfer(resource_import)
        assert not (operation/'receive-imports').exists()


@pytest.mark.parametrize('profile', ['source', 'guest'])
@pytest.mark.parametrize('refusal', [False, True])
def test_existing_owner_clients_keep_private_transfer_on_their_selected_pipe(monkeypatch, profile, refusal):
    from clusterctl.onboarding_receiving_update import SourceGroupClient, GuestGroupClient
    cls = SourceGroupClient if profile == 'source' else GuestGroupClient
    client = object.__new__(cls)
    request = {'fixture':'private transfer'}
    calls = []
    response = ({'schema':'cluster-private-receive-resource-refusal/v1', 'error':'receive_resource_capacity'}
        if refusal else {'schema':'cluster-private-receive-resource-export/v1', 'key_hex':'fixture only'})
    def call(*args, **kwargs):
        calls.append((args, kwargs))
        return response
    monkeypatch.setattr(client, '_call', call)
    if refusal:
        with pytest.raises(OnboardingError, match='receive_resource_capacity'):
            client.private_resource(request)
    else:
        assert client.private_resource(request) is response
    args, options = calls[0]
    assert options['maintenance'] is True
    if profile == 'source':
        assert args == (['--group-request', '-', '--private-resource'],)
        assert options['command'] == request
    else:
        assert args == ('group-resource',)
        assert options['group_request'] == request


@pytest.mark.parametrize('change',['filename','context','slot'])
def test_import_reference_is_resolved_only_inside_its_original_owner_operation(resource_import,change):
    from clusterctl.onboarding import digest
    *_,operation,packet=resource_import
    transfer(resource_import)
    route=packet['route']
    references={route['secret_file']:dict(receive_import=digest(route))}
    result=keys.resolve_sources(operation,references)
    assert list(result)==[route['secret_file']]
    assert Path(result[route['secret_file']]).read_bytes()==b'k'*32
    if change=='filename':
        references={'other.key':references[route['secret_file']]}
    elif change=='slot':
        references[route['secret_file']]['receive_import']='../outside'
    else:
        context=being_seed._read(operation/'owner/context.json')
        context['identity']['runtime_bundle_sha256']='f'*64
        being_seed._write(operation/'owner/context.json',context)
    with pytest.raises(OnboardingError):
        keys.resolve_sources(operation,references)
