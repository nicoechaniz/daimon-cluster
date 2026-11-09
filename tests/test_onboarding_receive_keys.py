"""Original own key intent survives lost replies without reminting or disclosure."""
import copy
import hashlib
import json
import os
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
