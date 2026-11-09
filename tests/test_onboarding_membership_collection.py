"""Original-job collection uses real public native fixtures, never authoring."""
import copy
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import JobStore, OnboardingError, digest
from clusterctl.onboarding_membership_collection import collect
from tests import test_onboarding_membership_intent as intent_fixtures
from tests.test_onboarding import FixtureBackend

group_source = intent_fixtures.group_source
inputs = intent_fixtures.inputs


@pytest.fixture
def prepared(inputs, group_source, tmp_path, monkeypatch):
    from clusterctl.onboarding_target import Target, document
    source, first, _peer_authority, peer_bundle, _old = group_source
    peer = Target(tmp_path/'candidate/guest', first.plan,
        document(tmp_path/'candidate/custody'/digest(first.plan)/'genesis.json'))
    selected = copy.deepcopy(inputs['owners'])
    selected['founder']['code_uid'] = 0
    selected['entrant']['root'] = str(peer.package/'runtime')
    source.qualified_startup = {'code_digest': 'a'*64, 'matrix_wheel_sha256': 'c'*64}
    peer.qualified_startup = {'code_digest': 'b'*64, 'matrix_wheel_sha256': 'c'*64}
    monkeypatch.setattr(source, 'writer', lambda: pytest.fail('source native writer'))
    monkeypatch.setattr(peer, '_runtime_writer', lambda: pytest.fail('entrant native writer'))
    calls, fault = [], {'lose': None}
    owners = {}
    for name, actual in (('founder', source), ('entrant', peer)):
        owner = SimpleNamespace(root=Path(selected[name]['root']),
            socket=Path(selected[name]['root'])/'tribe.sock', deadline_ns=None)
        def call(command, *, authority_closure, name=name, actual=actual, owner=owner):
            calls.append((name, command['action']))
            if fault['lose'] == (name, command['action']):
                fault['lose'] = None
                raise OSError('synthetic metadata reply loss')
            return actual.group_publication(command, authority_closure=authority_closure,
                                            deadline_ns=owner.deadline_ns)
        owner.group_publication = call
        owners[name] = owner
    template = dict(state=str(tmp_path/'collection'), participants=['entrant', 'founder'],
                    founder_owner='founder', authoring_seconds=60)
    identity = dict(being_ref=peer_bundle['manifest']['being_ref'],
                    embodiment_id=peer_bundle['local_origin']['embodiment_id'])
    granted = {'value': True}
    arguments = dict(plan=inputs['plan'], selected=selected, template=template, owners=owners,
        identity=identity, tribe_ref=inputs['admission']['tribe_ref'],
        deadline_ns=time.monotonic_ns()+60_000_000_000, authorize=lambda: granted['value'])
    return SimpleNamespace(arguments=arguments, calls=calls, fault=fault, granted=granted)


def test_collection_resumes_missing_reads_and_never_renews_a_finished_request(prepared, monkeypatch):
    f = prepared
    f.fault['lose'] = ('founder', 'context-preview')
    with pytest.raises(OSError, match='metadata reply loss'):
        collect(**f.arguments)
    root = Path(f.arguments['template']['state'])
    original = being_seed._read(root/'intent.json')
    assert 'issued_at_ms' not in original, 'native invitation starts after preparation'
    reference = collect(**f.arguments)
    request = being_seed._read(Path(reference['path']), limit=being_seed.MAX_SELECTION)
    intent = being_seed._read(root/'intent.json')
    assert all(intent[key] == original[key] for key in original)
    assert f.calls.count(('entrant', 'preparation-preview')) == 1
    assert f.calls.count(('founder', 'preparation-preview')) == 1
    assert f.calls.count(('entrant', 'context-preview')) == 1
    assert f.calls.count(('founder', 'context-preview')) == 2
    assert request['after']['portal_admission']['social']['invitation']['nonce'] == intent['nonce']
    assert set(request['after']) == {'cohort_admission', 'portal_admission', 'membership_only'}
    seen = list(f.calls)
    monkeypatch.setattr(time, 'time_ns', lambda: (intent['expires_at_ms']+1)*1_000_000)
    assert collect(**f.arguments) == reference
    assert being_seed._read(Path(reference['path']), limit=being_seed.MAX_SELECTION) == request
    assert f.calls == seen and all(owner.deadline_ns is None for owner in f.arguments['owners'].values())


def test_collection_preserves_work_when_grant_or_selection_changes(prepared):
    f = prepared
    reference = collect(**f.arguments)
    original = Path(reference['path']).read_bytes()
    f.granted['value'] = False
    with pytest.raises(OnboardingError, match='host_authorization_required'):
        collect(**f.arguments)
    f.granted['value'] = True
    changed = dict(f.arguments, template={**f.arguments['template'], 'authoring_seconds': 600})
    with pytest.raises(OnboardingError, match='membership_compilation_required'):
        collect(**changed)
    assert Path(reference['path']).read_bytes() == original


def test_existing_worker_collects_and_binds_without_a_manual_preparation_launcher(prepared, tmp_path, monkeypatch):
    from clusterctl.onboarding_group_coordinator import GroupCoordinator, SCHEMA, SOURCE_PATHS
    f = prepared
    args = f.arguments
    selected = args['selected']['founder']
    selected.update({key: str(tmp_path/key) for key in SOURCE_PATHS - {'root', 'code', 'socket_path'}})
    selected.update(owner_uid=1000, owner_gid=1000, config_sha256='f'*64)
    store = JobStore(tmp_path/'jobs')
    stages = FixtureBackend()
    store.submit(args['plan'], stages)
    for _ in range(3):
        store.tick('entrant', stages)
    settings = dict(schema=SCHEMA, tribe_ref=args['tribe_ref'], journal=str(tmp_path/'journal'),
        owners=args['selected'], admissions={}, membership_preparations={digest(args['plan']): args['template']})
    path = tmp_path/'policy.json'
    being_seed._write(path, settings)
    ceremony = SimpleNamespace(authorize=lambda p: True, admission_coordinates=lambda p: args['identity'])
    backend = SimpleNamespace(config=SimpleNamespace(group_admission=path, jobs=store.root),
        authorize=lambda *a: True, _consented=lambda *a, **k: True,
        _decision=lambda p: {'approved': True}, _ceremony=lambda p: ceremony)
    monkeypatch.setattr(GroupCoordinator, '_owner_client', lambda self, name: args['owners'][name])
    phases = []
    monkeypatch.setattr(GroupCoordinator, 'advance_membership_only',
        lambda self, name, **k: phases.append(name) or {'receiving_readiness': 'unobserved'})
    coordinator = GroupCoordinator(backend)
    assert coordinator.advance('entrant', timeout_seconds=60) == {'receiving_readiness': 'unobserved'}
    bound = coordinator._binding(args['plan'])
    assert bound is not None and bound[1]['runtime_observation'] is None
    retained = being_seed._read(path)
    assert retained['admissions'][digest(args['plan'])] == bound[1]['operation_id']
    assert retained['membership_requests'][digest(args['plan'])]['sha256']
    seen = list(f.calls)
    assert coordinator.advance('entrant', timeout_seconds=60) == {'receiving_readiness': 'unobserved'}
    assert phases == ['entrant', 'entrant'] and f.calls == seen
