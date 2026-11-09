"""Native signed-governance compilation, without native authoring or enrollment."""
import copy
import uuid

import pytest

from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_membership_intent import compile_request
from tests.test_onboarding import plan
from tests.test_onboarding_group_admission import closure, invitation
from tests import test_onboarding_group_admission as native_fixtures

group_source = native_fixtures.group_source


@pytest.fixture
def inputs(group_source, tmp_path):
    source, first, _peer, peer_bundle, _old = group_source
    bundles = {'founder': first.document_bundle(), 'entrant': peer_bundle}
    roots = {'founder': source.root, 'entrant': tmp_path/'entrant'}
    owners = dict(founder=dict(profile='source', root=str(roots['founder']),
                              code='/qualified/source', code_digest='a'*64,
                              socket_path=str(roots['founder']/'tribe.sock')),
                  entrant=dict(profile='guest', root=str(roots['entrant']),
                               plan=plan(name='entrant'),
                               candidate=dict(code='/qualified/entrant', digest='b'*64)))
    receivers = {}
    for name, bundle in bundles.items():
        selected = owners[name]
        candidate = (dict(code=selected['code'], digest=selected['code_digest'])
                     if name == 'founder' else selected['candidate'])
        receivers[name] = dict(being_ref=bundle['manifest']['being_ref'],
            embodiment_id=bundle['local_origin']['embodiment_id'], root=str(roots[name]),
            socket=str(roots[name]/'tribe.sock'), candidate=dict(code=candidate['code'], code_uid=0),
            recipe=dict(profile=selected['profile'], tooling={'profile': 'matrix-only'},
                        prepared=dict(being_ref=bundle['manifest']['being_ref'],
                                      embodiment_id=bundle['local_origin']['embodiment_id'],
                                      code_digest=candidate['digest'], matrix_wheel_sha256='c'*64)))
    payload = invitation(source, peer_bundle)['params']['payload']
    native = source._load(signed=False)
    declaration = next(row for row in native.service.relationships.store.events()
                       if row['kind'] == 'matrix/tribe-declaration')
    sender = dict(name='founder', root=str(source.root), socket=str(source.root/'tribe.sock'),
                  being_ref=receivers['founder']['being_ref'],
                  server=bundles['founder']['local_origin'], process={}, gate={})
    return dict(plan=owners['entrant']['plan'], owners=owners,
        admission=dict(schema='cluster-receiving-admission/v1', tribe_ref=payload['tribe_ref'],
            entrant=dict(being_ref=receivers['entrant']['being_ref'],
                         embodiment_ids=[receivers['entrant']['embodiment_id']]),
            receivers=receivers, activation=dict(manifest_path=str(tmp_path/'request.json'),
                manifest_uid=0, expires_at_ms=payload['expires_at_ms'], observation_window_ms=60000)),
        senders=[sender], governance=[declaration],
        authority_closure={**closure(bundles['founder']), **closure(peer_bundle)},
        owner_contexts={'founder': 'd'*64, 'entrant': 'e'*64}, invitation=payload,
        operation_id=str(uuid.uuid4()), founder_owner='founder', source='fixture',
        acceptance_not_after_ms=payload['expires_at_ms'])


def test_compilation_preserves_original_frames_without_outbound_policy(inputs, monkeypatch):
    from clusterctl import onboarding_group_admission as native
    import time
    before = copy.deepcopy(inputs)
    monkeypatch.setattr(native, 'relationship_request', lambda *a, **k: pytest.fail('native authoring'))
    value = compile_request(**inputs)
    monkeypatch.setattr(time, 'time_ns', lambda: (inputs['invitation']['expires_at_ms']+1)*1000000)
    assert compile_request(**inputs) == value, 'expiry cannot refresh the invitation or erase preparation'
    assert inputs == before
    after = value['after']
    assert set(after) == {'cohort_admission', 'portal_admission', 'membership_only'}
    assert after['portal_admission']['social']['invitation'] == inputs['invitation']
    assert after['portal_admission']['social']['membership_sequence'] == 0
    assert after['portal_admission']['owners_sha256'] == digest(inputs['owners'])
    assert value['original_plan_digest'] == digest(inputs['plan'])
    after['portal_admission']['social']['invitation']['nonce'] = 'changed-output'
    assert inputs == before


@pytest.mark.parametrize('part', ['identity', 'candidate', 'plan', 'governance', 'closure',
                                  'sender', 'invitation', 'contexts', 'outbound', 'manifest', 'socket'])
def test_compilation_refuses_mismatched_or_unsigned_preparation(inputs, part):
    value = copy.deepcopy(inputs)
    if part == 'identity':
        value['admission']['entrant']['being_ref'] = value['admission']['receivers']['founder']['being_ref']
    elif part == 'candidate':
        value['owners']['entrant']['candidate']['digest'] = 'f'*64
    elif part == 'plan':
        value['owners']['entrant']['plan']['name'] = 'another'
    elif part == 'governance':
        value['governance'][0]['payload']['founder_epoch'] = 9
    elif part == 'closure':
        value['authority_closure'] = {}
    elif part == 'sender':
        value['senders'][0]['server']['embodiment_id'] = 'another'
    elif part == 'invitation':
        value['invitation']['nonce'] = 'invalid'
    elif part == 'contexts':
        value['owner_contexts'].pop('entrant')
    elif part == 'manifest':
        value['admission']['activation']['manifest_path'] = 'relative-path'
    elif part == 'socket':
        value['owners']['founder']['socket_path'] = '/unselected/socket'
    else:
        value['admission']['receivers']['entrant']['recipe']['tooling'] = {'profile': 'codex'}
    with pytest.raises(OnboardingError, match='membership_compilation_required'):
        compile_request(**value)


@pytest.fixture
def caller(inputs, tmp_path):
    import os
    from types import SimpleNamespace
    from clusterctl import being_seed
    from clusterctl.onboarding import JobStore
    from clusterctl.onboarding_group_coordinator import GroupCoordinator, SCHEMA, SOURCE_PATHS
    from tests.test_onboarding import FixtureBackend
    selected = inputs['owners']['founder']
    selected.update({key: str(tmp_path/key) for key in SOURCE_PATHS - {'root', 'code', 'socket_path'}})
    selected.update(config_sha256='f'*64, owner_uid=1000, owner_gid=1000, code_uid=0)
    inputs['admission']['activation']['manifest_uid'] = os.geteuid()
    request = compile_request(**inputs)
    request_path = tmp_path/'request.json'
    inputs['admission']['activation']['manifest_path'] = str(request_path)
    request = compile_request(**inputs)
    being_seed._write(request_path, request, limit=being_seed.MAX_SELECTION)
    store = JobStore(tmp_path/'jobs')
    stages = FixtureBackend()
    store.submit(inputs['plan'], stages)
    for _ in range(3):
        store.tick('entrant', stages)
    assert store._load('entrant')['stage'] == 'matrix'
    policy = dict(schema=SCHEMA, tribe_ref=inputs['admission']['tribe_ref'],
        journal=str(tmp_path/'journal'), owners=inputs['owners'], admissions={},
        membership_requests={digest(inputs['plan']): dict(path=str(request_path), sha256=digest(request))})
    path = tmp_path/'policy.json'
    being_seed._write(path, policy)
    ceremony = SimpleNamespace(authorize=lambda p: stages.granted,
        admission_coordinates=lambda p: inputs['admission']['receivers']['entrant'])
    backend = SimpleNamespace(config=SimpleNamespace(group_admission=path, jobs=store.root),
        authorize=lambda *a: stages.granted, _decision=lambda p: {'approved': True},
        _consented=lambda *a, **k: True, _ceremony=lambda p: ceremony)
    return SimpleNamespace(coordinator=GroupCoordinator(backend), backend=backend,
        stages=stages, policy=path, request=request_path, fixed=request, inputs=inputs)


def test_worker_binds_after_actual_identity_and_resumes_lost_policy_write(caller, monkeypatch):
    from clusterctl import being_seed
    from clusterctl.onboarding_group_coordinator import GroupCoordinator
    from clusterctl.operation_journal import OperationJournal
    f = caller
    original = f.request.read_bytes()
    write = being_seed._write
    def lose(path, *args, **kwargs):
        if path == f.policy:
            raise OSError('synthetic loss after journal plan')
        return write(path, *args, **kwargs)
    monkeypatch.setattr(being_seed, '_write', lose)
    with pytest.raises(OSError, match='after journal plan'):
        f.coordinator.bind_membership_request('entrant')
    journal = OperationJournal(f.coordinator.settings['journal'])
    key = 'receiving-update:receiving:'+f.inputs['admission']['tribe_ref']+':'+digest(f.fixed)
    retained = journal.latest_for_idempotency_key(key)
    assert retained is not None and retained['runtime_observation'] is None
    monkeypatch.setattr(being_seed, '_write', write)
    seen = []
    monkeypatch.setattr(GroupCoordinator, 'advance_membership_only',
        lambda self, name, **kwargs: seen.append(name) or {'prepared': True})
    resumed = GroupCoordinator(f.backend)
    assert resumed.advance('entrant') == {'prepared': True}
    assert seen == ['entrant']
    assert resumed.bind_membership_request('entrant')['operation_id'] == retained['operation_id']
    assert journal.get(retained['operation_id'])['runtime_observation'] is None
    assert f.request.read_bytes() == original
    # A later owner selection cannot replace this original operation.
    changed = copy.deepcopy(f.fixed)
    changed['source'] = 'changed-intent'
    write(f.request, changed, limit=being_seed.MAX_SELECTION)
    policy = being_seed._read(f.policy)
    policy['membership_requests'][digest(f.inputs['plan'])]['sha256'] = digest(changed)
    write(f.policy, policy)
    with pytest.raises(OnboardingError, match='admission_binding_changed'):
        GroupCoordinator(f.backend).bind_membership_request('entrant')


def test_binding_rechecks_original_grant_and_real_identity(caller):
    from clusterctl.operation_journal import OperationJournal
    f = caller
    f.stages.granted = False
    with pytest.raises(OnboardingError, match='host_authorization_required'):
        f.coordinator.bind_membership_request('entrant')
    assert OperationJournal.existing(f.coordinator.settings['journal']) is None
    f.stages.granted = True
    f.backend._ceremony(f.inputs['plan']).admission_coordinates = lambda p: dict(
        being_ref='wrong-identity', embodiment_id='wrong-body')
    with pytest.raises(OnboardingError, match='membership_compilation_required'):
        f.coordinator.bind_membership_request('entrant')
    assert OperationJournal.existing(f.coordinator.settings['journal']) is None
