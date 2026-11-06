"""Verified proof reuse must not freeze authority inputs or expose mutable state."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from types import SimpleNamespace

import pytest

from clusterctl.homes.authority import NativeAuthority


def authority(tmp_path):
    return NativeAuthority(tmp_path/'bindings', tmp_path/'relationships', {})


def test_constructor_reuse_defensively_isolates_first_and_warm_results(tmp_path):
    a = authority(tmp_path)
    calls = []
    def construct(value):
        calls.append(deepcopy(value))
        return SimpleNamespace(state={'controls': [value['head']]})
    first = a._constructed('root', {'head': 'one'}, construct)
    first.state['controls'].append('corrupted-first')
    warm = a._constructed('root', {'head': 'one'}, construct)
    assert warm.state == {'controls': ['one']}
    warm.state['controls'][0] = 'corrupted-warm'
    assert a._constructed('root', {'head': 'one'}, construct).state == {'controls': ['one']}
    assert len(calls) == 1


def test_complete_inputs_constructor_kind_failure_and_instance_isolation(tmp_path):
    a = authority(tmp_path)
    calls = []
    def construct(value):
        calls.append(deepcopy(value))
        if 'unexpected' in value:
            raise ValueError('closed schema')
        return deepcopy(value)
    base = {'manifest': 'same', 'control': 'one', 'history': [{'successor': 'first'}]}
    assert a._constructed('root', base, construct) == base
    for change in [{'control': 'two'}, {'history': [{'successor': 'second'}]}]:
        value = {**base, **change}
        assert a._constructed('root', value, construct) == value
    a._constructed('history', base, construct)
    for _ in range(2):
        with pytest.raises(ValueError, match='closed schema'):
            a._constructed('root', {**base, 'unexpected': True}, construct)
    assert a._constructed('root', base, construct) == base
    authority(tmp_path)._constructed('root', base, construct)
    assert len(calls) == 7


def test_bounded_eviction_oversize_bypass_and_concurrent_defensive_copies(tmp_path):
    a = authority(tmp_path)
    a._proof_cache_entries = 2
    calls = []
    def construct(value):
        calls.append(value['id'])
        return {'nested': [value['id']]}
    def request(_):
        result = a._constructed('root', {'id': 'shared'}, construct)
        result['nested'].append('private')
        return result
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(request, range(12)))
    assert all(r == {'nested': ['shared', 'private']} for r in results)
    assert len({id(r['nested']) for r in results}) == 12
    assert calls == ['shared']
    for key in ['second', 'third', 'shared']:
        a._constructed('root', {'id': key}, construct)
    assert calls == ['shared', 'second', 'third', 'shared']
    assert len(a._proof_cache) == 2
    a._proof_cache_limit = 1
    # Existing entries are not a global heap claim; input over the configured
    # limit always bypasses retention, even when a prior key exists.
    for _ in range(2): a._constructed('root', {'id': 'oversize'}, construct)
    assert calls[-2:] == ['oversize', 'oversize']


def test_warm_bindings_recheck_source_permissions_and_current_origin(tmp_path, monkeypatch):
    import daimon_matrix.human_tribu_process as process
    import daimon_matrix.messaging_config as config
    import daimon_matrix.operator_rebirth as rebirth
    a = authority(tmp_path)
    source = {'document': '{"head":"one"}', 'deny': False, 'origin': 'active'}
    calls = []
    row = dict(authority_file='public-proof', being_ref='being', origin='active',
               human_id=1, bot_id=2, enabled=True, label='Being', human_name='Human', username='bot')
    monkeypatch.setattr(process, 'host_config', lambda _: {'participants': [{**row, 'origin': source['origin']}]})
    def read(_):
        if source['deny']: raise PermissionError('unreadable proof')
        return source['document']
    class Constructed:
        manifest = SimpleNamespace(being_ref='being')
        def validate_origin(self, origin, require_active):
            assert require_active
            if origin != 'active': raise ValueError('revoked origin')
    def construct(value):
        calls.append(value)
        return Constructed()
    monkeypatch.setattr(config, 'protected_read', read)
    monkeypatch.setattr(rebirth, 'authority_from_document', construct)
    a.bindings(); a.bindings()
    assert len(calls) == 1
    source['deny'] = True
    with pytest.raises(PermissionError): a.bindings()
    source['deny'] = False; source['origin'] = 'revoked'
    with pytest.raises(ValueError, match='revoked origin'): a.bindings()
    assert len(calls) == 1
    source['origin'] = 'active'; source['document'] = '{"head":"two"}'
    a.bindings()
    assert len(calls) == 2


def test_warm_history_rechecks_current_pin_unknown_epoch_fields_and_read_failure(tmp_path, monkeypatch):
    import json
    import clusterctl.homes.authority as module
    import daimon_matrix.messaging_config as config
    a = NativeAuthority(tmp_path/'bindings', tmp_path/'relationships', {},
                        authority_source=tmp_path/'current')
    document = dict(control_artifacts=[], control_head='one', manifest={},
                    credentials={}, incarnations={}, authority_history=[])
    calls = []
    source = {'value': document, 'deny': False}
    def read(_):
        if source['deny']: raise PermissionError('current source denied')
        return json.dumps(source['value'])
    def history(value):
        calls.append(deepcopy(value))
        if any(set(e) != {'manifest', 'successor'} for e in value['authority_history']):
            raise ValueError('invalid epoch')
        return SimpleNamespace(manifest=SimpleNamespace(being_ref='being', digest=value['control_head']))
    monkeypatch.setattr(config, 'protected_read', read)
    monkeypatch.setattr(module, 'public_history', history)
    monkeypatch.setattr(a, 'bindings', lambda: [dict(being_ref='being', authority=SimpleNamespace(manifest=SimpleNamespace(digest='one')))])
    a.authorities(); a.authorities()
    assert len(calls) == 1
    source['deny'] = True
    with pytest.raises(PermissionError): a.authorities()
    source['deny'] = False
    source['value'] = {**document, 'control_head': 'two'}
    with pytest.raises(ValueError, match='home_actor_authority_source_stale'): a.authorities()
    source['value'] = {**document, 'authority_history': [{'manifest': {}, 'successor': {}, 'unexpected': True}]}
    with pytest.raises(ValueError, match='invalid epoch'): a.authorities()
    source['value'] = {**document, 'sources': {'known_beings': [{**document, 'control_head': 'fork'}]}}
    with pytest.raises(ValueError, match='home_authority_source_fork'): a.authorities()
    source['value'] = document
    assert a.authorities()['being'].manifest.digest == 'one'
    assert len(calls) == 4


def test_roster_and_clock_remain_fresh_after_proof_cache_warming(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from clusterctl.homes.policy import Actor
    a = authority(tmp_path)
    a._constructed('root', {'signed': 'historical'}, lambda v: deepcopy(v))
    now = [100]
    roster = dict(revision=1, revoked=False, founder_principal_id='founder',
                  expires_at_ms=200, readers=['human'])
    a.clock = lambda: now[0]
    a.human_rosters = lambda: {'tribe': roster}
    @contextmanager
    def view():
        yield SimpleNamespace(snapshot=lambda _: SimpleNamespace(value={
            'founder_principal_id': 'founder', 'members': []}))
    monkeypatch.setattr(a, 'view', view)
    human = Actor('human', 'human', 'rev', 'Human')
    assert a.tribe_member('home', 'tribe', human)
    now[0] = 201
    assert not a.tribe_member('home', 'tribe', human)
    now[0] = 100; roster['revoked'] = True
    assert not a.tribe_member('home', 'tribe', human)


def test_accounting_limit_evicts_individually_cacheable_entries(tmp_path):
    a = authority(tmp_path)
    a._proof_cache_limit = 150000
    construct = lambda value: {'public': value}
    for key in ['one', 'two', 'three']:
        a._constructed('root', {'id': key}, construct)
    assert len(a._proof_cache) == 2
    assert all(key[1] != b'{"id":"one"}' for key in a._proof_cache)
    assert a._proof_cache_bytes == sum(charge for _, charge in a._proof_cache.values())
    assert a._proof_cache_bytes <= a._proof_cache_limit
