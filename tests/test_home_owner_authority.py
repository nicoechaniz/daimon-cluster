"""Explicit same-owner authority continuity without key or browser-session reset."""
import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from types import SimpleNamespace
from contextlib import closing
from pathlib import Path

import pytest

from clusterctl.homes.host import accept_owner_authority
from clusterctl.homes.authority import NativeAuthority
from clusterctl.homes.policy import Actor
from clusterctl.homes.provision import sha
from clusterctl.homes.service import Application
from clusterctl.homes.sessions import Sessions


def configuration(tmp_path):
    def key(name):
        p=tmp_path/name;p.write_text(name);p.chmod(0o600);return str(p)
    return {"schema":"dm.resource-access.host/v1", "state":str(tmp_path/'state'),
            "binding_source":str(tmp_path/'identities'),
            "relationship_store":str(tmp_path/'relationships'),
            "authority_source":str(tmp_path/'authority'),
            "viewer_port":8820,"owner_port":8821,
            "content_public_url":"https://content.example",
            "content_vpn_url":"https://private-content.example",
            "homes":{"one":{"name":"Home", "owner_being_ref":"being-one",
                    "owner_revision":"a"*64,"public_url":"https://one.example",
                    "vpn_url":"https://private-one.example", "backend":"http://127.0.0.1:8801",
                    "owner_token_file":key('owner'),"gateway_token_file":key('reader'),"ring":[]}}}


class Authority:
    revision='a'*64
    verified=0
    def __init__(self,*a,**kw):pass
    def authorities(self):
        type(self).verified+=1
        return {}
    def actor(self,ref):return Actor(ref,'being',self.revision,ref)
    def actors(self):return {'being-one':self.actor('being-one')}
    def tribes(self):return {}
    def paired_human(self,home):return 'human-one'
    def tribe_member(self,*a):return False


def test_real_owner_operation_needs_explicit_host_acceptance_preserves_credentials(tmp_path,monkeypatch):
    Authority.revision='a'*64;Authority.verified=0
    monkeypatch.setattr('clusterctl.homes.authority.NativeAuthority',Authority)
    cfg=configuration(tmp_path);p=tmp_path/'config.json';p.write_text(json.dumps(cfg));p.chmod(0o600)
    original=p.read_bytes();app=Application(cfg,Authority(),Sessions(Path(cfg['state'])))
    human=Actor('human-one','human','stable-human','Human')
    browser=app.sessions.issue(home='one',origin='https://one.example',subject=human)
    with closing(app.sessions.connect()) as db:credentials=[tuple(r) for r in db.execute('SELECT * FROM owner_credentials')]
    Authority.revision='b'*64
    with pytest.raises(ValueError,match='home_owner_binding_unavailable'):
        app.owner('one','owner','targets',{})
    with pytest.raises(ValueError,match='concurrent_gateway_configuration'):
        accept_owner_authority(p,'one',previous_digest='stale')
    assert Authority.verified==0
    result=accept_owner_authority(p,'one',previous_digest=sha(original))
    assert result['revision']=='b'*64 and Authority.verified==1
    assert app.owner('one','owner','targets',{})['actors'][0]['ref']=='being-one'
    assert p.read_bytes()==original and Path(cfg['homes']['one']['owner_token_file']).read_text()=='owner'
    assert app.sessions.resolve(browser,home='one',origin='https://one.example')['actor']==human.ref
    with closing(app.sessions.connect()) as db:assert [tuple(r) for r in db.execute('SELECT * FROM owner_credentials')]==credentials
    # No public/owner-local operation can grant this trusted host acceptance.
    with pytest.raises(ValueError):app.owner('one','owner','accept-owner-authority',{})
    Authority.revision='c'*64
    with pytest.raises(ValueError,match='home_owner_binding_unavailable'):app.owner('one','owner','targets',{})
    accept_owner_authority(p,'one',previous_digest=sha(original))
    assert app.owner('one','owner','targets',{})
    # Restart over the exact original config works without rebinding the token.
    restarted=Application(cfg,Authority(),Sessions(Path(cfg['state'])))
    assert restarted.owner('one','owner','targets',{})


def test_acceptance_cannot_rebind_home_actor_base_revision_or_revoked_key(tmp_path):
    s=Sessions(tmp_path/'state');s.register_owner(home='one',actor='being-one',revision='a',token='owner')
    owner=Actor('being-one','being','b','Owner')
    for change in [dict(home='two'),dict(subject=Actor('foreign','being','b','Foreign')),
                   dict(subject=Actor('being-one','human','b','Human')),
                   dict(subject=Actor('being-one','being','b','Disabled',False)),dict(binding_revision='wrong')]:
        kw=dict(home='one',subject=owner,binding_revision='a');kw.update(change)
        with pytest.raises(ValueError):s.accept_owner_authority('owner',**kw)
    with pytest.raises(ValueError,match='immutable'):
        s.register_owner(home='one',actor='being-one',revision='b',token='owner')
    s.accept_owner_authority('owner',home='one',subject=owner,binding_revision='a')
    assert s.owner('owner',home='one',subject=owner,binding_revision='a')
    assert not s.owner('owner',home='two',subject=owner,binding_revision='a')
    assert not s.owner('wrong',home='one',subject=owner,binding_revision='a')
    # Default API stays exact-revision; acceptance is explicit in the app path.
    assert not s.owner('owner',home='one',subject=owner)
    for i in range(100):s.accept_owner_authority('owner',home='one',subject=Actor('being-one','being',str(i),'Owner'),binding_revision='a')
    with closing(s.connect()) as db:
        assert db.execute('SELECT count(*) FROM owner_authority_acceptance').fetchone()[0]==1
        db.execute('UPDATE owner_credentials SET revoked=1')
    assert not s.owner('owner',home='one',subject=Actor('being-one','being','99','Owner'),binding_revision='a')
    with pytest.raises(ValueError):s.accept_owner_authority('owner',home='one',subject=owner,binding_revision='a')


def test_actor_lookup_refuses_a_historical_pin_against_current_source(monkeypatch,tmp_path):
    authority=NativeAuthority(tmp_path/'bindings',tmp_path/'relationships',{},
                              authority_source=tmp_path/'current-native-authority')
    def current():raise ValueError('home_actor_authority_source_stale')
    monkeypatch.setattr(authority,'authorities',current)
    # Every actor consumer, not only a later tribe read, must fail closed.
    with pytest.raises(ValueError,match='home_actor_authority_source_stale'):
        authority.actor('being-one')


def test_read_snapshot_is_lazy_success_only_nested_and_instance_local(monkeypatch, tmp_path):
    from types import SimpleNamespace
    authority = NativeAuthority(tmp_path/'bindings', tmp_path/'relationships', {})
    reads = []
    source = {'name': 'First', 'fail': False}
    def bindings():
        reads.append(source['name'])
        if source['fail']:
            raise ValueError('invalid_home_authority_history')
        return [dict(enabled=True, being_ref='being', origin='origin', label=source['name'],
                     human_id=123, human_name='Human',
                     authority=SimpleNamespace(manifest=SimpleNamespace(digest=source['name'])))]
    monkeypatch.setattr(authority, '_bindings', bindings)
    with authority.read_snapshot():
        assert reads == []  # Public GETs do not trigger proof reconstruction.
        assert authority.actor('being').name == 'First'
        assert authority.actor('being').name == 'First'
        assert reads == ['First']
        source['name'] = 'Second'
        with authority.read_snapshot():
            assert authority.actor('being').name == 'Second'
        assert authority.actor('being').name == 'First'
    assert authority.actor('being').name == 'Second'
    source['fail'] = True
    with pytest.raises(ValueError):
        with authority.read_snapshot():
            authority.actor('being')
    assert authority._read_snapshot.get() is None
    with authority.read_snapshot():
        with pytest.raises(ValueError): authority.actor('being')
        source['fail'] = False
        assert authority.actor('being').name == 'Second'  # Failed reads never cached.
    second = NativeAuthority(tmp_path/'other', tmp_path/'relationships', {})
    assert second._read_snapshot is not authority._read_snapshot
    with authority.read_snapshot():
        assert second._read_snapshot.get() is None


def test_read_snapshot_isolated_between_concurrent_requests(monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier, get_ident
    authority = NativeAuthority(tmp_path/'bindings', tmp_path/'relationships', {})
    barrier = Barrier(2)
    def actors():
        return {'being': Actor('being', 'being', 'revision', str(get_ident()))}
    monkeypatch.setattr(authority, '_actors', actors)
    def request():
        with authority.read_snapshot():
            first = authority.actor('being')
            barrier.wait(timeout=5)
            assert authority.actor('being') is first
            return first.name
    with ThreadPoolExecutor(max_workers=2) as executor:
        a, b = list(executor.map(lambda _: request(), range(2)))
    assert a != b
    assert authority._read_snapshot.get() is None


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


def test_registered_web_origin_does_not_require_founder_discovery(tmp_path, monkeypatch):
    import clusterctl.homes.authority as module
    import daimon_matrix.messaging_config as config
    a = NativeAuthority(tmp_path/'bindings', tmp_path/'relationships', {},
        authority_source=tmp_path/'current')
    document = dict(control_artifacts=[], control_head='current', manifest={},
        credentials={}, incarnations={}, authority_history=[])
    source = {'document': document}
    monkeypatch.setattr(config, 'protected_read', lambda _: json.dumps(source['document']))
    def proof(value):
        return SimpleNamespace(manifest=SimpleNamespace(being_ref='adult', digest=value['control_head']))
    monkeypatch.setattr(module, 'public_history', proof)
    adult = SimpleNamespace(manifest=SimpleNamespace(digest='current'))
    child = SimpleNamespace(manifest=SimpleNamespace(digest='child-proof'))
    rows = [dict(being_ref='adult', authority=adult),
        dict(being_ref='child', human_ref='human:local:103ac2fb-e3a1-42fe-810a-f571d87bcb64',
            authority=child)]
    monkeypatch.setattr(a, 'bindings', lambda: rows)
    assert a.authorities() == {'adult': proof(document), 'child': child}
    # Legacy/native pins still require the current public source. A missing
    # Telegram entry must never acquire the web-registration exception.
    del rows[1]['human_ref']
    with pytest.raises(ValueError, match='home_actor_authority_source_stale'):
        a.authorities()
    rows[1]['human_ref'] = 'human:local:103ac2fb-e3a1-42fe-810a-f571d87bcb64'
    source['document'] = {**document, 'control_head': 'later'}
    with pytest.raises(ValueError, match='home_actor_authority_source_stale'):
        a.authorities()
    # A conflicting catalog root is still refused, not overwritten by a pin.
    source['document'] = {**document, 'sources': {'known_beings': [
        {**document, 'control_head': 'child-fork'}]}}
    def conflicting(value):
        if value['control_head'] == 'child-fork':
            return SimpleNamespace(manifest=SimpleNamespace(being_ref='child', digest='different-proof'))
        return proof(value)
    monkeypatch.setattr(module, 'public_history', conflicting)
    with pytest.raises(ValueError, match='home_actor_authority_source_stale'):
        a.authorities()
