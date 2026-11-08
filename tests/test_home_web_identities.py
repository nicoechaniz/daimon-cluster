"""Web-only humans use the existing Home policy and native being proofs."""
import json
from types import SimpleNamespace

import pytest

from clusterctl.homes.authority import NativeAuthority, digest
from clusterctl.homes.applications import paired_receiver
from clusterctl.homes.policy import Policy
from clusterctl.homes.sessions import Sessions


@pytest.fixture
def source(tmp_path, monkeypatch):
    import daimon_matrix.human_tribu_process as legacy
    import daimon_matrix.messaging_config as files
    import daimon_matrix.operator_rebirth as native

    def row(n):
        return dict(being_ref=f'being-{n}', label=f'Companion {n}',
                    human_ref=f'human:local:00000000-0000-4000-8000-{n:012d}',
                    human_name=f'Person {n}', origin=dict(principal_id=f'principal-{n}',
                        embodiment_id=f'embodiment-{n}', incarnation_id=f'incarnation-{n}',
                        body_ref=f'body-{n}'),
                    authority_file=str(tmp_path / f'proof-{n}'), enabled=True)

    declaration = dict(schema='dm.home-identities/v1', telegram_source=None,
                       web=[row(1), row(2)])
    old = dict(being_ref='adult', label='Adult companion', human_id=123,
               human_name='Adult', bot_id=456, username='adult_bot',
               origin=dict(principal_id='adult-principal', embodiment_id='adult-embodiment',
                           incarnation_id='adult-incarnation', body_ref='adult-body'),
               authority_file=str(tmp_path/'adult-proof'), enabled=True)
    documents = {str(tmp_path/'bindings'): declaration,
                 **{r['authority_file']: {'being': r['being_ref'], 'origin': r['origin']}
                    for r in declaration['web'] + [old]}}
    monkeypatch.setattr(files, 'protected_read', lambda p: json.dumps(documents[str(p)]).encode())
    legacy_reads = []
    def host_config(p):
        legacy_reads.append(p)
        return {'participants': [old]}
    monkeypatch.setattr(legacy, 'host_config', host_config)
    class Proof:
        def __init__(self, value):
            self.manifest = SimpleNamespace(being_ref=value['being'], digest='signed-head')
            self.origin = value['origin']
        def validate_origin(self, origin, *, require_active):
            assert require_active
            if origin != self.origin:
                raise ValueError('inactive_origin')
    monkeypatch.setattr(native, 'authority_from_document', Proof)
    a = NativeAuthority(tmp_path/'bindings', tmp_path/'relationships',
                        {'one': {'owner_being_ref': 'being-1'},
                         'two': {'owner_being_ref': 'being-2'}})
    return a, declaration, documents, legacy_reads, old


def test_web_humans_have_no_bot_and_cannot_read_another_pair(source):
    a, doc, _, reads, _ = source
    first, second = [a.actor(r['human_ref']) for r in doc['web']]
    assert first and second and first.ref != second.ref
    assert a.bot('one') is None and not reads
    assert first.revision == digest({'provider': 'local', 'subject': first.ref[12:]})
    policy = Policy(actor=a.actor, paired_human=a.paired_human,
                    tribe_member=lambda *_: False)
    assert policy.allows({'visibility': 'human'}, home='one', subject=first)
    assert not policy.allows({'visibility': 'human'}, home='one', subject=second)
    doc['web'][0]['enabled'] = False
    assert a.actor(first.ref) is None and a.paired_human('one') is None
    assert not policy.allows({'visibility': 'human'}, home='one', subject=first)


def test_existing_telegram_actor_revision_and_bot_are_preserved(source, tmp_path):
    a, doc, _, reads, _ = source
    doc['telegram_source'] = str(tmp_path/'existing-tribu')
    a.homes['adult'] = {'owner_being_ref': 'adult'}
    assert a.paired_human('adult') == 'human:telegram:123'
    assert a.bot('adult') == {'id': 456, 'username': 'adult_bot'}
    assert a.actor('human:telegram:123').revision == digest({'provider': 'telegram', 'subject': 123})
    assert reads and a.actor(doc['web'][0]['human_ref'])


def test_existing_browser_approval_and_paired_app_route_need_no_telegram(source, tmp_path):
    a, doc, _, _, _ = source
    human = a.actor(doc['web'][0]['human_ref'])
    sessions = Sessions(tmp_path/'sessions')
    request, proof = sessions.request(home='one', origin='https://one.example')
    sessions.approve(home='one', code=request['code'], subject=human)
    def current(ref, revision):
        actor = a.actor(ref)
        return actor if actor is not None and actor.revision == revision else None
    _, token = sessions.claim(home='one', origin='https://one.example',
                             code=request['code'], proof=proof, current_actor=current)
    assert sessions.resolve(token, home='one', origin='https://one.example')['actor'] == human.ref
    assert sessions.resolve(token, home='two', origin='https://two.example') is None
    app = SimpleNamespace(homes=a.homes, authority=a)
    assert paired_receiver(app, 'two', human) == 'one'
    assert paired_receiver(app, 'one', a.actor(doc['web'][1]['human_ref'])) == 'two'
    assert paired_receiver(app, 'one', None) is None


@pytest.mark.parametrize('change', [
    {'human_ref': 'human:telegram:123'}, {'human_ref': 'human:local:invalid'},
    {'bot_id': 123}, {'enabled': 1}, {'authority_file': '../proof'},
    {'origin': 'revoked'}, {'origin': {'body_ref': 'foreign'}}, {'being_ref': 'foreign'},
])
def test_invalid_or_inactive_web_binding_is_refused(source, change):
    a, doc, _, _, _ = source
    doc['web'][0].update(change)
    with pytest.raises(ValueError): a.bindings()


@pytest.mark.parametrize('field', ['being_ref', 'human_ref'])
def test_duplicate_being_or_child_human_is_refused(source, field):
    a, doc, _, _, _ = source
    doc['web'][1][field] = doc['web'][0][field]
    with pytest.raises(ValueError): a.bindings()


@pytest.mark.parametrize('change', [
    {'web': []}, {'web': [None]}, {'web': [0] * 17},
    {'telegram_source': 'relative'}, {'extra': True},
])
def test_closed_bounded_operator_declaration(source, change):
    a, doc, _, _, _ = source
    doc.update(change)
    with pytest.raises(ValueError): a.bindings()


def test_real_native_authority_accepts_structured_origin_and_rejects_foreign_body(tmp_path):
    # Use the SDK's isolated synthetic identity, with real native signatures and
    # validators. No live custody, account, Matrix runtime or transport is read.
    from daimon_matrix.synthetic_relationships import _identity, _seed
    from daimon_matrix.identity import create_synthetic_genesis_in_process
    label = 'home-web-origin-test'
    identity = _identity(label)
    genesis = create_synthetic_genesis_in_process(
        [_seed(f'{label}:root:{n}') for n in range(3)], 2,
        [_seed(f'{label}:recovery:{n}') for n in range(3)], 2,
        created_at_ms=0, nonce=_seed(f'{label}:being'))
    proof = dict(schema='dm.operator.authority/v1', control_artifacts=[genesis],
                 control_head=identity.state.head, manifest=identity.authority.manifest.value,
                 credentials=list(identity.authority.credentials.values()),
                 incarnations=list(identity.authority.incarnations.values()))
    tmp_path.chmod(0o700)
    def write(name, value):
        path = tmp_path/name
        path.write_text(json.dumps(value)); path.chmod(0o600)
        return path
    authority = write('authority.json', proof)
    human = 'human:local:95c8fb8b-b71a-44bd-8c36-e4047b1d12bc'
    row = dict(being_ref=identity.state.being_ref, label='Fixture companion',
               human_ref=human, human_name='Fixture human', origin=dict(identity.origin),
               authority_file=str(authority), enabled=True)
    declaration = dict(schema='dm.home-identities/v1', telegram_source=None, web=[row])
    binding = write('bindings.json', declaration)
    a = NativeAuthority(binding, tmp_path/'relationships',
                        {'fixture': {'owner_being_ref': identity.state.being_ref}})
    assert a.actor(human).kind == 'human'
    assert a.actor(identity.state.being_ref).kind == 'being'
    assert a.paired_human('fixture') == human and a.bot('fixture') is None
    row['origin']['body_ref'] = 'cluster:synthetic:foreign-body'
    write('bindings.json', declaration)
    with pytest.raises(ValueError): a.actor(human)
