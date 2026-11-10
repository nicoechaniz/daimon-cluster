import json
from pathlib import Path

import pytest

from clusterctl import being_seed, onboarding_conversation_routes as routes
from clusterctl.onboarding import OnboardingError, digest
from tests.test_onboarding_conversation import request


def assembled(tmp_path):
    path = tmp_path/'Caddyfile'
    before = b'*.example.org {\n @existing host existing.example.org\n}\n'
    path.write_bytes(before)
    path.chmod(0o600)
    value = dict(config=str(path), state=str(tmp_path/'route-state'), anchor=' @existing host existing.example.org')
    writer = routes.Routes(value)
    process = dict(pid='123', invocation='a'*32, started='456')
    writer._process = lambda: process
    state = dict(loaded=digest({'file':before.decode()}), effect=True, lost=False)
    calls = []
    def command(selected, *args):
        assert selected == process
        calls.append(args[0])
        if args[0] == 'adapt':
            return json.dumps({'file':Path(args[2]).read_text()}).encode()
        if args[0] == 'reload':
            if state['effect']:
                state['loaded'] = digest({'file':path.read_text()})
            if state['lost']:
                raise TimeoutError('Lost control response after fixture reload')
        return b''
    writer._command = command
    writer._live = lambda _: state['loaded']
    writer._live_configuration = lambda _: {'file':before.decode()}
    args = (request(), dict(listen_host='10.20.30.40', listen_port=18741), 'http://127.0.0.1:8820')
    return writer, args, state, calls, before


def test_absent_observation_then_one_reload_with_loaded_proof(tmp_path):
    writer, args, _, calls, before = assembled(tmp_path)
    assert writer.reconcile(*args, apply=False, authorize=lambda: True) == {'state':'absent'}
    assert writer.path.read_bytes() == before and calls == []
    assert writer.reconcile(*args, apply=True, authorize=lambda: True) == {'state':'complete','route_loaded':True}
    selected = writer.path.read_bytes()
    assert selected.replace(routes.render(*args), b'') == before
    assert b'header_up -X-Daimon-Actor' in selected
    assert writer.reconcile(*args, apply=True, authorize=lambda: True)['state'] == 'complete'
    assert calls.count('reload') == 1


def test_staged_caddyfile_hidden_name_uses_actual_load_destination(tmp_path):
    writer, _, _, _, _ = assembled(tmp_path)
    staged = writer.state / 'candidate.caddyfile'
    value = {'routes': [{'handler': 'file_server', 'hide': [str(staged), '/private']},
                        {'handler': 'static_response', 'body': str(staged)}]}
    writer._command = lambda *_: json.dumps(value).encode()
    expected = {'routes': [{'handler': 'file_server', 'hide': [str(writer.path), '/private']},
                           {'handler': 'static_response', 'body': str(staged)}]}
    assert writer._adapt({}, staged) == digest(expected)


def test_lost_reload_response_recovers_actual_effect_without_repeating(tmp_path):
    writer, args, state, calls, _ = assembled(tmp_path)
    state['lost'] = True
    with pytest.raises(TimeoutError):
        writer.reconcile(*args, apply=True, authorize=lambda: True)
    assert being_seed._read(writer.state/'active.json')['phase'] == 'reload-intent'
    assert writer.reconcile(*args, apply=True, authorize=lambda: True)['state'] == 'complete'
    assert calls.count('reload') == 1


def test_unknown_effect_and_other_job_preserve_pending_work(tmp_path):
    writer, args, state, calls, _ = assembled(tmp_path)
    state['effect'] = False
    assert writer.reconcile(*args, apply=True, authorize=lambda: True)['state'] == 'waiting'
    original = writer.path.read_bytes()
    assert writer.reconcile(*args, apply=True, authorize=lambda: True)['state'] == 'waiting'
    other = dict(args[0], name='another', origin='https://another.example.org')
    with pytest.raises(OnboardingError, match='conversation_route_operation_pending'):
        writer.reconcile(other, *args[1:], apply=True, authorize=lambda: True)
    assert writer.path.read_bytes() == original and calls.count('reload') == 1


def test_crash_after_file_publish_before_reload_intent_recovers_same_candidate(tmp_path, monkeypatch):
    writer, args, _, calls, _ = assembled(tmp_path)
    original = routes.atomic
    writes = []
    def crash(path, raw, **options):
        original(path, raw, **options)
        if path == writer.path:
            writes.append('published')
            raise TimeoutError('Lost operator after owned file publication')
    monkeypatch.setattr(routes, 'atomic', crash)
    with pytest.raises(TimeoutError):
        writer.reconcile(*args, apply=True, authorize=lambda: True)
    assert being_seed._read(writer.state/'active.json')['phase'] == 'prepared'
    assert writer.reconcile(*args, apply=True, authorize=lambda: True)['state'] == 'complete'
    assert writes == ['published'] and calls.count('reload') == 1


@pytest.mark.parametrize('concurrent', [False, True])
def test_revocation_or_concurrent_edit_is_preserved_before_reload(tmp_path, concurrent):
    writer, args, _, calls, before = assembled(tmp_path)
    def authorize():
        if concurrent:
            writer.path.write_bytes(before+b'# later operator edit\n')
        return concurrent
    code = 'conversation_route_concurrent_configuration_preserved' if concurrent else 'host_authorization_required'
    with pytest.raises(OnboardingError, match=code):
        writer.reconcile(*args, apply=True, authorize=authorize)
    assert writer.path.read_bytes() == before+(b'# later operator edit\n' if concurrent else b'')
    assert 'reload' not in calls


def test_foreign_block_and_unmarked_route_cannot_be_replaced():
    req = request()
    block = routes.render(req, dict(listen_host='10.20.30.40', listen_port=18741), 'http://127.0.0.1:8820')
    for text in (block.replace(b':18741', b':18742'), block+block,
                 b'fixture.example.org { reverse_proxy 127.0.0.1:9999 }\n'):
        with pytest.raises(OnboardingError, match='existing_conversation_route_preserved'):
            routes.compose(text, req, block, 'anchor')


def test_existing_owned_block_reconciles_whitespace_only_at_its_edges():
    req = request()
    block = routes.render(req, dict(listen_host='10.20.30.40', listen_port=18741), 'http://127.0.0.1:8820')
    existing = block.lstrip()+b'\n# other operator state\n'
    assert routes.compose(existing, req, block, 'missing-but-unneeded') == existing


def test_another_hostname_containing_the_requested_name_is_not_a_conflict():
    req = request()
    block = routes.render(req, dict(listen_host='10.20.30.40', listen_port=18741), 'http://127.0.0.1:8820')
    before = b'*.example.org {\n @other host other-fixture.example.org\n}\n'
    assert routes.compose(before, req, block, ' @other host other-fixture.example.org').replace(block,b'') == before


def test_corrupt_checkpoint_cannot_select_a_path_outside_private_state(tmp_path):
    writer, args, _, calls, before = assembled(tmp_path)
    being_seed._write(writer.state/'active.json', dict(schema='cluster-conversation-route/v1',
        name='../escaped', pins='a'*64, phase='prepared', before='b'*64, after='c'*64, adapted='d'*64))
    with pytest.raises(OnboardingError, match='conversation_route_checkpoint_changed'):
        writer.reconcile(*args, apply=True, authorize=lambda: True)
    assert writer.path.read_bytes() == before and calls == []


def test_capacity_preserves_unfinished_buffers(tmp_path):
    writer, _, _, _, _ = assembled(tmp_path)
    for index in range(25):
        (writer.state/str(index)).write_bytes(b'owned unfinished work')
    with pytest.raises(OnboardingError, match='conversation_route_capacity'):
        routes.Routes(writer.value)
    assert len(list(writer.state.iterdir())) == 25


def test_existing_voice_backend_requires_covered_actual_maintenance_before_publish(tmp_path):
    writer,args,_,calls,before=assembled(tmp_path)
    live={'match':[{'path':['/interaction/*']}],'handle':[{'handler':'reverse_proxy',
          'upstreams':[{'dial':'127.0.0.1:8800'}]}]}
    writer._live_configuration=lambda _:live
    with pytest.raises(OnboardingError,match='conversation_route_maintenance_required'):
        writer.reconcile(*args,apply=True,authorize=lambda:True)
    assert writer.path.read_bytes()==before and 'reload' not in calls
    assert routes.interaction_upstreams(live)=={'127.0.0.1:8800'}
