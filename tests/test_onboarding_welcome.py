"""Approved welcome transport is distinct from human conversation acceptance."""
import hashlib
import json
from types import SimpleNamespace

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_welcome import Welcome, text
from tests.test_onboarding import plan

TOKEN = '123456789:' + 'x' * 40


def configured(tmp_path):
    root = tmp_path / 'jobs'
    root.mkdir(mode=0o700)
    (root / 'eko').mkdir(mode=0o700)
    supplied = dict(telegram_bot_token=TOKEN, telegram_chat_id=1234)
    host = SimpleNamespace(config=SimpleNamespace(jobs=root), authorize=lambda *args: True,
        _telegram_connections=lambda p: supplied,
        _telegram_command=lambda p, a: dict(configured=True, listening=True, bot_id=123456789,
                                            plan_digest=digest(p)),
        _telegram_binding=lambda p: dict(plan_digest=digest(p), bot_id=123456789,
            destination_digest=digest({'human': 1234}), token_sha256=hashlib.sha256(TOKEN.encode()).hexdigest()))
    calls = []
    def request(token, human, message):
        calls.append((token, human, message))
        return dict(message_id=987, chat=dict(id=human, type='private'),
                    **{'from': dict(id=123456789, is_bot=True)}, text=message)
    return host, Welcome(host, request=request), calls


def test_acknowledged_welcome_is_durable_and_retry_does_not_send_again(tmp_path):
    host, welcome, calls = configured(tmp_path)
    selected = plan()
    assert welcome.observe(selected).safe_to_execute
    # The enclosing durable job holds its own lock during stage execution.
    with being_seed._locked(host.config.jobs / 'eko'):
        welcome.execute(selected)
    welcome.execute(selected)
    observed = welcome.observe(selected)
    assert observed.facts == dict(verified=True, welcome_delivered=True)
    assert len(calls) == 1 and calls[0][1:] == (1234, text(selected))
    stored = (host.config.jobs / 'eko/welcome/receipt.json').read_text()
    assert TOKEN not in stored and 'human_id' not in json.loads(stored)
    assert not any(key in observed.facts for key in ('human_contact_verified', 'telegram_verified'))


@pytest.mark.parametrize('failure', ['lost-ack', 'wrong-human', 'wrong-bot', 'wrong-text'])
def test_uncertain_external_send_is_never_replayed(tmp_path, failure):
    host, welcome, calls = configured(tmp_path)
    original = welcome.request
    def request(*args):
        result = original(*args)
        if failure == 'lost-ack':
            raise OnboardingError('uncertain_external_effect')
        if failure == 'wrong-human':
            result['chat']['id'] = 5678
        elif failure == 'wrong-bot':
            result['from']['id'] = 987654321
        else:
            result['text'] = 'different'
        return result
    welcome.request = request
    for _ in range(2):
        with pytest.raises(OnboardingError, match='uncertain_external_effect'):
            welcome.execute(plan())
    assert welcome.observe(plan()).state == 'uncertain'
    assert len(calls) == 1
    assert (host.config.jobs / 'eko/welcome/intent.json').exists()
    assert not (host.config.jobs / 'eko/welcome/receipt.json').exists()


@pytest.mark.parametrize('problem', ['revoked', 'changed-human', 'changed-plan', 'not-listening', 'guest-human'])
def test_authorization_and_installed_receiver_must_match_before_any_send(tmp_path, problem):
    host, welcome, calls = configured(tmp_path)
    selected = plan()
    if problem in {'changed-human', 'changed-plan'}:
        welcome.execute(selected)
        calls.clear()
    if problem == 'revoked':
        host.authorize = lambda *args: False
    elif problem == 'changed-human':
        host._telegram_connections = lambda p: dict(telegram_bot_token=TOKEN, telegram_chat_id=5678)
    elif problem == 'changed-plan':
        selected = plan(owner='ani')
    elif problem == 'not-listening':
        host._telegram_command = lambda *args: dict(configured=True, listening=False)
    else:
        host._telegram_binding = lambda p: dict(plan_digest=digest(p), bot_id=123456789,
            destination_digest=digest({'human': 5678}), token_sha256=hashlib.sha256(TOKEN.encode()).hexdigest())
    with pytest.raises(OnboardingError):
        welcome.execute(selected)
    assert calls == []


def test_corrupted_receipt_never_establishes_completion(tmp_path):
    host, welcome, _ = configured(tmp_path)
    welcome.execute(plan())
    path = host.config.jobs / 'eko/welcome/receipt.json'
    value = json.loads(path.read_bytes())
    being_seed._write(path, {**value, 'message_id': True})
    assert welcome.observe(plan()).state == 'conflict'


def test_host_routes_welcome_to_typed_adapter(tmp_path, monkeypatch):
    from dataclasses import replace
    from tests.test_onboarding_host import configured as host_fixture
    from clusterctl.onboarding_host import HostBackend
    config, selected, _, _ = host_fixture(tmp_path)
    host = HostBackend(replace(config, code=tmp_path, consent_state=tmp_path))
    (config.jobs / 'eko').mkdir(mode=0o700)
    monkeypatch.setattr(host, '_telegram_connections', lambda p: dict(telegram_bot_token=TOKEN, telegram_chat_id=1234))
    assert host.observe(selected, 'welcome', 'unused').safe_to_execute
    executed = []
    monkeypatch.setattr(Welcome, 'execute', lambda self, p: executed.append(p))
    host.execute(selected, 'welcome', 'unused')
    assert executed == [selected]
