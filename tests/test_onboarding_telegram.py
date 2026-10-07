"""Dedicated listener defaults and preservation before any live bot consumer."""
import json
import tomllib
from pathlib import Path

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_telegram import configuration, native_service, prepare, service
from tests.test_onboarding import plan

PROFILE = dict(model='gpt-6.1-sol', reasoning='xhigh', approval='never', sandbox='danger-full-access')
TOKEN = '123456789:' + 'x' * 40


def bot_request(token, method):
    assert token == TOKEN
    if method == 'getMe':
        return dict(id=123456789, is_bot=True, username='fixture_bot', has_topics_enabled=True)
    assert method == 'getWebhookInfo'
    return dict(url='')


def test_configuration_displays_only_completed_responses_and_uses_own_harness():
    home, code, codex = Path('/home/agent'), Path('/opt/qualified-code'), Path('/usr/bin/codex')
    value = tomllib.loads(configuration(home, code, codex, 1234, PROFILE).decode())
    assert value['telegram']['show_unfinished_messages'] is False
    assert value['telegram']['use_message_drafts'] is False
    assert value['codex']['shared_app_server'] is True
    assert value['codex']['import_cli_history'] is False
    assert value['codex']['import_desktop_history'] is False
    assert value['codex']['auto_attach_latest_history'] is False
    assert value['background_maintenance'] is False
    assert value['startup_admin_ids'] == [1234]
    assert value['codex']['default_cwd'] == '/home/agent/Projects/being'
    assert TOKEN not in json.dumps(value) + service(home, code).decode()


def test_retry_preserves_later_conversations_and_refuses_changed_bot_or_human(tmp_path):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    supplied = dict(telegram_bot_token=TOKEN, telegram_chat_id=1234)
    first = prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE, supplied, request=bot_request)
    state = home / '.local/state/daimon-onboarding/telegram'
    conversation = state / 'telegram.sqlite3'
    conversation.write_bytes(b'later conversation/input journal fixture')
    conversation.chmod(0o600)
    assert prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE, supplied, request=bot_request) == first
    assert conversation.read_bytes() == b'later conversation/input journal fixture'
    with pytest.raises(OnboardingError, match='preserved'):
        prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE,
                {**supplied, 'telegram_chat_id': 5678}, request=bot_request)
    assert (state / 'bot.token').stat().st_mode & 0o777 == 0o600
    assert TOKEN not in (state / 'config.toml').read_text() + (state / 'binding.json').read_text()


@pytest.mark.parametrize('problem', ['topics', 'webhook'])
def test_incompatible_bot_never_freezes_binding_or_changes_existing_gateway(tmp_path, problem):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    def request(token, method):
        value = bot_request(token, method)
        if problem == 'topics' and method == 'getMe':
            return {**value, 'has_topics_enabled': False}
        if problem == 'webhook' and method == 'getWebhookInfo':
            return dict(url='https://private-existing-gateway.invalid')
        return value
    with pytest.raises(OnboardingError):
        prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE,
                dict(telegram_bot_token=TOKEN, telegram_chat_id=1234), request=request)
    assert not (home / '.local/state/daimon-onboarding/telegram/binding.json').exists()
    assert prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE,
                   dict(telegram_bot_token=TOKEN, telegram_chat_id=1234), request=bot_request)['configured']


def test_interrupted_preparation_recovers_without_resetting_conversations(tmp_path):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    supplied = dict(telegram_bot_token=TOKEN, telegram_chat_id=1234)
    prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE, supplied, request=bot_request)
    state = home / '.local/state/daimon-onboarding/telegram'
    (state / 'config.toml').unlink()
    (state / 'bot.token').unlink()
    (state / 'telegram.sqlite3').write_bytes(b'later-history')
    prepare(home, tmp_path / 'code', Path('/usr/bin/codex'), plan(), PROFILE, supplied, request=bot_request)
    assert (state / 'telegram.sqlite3').read_bytes() == b'later-history'
    assert (state / 'bot.token').read_text() == TOKEN


def test_same_bot_cannot_be_reserved_by_another_job_after_retry(tmp_path):
    from clusterctl.onboarding_telegram import reserve
    tmp_path.chmod(0o700)
    supplied = dict(telegram_bot_token=TOKEN, telegram_chat_id=1234)
    reserve(tmp_path, plan(), supplied)
    original = (tmp_path / 'telegram-consumers/123456789.json').read_bytes()
    reserve(tmp_path, plan(), supplied)
    with pytest.raises(OnboardingError, match='existing_telegram_consumer_preserved'):
        reserve(tmp_path, plan(name='oliva', owner='ani'), supplied)
    assert (tmp_path / 'telegram-consumers/123456789.json').read_bytes() == original
    assert TOKEN not in original.decode()


def test_listener_readiness_does_not_satisfy_final_telegram_acceptance(tmp_path):
    from clusterctl import onboarding as ob
    from tests.test_onboarding import FixtureBackend, advance
    backend = FixtureBackend()
    backend.wait = 'acceptance'
    store = ob.JobStore(tmp_path / 'jobs')
    store.submit(plan(), backend)
    result = advance(store, backend)
    assert result['active'] is False
    assert result['stage'] == 'acceptance'
    assert ob.STAGE_FACTS['telegram'] == dict(telegram_ready=True)
    assert 'telegram_verified' in ob.ACCEPTANCE


def test_shared_codex_daemon_has_its_own_lifecycle_outside_listener_cgroup():
    home, code, codex = Path('/home/agent'), Path('/opt/code'), Path('/usr/local/bin/codex')
    listener = service(home, code, codex).decode()
    native = native_service(home, codex, code).decode()
    assert 'Requires=daimon-onboarding-codex.service' in listener
    assert 'ExecStartPre=' not in listener
    assert 'Type=simple' in native and 'Restart=on-failure' in native
    assert 'native-serve' in native and 'app-server daemon stop' in native
    assert 'StandardOutput=null' in native and 'CODEX_HOME=/home/agent/.codex' in native


def test_native_supervisor_reconciles_singleton_without_model_or_message_commands():
    from types import SimpleNamespace
    from clusterctl.onboarding_telegram import native_serve
    calls, waits = [], []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0)
    native_serve(Path('/home/agent'), Path('/usr/local/bin/codex'), run=run, wait=waits.append, cycles=3)
    assert waits == [5, 5, 5]
    assert all(argv == ['/usr/local/bin/codex', 'app-server', 'daemon', 'start'] for argv, _ in calls)
    assert all(options['env']['CODEX_HOME'] == '/home/agent/.codex' for _, options in calls)
    with pytest.raises(OnboardingError, match='native_codex_daemon_start_failed'):
        native_serve(Path('/home/agent'), Path('/usr/local/bin/codex'),
                     run=lambda *a, **k: SimpleNamespace(returncode=1), wait=waits.append, cycles=1)
