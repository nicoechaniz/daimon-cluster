"""Receiving login isolation, private device actions and refreshed-cache continuity."""
import json
import subprocess
from types import SimpleNamespace

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_provider import DEVICE_URL, Provider, service
from tests.test_onboarding import plan


def receiver(tmp_path, run):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    (home / '.codex').mkdir(mode=0o700)
    return Provider(home, plan(), run=run)


def test_native_login_uses_only_own_home_and_exposes_bounded_device_action(tmp_path):
    environments = []
    def run(argv, **kwargs):
        environments.append(kwargs['env'])
        if '--device-auth' in argv:
            kwargs['stdout'].write((DEVICE_URL + '\nABCD-EFGHI\nprivate diagnostic').encode())
            raise subprocess.TimeoutExpired(argv, 900)
        return SimpleNamespace(returncode=1)
    provider = receiver(tmp_path, run)
    with pytest.raises(subprocess.TimeoutExpired):
        provider.login()
    result = provider.observe()
    assert result['authorized'] is False and result['provider_verified'] is False
    assert result['action']['user_code'] == 'ABCD-EFGHI'
    assert result['action']['verification_uri'] == DEVICE_URL
    assert 'private diagnostic' not in json.dumps(result)
    assert all(set(env) == {'HOME', 'CODEX_HOME', 'PATH', 'LANG'} for env in environments)
    assert all(env['CODEX_HOME'] == str(provider.home / '.codex') for env in environments)
    assert (provider.state / 'login.txt').stat().st_mode & 0o777 == 0o600


def test_existing_native_auth_is_preserved_without_login_or_entitlement_claim(tmp_path):
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0)
    provider = receiver(tmp_path, run)
    auth = provider.home / '.codex/auth.json'
    raw = json.dumps(dict(auth_mode='chatgpt', tokens={'account_id': 'fixture-account',
                     'access_token': 'refreshed private native cache'})).encode()
    auth.write_bytes(raw)
    auth.chmod(0o600)
    provider.login()
    assert provider.observe()['authorized'] is True
    assert provider.observe()['provider_verified'] is False
    assert auth.read_bytes() == raw
    assert all(argv == ['codex', '-c', 'cli_auth_credentials_store="file"', 'login', 'status'] for argv in calls)
    assert not (provider.state / 'attempt.json').exists()


def test_expired_or_foreign_device_action_is_not_exposed(tmp_path):
    from clusterctl import being_seed
    provider = receiver(tmp_path, lambda *args, **kwargs: SimpleNamespace(returncode=1))
    log = provider.state / 'login.txt'
    log.write_text('https://untrusted.example/device\nABCD-EFGHI')
    log.chmod(0o600)
    being_seed._write(provider.state / 'attempt.json', dict(deadline_ms=2**60))
    assert provider.observe()['action'] is None
    log.write_text(DEVICE_URL + '\nABCD-EFGHI')
    being_seed._write(provider.state / 'attempt.json', dict(deadline_ms=0))
    assert provider.observe()['action'] is None
    log.chmod(0o644)
    with pytest.raises(OnboardingError, match='private_provider_login_required'):
        provider.observe()


def test_login_unit_keeps_native_output_out_of_system_journal():
    from pathlib import Path
    raw = service(Path('/opt/daimon-onboarding') / ('2' * 64)).decode()
    assert 'User=agent\n' in raw and 'KillMode=control-group\n' in raw
    assert 'Environment=CODEX_HOME=/home/agent/.codex\n' in raw
    assert 'StandardOutput=null\nStandardError=null\n' in raw
    assert 'Restart=' not in raw


def test_private_account_matcher_rejects_foreign_modes_without_exposing_tokens(tmp_path):
    provider = receiver(tmp_path, lambda *args, **kwargs: SimpleNamespace(returncode=0))
    auth = provider.home / '.codex/auth.json'
    auth.write_text(json.dumps(dict(auth_mode='chatgptAuthTokens', tokens={'account_id': 'account-fixture'})))
    auth.chmod(0o600)
    assert provider.account() is None
    auth.write_text(json.dumps(dict(auth_mode='chatgpt', tokens={'account_id': 'account-fixture', 'access_token': 'secret fixture'})))
    assert provider.account() == 'account-fixture'
    assert 'secret fixture' not in json.dumps(provider.observe())
    auth.chmod(0o644)
    with pytest.raises(OnboardingError, match='private_provider_login_required'):
        provider.account()


def test_lost_probe_ack_recovers_native_completion_without_another_model_turn(tmp_path):
    from clusterctl.onboarding import digest
    calls = []
    def run(argv, **kwargs):
        if 'exec' in argv:
            calls.append(argv)
            token = 'PROVIDER_OK_' + digest(plan())[:20]
            kwargs['stdout'].write((json.dumps(dict(type='item.completed', item=dict(type='agent_message', text=token)))
                + '\n' + json.dumps(dict(type='turn.completed')) + '\n').encode())
            kwargs['stdout'].flush()
            raise OSError('lost model acknowledgement')
        return SimpleNamespace(returncode=0)
    provider = receiver(tmp_path, run)
    cache = provider.home / '.codex/auth.json'
    cache.write_text(json.dumps(dict(auth_mode='chatgpt', tokens={'account_id': 'expected-fixture'})))
    cache.chmod(0o600)
    with pytest.raises(OSError, match='lost model'):
        provider.probe('expected-fixture', 'configured-model', 'xhigh')
    assert provider.probe('expected-fixture', 'configured-model', 'xhigh')['provider_verified'] is True
    assert len(calls) == 1
    assert provider.probe('expected-fixture', 'configured-model', 'xhigh')['provider_verified'] is True
    assert len(calls) == 1


def test_uncertain_or_wrong_account_probe_does_not_repeat_inference(tmp_path):
    calls = []
    def run(argv, **kwargs):
        if 'exec' in argv:
            calls.append(argv)
            kwargs['stdout'].write(b'{"type":"thread.started"}\n')
        return SimpleNamespace(returncode=0)
    provider = receiver(tmp_path, run)
    cache = provider.home / '.codex/auth.json'
    cache.write_text(json.dumps(dict(auth_mode='chatgpt', tokens={'account_id': 'expected-fixture'})))
    cache.chmod(0o600)
    with pytest.raises(OnboardingError, match='account_authorization_required'):
        provider.probe('another-account', 'configured-model', 'xhigh')
    assert not calls
    for _ in range(2):
        with pytest.raises(OnboardingError, match='uncertain_external_effect'):
            provider.probe('expected-fixture', 'configured-model', 'xhigh')
    assert len(calls) == 1


def test_account_selection_copies_only_metadata_and_preserves_native_cache(tmp_path):
    import os
    from tools.configure_onboarding_account import configure
    root = tmp_path / 'accounts'
    root.mkdir(mode=0o700)
    cache = tmp_path / 'auth.json'
    original = json.dumps(dict(auth_mode='chatgpt', tokens={'account_id': 'selected-account', 'access_token': 'private access', 'refresh_token': 'private refresh'})).encode()
    cache.write_bytes(original)
    cache.chmod(0o600)
    result = configure(root, 'shared', cache, source_uid=os.geteuid())
    assert result == dict(configured=True, profile='shared', credentials_copied=False)
    assert cache.read_bytes() == original
    profile = (root / 'shared.json').read_bytes()
    assert b'private access' not in profile and b'private refresh' not in profile
    assert json.loads(profile)['account_id'] == 'selected-account'
    assert configure(root, 'shared', cache, source_uid=os.geteuid()) == result
    cache.write_text(json.dumps(dict(auth_mode='chatgpt', tokens={'account_id': 'different-account'})))
    with pytest.raises(OnboardingError, match='preserved'):
        configure(root, 'shared', cache, source_uid=os.geteuid())
    assert (root / 'shared.json').read_bytes() == profile
