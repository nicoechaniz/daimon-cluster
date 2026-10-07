"""Root account selection is distinct from native login and receiving acceptance."""
from types import SimpleNamespace

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_accounts import ManagedAccount
from clusterctl.onboarding_actions import Actions
from clusterctl.onboarding_provider import SCHEMA
from tests.test_onboarding import plan


def manager(tmp_path, monkeypatch, value):
    folders = {}
    for name in ('accounts', 'views', 'progress'):
        path = tmp_path / name
        path.mkdir(mode=0o750 if name == 'progress' else 0o700)
        folders[name] = path
    being_seed._write(folders['accounts'] / 'shared.json', dict(schema='cluster-onboarding-account/v1',
                      name='shared', account_id='selected-fixture'))
    host = SimpleNamespace(config=SimpleNamespace(**folders), _mounted=lambda *args: True)
    result = ManagedAccount(host)
    monkeypatch.setattr(result, 'command', lambda *args: value)
    return result


def test_pending_device_login_is_waiting_not_another_effect(tmp_path, monkeypatch):
    import os
    value = dict(authorized=False, login_running=True, action=None)
    account = manager(tmp_path, monkeypatch, value)
    observed = account.observe(plan())
    assert observed.state == 'waiting' and observed.reason == 'account_authorization_required'
    assert observed.facts == {} and not observed.safe_to_execute
    assert Actions(account.config.progress, worker_uid=os.geteuid()).read('eko', owner='sai')['action'] is None


def test_wrong_account_never_advances_or_launches_probe(tmp_path, monkeypatch):
    value = dict(authorized=True, account_id='different-fixture', action=None)
    account = manager(tmp_path, monkeypatch, value)
    observed = account.observe(plan())
    assert observed.state == 'waiting' and observed.reason == 'account_authorization_required'


def test_provider_success_does_not_claim_real_ssh_cli_acceptance(tmp_path, monkeypatch):
    value = dict(authorized=True, account_id='selected-fixture', action=None,
                 probe_receipt=dict(schema=SCHEMA, plan_digest=digest(plan()), provider_verified=True))
    account = manager(tmp_path, monkeypatch, value)
    observed = account.observe(plan())
    assert observed.state == 'complete'
    assert observed.facts == dict(verified=True, ssh_ready=True, provider_verified=True)
    assert 'ssh_verified' not in observed.facts
    value['probe_receipt']['plan_digest'] = 'f' * 64
    with pytest.raises(OnboardingError, match='invalid_onboarding_observation'):
        account.observe(plan())


def test_missing_root_profile_is_recoverable_waiting(tmp_path, monkeypatch):
    account = manager(tmp_path, monkeypatch, {})
    (account.config.accounts / 'shared.json').unlink()
    assert account.observe(plan()).reason == 'account_authorization_required'
