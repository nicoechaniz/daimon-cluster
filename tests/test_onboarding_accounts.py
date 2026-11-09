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


def test_conversation_login_does_not_prime_provider_or_claim_inference(tmp_path, monkeypatch):
    value = dict(authorized=True, account_id='selected-fixture', action=None)
    account = manager(tmp_path, monkeypatch, value)
    calls = []
    (account.config.views/digest(plan())).mkdir(mode=0o700)
    def command(selected, action):
        calls.append(action)
        return value
    monkeypatch.setattr(account, 'command', command)
    account.execute(plan(), probe=False)
    observed = account.observe(plan(), probe=False)
    assert calls == ['observe', 'observe']
    assert observed.state == 'complete'
    assert observed.facts == {'ssh_ready': True, 'provider_configured': True}
    # The legacy mode still requires its real retained provider receipt.
    assert account.observe(plan()).state == 'absent'
    value['account_id'] = 'foreign-fixture'
    assert account.observe(plan(), probe=False).state == 'waiting'


def test_conversation_never_starts_missing_account_device_enrollment(tmp_path, monkeypatch):
    value = dict(authorized=False, login_running=False, action=None)
    account = manager(tmp_path, monkeypatch, value)
    (account.config.views/digest(plan())).mkdir(mode=0o700)
    calls = []
    monkeypatch.setattr(account, 'command', lambda p, action: calls.append(action) or value)
    with pytest.raises(OnboardingError, match='account_authorization_required'):
        account.execute(plan(), probe=False)
    assert calls == ['observe']


@pytest.mark.parametrize('existing_private_directory', [False, True])
def test_account_profile_reaches_receiving_agent_under_private_worker_umask(tmp_path, monkeypatch, existing_private_directory):
    import os
    import stat
    from pathlib import Path
    value = dict(authorized=True, account_id='selected-fixture', action=None)
    account = manager(tmp_path, monkeypatch, value)
    selected = plan()
    parent = account.config.views / digest(selected)
    parent.mkdir(mode=0o700)
    source = Path(account.mount(selected)['source'])
    if existing_private_directory:
        source.mkdir(mode=0o700)
    calls = []
    monkeypatch.setattr(account, 'command', lambda p, action: calls.append(action) or value)
    before = os.umask(0o077)
    try:
        account.execute(selected)
        profile = (source / 'profile.json').read_bytes()
        account.execute(selected)
    finally:
        os.umask(before)
    assert stat.S_IMODE(source.stat().st_mode) == 0o755
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert stat.S_IMODE((source / 'profile.json').stat().st_mode) == 0o644
    assert (source / 'profile.json').read_bytes() == profile
    assert calls == ['observe', 'probe', 'observe', 'probe']
    assert not (source / 'auth.json').exists()
