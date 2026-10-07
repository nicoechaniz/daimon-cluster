"""Shared provider auth is explicit, isolated, atomic and absent from argv."""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_accounts import ManagedAccount, install_shared_cache
from tests.test_onboarding import plan


def caches(tmp_path):
    source = tmp_path / 'source'
    source.mkdir(mode=0o700)
    received = tmp_path / 'received'
    received.mkdir(mode=0o700)
    original = dict(auth_mode='chatgpt', tokens=dict(account_id='fixture', access_token='synthetic-test-value'))
    path = source / 'auth.json'
    being_seed._write(path, original)
    (source / 'private-history').write_text('Preserve source history.')
    return path, received / 'auth.json'


def install(src, dst, account='fixture'):
    install_shared_cache(src, dst, uid=os.geteuid(), gid=os.getegid(), account=account)


def test_atomic_shared_cache_is_idempotent_and_preserves_source_and_local_history(tmp_path):
    src, dst = caches(tmp_path)
    source = src.read_bytes()
    (dst.parent / 'sessions').mkdir()
    (dst.parent / 'sessions/original').write_text('Keep receiving conversation.')
    install(src, dst)
    inode = dst.stat().st_ino
    install(src, dst)
    assert dst.stat().st_ino == inode
    assert dst.read_bytes() == source == src.read_bytes()
    assert dst.stat().st_mode & 0o777 == 0o600
    assert (src.parent / 'private-history').exists()
    assert (dst.parent / 'sessions/original').read_text() == 'Keep receiving conversation.'
    assert not (dst.parent / 'private-history').exists()


@pytest.mark.parametrize('partial', [False, True])
def test_recovers_crash_before_or_after_atomic_publish(tmp_path, partial):
    src, dst = caches(tmp_path)
    candidate = dst.with_name('.shared-login-candidate')
    candidate.write_bytes(b'partial' if partial else src.read_bytes())
    candidate.chmod(0o600)
    if not partial:
        os.link(candidate, dst)
    install(src, dst)
    assert dst.read_bytes() == src.read_bytes() and not candidate.exists()
    assert dst.stat().st_nlink == 1


def test_foreign_cache_symlink_and_wrong_account_are_preserved(tmp_path):
    src, dst = caches(tmp_path)
    with pytest.raises(ValueError, match='shared_login_account_mismatch'):
        install(src, dst, 'different')
    assert not dst.exists()
    dst.write_bytes(b'foreign-cache')
    dst.chmod(0o600)
    with pytest.raises(ValueError, match='existing_shared_login_preserved'):
        install(src, dst)
    assert dst.read_bytes() == b'foreign-cache'
    dst.unlink()
    dst.symlink_to(src)
    with pytest.raises(OSError):
        install(src, dst)
    assert dst.is_symlink()


def test_manager_private_handoff_never_passes_credentials_in_command_arguments(tmp_path):
    src, _ = caches(tmp_path)
    accounts, views = tmp_path / 'accounts', tmp_path / 'views'
    accounts.mkdir(mode=0o700)
    views.mkdir(mode=0o700)
    selected = dict(schema='cluster-onboarding-account/v1', name='shared', account_id='fixture')
    being_seed._write(accounts / 'shared.json', selected)
    authorization = dict(schema='cluster-onboarding-shared-login/v1', name='shared', account_id='fixture',
        cache=str(src), source_uid=os.geteuid(), pairs={'eko': 'sai'},
        human_instruction_digest='a' * 64, revoked=False)
    being_seed._write(accounts / 'shared.credentials.json', authorization)
    commands, mounts = [], {}
    def dispatch(p, argv):
        commands.append(argv)
        if argv[:3] == ['config', 'device', 'add']:
            mounts[argv[4]] = {**dict(item.split('=', 1) for item in argv[6:]), 'type': argv[5]}
        elif argv[:3] == ['config', 'device', 'remove']:
            mounts.pop(argv[4])
        return ''
    host = SimpleNamespace(config=SimpleNamespace(accounts=accounts, views=views),
        _guest_paths=lambda p: (None, Path('/opt/approved-code'), {}), instance=lambda p: 'dm-eko',
        _mounted=lambda p, expected: all(mounts.get(k) == v for k, v in expected.items()), _dispatch=dispatch)
    manager = ManagedAccount(host)
    assert manager.shared(plan(), selected) == authorization
    manager.install_shared(plan(), selected, authorization)
    assert not mounts
    assert not (views / digest(plan()) / 'account-private/auth.json').exists()
    assert 'synthetic-test-value' not in json.dumps(commands)
    with pytest.raises(OnboardingError, match='account_authorization_required'):
        manager.shared({**plan(), 'owner': 'ani'}, selected)


def test_configure_sharing_requires_private_attribution_and_retains_existing_profile(tmp_path):
    from tools.configure_onboarding_account import configure
    src, _ = caches(tmp_path)
    accounts = tmp_path / 'accounts'
    accounts.mkdir(mode=0o700)
    instruction = tmp_path / 'human-approval'
    instruction.write_text('The local human explicitly approves the selected shared account.')
    instruction.chmod(0o600)
    assert configure(accounts, 'shared', src, source_uid=os.geteuid())['credentials_copied'] is False
    original = (accounts / 'shared.json').read_bytes()
    assert not (accounts / 'shared.credentials.json').exists()
    instruction.chmod(0o644)
    with pytest.raises(OnboardingError, match='private_provider_login_required'):
        configure(accounts, 'shared', src, source_uid=os.geteuid(), shared_pairs={'eko': 'sai'},
            instruction=instruction, instruction_uid=os.geteuid())
    assert not (accounts / 'shared.credentials.json').exists()
    instruction.chmod(0o600)
    result = configure(accounts, 'shared', src, source_uid=os.geteuid(), shared_pairs={'eko': 'sai'},
        instruction=instruction, instruction_uid=os.geteuid())
    assert result['sharing_authorized'] is True and result['credentials_copied'] is False
    assert (accounts / 'shared.json').read_bytes() == original
    assert being_seed._read(accounts / 'shared.credentials.json')['pairs'] == {'eko': 'sai'}
