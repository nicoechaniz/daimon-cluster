"""Dedicated SSH proposals cannot widen operating-system login admission."""
import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_ssh import proposal
from tests.test_onboarding import plan


def test_standalone_proposal_is_deterministic_and_scoped_to_receiving_account():
    key = 'ssh-ed25519 ' + 'A' * 43 + ' receiving-human'
    value = proposal(plan(), key)
    assert proposal(plan(), key) == value
    assert value['account'] == 'agent' and value['port'] == 2222
    assert 'AllowUsers agent\n' in value['configuration']
    assert 'PermitRootLogin no\n' in value['configuration']
    assert 'PasswordAuthentication no\n' in value['configuration']
    assert 'Include ' not in value['configuration']
    assert '/etc/ssh/' not in value['configuration'] + value['service']
    assert 'AuthorizedKeysFile /etc/daimon-onboarding/ssh/owner.pub' in value['configuration']
    assert proposal(plan(), key + ' other')['public_key_sha256'] != value['public_key_sha256']


@pytest.mark.parametrize('key', [None, '', 'ssh-ed25519 abc',
    'ssh-ed25519 ' + 'A' * 43 + '\nAllowUsers other', 'ssh-ed25519 ' + 'A' * 43 + '\0'])
def test_untrusted_key_cannot_inject_configuration(key):
    with pytest.raises(OnboardingError, match='public_key_required'):
        proposal(plan(), key)


def test_lost_start_ack_preserves_host_key_and_owner_binding(tmp_path):
    from clusterctl.onboarding_ssh import install
    root, units = tmp_path / 'ssh', tmp_path / 'units'
    units.mkdir(mode=0o700)
    key = 'ssh-ed25519 ' + 'A' * 43
    generated, failed = [], []
    def run(argv):
        if '-q' in argv:
            from pathlib import Path
            path = Path(argv[-1])
            path.write_bytes(b'private fixture')
            path.chmod(0o600)
            generated.append(path)
        if '-y' in argv:
            return key
        if argv[:3] == ['systemctl', 'enable', '--now'] and not failed:
            failed.append(True)
            raise OSError('lost start acknowledgement')
        return ''
    with pytest.raises(OSError, match='lost start'):
        install(plan(), key, root=root, units=units, run=run)
    original = (root / 'private/host.key').read_bytes()
    assert install(plan(), key, root=root, units=units, run=run)['installed'] is True
    assert len(generated) == 1 and (root / 'private/host.key').read_bytes() == original
    with pytest.raises(OnboardingError, match='preserved'):
        install(plan(), key + ' changed', root=root, units=units, run=run)
    (root / 'private/host.key').unlink()
    with pytest.raises(OnboardingError, match='preserved'):
        install(plan(), key, root=root, units=units, run=run)
    assert len(generated) == 1


def test_invalid_native_key_does_not_poison_durable_binding(tmp_path):
    from clusterctl.onboarding_ssh import install
    root, units = tmp_path / 'ssh', tmp_path / 'units'
    units.mkdir(mode=0o700)
    def refuse(_argv):
        raise OnboardingError('onboarding_ssh_operation_failed')
    with pytest.raises(OnboardingError):
        install(plan(), 'ssh-ed25519 ' + 'A' * 43, root=root, units=units, run=refuse)
    assert not (root / 'private/binding.json').exists()
    assert not (root / 'owner.pub').exists()


def test_native_host_key_and_standalone_configuration_retry_without_starting_listener(tmp_path):
    import shutil
    import subprocess
    from pathlib import Path
    from clusterctl.onboarding_ssh import _run, install
    if (not shutil.which('ssh-keygen') or not Path('/usr/sbin/sshd').is_file()
            or not Path('/run/sshd').is_dir()):
        pytest.skip('native OpenSSH configuration validator unavailable')
    owner = tmp_path / 'owner-key'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(owner)], check=True)
    key = Path(str(owner) + '.pub').read_text().strip()
    units = tmp_path / 'units'
    units.mkdir(mode=0o700)
    calls = []
    def execute(argv):
        if argv[0] == 'systemctl':
            calls.append(argv)
            return ''
        return _run(argv)
    root = tmp_path / 'dedicated'
    first = install(plan(), key, root=root, units=units, run=execute)
    preserved = (root / 'private/host.key').read_bytes()
    assert install(plan(), key, root=root, units=units, run=execute) == first
    assert (root / 'private/host.key').read_bytes() == preserved
    assert calls == [['systemctl', 'daemon-reload'],
                     ['systemctl', 'enable', '--now', 'daimon-onboarding-ssh.service']] * 2


def test_observation_requires_exact_live_listener_and_preserved_host_key(tmp_path):
    from pathlib import Path
    from clusterctl.onboarding_ssh import install, observe
    key = 'ssh-ed25519 ' + 'A' * 43
    units = tmp_path / 'units'
    units.mkdir(mode=0o700)
    root = tmp_path / 'ssh'
    state = {'active': True, 'pid': 42}
    def run(argv):
        if '-q' in argv:
            path = Path(argv[-1])
            path.write_bytes(b'private fixture')
            path.chmod(0o600)
        if '-y' in argv:
            return key
        if argv[:2] == ['systemctl', 'show']:
            return 'ActiveState=%s\nMainPID=42\n' % ('active' if state['active'] else 'inactive')
        if argv[0] == '/usr/bin/ss':
            return 'LISTEN 0 128 0.0.0.0:2222 *:* users:(("sshd",pid=%s,fd=3))' % state['pid']
        return ''
    assert not observe(plan(), key, root=root, units=units, run=run)['installed']
    install(plan(), key, root=root, units=units, run=run)
    assert observe(plan(), key, root=root, units=units, run=run)['service_verified']
    state['pid'] = 142
    assert not observe(plan(), key, root=root, units=units, run=run)['installed']
    state['pid'], state['active'] = 42, False
    assert not observe(plan(), key, root=root, units=units, run=run)['installed']
    (root / 'private/host-public.json').write_text('{}')
    with pytest.raises(OnboardingError, match='preserved'):
        observe(plan(), key, root=root, units=units, run=run)


def test_interrupted_dependency_install_finishes_before_removing_own_suppression(tmp_path):
    from clusterctl.onboarding_ssh import dependencies
    sshd, policy = tmp_path / 'sshd', tmp_path / 'policy'
    calls = []
    def interrupted(argv):
        calls.append(argv)
        if 'install' in argv:
            sshd.write_bytes(b'partially installed')
            raise OnboardingError('lost package acknowledgement')
    with pytest.raises(OnboardingError):
        dependencies(run=interrupted, sshd=sshd, policy=policy)
    assert policy.exists() and sshd.exists()
    calls.clear()
    dependencies(run=lambda argv: calls.append(argv), sshd=sshd, policy=policy)
    assert any('install' in argv for argv in calls)
    assert calls[-1] == ['systemctl', 'disable', '--now', 'ssh.service']
    assert not policy.exists()
    calls.clear()
    dependencies(run=lambda argv: calls.append(argv), sshd=sshd, policy=policy)
    assert not calls


def test_foreign_package_policy_is_preserved(tmp_path):
    from clusterctl.onboarding_ssh import dependencies
    policy = tmp_path / 'policy'
    policy.write_bytes(b'foreign policy')
    policy.chmod(0o755)
    calls = []
    with pytest.raises(OnboardingError, match='preserved'):
        dependencies(run=lambda argv: calls.append(argv), sshd=tmp_path / 'missing', policy=policy)
    assert policy.read_bytes() == b'foreign policy' and not calls
