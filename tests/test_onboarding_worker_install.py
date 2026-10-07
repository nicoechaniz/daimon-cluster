"""Dedicated worker installation preserves the selected release and singleton."""
from pathlib import Path
import hashlib

import pytest

from clusterctl.onboarding import OnboardingError
from tools.install_onboarding_worker import UNIT, install_unit, service


def test_worker_unit_uses_one_native_engine_and_restartable_private_configuration():
    release = Path('/opt/daimon-cluster-releases') / ('a' * 40)
    config = Path('/var/lib/own-onboarding/host.json')
    value = service(release, config).decode()
    assert 'clusterctl.onboarding_worker' in value
    assert 'User=root\nGroup=root\nUMask=0077' in value
    assert 'Restart=on-failure' in value and 'KillMode=control-group' in value
    assert 'WantedBy=multi-user.target' in value
    assert 'StandardOutput=null' in value
    assert 'Matrix' not in value and 'codex exec' not in value


@pytest.mark.parametrize('release,config', [
    ('/opt/mutable-checkout', '/var/lib/own/host.json'),
    ('/opt/daimon-cluster-releases/main', '/var/lib/own/host.json'),
    ('/opt/daimon-cluster-releases/' + 'a' * 40, 'relative-config'),
])
def test_unqualified_installation_is_refused(release, config):
    with pytest.raises(OnboardingError, match='qualified_worker_release_required'):
        service(Path(release), Path(config))


def test_worker_upgrade_keeps_predecessor_and_retries_without_context_change(tmp_path):
    before = service(Path('/opt/daimon-cluster-releases') / ('a' * 40), Path('/var/lib/own/host.json'))
    after = service(Path('/opt/daimon-cluster-releases') / ('b' * 40), Path('/var/lib/own/host.json'))
    install_unit(tmp_path, before)
    fingerprint = hashlib.sha256(before).hexdigest()
    with pytest.raises(OnboardingError, match='existing_onboarding_service_preserved'):
        install_unit(tmp_path, after)
    with pytest.raises(OnboardingError, match='existing_onboarding_service_preserved'):
        install_unit(tmp_path, after, previous_sha256='c' * 64)
    assert (tmp_path / UNIT).read_bytes() == before
    assert install_unit(tmp_path, after, previous_sha256=fingerprint)
    assert (tmp_path / UNIT).read_bytes() == after
    assert (tmp_path / (UNIT + '.' + fingerprint + '.previous')).read_bytes() == before
    assert not install_unit(tmp_path, after, previous_sha256=fingerprint)
    assert not list(tmp_path.glob('.onboarding-worker-*'))


def test_worker_upgrade_preserves_foreign_symlink(tmp_path):
    foreign = tmp_path / 'original'
    foreign.write_bytes(b'foreign')
    (tmp_path / UNIT).symlink_to(foreign)
    with pytest.raises((OnboardingError, ValueError)):
        install_unit(tmp_path, b'new', previous_sha256=hashlib.sha256(b'foreign').hexdigest())
    assert foreign.read_bytes() == b'foreign'
