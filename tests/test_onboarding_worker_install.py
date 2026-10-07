"""Dedicated worker installation preserves the selected release and singleton."""
from pathlib import Path

import pytest

from clusterctl.onboarding import OnboardingError
from tools.install_onboarding_worker import service


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
