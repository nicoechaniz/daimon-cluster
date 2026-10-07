"""Persistent guest service publication survives effects with missing ACKs."""
from pathlib import Path

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_service import UNIT, install


def test_retry_after_enable_ack_loss_keeps_unit_bytes_and_no_restart(tmp_path):
    calls = []
    def execute(argv):
        calls.append(argv)
        if len(calls) == 2:
            raise OSError('lost acknowledgement after enable')
    with pytest.raises(OSError):
        install(Path('/opt/daimon-onboarding') / ('a' * 64), receive_only=True,
                directory=tmp_path, run=execute)
    original = (tmp_path / UNIT).read_bytes()
    install(Path('/opt/daimon-onboarding') / ('a' * 64), receive_only=True,
            directory=tmp_path, run=execute)
    assert (tmp_path / UNIT).read_bytes() == original
    assert calls == [['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', UNIT]] * 2
    assert not list(tmp_path.glob('.onboarding-service-*'))
    assert b'User=agent\nGroup=agent' in original
    assert b'Restart=on-failure' in original and b'WantedBy=multi-user.target' in original


@pytest.mark.parametrize('foreign', ['bytes', 'symlink', 'different-release'])
def test_foreign_unit_is_preserved_before_any_systemctl_effect(tmp_path, foreign):
    calls = []
    code = Path('/opt/daimon-onboarding') / ('a' * 64)
    unit = tmp_path / UNIT
    if foreign == 'symlink':
        (tmp_path / 'other').write_text('original')
        unit.symlink_to(tmp_path / 'other')
    elif foreign == 'different-release':
        install(code, receive_only=True, directory=tmp_path, run=lambda _: None)
        code = Path('/opt/daimon-onboarding') / ('b' * 64)
    else:
        unit.write_bytes(b'original')
    original = unit.read_bytes()
    with pytest.raises((OnboardingError, ValueError)):
        install(code, receive_only=True, directory=tmp_path, run=calls.append)
    assert unit.read_bytes() == original and not calls
