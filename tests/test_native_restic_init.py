"""Native backup preparation never substitutes new credentials for lost history."""
import importlib.util
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location('native_restic_init',
    Path(__file__).resolve().parents[1] / 'scripts/native-restic-init.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def public(tmp_path):
    path = tmp_path / 'selected.pub'
    path.write_text('age1fixture\n')
    path.chmod(0o600)
    return path


def test_missing_existing_password_never_rekeys_repository(tmp_path):
    selected = public(tmp_path)
    state = tmp_path / 'state'
    (state / 'restic').mkdir(parents=True)
    state.chmod(0o700)
    (state / 'restic/config').write_bytes(b'existing encrypted history')
    with pytest.raises(module.PreparationError, match='existing_unlock_unavailable'):
        module.initialize(state, selected, selected)
    assert not (state / 'credentials/restic-password').exists()
    assert (state / 'restic/config').read_bytes() == b'existing encrypted history'


def test_unselected_operator_has_no_credential_effect(tmp_path):
    selected = public(tmp_path)
    other = tmp_path / 'operator.pub'
    other.write_text('age1another\n')
    other.chmod(0o600)
    state = tmp_path / 'state'
    with pytest.raises(module.PreparationError, match='operator_recipient_required'):
        module.initialize(state, selected, other)
    assert not state.exists()


def test_partial_envelope_retains_the_same_unlock_material(tmp_path):
    selected = public(tmp_path)
    state = tmp_path / 'state'
    credentials = state / 'credentials'
    credentials.mkdir(parents=True)
    state.chmod(0o700)
    credentials.chmod(0o700)
    password = credentials / 'restic-password'
    password.write_bytes(b'original retained unlock\n')
    password.chmod(0o600)
    (state / 'recovery.age.partial').write_bytes(b'uncertain partial ciphertext')
    with pytest.raises(module.PreparationError, match='partial_envelope_retained'):
        module.initialize(state, selected, selected)
    assert password.read_bytes() == b'original retained unlock\n'
    assert (state / 'recovery.age.partial').read_bytes() == b'uncertain partial ciphertext'


@pytest.mark.skipif(not shutil.which('age-keygen') or not shutil.which('restic'),
                    reason='requires existing age/restic tools')
def test_real_envelope_recovers_same_password_and_repeated_init_preserves_history(tmp_path):
    private = tmp_path / 'recovery-key'
    subprocess.run(['age-keygen', '-o', str(private)], check=True, capture_output=True)
    key = subprocess.check_output(['age-keygen', '-y', str(private)])
    selected = tmp_path / 'selected.pub'
    selected.write_bytes(key)
    selected.chmod(0o600)
    state = tmp_path / 'state'
    result = module.initialize(state, selected, selected)
    password = (state / 'credentials/restic-password').read_bytes()
    envelope = (state / 'recovery.age').read_bytes()
    config = (state / 'restic/config').read_bytes()
    restored = subprocess.check_output(['age', '-d', '-i', str(private), str(state / 'recovery.age')])
    assert restored == password
    assert result['backup_accepted'] is False and result['restore_verified'] is False
    assert module.initialize(state, selected, selected) == result
    assert (state / 'credentials/restic-password').read_bytes() == password
    assert (state / 'recovery.age').read_bytes() == envelope
    assert (state / 'restic/config').read_bytes() == config
    assert os.stat(state / 'credentials/restic-password').st_mode & 0o077 == 0
