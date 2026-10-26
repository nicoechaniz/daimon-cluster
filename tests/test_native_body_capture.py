"""Exercise the consistency/availability boundary without stopping real units."""
import importlib.util
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

_spec = importlib.util.spec_from_file_location(
    'native_body_capture', Path(__file__).resolve().parents[1] / 'scripts/native-body-capture.py')
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def state(tmp_path):
    root = tmp_path / 'private'
    root.mkdir(mode=0o700)
    (root / 'capture/root').mkdir(parents=True)
    return root


@pytest.mark.parametrize('failure', ['none', 'copy', 'quiescence'])
def test_capture_always_recovers_previous_availability(tmp_path, failure):
    root = state(tmp_path)
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        if argv[0] == 'rsync' and failure == 'copy':
            raise subprocess.CalledProcessError(24, argv)
        return subprocess.CompletedProcess(argv, 0)
    with patch.object(mod, 'active', side_effect=lambda unit: unit != 'idle.service'), \
         patch.object(mod, 'stopped', return_value=failure != 'quiescence'), \
         patch.object(mod.subprocess, 'run', side_effect=run):
        if failure == 'none':
            assert mod.capture(root, ['writer.service', 'idle.service'], ['source.timer'])[
                'capture_consistent']
        else:
            with pytest.raises(mod.CaptureError):
                mod.capture(root, ['writer.service', 'idle.service'], ['source.timer'])
    assert calls[:3] == [['systemctl', 'stop', 'source.timer'],
                         ['systemctl', 'stop', 'writer.service'],
                         ['systemctl', 'stop', 'idle.service']]
    assert calls[-2:] == [['systemctl', 'start', 'writer.service'],
                          ['systemctl', 'start', 'source.timer']]
    assert ['systemctl', 'start', 'idle.service'] not in calls
    assert any(c[0] == 'rsync' for c in calls) == (failure != 'quiescence')
    receipt = json.loads((root / 'capture-attempt.json').read_text())
    assert receipt['availability_restored']
    assert receipt['capture_consistent'] == (failure == 'none')


def test_failed_recovery_not_claimed_healthy(tmp_path):
    root = state(tmp_path)
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1 if argv[:2] == ['systemctl', 'start'] else 0)
    with patch.object(mod, 'active', return_value=True), \
         patch.object(mod, 'stopped', return_value=True), \
         patch.object(mod.subprocess, 'run', side_effect=run), \
         pytest.raises(mod.CaptureError):
        mod.capture(root, ['writer.service'], [])
    assert not json.loads((root / 'capture-attempt.json').read_text())['availability_restored']


def test_retained_attempt_and_invalid_units_have_no_effects(tmp_path):
    root = state(tmp_path)
    (root / 'capture-attempt.json').write_text('{}')
    with patch.object(mod, 'active', return_value=True), \
         patch.object(mod.subprocess, 'run') as run:
        with pytest.raises(mod.CaptureError, match='attempt_retained'):
            mod.capture(root, ['writer.service'], [])
        with pytest.raises(mod.CaptureError, match='boundary_invalid'):
            mod.capture(root, ['--all.service'], [])
        run.assert_not_called()


def test_partial_stop_failure_still_recovers_all_previous_units(tmp_path):
    root = state(tmp_path)
    starts = []
    def run(argv, **kwargs):
        if argv == ['systemctl', 'stop', 'writer.service']:
            raise subprocess.CalledProcessError(1, argv)
        if argv[:2] == ['systemctl', 'start']:
            starts.append(argv[-1])
        assert argv[0] != 'rsync'
        return subprocess.CompletedProcess(argv, 0)
    with patch.object(mod, 'active', return_value=True), \
         patch.object(mod.subprocess, 'run', side_effect=run), \
         pytest.raises(mod.CaptureError):
        mod.capture(root, ['writer.service'], ['source.timer'])
    assert starts == ['writer.service', 'source.timer']
    assert not json.loads((root / 'capture-attempt.json').read_text())['capture_consistent']


def test_reactivation_during_copy_is_not_accepted(tmp_path):
    root = state(tmp_path)
    with patch.object(mod, 'active', return_value=True), \
         patch.object(mod, 'stopped', side_effect=[True, False]), \
         patch.object(mod.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)), \
         pytest.raises(mod.CaptureError):
        mod.capture(root, ['writer.service'], [])
    receipt = json.loads((root / 'capture-attempt.json').read_text())
    assert receipt['error'] == 'capture_writer_reactivated'
    assert receipt['availability_restored']


def test_recovery_only_never_recaptures_and_continues_after_timeout(tmp_path):
    root = state(tmp_path)
    receipt = {'previously_active': ['first.timer', 'second.service'], 'capture_consistent': False}
    mod.persist(root / 'capture-attempt.json', receipt)
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        if argv[-1] == 'second.service':
            raise subprocess.TimeoutExpired(argv, 120)
        return subprocess.CompletedProcess(argv, 0)
    with patch.object(mod, 'active', return_value=True), \
         patch.object(mod.subprocess, 'run', side_effect=run):
        result = mod.recover(root)
    assert calls == [['systemctl', 'start', 'second.service'],
                     ['systemctl', 'start', 'first.timer']]
    assert result['recovery_failures'] == ['second.service']
    assert not result['availability_restored']
    assert not result['capture_consistent']


def test_exclusion_metacharacters_rejected_before_effects(tmp_path):
    root = tmp_path / 'backup[1]'
    root.mkdir(mode=0o700)
    with patch.object(mod.subprocess, 'run') as run, pytest.raises(mod.CaptureError):
        mod.capture(root, ['writer.service'], [])
    run.assert_not_called()
