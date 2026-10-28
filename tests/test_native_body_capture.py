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


@pytest.fixture(autouse=True)
def selected_plan(monkeypatch):
    monkeypatch.setattr(mod, 'load_plan', lambda state: {
        'source_roots': ['/'], 'excluded_mounts_and_runtime': [str(state)]})


def state(tmp_path):
    root = tmp_path / 'private'
    root.mkdir(mode=0o700)
    (root / 'capture/root').mkdir(parents=True)
    return root


@pytest.mark.parametrize('unit', ['user:0:writer.service', 'user:01000:writer.service',
    'user:1000:--all.service', 'user:1000:writer.service:extra',
    'user:9999999999:writer.service', 'user:alice:writer.service'])
def test_invalid_user_scope_never_controls_services(tmp_path, unit):
    with patch.object(mod.subprocess, 'run') as run, \
         pytest.raises(mod.CaptureError, match='boundary_invalid'):
        mod.capture(state(tmp_path), [unit], [])
    run.assert_not_called()


def test_user_target_uses_exact_manager_and_clean_environment():
    import types
    account=types.SimpleNamespace(pw_name='selected',pw_dir='/home/selected')
    with patch.object(mod.pwd, 'getpwuid', return_value=account) as lookup:
        argv=mod.systemctl('user:1000:writer.service','stop')
    lookup.assert_called_once_with(1000)
    assert argv[:6]==['/usr/sbin/runuser','--user','selected','--','/usr/bin/env','-i']
    assert 'XDG_RUNTIME_DIR=/run/user/1000' in argv
    assert 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus' in argv
    assert argv[-4:]==['/usr/bin/systemctl','--user','stop','writer.service']
    assert mod.systemctl('writer.service','stop')==['systemctl','stop','writer.service']


def test_mixed_scope_failure_recovers_same_managers_and_retains_scope(tmp_path):
    root=state(tmp_path)
    calls=[]
    def run(argv,**kwargs):
        calls.append(argv)
        if argv[0]=='rsync':raise subprocess.CalledProcessError(24,argv)
        return subprocess.CompletedProcess(argv,0)
    with patch.object(mod,'active',return_value=True), \
         patch.object(mod,'stopped',return_value=True), \
         patch.object(mod.subprocess,'run',side_effect=run), \
         pytest.raises(mod.CaptureError):
        mod.capture(root,['writer.service','user:1000:writer.service'],['user:1000:source.timer'])
    assert calls[0][-3:]==['--user','stop','source.timer']
    assert calls[1]==['systemctl','stop','writer.service']
    assert calls[-2]==['systemctl','start','writer.service']
    assert calls[-1][-3:]==['--user','start','source.timer']
    receipt=json.loads((root/'capture-attempt.json').read_text())
    assert receipt['previously_active']==['user:1000:source.timer','writer.service','user:1000:writer.service']
    assert receipt['availability_restored'] and not receipt['capture_consistent']


def test_missing_user_account_refuses_before_any_stop(tmp_path):
    with patch.object(mod.pwd,'getpwuid',side_effect=KeyError), \
         patch.object(mod.subprocess,'check_output',return_value='active\n'), \
         patch.object(mod.subprocess,'run') as run, \
         pytest.raises(mod.CaptureError,match='user_account_unavailable'):
        mod.capture(state(tmp_path),['writer.service','user:1000:writer.service'],[])
    run.assert_not_called()


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


def test_seed_rejects_external_hardlinks_but_accepts_internal_links(tmp_path):
    import os
    root = state(tmp_path)
    dest = root / 'capture/root'
    live = tmp_path / 'live'
    live.write_text('retained work')
    os.link(live, dest / 'aliased')
    with pytest.raises(mod.CaptureError, match='external_hardlinks'):
        mod.seed_boundary(dest, [])
    (dest / 'aliased').unlink()
    (dest / 'file').write_text('independent')
    os.link(dest / 'file', dest / 'second-name')
    assert mod.seed_boundary(dest, [])['purpose'] == 'disposable-independent-backup-seed'


def test_seed_rejects_symlink_or_mounted_destination(tmp_path):
    root = state(tmp_path)
    dest = root / 'capture/root'
    with pytest.raises(mod.CaptureError, match='is_mounted'):
        mod.seed_boundary(dest, [{'target': str(dest / 'live')}])
    dest.rmdir()
    dest.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(mod.CaptureError, match='path_invalid'):
        mod.seed_boundary(dest, [])


def test_required_store_on_excluded_remote_mount_is_not_claimed_backed_up(tmp_path):
    root = state(tmp_path)
    remote = Path('/srv/selected-remote')
    rows = [{'target': '/', 'fstype': 'ext4'},
            {'target': str(remote), 'fstype': 'fuse.sshfs'}]
    resolve = Path.resolve
    with patch.object(Path, 'resolve', lambda path, **kwargs:
                      path if path == remote else resolve(path, **kwargs)):
        with pytest.raises(mod.CaptureError, match='required_store_excluded'):
            mod.coverage(root, rows, [remote])
        result = mod.coverage(root, rows, [Path('/')])
    assert str(remote) in result['excluded_mounts_and_runtime']
    assert result['source_roots'] == ['/']


def test_actual_rsync_final_delta_removes_stale_seed_without_touching_live(tmp_path):
    import shutil
    if not shutil.which('rsync'):
        pytest.skip('rsync is required for actual capture delta test')
    root = state(tmp_path)
    live = tmp_path / 'source'
    live.mkdir()
    (live / 'current').write_text('new version')
    (live / 'link').symlink_to('current')
    target = root / 'capture/root' / str(live).lstrip('/')
    target.mkdir(parents=True)
    (target / 'stale').write_text('old version')
    with patch.object(mod, 'load_plan', return_value={
            'source_roots': [str(live)], 'excluded_mounts_and_runtime': [str(root)]}), \
         patch.object(mod, 'active', return_value=True), \
         patch.object(mod, 'stopped', return_value=True), \
         patch.object(mod.subprocess, 'run', wraps=mod.subprocess.run) as run:
        # Keep rsync real and isolate systemd from the host.
        def selected(argv, **kwargs):
            if argv[0] == 'systemctl':
                return subprocess.CompletedProcess(argv, 0)
            return run._mock_wraps(argv, **kwargs)
        run.side_effect = selected
        result = mod.capture(root, ['writer.service'], [])
    assert result['capture_consistent']
    assert not (target / 'stale').exists()
    assert (target / 'current').read_text() == (live / 'current').read_text()
    assert (target / 'link').is_symlink()
    assert not (live / 'stale').exists()


def test_state_lock_excludes_capture_recovery_and_preparation(tmp_path):
    root = state(tmp_path)
    with mod.state_lock(root):
        with pytest.raises(mod.CaptureError, match='already_running'):
            with mod.state_lock(root):
                pytest.fail('concurrent operation admitted')
    with mod.state_lock(root):
        pass


def test_additional_root_target_rejects_symlink_ancestor(tmp_path):
    root = state(tmp_path)
    destination = root / 'capture/root'
    (destination / 'boot').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(mod.CaptureError, match='not_directory'):
        mod.safe_target(destination, '/boot/efi')


def test_actual_rsync_preserves_child_seed_during_parent_pass(tmp_path):
    import shutil
    assert shutil.which('rsync'), 'rsync required for native capture contract'
    root = state(tmp_path)
    live = tmp_path / 'source'
    child = live / 'boot'
    child.mkdir(parents=True)
    (child / 'kernel').write_text('retained kernel bytes')
    (live / 'config').write_text('native configuration')
    target = root / 'capture/root' / str(child).lstrip('/')
    target.mkdir(parents=True)
    shutil.copy2(child / 'kernel', target / 'kernel')
    retained_inode = (target / 'kernel').stat().st_ino
    (target / 'stale').write_text('removed source file')
    real_run = subprocess.run
    def selected(argv, **kwargs):
        if argv[0] == 'systemctl':
            return subprocess.CompletedProcess(argv, 0)
        return real_run(argv, **kwargs)
    with patch.object(mod, 'load_plan', return_value={
            'source_roots': [str(live), str(child)], 'excluded_mounts_and_runtime': [str(root)]}), \
         patch.object(mod, 'active', return_value=True), \
         patch.object(mod, 'stopped', return_value=True), \
         patch.object(mod.subprocess, 'run', side_effect=selected):
        assert mod.capture(root, ['writer.service'], [])['capture_consistent']
    assert (target / 'kernel').stat().st_ino == retained_inode
    assert not (target / 'stale').exists()
    assert (target.parent / 'config').read_text() == 'native configuration'
