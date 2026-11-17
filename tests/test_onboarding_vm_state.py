"""Private state cutover keeps originals and never replays a completed copy."""
import json
import os
from pathlib import Path
import subprocess

import pytest

from clusterctl import onboarding_vm_state as state


def test_boot_state_preserves_paths_and_newer_writes_across_remount(tmp_path):
    namespace = {'__name__': 'qualification'}
    exec(compile(state.BOOTSTRAP, 'standalone-vm-state', 'exec'), namespace)
    home, base = tmp_path/'home', tmp_path/'state'
    home.mkdir(mode=0o700)
    (home/'.local').mkdir(mode=0o700)
    (home/'.local/own-test-state').write_text('initial disposable state')
    mounts, calls = {}, []
    class GuestPath(type(Path())):
        def is_mount(self):
            return str(self) == str(home) or str(self) in mounts
        def stat(self, **kwargs):
            if str(self) in mounts:
                return Path(mounts[str(self)]).stat(**kwargs)
            return super().stat(**kwargs)
    real_private = namespace['private']
    namespace['private'] = lambda p, uid=0: real_private(p, os.getuid() if uid == 0 else uid)
    class GuestOS:
        def __getattr__(self, name):
            return getattr(os, name)
        def geteuid(self):
            return 0
    namespace.update(Path=GuestPath, HOME=GuestPath(home), BASE=GuestPath(base),
                     os=GuestOS(), native=lambda root, home: True)
    def run(argv):
        calls.append(argv)
        if argv[0] == '/usr/bin/mount':
            mounts[argv[-1]] = argv[-2]
            return b''
        result = subprocess.run(argv, capture_output=True, check=True)
        return result.stdout
    namespace['run'] = run
    request = {'schema':'cluster-vm-state/v1', 'plan_digest':'a'*64, 'name':'fixture'}
    namespace['activate'](request)
    root = base/request['plan_digest']
    assert json.loads((root/'current.json').read_text())['ready']
    source = root/'.local/own-test-state'
    assert source.read_text() == 'initial disposable state'
    source.write_text('newer disposable state after cutover')
    copied = len([c for c in calls if c[0] == '/usr/bin/rsync'])
    namespace['activate'](request)
    mounts.clear()  # Next boot sees the original Home before the bind mounts.
    namespace['activate'](request)
    assert source.read_text() == 'newer disposable state after cutover'
    assert len([c for c in calls if c[0] == '/usr/bin/rsync']) == copied
    assert (home/'.local/own-test-state').read_text() == 'initial disposable state'
    # The receipt is an own-path cutover, not another native history or DB.
    assert set(mounts) == {str(home/r) for r in ('.agents','.local','.codex')}


def test_state_unit_gates_consumers_without_attention_or_account_commands():
    unit = state.unit().decode()
    assert 'Type=oneshot' in unit and 'TimeoutStartSec=300' in unit
    assert 'Before='+' '.join(state.CONSUMERS) in unit
    for forbidden in ('Restart=', 'Timer', 'prime', 'login', 'goal resume', 'stop all'):
        assert forbidden not in unit


def test_state_install_refuses_nonroot_before_any_effect(monkeypatch):
    monkeypatch.setattr(state.os, 'geteuid', lambda: 1000)
    with pytest.raises(ValueError, match='companion_native_state_required'):
        state.install('a'*64, 'fixture')
