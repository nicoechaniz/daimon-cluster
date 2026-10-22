from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from clusterctl.native_codex_supervisor import serve


@pytest.mark.parametrize('slow_probe', [False, True])
def test_slow_start_is_allowed_to_complete_without_restart(slow_probe, capsys):
    now, calls = [0], []
    def run(argv, **kwargs):
        calls.append(argv[-1])
        if len(calls) == 2 and slow_probe:
            now[0] += 15
            raise subprocess.TimeoutExpired(argv, 15)
        return SimpleNamespace(returncode=0 if len(calls) >= 3 else 1)
    serve(Path('/fixture'), Path('/codex'), run=run,
          wait=lambda n: now.__setitem__(0, now[0]+n), clock=lambda: now[0], cycles=1)
    assert calls == ['start', 'version', 'version']
    assert 'readiness_recovered' in capsys.readouterr().err


def test_unconfirmed_readiness_preserves_child_and_retries_without_exiting(capsys):
    now, calls = [0], []
    def run(argv, **kwargs):
        calls.append(argv[-1])
        return SimpleNamespace(returncode=1)
    serve(Path('/fixture'), Path('/codex'), run=run,
          wait=lambda n: now.__setitem__(0, now[0]+n), clock=lambda: now[0],
          cycles=2, readiness_seconds=20)
    assert calls == (['start'] + ['version']*4)*2
    assert now[0] == 100
    assert capsys.readouterr().err.count('readiness_unconfirmed') == 2


def test_native_start_timeout_retains_supervisor_until_control_recovers(capsys):
    now,calls=[0],[]
    def run(argv,**kwargs):
        calls.append(argv[-1])
        if argv[-1]=='start':raise subprocess.TimeoutExpired(argv,180)
        return SimpleNamespace(returncode=0)
    serve(Path('/fixture'),Path('/codex'),run=run,wait=lambda n:now.__setitem__(0,now[0]+n),
          clock=lambda:now[0],cycles=1)
    assert calls==['start','version']
    assert 'readiness_recovered' in capsys.readouterr().err
