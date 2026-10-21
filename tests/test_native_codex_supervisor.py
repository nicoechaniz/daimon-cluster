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


def test_permanent_failure_is_bounded_and_never_stops_or_restarts_child():
    now, calls = [0], []
    def run(argv, **kwargs):
        calls.append(argv[-1])
        return SimpleNamespace(returncode=1)
    with pytest.raises(RuntimeError, match='native_codex_daemon_start_failed'):
        serve(Path('/fixture'), Path('/codex'), run=run,
              wait=lambda n: now.__setitem__(0, now[0]+n), clock=lambda: now[0],
              cycles=1, readiness_seconds=20)
    assert calls == ['start'] + ['version']*4
    assert now[0] == 20
