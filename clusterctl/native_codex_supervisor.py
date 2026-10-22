"""Supervise the existing Codex singleton without restarting slow startup."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import time


def serve(home: Path, codex: Path, *, run=subprocess.run, wait=time.sleep,
          clock=time.monotonic, cycles=None, readiness_seconds=180,
          interval_seconds=30) -> None:
    env = dict(HOME=str(home), CODEX_HOME=str(home / '.codex'),
               PATH='/usr/local/bin:/usr/bin:/bin')
    count = 0
    while cycles is None or count < cycles:
        try:
            result = run([str(codex), 'app-server', 'daemon', 'start'], capture_output=True,
                         text=True, timeout=180, check=False, env=env)
            ready = result.returncode == 0
        except subprocess.TimeoutExpired:
            ready = False
        if not ready:
            # A native start can time out while its child is still starting.
            # Exiting this cgroup supervisor would kill that child and repeat
            # the same cold start. Probe only; do not issue stop or another start.
            print('native_codex_waiting_for_readiness', file=sys.stderr, flush=True)
            deadline = clock() + readiness_seconds
            while clock() < deadline:
                wait(min(5, max(0, deadline - clock())))
                try:
                    probe = run([str(codex), 'app-server', 'daemon', 'version'],
                                capture_output=True, text=True, timeout=15,
                                check=False, env=env)
                except subprocess.TimeoutExpired:
                    continue
                if probe.returncode == 0:
                    print('native_codex_readiness_recovered', file=sys.stderr, flush=True)
                    break
            else:
                # A failed control RPC does not prove process death. Exiting
                # would run systemd ExecStop and kill uncertain active work.
                # Retain the singleton; the independent runtime observer alerts.
                # The next idempotent native start recovers an actually dead
                # backend using its own process/lock validation, never replay.
                print('native_codex_readiness_unconfirmed', file=sys.stderr, flush=True)
        count += 1
        wait(interval_seconds)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', required=True, type=Path)
    parser.add_argument('--codex', required=True, type=Path)
    args = parser.parse_args()
    try:
        serve(args.home, args.codex)
    except (RuntimeError, subprocess.TimeoutExpired):
        # Native stderr may contain private configuration. Emit only a safe code.
        print('native_codex_daemon_start_failed', file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
