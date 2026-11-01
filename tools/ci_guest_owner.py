"""Run the guest-owner contracts with real kernel UID1000 on a disposable CI host.

Keep host root mapped to root so protected-path validation retains its real
meaning. No account, source ownership, interpreter or SDK file is changed.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import shlex
import sys
import tempfile


def run(command: list[str], uid: int, gid: int) -> int:
    if os.geteuid() != 0 or uid <= 0 or gid <= 0 or uid == 65534 or gid == 65534:
        raise ValueError('root and an actual non-root runner owner are required')
    # Root and owner lanes can inherit the same account name. Their pytest
    # temporary trees must still have separate real owners.
    with tempfile.TemporaryDirectory(prefix='cluster-ci-owner-', dir='/tmp') as name:
        os.chown(name, uid, gid)
        return _mapped_run(command, uid, gid, name)


def _owner_environment(temporary: str) -> dict[str, str]:
    # Isolate pytest's owner, not every native runtime's home. Changing TMPDIR
    # lengthens short AF_UNIX paths created by unrelated tempfile callers.
    options = shlex.split(os.environ.get('PYTEST_ADDOPTS', ''))
    options.extend(['--basetemp', str(Path(temporary) / 'pytest')])
    return {**os.environ, 'PYTEST_ADDOPTS': shlex.join(options)}


def _mapped_run(command: list[str], uid: int, gid: int, temporary: str) -> int:
    ready_read, ready_write = os.pipe()
    mapped_read, mapped_write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(ready_read)
        os.close(mapped_write)
        try:
            os.setgroups([])
            os.unshare(os.CLONE_NEWUSER)
            os.write(ready_write, b'1')
            os.close(ready_write)
            if os.read(mapped_read, 1) != b'1':
                raise RuntimeError('owner mapping was not installed')
            os.close(mapped_read)
            os.setresgid(1000, 1000, 1000)
            os.setresuid(1000, 1000, 1000)
            os.execve(command[0], command, _owner_environment(temporary))
        except BaseException as error:
            print(f'guest-owner namespace child failed: {error}', file=sys.stderr, flush=True)
            os._exit(1)
    os.close(ready_write)
    os.close(mapped_read)
    try:
        if os.read(ready_read, 1) != b'1':
            raise RuntimeError('guest-owner user namespace unavailable')
        process = Path('/proc') / str(child)
        # The parent retains real host-root map authority. newuidmap's separate
        # subordinate-ID allocation is not needed for this disposable mapping.
        (process / 'setgroups').write_text('deny')
        (process / 'uid_map').write_text(f'0 0 1\n1000 {uid} 1\n')
        (process / 'gid_map').write_text(f'0 0 1\n1000 {gid} 1\n')
        os.write(mapped_write, b'1')
    except BaseException:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
        raise
    finally:
        os.close(ready_read)
        os.close(mapped_write)
    return os.waitstatus_to_exitcode(os.waitpid(child, 0)[1])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', required=True, type=int)
    parser.add_argument('--gid', required=True, type=int)
    parser.add_argument('--sdk-commit')
    parser.add_argument('--identity-python', type=Path)
    parser.add_argument('tests', nargs='*')
    args = parser.parse_args(argv)
    if (args.sdk_commit is None) != (args.identity_python is None):
        parser.error('candidate SDK and unchanged identity interpreter must be selected together')
    if args.tests and args.sdk_commit is None:
        parser.error('explicit native selectors require the qualified candidate SDK')
    if args.sdk_commit is None:
        command = [sys.executable, '-B', '-m', 'pytest', '-q',
            'tests/test_guest_owner_bootstrap.py', '-W', 'error::ResourceWarning',
            '-W', 'error::pytest.PytestUnraisableExceptionWarning', '--durations=5']
    else:
        command = [sys.executable, '-B', 'tools/qualify_candidate_admission.py',
            '--sdk-commit', args.sdk_commit, '--identity-python', str(args.identity_python),
            *(args.tests or ['tests/test_guest_owner_bootstrap.py'])]
    return run(command, args.uid, args.gid)


if __name__ == '__main__':
    raise SystemExit(main())
