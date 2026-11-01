"""Kernel process observations reused from the reviewed existing-owner runtime."""
from __future__ import annotations

import os
import socket
import struct
from contextlib import ExitStack, contextmanager
from pathlib import Path
import select
import math
from typing import Any
import uuid

PROCESS_FIELDS = {"uid", "pid", "start_ticks", "boot_id"}

_LOCK_CUSTODY = '''import os,select,signal,sys,time
deadline=int(sys.argv[1])
remaining=(deadline-time.monotonic_ns())/1e9
if not 0<remaining<=300:raise SystemExit(1)
signal.signal(signal.SIGALRM,signal.SIG_DFL)
signal.setitimer(signal.ITIMER_REAL,remaining)
os.write(1,b'R')
while True:
    remaining=(deadline-time.monotonic_ns())/1e9
    if remaining<=0:break
    if not select.select([0],[],[],remaining)[0]:break
    value=os.read(0,1)
    if value==b'D':break
    # EOF is coordinator loss, not receiving exit. Retain the inherited
    # locks through the exact owner horizon, including a lost transport.
    if not value:
        time.sleep(max(0,(deadline-time.monotonic_ns())/1e9))
        break
'''


@contextmanager
def lock_custody(descriptors: tuple[int, ...], *, deadline_ns: int):
    """Keep held flock ownership through a finite remote owner invocation.

    Normal return acknowledges observed owner completion. An exception or
    coordinator death retains ownership until the receiver-enforced deadline.
    No persisted lease, daemon, model, retry or receiving credential is created.
    """
    import subprocess
    import sys
    import time
    if (not descriptors or len(set(descriptors)) != len(descriptors)
            or any(type(fd) is not int or fd < 3 for fd in descriptors)
            or type(deadline_ns) is not int
            or not 0 < deadline_ns-time.monotonic_ns() <= 300_000_000_000):
        raise PresenceError('owner_lock_custody_required')
    process = subprocess.Popen([sys.executable, '-B', '-I', '-c', _LOCK_CUSTODY, str(deadline_ns)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        pass_fds=descriptors, start_new_session=True)
    assert process.stdin is not None and process.stdout is not None
    dispatched = False
    try:
        remaining = max(0, (deadline_ns-time.monotonic_ns())/1e9)
        if not select.select([process.stdout], [], [], remaining)[0] or process.stdout.read(1) != b'R':
            raise PresenceError('owner_lock_custody_unavailable')
        dispatched = True
        yield
        process.stdin.write(b'D')
        process.stdin.flush()
    finally:
        try:
            process.stdin.close()
        except OSError:
            pass  # A deadline exit must not skip descriptor/process cleanup.
        if not dispatched and process.poll() is None:
            process.kill()  # No receiving invocation was allowed to start.
        try:
            process.wait(timeout=max(0, (deadline_ns-time.monotonic_ns())/1e9)+1)
        except subprocess.TimeoutExpired:
            # The exact receiving horizon has elapsed; no fresh effect remains
            # authorized. Bound this task-owned helper even if cleanup stalls.
            process.kill()
            process.wait()
        finally:
            process.stdout.close()


def require_parent_lifetime(expected_pid: int) -> None:
    """Bind a technical owner CLI to its dispatching coordinator thread.

    Arm after UID/GID admission, before any owner effect. Checking both sides
    closes the fork/registration race; exec of the ordinary non-setuid Python
    owner preserves the kernel death signal. This is process-local, not a
    supervisor, daemon hook or administrative-access change.
    """
    import ctypes
    import signal
    if type(expected_pid) is not int or expected_pid < 2 or os.getppid() != expected_pid:
        raise PresenceError('owner_parent_unavailable')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != expected_pid:
        raise PresenceError('owner_parent_unavailable')


class PresenceError(ValueError):
    """Generic refusal without disclosing process or private path details."""


def validate_process(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != PROCESS_FIELDS:
        raise PresenceError("owner_process_rejected")
    for field, minimum, maximum in (
        ("uid", 0, 2**32), ("pid", 1, 2**31), ("start_ticks", 1, 2**64),
    ):
        item = value[field]
        if isinstance(item, bool) or not isinstance(item, int) or not minimum <= item < maximum:
            raise PresenceError("owner_process_rejected")
    try:
        if not isinstance(value["boot_id"], str) or str(uuid.UUID(value["boot_id"])) != value["boot_id"]:
            raise ValueError("invalid boot identifier")
    except (ValueError, AttributeError) as error:
        raise PresenceError("owner_process_rejected") from error
    return dict(value)


def observe_process_exit(process: dict[str, Any]) -> bool:
    """Resume a retained authenticated tuple after the original pin was lost.

    Kernel absence or a readable pidfd proves exit. A different boot, recycled
    PID, changed owner or unavailable observation is refused, never exit proof.
    """
    expected = validate_process(process)
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip() != expected['boot_id']:
        raise PresenceError('owner_process_exit_observation_rejected')
    try:
        descriptor = os.pidfd_open(expected['pid'], 0)
    except ProcessLookupError:
        return True
    try:
        root = Path('/proc') / str(expected['pid'])
        fields = (root / 'stat').read_text().rpartition(')')[2].split()
        uids = [line.split()[1:] for line in (root / 'status').read_text().splitlines() if line.startswith('Uid:')]
        if (int(fields[19]) != expected['start_ticks'] or len(uids) != 1
                or [int(value) for value in uids[0]] != [expected['uid']] * 4):
            raise PresenceError('owner_process_exit_observation_rejected')
        poller = select.poll()
        poller.register(descriptor, select.POLLIN | select.POLLERR | select.POLLHUP)
        events = poller.poll(0)
        if any(mask & (select.POLLERR | select.POLLNVAL) for _fd, mask in events):
            raise PresenceError('owner_process_exit_observation_rejected')
        return any(mask & (select.POLLIN | select.POLLHUP) for _fd, mask in events)
    except (OSError, ValueError, IndexError) as error:
        raise PresenceError('owner_process_exit_observation_rejected') from error
    finally:
        os.close(descriptor)


class ProcessPresence:
    """Pin one kernel process; no signals, polling loop, runtime RPC or key I/O."""

    def __init__(self, process: dict[str, Any]):
        self.process = validate_process(process)
        self.descriptor = -1
        try:
            self.descriptor = os.pidfd_open(self.process["pid"], 0)
            os.set_inheritable(self.descriptor, False)
            self.verify()
        except Exception as error:
            self.close()
            raise PresenceError("owner_process_unavailable") from error

    def verify(self) -> None:
        try:
            if self.descriptor < 0:
                raise ValueError("closed process observer")
            poller = select.poll()
            poller.register(self.descriptor, select.POLLIN | select.POLLERR | select.POLLHUP)
            if poller.poll(0):
                raise ValueError("process has exited")
            if Path("/proc/sys/kernel/random/boot_id").read_text().strip() != self.process["boot_id"]:
                raise ValueError("different host boot")
            root = Path("/proc") / str(self.process["pid"])
            uid_lines = [line.split()[1:] for line in (root / "status").read_text().splitlines() if line.startswith("Uid:")]
            if len(uid_lines) != 1 or [int(item) for item in uid_lines[0]] != [self.process["uid"]] * 4:
                raise ValueError("different process owner")
            fields = (root / "stat").read_text().rpartition(")")[2].split()
            if fields[0] in {"Z", "X", "x"} or int(fields[19]) != self.process["start_ticks"]:
                raise ValueError("different process start")
            if poller.poll(0):
                raise ValueError("process exited during observation")
        except Exception as error:
            raise PresenceError("owner_process_unavailable") from error

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def wait_for_exit(self, timeout_seconds: float) -> bool:
        """Bounded observation of this pinned process, never a stop or a signal.

        False means the wait ended without exit proof. An invalid/unavailable
        observation raises; a generic verify failure is never treated as exit.
        """
        if (type(timeout_seconds) not in {int, float}
                or not 0 <= timeout_seconds <= 60 or self.descriptor < 0):
            raise PresenceError('owner_process_exit_observation_rejected')
        poller = select.poll()
        poller.register(self.descriptor, select.POLLIN | select.POLLERR | select.POLLHUP)
        def exited(events) -> bool:
            if any(mask & (select.POLLERR | select.POLLNVAL) for _fd, mask in events):
                raise PresenceError('owner_process_exit_observation_rejected')
            return any(mask & (select.POLLIN | select.POLLHUP) for _fd, mask in events)
        if exited(poller.poll(math.ceil(timeout_seconds * 1000))):
            return True
        try:
            self.verify()
        except PresenceError:
            # Exit may race the timeout. Only the pinned kernel descriptor,
            # not the exception or a vanished path, supplies the exit proof.
            if exited(poller.poll(0)):
                return True
            raise
        return False

    def __enter__(self) -> ProcessPresence:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()


class ConnectedProcessObserver:
    """Pin the actual RPC peer through authentication and the complete observation.

    Use as LocalClient's owner-only connection observer within one foreground
    scope. Multiple RPCs must reach the same kernel process; this is transport
    association, not SDK/application/admission qualification or remote liveness.
    """

    def __init__(self) -> None:
        self._process: dict[str, Any] | None = None
        self._stack = ExitStack()
        self._presence: ProcessPresence | None = None
        self._active = False

    def __enter__(self) -> ConnectedProcessObserver:
        if self._active or self._process is not None:
            raise PresenceError("owner_process_observation_rejected")
        self._active = True
        return self

    @property
    def process(self) -> dict[str, Any] | None:
        return None if self._process is None else dict(self._process)

    @contextmanager
    def __call__(self, connection: socket.socket):
        if not self._active or not hasattr(socket, "SO_PEERCRED"):
            raise PresenceError("owner_process_observation_rejected")
        try:
            pid, uid, _gid = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.geteuid():
                raise ValueError("different process owner")
            process = dict(uid=uid, pid=pid,
                start_ticks=int((Path("/proc") / str(pid) / "stat").read_text().rpartition(")")[2].split()[19]),
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip())
            if self._process is not None and process != self._process:
                raise ValueError("different process on later connection")
            if self._presence is None:
                self._presence = self._stack.enter_context(ProcessPresence(process))
                self._process = process
            self._presence.verify()
        except Exception as error:
            raise PresenceError("owner_process_observation_rejected") from error
        yield
        self.verify()

    def verify(self) -> None:
        if not self._active or self._presence is None:
            raise PresenceError("owner_process_observation_rejected")
        self._presence.verify()

    def wait_for_exit(self, timeout_seconds: float) -> bool:
        if not self._active or self._presence is None:
            raise PresenceError('owner_process_exit_observation_rejected')
        return self._presence.wait_for_exit(timeout_seconds)

    def __exit__(self, *_args: Any) -> None:
        self._active = False
        self._stack.close()


class ParentProcessPresence:
    """Pin a child's current same-owner parent without claiming its SDK or manager.

    An admitted Matrix RPC identifies the child, whereas a service manager owns
    the admission parent. Keep both kernel tuples distinct. The caller still
    has to bind the parent to the selected manager scope and candidate.
    """

    def __init__(self, child: dict[str, Any]):
        self._stack = ExitStack()
        try:
            self.child = self._stack.enter_context(ProcessPresence(child))
            parent_id = self._parent_id()
            fields = (Path('/proc') / str(parent_id) / 'stat').read_text().rpartition(')')[2].split()
            self.parent = self._stack.enter_context(ProcessPresence(dict(
                uid=self.child.process['uid'], pid=parent_id, start_ticks=int(fields[19]),
                boot_id=self.child.process['boot_id'])))
            self.verify()
        except Exception as error:
            self._stack.close()
            raise PresenceError('owner_parent_process_unavailable') from error

    def _parent_id(self) -> int:
        fields = (Path('/proc') / str(self.child.process['pid']) / 'stat').read_text().rpartition(')')[2].split()
        return int(fields[1])

    @property
    def process(self) -> dict[str, Any]:
        return dict(self.parent.process)

    def verify(self) -> None:
        try:
            self.child.verify()
            self.parent.verify()
            if self._parent_id() != self.parent.process['pid']:
                raise ValueError('child was reparented')
            self.child.verify()
            self.parent.verify()
        except Exception as error:
            raise PresenceError('owner_parent_process_unavailable') from error

    def __enter__(self) -> ParentProcessPresence:
        try:
            self.verify()
        except Exception:
            self._stack.close()
            raise
        return self

    def __exit__(self, *_args: Any) -> None:
        self._stack.close()

