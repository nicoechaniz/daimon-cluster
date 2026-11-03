"""Shared lease supervision for an already-admitted native runtime process.

Reuse the maintained rebirth watchdog and renewal behavior for receiving guests.
It owns neither Matrix custody nor the authority database; callers supply the
explicitly enrolled holder client and the concrete child process.
"""
from __future__ import annotations

import subprocess
import threading
import time
from typing import Any

from .admission import AdmissionClient, AdmissionError

_SUPERVISORS: dict[int, AdmissionSupervisor] = {}
_SUPERVISORS_LOCK = threading.Lock()

_RENEWAL_CODES = {
    'admission authority is unavailable': 'authority-unavailable',
    'admission round-trip deadline expired': 'roundtrip-deadline',
    'admission response is malformed': 'response-malformed',
    'admission response binding mismatch': 'response-binding-mismatch',
    'admission response signature is invalid': 'response-signature-invalid',
    'admission session does not own the lease': 'session-not-owner',
    'resource fence expected position is stale': 'fence-position-stale',
    'cannot renew expired resource fence': 'lease-expired',
}
_RENEWAL_CAUSES = frozenset({
    'none', 'timeout', 'connection-refused', 'connection-reset',
    'connection-aborted', 'broken-pipe', 'os-error', 'other',
})


def renewal_failure_diagnostic(value: Any) -> dict[str, Any] | None:
    """Accept only the closed, non-private failure frame for journal output."""
    if (not isinstance(value, dict)
            or set(value) != {'schema', 'code', 'cause', 'errno', 'elapsed_ms'}
            or value['schema'] != 'cluster-admission-renewal-failure/v1'
            or not isinstance(value['code'], str)
            or value['code'] not in {*_RENEWAL_CODES.values(), 'other-admission-refusal'}
            or not isinstance(value['cause'], str) or value['cause'] not in _RENEWAL_CAUSES
            or (value['errno'] is not None and (type(value['errno']) is not int
                or not 0 < value['errno'] <= 4095))
            or type(value['elapsed_ms']) is not int or not 0 <= value['elapsed_ms'] <= 1_000_000):
        return None
    return dict(value)


def _renewal_failure(error: AdmissionError, elapsed_s: float) -> dict[str, Any]:
    """Bounded local evidence, never an authority-supplied exception message."""
    cause = error.__cause__
    kinds: dict[type[BaseException], str] = {
        TimeoutError: 'timeout', ConnectionRefusedError: 'connection-refused',
        ConnectionResetError: 'connection-reset', ConnectionAbortedError: 'connection-aborted',
        BrokenPipeError: 'broken-pipe', OSError: 'os-error',
    }
    errno = getattr(cause, 'errno', None)
    return {
        'schema': 'cluster-admission-renewal-failure/v1',
        'code': _RENEWAL_CODES.get(str(error), 'other-admission-refusal'),
        'cause': 'none' if cause is None else kinds.get(type(cause), 'other'),
        'errno': errno if type(errno) is int and 0 < errno <= 4095 else None,
        'elapsed_ms': max(0, min(1_000_000, round(elapsed_s * 1000))),
    }

def _terminate_without_consuming_output(process: subprocess.Popen[bytes]) -> None:
    """Revoke execution immediately while leaving pipes to the owning caller."""

    if process.poll() is None:
        process.kill()
    process.wait(timeout=2)



class AdmissionSupervisor:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        client: AdmissionClient,
        receipt: dict[str, Any],
        ttl_s: int,
        *,
        lease_started_monotonic: float,
    ):
        self.process = process
        self.client = client
        self.receipt = receipt
        self.ttl_s = ttl_s
        self._lease_deadline = lease_started_monotonic + ttl_s
        self._condition = threading.Condition()
        self._client_lock = threading.Lock()
        self._finished = threading.Event()
        self._shutdown_requested = threading.Event()
        self._shutdown_signal_sent = threading.Event()
        self._termination_reason: str | None = None
        self._renewal_failure: dict[str, Any] | None = None
        self.thread = threading.Thread(
            target=self._run,
            name=f"rebirth-admission-{process.pid}",
            # A launcher must not exit between runtime termination and the
            # final release attempt.  Admission I/O is already bounded by the
            # client timeout, so keeping this thread non-daemon closes that
            # shutdown window without weakening the independent watchdog.
            daemon=False,
        )
        self.watchdog = threading.Thread(
            target=self._watchdog,
            name=f"rebirth-admission-hard-deadline-{process.pid}",
            daemon=True,
        )

    def start(self) -> None:
        with _SUPERVISORS_LOCK:
            _SUPERVISORS[self.process.pid] = self
        self.watchdog.start()
        self.thread.start()

    def _hard_kill_at(self) -> float:
        return self._lease_deadline - self.ttl_s / 4

    @property
    def termination_reason(self) -> str | None:
        with self._condition:
            return self._termination_reason

    @property
    def renewal_failure(self) -> dict[str, Any] | None:
        with self._condition:
            return None if self._renewal_failure is None else dict(self._renewal_failure)

    @property
    def shutdown_requested(self) -> bool:
        return self._shutdown_requested.is_set()

    @property
    def shutdown_signal_sent(self) -> bool:
        return self._shutdown_signal_sent.is_set()

    def _record_termination(self, reason: str) -> None:
        with self._condition:
            if self._termination_reason is None:
                self._termination_reason = reason
            self._condition.notify_all()

    def request_shutdown(self) -> None:
        self._shutdown_requested.set()
        with self._condition:
            self._condition.notify_all()

    def force_stop(self, reason: str) -> None:
        self._record_termination(reason)
        _terminate_without_consuming_output(self.process)

    def _watchdog(self) -> None:
        """Kill independently of renew I/O or either host's wall clock."""

        while not self._finished.is_set() and self.process.poll() is None:
            with self._condition:
                remaining = self._hard_kill_at() - time.monotonic()
                if remaining > 0:
                    self._condition.wait(timeout=min(remaining, 0.25))
                    continue
            self.force_stop("lease-hard-deadline")
            return

    def verify_current(self, *, minimum_remaining_s: float) -> dict[str, Any] | None:
        with self._client_lock:
            current = self.client.current()
        with self._condition:
            enough_budget = (
                self._lease_deadline - time.monotonic() > minimum_remaining_s
            )
        if (
            not enough_budget
            or current is None
            or current.get("session_id") != self.client.session_id
        ):
            return None
        return current

    def inventory(self) -> dict[str, Any]:
        """Explicit bounded discovery using the existing admitted launch session."""
        with self._client_lock:
            return self.client.inventory()

    def _run(self) -> None:
        try:
            while self.process.poll() is None:
                if (
                    self._shutdown_requested.is_set()
                    and not self._shutdown_signal_sent.is_set()
                ):
                    # The supervisor, not the caller, owns the transition from
                    # admitted execution to shutdown.  If the remaining local
                    # budget is narrow, first obtain a confirmed renewal; a
                    # lost renewal response still fails closed below.
                    with self._condition:
                        renew_before_stop = (
                            self._lease_deadline - time.monotonic()
                            <= self.ttl_s / 2
                        )
                    if not renew_before_stop:
                        self.process.terminate()
                        self._shutdown_signal_sent.set()
                        continue
                with self._condition:
                    renew_at = self._lease_deadline - self.ttl_s * 3 / 4
                interval = max(
                    0.01,
                    min(0.25, renew_at - time.monotonic()),
                )
                try:
                    self.process.wait(timeout=interval)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() < renew_at:
                    continue
                try:
                    renew_started = time.monotonic()
                    with self._client_lock:
                        receipt = self.client.renew(ttl_s=self.ttl_s)
                except AdmissionError as error:
                    with self._condition:
                        self._renewal_failure = _renewal_failure(
                            error, time.monotonic() - renew_started)
                    self.force_stop("admission-renew-failed")
                    return
                with self._condition:
                    self.receipt = receipt
                    # The remote authority can only create this TTL after the
                    # local request began, so request-start + TTL is a safe,
                    # conservative deadline independent of wall-clock skew.
                    self._lease_deadline = renew_started + self.ttl_s
                    if time.monotonic() >= self._hard_kill_at():
                        self.force_stop("admission-renew-deadline")
                        return
                    self._condition.notify_all()
        finally:
            # Once the runtime is no longer executing, always attempt to
            # publish the release.  In particular, a renew may have committed
            # remotely even when its response is lost while the runtime is
            # shutting down.  The authority's exact-position checks make this
            # retry safe; omitting it leaves a stale current lease until a
            # later contender advances the fence.
            if self.process.poll() is not None:
                try:
                    with self._client_lock:
                        self.client.release()
                except AdmissionError:
                    pass
            if self.termination_reason is None:
                self._record_termination(
                    "graceful-shutdown"
                    if self._shutdown_signal_sent.is_set()
                    and self.process.returncode == 0
                    else "runtime-exited"
                )
            self._finished.set()
            with self._condition:
                self._condition.notify_all()
            with _SUPERVISORS_LOCK:
                _SUPERVISORS.pop(self.process.pid, None)
