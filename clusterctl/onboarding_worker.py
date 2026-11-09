"""Bounded host worker; no HTTP privilege, model turns or Matrix inbox attention.

A backend reconciles only explicitly authorized onboarding jobs. A slow job has
its own slot and lock; HTTP request lifetime and stdout capture are irrelevant.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import fcntl
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

from . import being_seed
from .onboarding import Backend, JobStore, OnboardingError, refusal_diagnostic, CONVERSATION_JOB_SCHEMA


def completed_result(store: JobStore, backend: Backend, name: str, value: dict) -> tuple[int, dict]:
    """A terminal v2 command includes its own authorized entry, not another job."""
    if value.get('schema') != CONVERSATION_JOB_SCHEMA:
        return 0, value
    try:
        record = store._load(name)
        if (record['state'] != 'complete' or store.project(record) != value
                or not store.accepted(record['plan'], record['steps']['acceptance'].get('facts', {}))):
            raise OnboardingError('verification_failed')
        entry = getattr(backend, 'companion_entry', None)
        if entry is None:
            raise OnboardingError('conversation_selection_required')
        return 0, dict(value, entry=entry(record['plan']))
    except (OnboardingError, being_seed.SeedError, OSError, ValueError, TypeError, KeyError) as error:
        # Keep a completed native job intact when its current entry/config is
        # unavailable. The operator failed, not its preserved historical work.
        return 3, dict(state='attention-required', reason='verification_failed', job=value,
            diagnostic=refusal_diagnostic(error, stage='completed-entry'))


class ForegroundRun:
    """One bounded continuation record per original job; extensions retain it."""

    def __init__(self, store: JobStore, name: str, fingerprint: str):
        from .onboarding import private_directory
        self.root = private_directory(store.directory(name)/'foreground', create=True)
        self.path = self.root/'current.json'
        self.name, self.fingerprint = name, fingerprint

    def read(self):
        from .onboarding_custody import document
        value = document(self.path)
        if (value.get('schema') != 'cluster-onboarding-foreground-run/v1'
                or value.get('name') != self.name or value.get('plan_digest') != self.fingerprint
                or not isinstance(value.get('deadline_epoch'), (float, int))
                or not math.isfinite(value['deadline_epoch'])):
            raise OnboardingError('foreground_original_changed')
        return value

    def prepare(self, seconds: float, *, extend: float | None = None):
        with being_seed._locked(self.root):
            if self.path.exists():
                value = self.read()
                if extend is not None:
                    if value['phase'] == 'complete':
                        raise OnboardingError('foreground_already_complete')
                    # Expired idle time is not charged to this continuation.
                    # Keep the original start/deadline and effect identities.
                    value['deadline_epoch'] = max(time.time(), value['deadline_epoch'])+extend
                    value['extension_count'] += 1
                    value['added_seconds'] += extend
                    being_seed._write(self.path, value)
                return value
            if extend is not None:
                raise OnboardingError('foreground_original_required')
            now = time.time()
            value = dict(schema='cluster-onboarding-foreground-run/v1', name=self.name,
                plan_digest=self.fingerprint, phase='prepared', started_epoch=now,
                original_deadline_epoch=now+seconds, deadline_epoch=now+seconds,
                extension_count=0, added_seconds=0, child=None)
            being_seed._write(self.path, value)
            return value

    def remaining(self):
        return max(0, self.read()['deadline_epoch']-time.time())

    def update(self, **fields):
        with being_seed._locked(self.root):
            value = self.read()
            value.update(fields)
            being_seed._write(self.path, value)
            return value

    @staticmethod
    def process_start(pid):
        try:
            return Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19]
        except (OSError, IndexError):
            return None

    def child_started(self, pid):
        self.update(phase='running', child={'pid': pid, 'start': self.process_start(pid)})

    def child_alive(self):
        child = self.read().get('child')
        return bool(child and child.get('start') is not None
                    and self.process_start(child['pid']) == child['start'])

    def finish(self, result, lease):
        with being_seed._locked(self.root):
            value = self.read()
            if (result.get('reason') == 'foreground_deadline_expired'
                    and value['deadline_epoch'] > time.time()):
                # An extension raced the deadline's process teardown. Continue
                # the same job from its retained checkpoint, not a new plan.
                return False
            value.update(phase=result['state'], result=result, child=None)
            being_seed._write(self.path, value)
            # Release under this same state lock. A later extension either
            # reaches the still-running supervisor or can claim continuation;
            # it cannot be acknowledged into an already-closing lease.
            os.close(lease)
            return True

    def claim(self):
        descriptor = os.open(self.root/'supervisor.lock',
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except BlockingIOError:
            os.close(descriptor)
            return None


class Worker:
    def __init__(self, store: JobStore, backend: Callable[[], Backend], *, concurrency: int = 2,
                 publish: Callable[[dict], None] | None = None,
                 plans: Callable[[], list[dict]] | None = None,
                 homes: Callable[[dict], dict] | None = None,
                 runtime_health: Callable[[dict], dict] | None = None,
                 relocated: Callable[[str], dict | None] | None = None,
                 advance_group_admission: Callable[[str], object] | None = None):
        if type(concurrency) is not int or not 1 <= concurrency <= 8:
            raise OnboardingError("invalid_worker_concurrency")
        self.store, self.backend = store, backend
        self.concurrency = concurrency
        self.publish = publish
        self.plans = plans
        self.homes = homes
        self.runtime_health = runtime_health
        self.relocated = relocated
        self.advance_group_admission = advance_group_admission

    def _enqueue(self) -> None:
        if self.plans:
            for plan in self.plans():
                try:
                    self.store.submit(plan, self.backend)
                except (OnboardingError, being_seed.SeedError, OSError, ValueError):
                    continue

    def _tick(self, name: str) -> dict:
        try:
            # A physical move preserves completed enrollment history. Its new
            # placement owns maintenance; old home/health callbacks must not
            # reconcile a stopped source container from that historical job.
            retained = self.relocated(name) if self.relocated else None
            if retained is not None:
                if self.publish:
                    self.publish(retained)
                return retained
            reconcile = getattr(self.homes, 'reconcile_committed', None)
            if reconcile:
                reconcile(name)
            if self.advance_group_admission:
                self.advance_group_admission(name)
            # Resolve again inside the job lock: a concurrent receiving
            # selection can change runtime pins while the coordinator runs.
            result = self.store.tick(name, self.backend)
            if self.publish:
                self.publish(result)
            if self.runtime_health:
                self.runtime_health(result)
            if self.homes:
                self.homes(result)
            return result
        except (OnboardingError, being_seed.SeedError, OSError, ValueError, TypeError, KeyError) as error:
            # Do not print name/content/exception from an invalid private record.
            return {"state": "attention-required", "reason": "verification_failed",
                    "diagnostic": refusal_diagnostic(error, stage='host-preparation')}
        except Exception:
            return {"state": "attention-required", "reason": "backend_unavailable"}

    def once(self) -> list[dict]:
        self._enqueue()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            return list(pool.map(self._tick, self.store.names()))

    def until(self, name: str, *, deadline: float | Callable[[], float]) -> tuple[int, dict]:
        """Finish one existing job, never enqueue or reconcile another body.

        A known waiting/refusal is a terminal command outcome, not an excuse
        for an unbounded retry loop. The caller supplies a process deadline as
        well, since an individual host operation may block past this check.
        """
        while True:
            end = deadline() if callable(deadline) else deadline
            if time.monotonic() >= end:
                break
            value = self._tick(name)
            if value['state'] == 'complete':
                return completed_result(self.store, self.backend(), name, value)
            if value['state'] == 'attention-required':
                failure = self.store.directory(name)/'failure.json'
                if failure.exists():
                    detail = being_seed._read(failure)
                    stage = value.get('stage')
                    if (isinstance(stage, str)
                            and detail.get('plan_digest') == value.get('plan_digest')
                            and detail.get('stage') == stage
                            and detail.get('operation_id') == self.store.operation_id(value['plan_digest'], stage)):
                        value = {**value, 'diagnostic': detail}
                return 3, value
            if value['state'] == 'waiting':
                return 2, value
        return 2, {'state': 'attention-required', 'reason': 'foreground_deadline_expired'}

    def run(self, stop: threading.Event, *, interval: float = 5) -> None:
        if not 0.1 <= interval <= 60:
            raise OnboardingError("invalid_worker_interval")
        # A running job is never submitted twice by this process. Completed
        # slots are replenished immediately, even if another job remains slow.
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            pending: dict[str, concurrent.futures.Future] = {}
            scheduled: dict[str, float] = {}
            while not stop.is_set():
                self._enqueue()
                for name in list(pending):
                    if pending[name].done():
                        pending.pop(name).result()
                for name in sorted(self.store.names(), key=lambda name: scheduled.get(name, 0)):
                    if len(pending) >= self.concurrency:
                        break
                    if name not in pending:
                        pending[name] = pool.submit(self._tick, name)
                        scheduled[name] = time.monotonic()
                stop.wait(interval)


def supervise(argv: list[str], *, seconds: float,
              remaining: Callable[[], float] | None = None,
              started_child: Callable[[int], None] | None = None) -> tuple[int, dict]:
    """Bound only this foreground operator and its children, never services.

    A timed-out Incus/native request can already have taken effect. Do not
    cancel its journal or assert rollback: the next invocation must reconcile
    that same job/operation identity. No model, daemon or scheduler is launched
    by this supervisor itself.
    """
    started = time.monotonic()
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        child = subprocess.Popen(argv, stdout=output, stderr=errors, start_new_session=True)
        if started_child:
            try:
                started_child(child.pid)
            except Exception:
                child.terminate()
                child.wait(timeout=3)
                raise
        try:
            deadline = time.monotonic()+seconds
            while True:
                left = remaining() if remaining else deadline-time.monotonic()
                if left <= 0:
                    raise subprocess.TimeoutExpired(argv, seconds)
                try:
                    status = child.wait(timeout=min(1, left))
                    break
                except subprocess.TimeoutExpired:
                    # This is the same live process handle. An explicit time
                    # extension changes its deadline, never starts another one.
                    continue
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
            return 2, dict(schema='cluster-onboarding-foreground/v1',
                state='attention-required', reason='foreground_deadline_expired',
                elapsed_seconds=time.monotonic()-started,
                effect='inspect-original-job-and-operation; external effects may continue')
        output.seek(0)
        raw = output.read(65537)
        try:
            value = json.loads(raw)
            if (len(raw) > 65536 or not isinstance(value, dict)
                    or value.get('schema') != 'cluster-onboarding-foreground/v1'):
                raise ValueError
        except (ValueError, TypeError):
            value = dict(schema='cluster-onboarding-foreground/v1', state='attention-required',
                reason='foreground_outcome_unavailable', effect='inspect-original-job-and-operation')
            status = 3
        value['elapsed_seconds'] = time.monotonic()-started
        return status, value


def main(argv: list[str] | None = None) -> int:
    invocation_started = time.monotonic()
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument('--home-placements',type=Path)
    parser.add_argument('--until', help='Execute one exact owner-granted companion to a finite outcome')
    parser.add_argument('--timeout-seconds', type=float, default=600)
    parser.add_argument('--extend-seconds', type=float,
        help='Add time to the same retained job; continue it if its operator already expired')
    parser.add_argument('--foreground-child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if (not math.isfinite(args.timeout_seconds) or not 10 <= args.timeout_seconds <= 7200
                or args.until and (not being_seed.NAME.fullmatch(args.until) or args.once)
                or args.foreground_child and not args.until
                or args.extend_seconds is not None and (not args.until
                    or not math.isfinite(args.extend_seconds) or not 10 <= args.extend_seconds <= 7200)):
            raise OnboardingError('invalid_foreground_selection')
        if args.until and not args.foreground_child:
            from .onboarding_host import HostBackend, CurrentHostConfig
            config = CurrentHostConfig(args.config).current()
            selected = being_seed._read(config.grants/(args.until+'.json')).get('plan')
            if not isinstance(selected, dict) or selected.get('name') != args.until:
                raise OnboardingError('host_authorization_required')
            store = JobStore(config.jobs)
            original = store.submit(selected, HostBackend(config))
            control = ForegroundRun(store, args.until, original['plan_digest'])
            record = control.prepare(args.timeout_seconds, extend=args.extend_seconds)
            lease = control.claim()
            result: dict
            if lease is None:
                print(json.dumps(dict(schema='cluster-onboarding-foreground/v1',
                    state='extension-recorded' if args.extend_seconds is not None else 'running',
                    deadline_epoch=record['deadline_epoch'], effect='existing-supervisor; no duplicate launch',
                    elapsed_seconds=time.monotonic()-invocation_started)))
                return 0
            try:
                if control.child_alive():
                    result = dict(schema='cluster-onboarding-foreground/v1', state='running',
                        effect='original-worker-still-running; no duplicate launch')
                    status = 2
                elif original['state'] == 'complete':
                    status, completed = completed_result(store, HostBackend(config), args.until, original)
                    result = dict(schema='cluster-onboarding-foreground/v1', state=completed['state'], result=completed)
                    if control.finish(result, lease):
                        lease = None
                elif control.remaining() <= 0:
                    result = dict(schema='cluster-onboarding-foreground/v1', state='attention-required',
                        reason='foreground_deadline_expired', resume='use --extend-seconds with this same --until name',
                        effect='original-job-checkpoints-preserved')
                    status = 2
                else:
                    while True:
                        status, result = supervise([sys.executable, '-m', 'clusterctl.onboarding_worker',
                            *argv, '--foreground-child'], seconds=control.remaining(),
                            remaining=control.remaining, started_child=control.child_started)
                        if control.finish(result, lease):
                            lease = None
                            break
                result['elapsed_seconds'] = time.monotonic()-invocation_started
                print(json.dumps(result))
            finally:
                if lease is not None:
                    os.close(lease)
            return status
        from .onboarding_host import HostBackend, CurrentHostConfig

        selections = CurrentHostConfig(args.config)
        config = selections.current()
        from .onboarding_input import VerificationCache
        inputs = VerificationCache()
        homes = None
        def backend():
            return HostBackend(selections.current(), input_cache=inputs,
                home_access=homes.conversation_access if homes else None)
        from .onboarding_progress import Progress

        progress = Progress(config.progress, worker_uid=os.geteuid()) if config.progress else None
        store=JobStore(config.jobs)
        def relocated(name: str) -> dict | None:
            if name not in (selections.current().native_by_name or {}):
                return None
            record = store._load(name)
            owner = backend()
            if (record['state'] != 'complete' or owner.native_body(record['plan']) is None
                    or not owner.authorize(record['plan'], record['plan_digest'])):
                raise OnboardingError('native_receiving_completed_enrollment_required')
            return store.project(record)
        if args.home_placements:
            if progress is None:
                raise OnboardingError('trusted_home_progress_required')
            from .onboarding_homes import configure
            homes=configure(args.home_placements,progress=config.progress,store=store,
                            backend=backend,worker_uid=os.geteuid())
        from .onboarding_runtime_health import reconcile as enroll_health
        registry_path = os.environ.get('DAIMON_RUNTIME_HEALTH_REGISTRY')
        registry: Path | None = None
        if registry_path is not None:
            from .onboarding import private_directory
            if not Path(registry_path).is_absolute():
                raise OnboardingError('runtime_health_registry_required')
            registry = private_directory(Path(registry_path))
        worker = Worker(store, backend, concurrency=config.concurrency,
                        publish=progress.publish if progress else None,
                        plans=lambda: selections.current().approved_plans(), homes=homes,
                        runtime_health=lambda result: enroll_health(registry, store, backend(), result),
                        relocated=relocated,
                        advance_group_admission=(lambda name: backend().advance_group_admission(name))
                            if config.group_admission is not None else None)
        if args.until:
            # Read only this held grant. approved_plans() can also run the
            # ordinary intake; a foreground request must not enqueue peers.
            grant = being_seed._read(config.grants/(args.until+'.json'))
            selected = grant.get('plan')
            if not isinstance(selected, dict) or selected.get('name') != args.until:
                raise OnboardingError('host_authorization_required')
            store.submit(selected, backend)
            retained = ForegroundRun(store, args.until, store._load(args.until)['plan_digest'])
            status, result = worker.until(args.until,
                deadline=lambda: time.monotonic()+retained.remaining())
            print(json.dumps(dict(schema='cluster-onboarding-foreground/v1',
                result=result, state=result['state'],
                effect='original-job-and-operation-journals-retained')))
            return status
        if args.once:
            print(json.dumps(worker.once()))
            return 0
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        worker.run(stop)
        return 0
    except Exception:
        print(json.dumps(dict(schema='cluster-onboarding-foreground/v1', state='attention-required',
            reason='onboarding_worker_configuration_refused', effect='inspect-original-job-and-operation')
            if args.until else {"error": "onboarding_worker_configuration_refused"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
