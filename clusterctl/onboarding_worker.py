"""Bounded host worker; no HTTP privilege, model turns or Matrix inbox attention.

A backend reconciles only explicitly authorized onboarding jobs. A slow job has
its own slot and lock; HTTP request lifetime and stdout capture are irrelevant.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import signal
import threading
import time
from pathlib import Path
from typing import Callable

from . import being_seed
from .onboarding import Backend, JobStore, OnboardingError


class Worker:
    def __init__(self, store: JobStore, backend: Callable[[], Backend], *, concurrency: int = 2,
                 publish: Callable[[dict], None] | None = None,
                 plans: Callable[[], list[dict]] | None = None):
        if type(concurrency) is not int or not 1 <= concurrency <= 8:
            raise OnboardingError("invalid_worker_concurrency")
        self.store, self.backend = store, backend
        self.concurrency = concurrency
        self.publish = publish
        self.plans = plans

    def _enqueue(self) -> None:
        if self.plans:
            for plan in self.plans():
                try:
                    self.store.submit(plan, self.backend())
                except (OnboardingError, being_seed.SeedError, OSError, ValueError):
                    continue

    def _tick(self, name: str) -> dict:
        try:
            result = self.store.tick(name, self.backend())
            if self.publish:
                self.publish(result)
            return result
        except (OnboardingError, being_seed.SeedError, OSError, ValueError, TypeError, KeyError):
            # Do not print name/content/exception from an invalid private record.
            return {"state": "attention-required", "reason": "verification_failed"}
        except Exception:
            return {"state": "attention-required", "reason": "backend_unavailable"}

    def once(self) -> list[dict]:
        self._enqueue()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            return list(pool.map(self._tick, self.store.names()))

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    try:
        from .onboarding_host import HostBackend, HostConfig

        config = HostConfig.load(args.config)
        from .onboarding_input import VerificationCache
        inputs = VerificationCache()
        from .onboarding_progress import Progress

        progress = Progress(config.progress, worker_uid=os.geteuid()) if config.progress else None
        worker = Worker(JobStore(config.jobs), lambda: HostBackend(config, input_cache=inputs), concurrency=config.concurrency,
                        publish=progress.publish if progress else None, plans=config.approved_plans)
        if args.once:
            print(json.dumps(worker.once()))
            return 0
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        worker.run(stop)
        return 0
    except Exception:
        print(json.dumps({"error": "onboarding_worker_configuration_refused"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
