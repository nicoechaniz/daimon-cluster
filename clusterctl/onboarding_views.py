"""Serve the native owner surface and signed peer app under one runtime lock.

Readiness is published only after every native daemon has bound its listeners.
Any view failure stops the complete body. Controllers retain their independent
catalog authentication; applications retain the canonical relationship graph.
"""
from __future__ import annotations

import os
import select
import threading
import time
from typing import Any

from .onboarding import OnboardingError


def serve_views(views: list[Any], stop: threading.Event, *, ready_descriptor: int | None = None) -> None:
    from daimon_matrix import daemon
    listeners = [view.messaging_http.listen for view in views if view.messaging_http]
    listeners.extend(view.peer_listen for view in views if view.peer_dispatcher and view.peer_listen)
    if not views or len(listeners) != len(set(listeners)) or len({view.socket_path for view in views}) != len(views):
        raise OnboardingError('onboarding_runtime_listener_collision')
    for view in views:
        view.egress.validate_registry(daemon._enabled_egress_paths(view))
    pipes = [os.pipe() for _ in views]
    identities = {writer: (os.fstat(writer).st_dev, os.fstat(writer).st_ino) for _, writer in pipes}
    errors: list[BaseException] = []

    def run(view: Any, writer: int) -> None:
        try:
            daemon.serve_forever(view, stop=stop, ready_descriptor=writer)
        except BaseException as error:
            errors.append(error)
        finally:
            # Native serving owns/closes its readiness fd after binding. Close
            # only the original pipe if failure occurred before that transfer.
            try:
                info = os.fstat(writer)
                if (info.st_dev, info.st_ino) == identities[writer]:
                    os.close(writer)
            except OSError:
                pass
            stop.set()

    threads = [threading.Thread(target=run, args=(view, writer), name='onboarding-native-view')
               for view, (_, writer) in zip(views, pipes, strict=True)]
    try:
        for thread in threads:
            thread.start()
        waiting = {reader for reader, _ in pipes}
        deadline = time.monotonic() + 5
        while waiting and not stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select(list(waiting), [], [], min(0.1, remaining))
            for reader in readable:
                if os.read(reader, 16) != b'READY\n':
                    raise OnboardingError('onboarding_runtime_not_ready')
                waiting.remove(reader)
        if waiting or stop.is_set():
            raise OnboardingError('onboarding_runtime_not_ready')
        if ready_descriptor is not None:
            os.write(ready_descriptor, b'READY\n')
            os.close(ready_descriptor)
        while not stop.wait(0.25):
            pass
    finally:
        stop.set()
        for thread in threads:
            if thread.ident is not None:
                thread.join()
        for reader, writer in pipes:
            os.close(reader)
            try:
                info = os.fstat(writer)
                if (info.st_dev, info.st_ino) == identities[writer]:
                    os.close(writer)
            except OSError:
                pass
    if errors:
        raise OnboardingError('onboarding_runtime_view_failed') from errors[0]
