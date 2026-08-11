#!/usr/bin/env python3
"""Wait boundedly for private service bind addresses to exist on this host."""

from __future__ import annotations

import argparse
import errno
import socket
import sys
import time
from collections.abc import Sequence


class BindWaitError(RuntimeError):
    """A configured local bind did not become usable within the gate."""


def _bindable(address: str) -> bool:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    endpoint: tuple[object, ...]
    endpoint = (address, 0, 0, 0) if family == socket.AF_INET6 else (address, 0)
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(endpoint)
        except OSError as exception:
            if exception.errno == errno.EADDRNOTAVAIL:
                return False
            raise BindWaitError("bind_address_probe_failed") from exception
    return True


def wait_for_addresses(
    addresses: Sequence[str],
    *,
    timeout_seconds: float,
    interval_seconds: float,
) -> None:
    if (
        not addresses
        or len(set(addresses)) != len(addresses)
        or not 0 < timeout_seconds <= 120
        or not 0 < interval_seconds <= 5
    ):
        raise BindWaitError("invalid_bind_wait_configuration")
    pending = set(addresses)
    deadline = time.monotonic() + timeout_seconds
    while pending:
        pending = {address for address in pending if not _bindable(address)}
        if not pending:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BindWaitError("bind_address_unavailable")
        time.sleep(min(interval_seconds, remaining))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--address", action="append", default=[])
    result.add_argument("--timeout", type=float, default=30.0)
    result.add_argument("--interval", type=float, default=0.25)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        wait_for_addresses(
            args.address,
            timeout_seconds=args.timeout,
            interval_seconds=args.interval,
        )
        return 0
    except BindWaitError as exception:
        print(str(exception), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
