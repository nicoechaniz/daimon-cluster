"""Explicit existing-owner enrollment and kernel process observations on Linux."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import select
from typing import Any
import uuid

from .embodiments import Registry

PROCESS_FIELDS = {"uid", "pid", "start_ticks", "boot_id"}


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

    def __enter__(self) -> ProcessPresence:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()


def enroll(state_root: Path, profile: dict[str, Any]) -> dict[str, Any]:
    """Explicitly mutate only the native registry after physical admission."""
    from .owner_body_reader import PROCESS_PROFILE_SCHEMA, validate_profile, _path

    admitted = validate_profile(profile)
    if admitted["schema"] != PROCESS_PROFILE_SCHEMA:
        raise PresenceError("owner_process_profile_required")
    state_root = _path(str(state_root))
    with ProcessPresence(admitted["process"]) as presence:
        record = Registry(state_root).adopt_running(**admitted["origin"])
        # A lost acknowledgement never rewinds accepted registry history.
        # Explicit exact replay rechecks physical presence and adds no history.
        presence.verify()
        return record


def main(argv: list[str] | None = None) -> int:
    from .owner_body_reader import load_profile
    from .matrix_host import _matrix_api

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        _matrix_api()
        enroll(args.state_root, load_profile(args.profile))
        print('{"schema":"dm.cluster-owner-enrollment-result/v1","status":"accepted"}')
        return 0
    except Exception:
        print('{"schema":"dm.cluster-owner-enrollment-result/v1","status":"refused"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
