#!/usr/bin/env python3
"""Atomically exchange two directory names with Linux renameat2."""

from __future__ import annotations

import argparse
import ctypes
import os
from pathlib import Path


AT_FDCWD = -100
RENAME_EXCHANGE = 2


def exchange(left: Path, right: Path) -> None:
    """Exchange two existing non-symlink directories or leave both unchanged."""
    for path in (left, right):
        if not path.is_dir() or path.is_symlink():
            raise ValueError(f"unsafe_directory:{path}")

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError("renameat2_unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD,
        os.fsencode(left),
        AT_FDCWD,
        os.fsencode(right),
        RENAME_EXCHANGE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), f"{left} <-> {right}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    args = parser.parse_args()
    exchange(args.left, args.right)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
