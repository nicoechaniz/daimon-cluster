"""Optional owner-local graphical browser, with fresh per-environment state.

The host supplies code artifacts and their hashes. No browser profile, cookies,
agent identity or credentials are copied. Launch is a human-requested process.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

PACKAGES = ("chromium", "xvfb", "xauth", "openbox", "fonts-dejavu-core")


def _regular(path: Path) -> bytes:
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("browser_code_symlink_refused")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 128 * 1024**2:
            raise ValueError("bounded_regular_browser_code_required")
        return stream.read()


def extension_digest(root: Path) -> tuple[str, list[tuple[str, bytes]]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("browser_extension_directory_required")
    rows: list[tuple[str, bytes]] = []
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("browser_extension_symlink_refused")
        if path.is_dir():
            continue
        raw = _regular(path)
        total += len(raw)
        if total > 128 * 1024**2 or len(rows) >= 10000:
            raise ValueError("browser_extension_too_large")
        rows.append((path.relative_to(root).as_posix(), raw))
    if "manifest.json" not in {name for name, _ in rows}:
        raise ValueError("browser_extension_manifest_required")
    inventory = [[name, hashlib.sha256(raw).hexdigest()] for name, raw in rows]
    digest = hashlib.sha256(json.dumps(inventory, separators=(",", ":")).encode()).hexdigest()
    return digest, rows


def prepare(daemon: Path, daemon_sha256: str, extension: Path, extension_sha256: str,
            home: Path, *, apply: bool) -> dict:
    raw = _regular(daemon.absolute())
    actual = hashlib.sha256(raw).hexdigest()
    digest, files = extension_digest(extension.absolute())
    if actual != daemon_sha256 or digest != extension_sha256:
        raise ValueError("browser_code_hash_mismatch")
    for program in ("chromium", "Xvfb", "xvfb-run", "xauth"):
        if shutil.which(program) is None:
            raise ValueError("browser_system_packages_required")
    root = home.absolute() / ".kimi-webbridge"
    if any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError("browser_home_symlink_refused")
    if home.stat().st_uid != os.geteuid():
        raise ValueError("browser_home_must_belong_to_invoking_user")
    result = {"schema": "cluster-browser-code/v1", "daemon_sha256": actual,
              "extension_sha256": digest, "fresh_profile": True, "applied": apply}
    if not apply:
        return result
    marker = root / "cluster-code.json"
    if root.exists():
        if marker.is_file() and json.loads(_regular(marker)) == result:
            if hashlib.sha256(_regular(root / "bin/kimi-webbridge")).hexdigest() != actual:
                raise ValueError("installed_browser_code_changed")
            if extension_digest(root / "extension")[0] != digest:
                raise ValueError("installed_browser_code_changed")
            return result
        raise ValueError("existing_browser_state_preserved")
    root.mkdir(mode=0o700)
    (root / "bin").mkdir(mode=0o700)
    for path, contents, mode in [(root / "bin/kimi-webbridge", raw, 0o700),
                                  *[(root / "extension" / name, data, 0o600) for name, data in files]]:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(result, stream)
        stream.flush()
        os.fsync(stream.fileno())
    return result


def status() -> dict:
    try:
        with urllib.request.urlopen("http://127.0.0.1:10086/status", timeout=3) as response:
            value = json.load(response)
        return {"running": value.get("running") is True,
                "extension_connected": value.get("extension_connected") is True,
                "version": str(value.get("version", ""))[:40]}
    except (OSError, ValueError, urllib.error.URLError):
        return {"running": False, "extension_connected": False, "version": ""}


def run(home: Path) -> int:
    if os.geteuid() == 0:
        raise ValueError("browser_requires_dedicated_unprivileged_user")
    root = home.absolute() / ".kimi-webbridge"
    marker = json.loads(_regular(root / "cluster-code.json"))
    prepare(root / "bin/kimi-webbridge", marker["daemon_sha256"], root / "extension",
            marker["extension_sha256"], home, apply=True)
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", 10086)) == 0:
            raise ValueError("existing_webbridge_process_preserved")
    environment = dict(os.environ, HOME=str(home.absolute()))
    (root / "chromium-profile").mkdir(mode=0o700, exist_ok=True)
    children = []
    def interrupt(_signal, _frame):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, interrupt)
    log_fd = os.open(root / "cluster-launch.log", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        with os.fdopen(log_fd, "ab") as log:
            commands = [
                [str(root / "bin/kimi-webbridge"), "run", "--addr", "127.0.0.1:10086"],
                ["xvfb-run", "-a", "-s", "-screen 0 1440x1000x24 -nolisten tcp", "chromium",
                 "--user-data-dir=" + str(root / "chromium-profile"),
                 "--load-extension=" + str(root / "extension"), "--no-first-run",
                 "--no-default-browser-check", "--disable-dev-shm-usage", "about:blank"],
            ]
            for command in commands:
                children.append(subprocess.Popen(command, env=environment, stdout=log,
                                                 stderr=log, start_new_session=True))
            for _ in range(30):
                if any(child.poll() is not None for child in children):
                    raise ValueError("browser_process_exited")
                if status()["extension_connected"]:
                    print(json.dumps({"browser": "accepted", **status()}), flush=True)
                    break
                time.sleep(1)
            else:
                raise ValueError("browser_extension_not_connected")
            children[-1].wait()
    finally:
        for child in children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
        signal.signal(signal.SIGTERM, previous)
    return 0


def main(argv=None) -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--daemon", type=Path, required=True)
    prep.add_argument("--daemon-sha256", required=True)
    prep.add_argument("--extension", type=Path, required=True)
    prep.add_argument("--extension-sha256", required=True)
    prep.add_argument("--apply", action="store_true")
    sub.add_parser("status")
    sub.add_parser("run")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            print(json.dumps(prepare(args.daemon, args.daemon_sha256, args.extension,
                                     args.extension_sha256, Path.home(), apply=args.apply)))
        elif args.command == "status":
            print(json.dumps(status()))
        else:
            return run(Path.home())
        return 0
    except (ValueError, OSError, KeyError, TypeError):
        print(json.dumps({"browser": "attention-required"}))
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
