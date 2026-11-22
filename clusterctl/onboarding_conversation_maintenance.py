"""Finite transport for the existing App web/voice maintenance operator.

No new lock policy: the installed App script checks its live health header and
holds its own kernel lock through exec. Helpers exit on stdin close or timeout.
"""

from contextlib import contextmanager
import json
import os
import selectors
import shlex
import signal
import subprocess
import time
import uuid

from .onboarding import OnboardingError

BOOTSTRAP = r"""
import hashlib,json,os,sys
from pathlib import Path
value=json.loads(sys.stdin.buffer.readline(16385))
script=Path(value['script'])
if script.is_symlink() or not script.is_file() or script.stat().st_size>65536:
 raise ValueError('Selected maintenance source unavailable')
if hashlib.sha256(script.read_bytes()).hexdigest()!=value['script_sha256']:
 raise ValueError('Selected maintenance source changed')
hold="import json,sys\nnonce=sys.argv[1]\nprint(json.dumps({'held':nonce}),flush=True)\nwhile True:\n line=sys.stdin.buffer.readline(64)\n if not line or not line.startswith(b'check:'):break\n print(json.dumps({'held':nonce,'check':line[6:].decode().strip()}),flush=True)"
os.execv(value['python'],[value['python'],'-B',str(script),'--config',value['config'],
 '--owner-uid',str(value['owner_uid']),'--health-url',value['health_url'],
 '--seconds','300','--',value['python'],'-B','-I','-c',hold,value['nonce']])
"""


def configuration(targets):
    if (
        not isinstance(targets, list)
        or not 1 <= len(targets) <= 16
        or len(json.dumps(targets).encode()) > 65536
    ):
        raise OnboardingError("conversation_route_maintenance_required")
    names = set()
    upstreams = set()
    for row in targets:
        if (
            not isinstance(row, dict)
            or set(row)
            != {
                "name",
                "upstream",
                "command",
                "python",
                "script",
                "script_sha256",
                "config",
                "owner_uid",
                "health_url",
            }
            or not isinstance(row["name"], str)
            or not 1 <= len(row["name"]) <= 80
            or row["name"] in names
            or type(row["owner_uid"]) is not int
            or row["owner_uid"] < 0
            or not isinstance(row["upstream"], str)
            or not 1 <= len(row["upstream"]) <= 256
            or row["upstream"] in upstreams
            or not isinstance(row["command"], list)
            or not 1 <= len(row["command"]) <= 64
            or any(
                not isinstance(a, str) or not a or len(a) > 2048 for a in row["command"]
            )
            or sum(
                a.count("{program}") + a.count("{shell_program}")
                for a in row["command"]
            )
            != 1
            or any(
                not isinstance(row[k], str)
                or not row[k].startswith("/")
                or ".." in row[k].split("/")
                for k in ("python", "script", "config")
            )
            or not row["script"].endswith("/scripts/interaction_web_maintenance.py")
            or not isinstance(row["script_sha256"], str)
            or len(row["script_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in row["script_sha256"])
            or not isinstance(row["health_url"], str)
            or len(row["health_url"]) > 512
        ):
            raise OnboardingError("conversation_route_maintenance_required")
        names.add(row["name"])
        upstreams.add(row["upstream"])
    return targets


def _frame(process, seconds):
    raw = bytearray()
    deadline = time.monotonic() + seconds
    with selectors.DefaultSelector() as poll:
        poll.register(process.stdout, selectors.EVENT_READ)
        while b"\n" not in raw and len(raw) <= 4096:
            if time.monotonic() >= deadline:
                raise OnboardingError("conversation_route_maintenance_unavailable")
            if not poll.select(0.2):
                continue
            chunk = os.read(process.stdout.fileno(), 4097 - len(raw))
            if not chunk:
                code = process.wait(timeout=1)
                raise OnboardingError(
                    "conversation_route_voice_active"
                    if code == 75
                    else "conversation_route_maintenance_unavailable"
                )
            raw.extend(chunk)
    try:
        return json.loads(raw) if len(raw) <= 4096 else None
    except ValueError:
        return None


@contextmanager
def guard(targets):
    targets = configuration(targets)
    held = []
    try:
        for row in targets:
            nonce = uuid.uuid4().hex
            argv = [
                a.replace("{program}", BOOTSTRAP).replace(
                    "{shell_program}", shlex.quote(BOOTSTRAP)
                )
                for a in row["command"]
            ]
            started = time.monotonic()
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            held.append((process, started, nonce))
            value = {
                k: row[k]
                for k in (
                    "python",
                    "script",
                    "script_sha256",
                    "config",
                    "owner_uid",
                    "health_url",
                )
            }
            try:
                process.stdin.write(
                    json.dumps(dict(value, nonce=nonce)).encode() + b"\n"
                )
                process.stdin.flush()
            except OSError:
                raise OnboardingError(
                    "conversation_route_maintenance_unavailable"
                ) from None
            if _frame(process, 8) != {"held": nonce}:
                raise OnboardingError("conversation_route_maintenance_unavailable")

        def check():
            if any(
                p.poll() is not None or time.monotonic() - start > 210
                for p, start, _ in held
            ):
                raise OnboardingError("conversation_route_maintenance_lost")
            for process, _, nonce in held:
                probe = uuid.uuid4().hex
                try:
                    process.stdin.write(("check:" + probe + "\n").encode())
                    process.stdin.flush()
                except OSError:
                    raise OnboardingError(
                        "conversation_route_maintenance_lost"
                    ) from None
                if _frame(process, 3) != {"held": nonce, "check": probe}:
                    raise OnboardingError("conversation_route_maintenance_lost")

        check()
        yield check
    finally:
        for process, _, _ in reversed(held):
            try:
                if process.poll() is None:
                    process.stdin.write(b"release\n")
                    process.stdin.flush()
            except (OSError, ValueError):
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            process.stdin.close()
            process.stdout.close()
