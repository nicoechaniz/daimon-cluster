"""clusterd prepare/confirm binding (issue #18, design §2).

Destructive-class mutations (destroy; update in a later milestone) are
two-step over HTTP:

1. First POST (no ``X-Confirm-Token`` header) -> 409 with a
   ``confirmation/v1`` challenge::

       {schema, token, operation, target, actor,
        action_digest, created_ms, ttl_s}

   ``action_digest`` is the sha256 of the canonical JSON of
   ``{operation, target, actor, args}`` — it binds the confirmation to
   EXACTLY that action. The challenge is persisted under
   ``<state_dir>/confirmations/``.

2. Re-POST with header ``X-Confirm-Token: <token>`` -> the challenge is
   validated: it must exist, be unused, be unexpired, and its digest
   must match the request's operation+target+actor+args EXACTLY.
   Altered args, wrong actor, wrong target all fail with 409. On
   success the challenge is consumed (single-use: replay -> 409).

Non-destructive mutations (start/stop/restart) never require a
challenge; ``X-Confirm: none`` executes them directly. ``X-Confirm:
none`` does NOT bypass the destructive class — confirmation is
mandatory there.

Unattended steward denial (v1 mechanism for "mutation attempts from
unattended steward ticks are denied"): tokens whose actor matches
``steward@*`` must carry ``X-Attended: true`` on mutations, a human
presence marker; missing -> 403 ``unattended-steward-denied``. The real
presence flow lands in M5 — see docs/design/clusterd.md.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from pathlib import Path

from .auth import now_ms

CONFIRMATION_SCHEMA = "confirmation/v1"
CONFIRMATION_TOKEN_PREFIX = "cfm_"
DEFAULT_TTL_S = 900

STWARD_ACTOR_PREFIX = "steward@"
ATTENDED_HEADER_VALUE = "true"

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class ConfirmationError(Exception):
    """Raised when a confirmation token fails validation.

    ``reason`` is a stable machine-readable string for the 409 body.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def action_digest(operation: str, target: str, actor: str,
                  args: dict | None = None) -> str:
    """sha256 of the canonical JSON of the bound action."""
    canonical = json.dumps(
        {"operation": operation, "target": target,
         "actor": actor, "args": args or {}},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def confirmations_dir(state_dir: str | Path) -> Path:
    return Path(state_dir) / "confirmations"


def issue_challenge(state_dir: str | Path, *, operation: str, target: str,
                    actor: str, args: dict | None = None,
                    ttl_s: int = DEFAULT_TTL_S) -> dict:
    """Persist and return a ``confirmation/v1`` challenge."""
    token = CONFIRMATION_TOKEN_PREFIX + uuid.uuid4().hex
    challenge = {
        "schema": CONFIRMATION_SCHEMA,
        "token": token,
        "operation": operation,
        "target": target,
        "actor": actor,
        "action_digest": action_digest(operation, target, actor, args),
        "created_ms": now_ms(),
        "ttl_s": ttl_s,
        "used": False,
    }
    d = confirmations_dir(state_dir)
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / f"{token}.tmp"
    tmp.write_text(json.dumps(challenge, indent=2, sort_keys=True),
                   encoding="utf-8")
    os.replace(tmp, d / f"{token}.json")
    return challenge


def _challenge_path(state_dir: str | Path, token: str) -> Path:
    if not token or not _TOKEN_RE.match(token):
        raise ConfirmationError("unknown-confirmation")
    return confirmations_dir(state_dir) / f"{token}.json"


def consume_challenge(state_dir: str | Path, token: str, *,
                      operation: str, target: str, actor: str,
                      args: dict | None = None,
                      now: int | None = None) -> dict:
    """Validate and consume (single-use) a confirmation challenge.

    Raises ``ConfirmationError`` with a stable reason on any failure:
    ``unknown-confirmation``, ``confirmation-already-used``,
    ``confirmation-expired``, ``confirmation-digest-mismatch`` (covers
    altered args, wrong actor and wrong target — the digest binds all).
    """
    path = _challenge_path(state_dir, token)
    if not path.is_file():
        raise ConfirmationError("unknown-confirmation")
    try:
        challenge = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        raise ConfirmationError("unknown-confirmation")
    if challenge.get("used"):
        raise ConfirmationError("confirmation-already-used")
    created = challenge.get("created_ms", 0)
    ttl_s = challenge.get("ttl_s", DEFAULT_TTL_S)
    if (now if now is not None else now_ms()) > created + ttl_s * 1000:
        raise ConfirmationError("confirmation-expired")
    expected = action_digest(operation, target, actor, args)
    if not _digests_equal(challenge.get("action_digest", ""), expected):
        raise ConfirmationError("confirmation-digest-mismatch")
    challenge["used"] = True
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(challenge, indent=2, sort_keys=True),
                   encoding="utf-8")
    os.replace(tmp, path)
    return challenge


def _digests_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(str(a), str(b))


def steward_requires_attendance(actor: str) -> bool:
    """v1 unattended-steward guard: actor ``steward@*`` must prove a
    human marker (X-Attended: true) on mutations. Real presence flow: M5."""
    return actor.startswith(STWARD_ACTOR_PREFIX)
