"""clusterd auth (issue #18): scoped bearer tokens, hashed at rest.

Token store: ``<state_dir>/auth/tokens.json`` holding ``auth-token/v1``
records::

    {schema, token_id, sha256_of_token, actor, scopes, owner,
     created_ms, expires_ms, revoked}

The RAW token (``dcd_<uuid4hex>``) is shown exactly once at creation and
NEVER stored — only its sha256. Resolution is a constant-time digest
compare (``hmac.compare_digest``) against every record.

Revocation without restart: ``TokenStore`` re-reads tokens.json whenever
the file's mtime changes, so ``--token-revoke`` takes effect on the very
next request.

Default-deny: every route except GET /v1/health requires a valid token
(enforced in ``clusterd.server``). Scopes name exact operation classes. Owner:
if a token's ``owner`` is not ``"*"``, requests targeting ``{name}``
require the instance spec's ``created_by`` to equal the owner.

Rate limit: per-token sliding window, 60 mutations/minute -> 429.

Security logging: denials append ``audit-event/v1`` lines via
``clusterctl.audit.append_event`` with actor + request_id + reason —
NEVER any token material (not even a prefix).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from pathlib import Path

import yaml

TOKEN_SCHEMA = "auth-token/v1"
TOKEN_PREFIX = "dcd_"
VALID_SCOPES = (
    "metadata:read",
    "fleet:read",
    "dashboard:read",
    "dashboard:prepare",
    "dashboard:confirm",
    "lifecycle:write",
    "backup:write",
    "restore:write",
    "destroy:write",
)

MUTATION_RATE_LIMIT = 60          # mutations ...
MUTATION_RATE_WINDOW_S = 60       # ... per minute, per token


def now_ms() -> int:
    return int(time.time() * 1000)


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# store management (CLI-side)
# --------------------------------------------------------------------------

def auth_dir(state_dir: str | Path) -> Path:
    return Path(state_dir) / "auth"


def store_path(state_dir: str | Path) -> Path:
    return auth_dir(state_dir) / "tokens.json"


def _load_tokens(state_dir: str | Path) -> list[dict]:
    path = store_path(state_dir)
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    tokens = raw.get("tokens", [])
    return tokens if isinstance(tokens, list) else []


def _save_tokens(state_dir: str | Path, tokens: list[dict]) -> None:
    d = auth_dir(state_dir)
    d.mkdir(parents=True, exist_ok=True)
    tmp = store_path(state_dir).with_name("tokens.json.tmp")
    tmp.write_text(json.dumps({"tokens": tokens}, indent=2, sort_keys=True),
                   encoding="utf-8")
    os.replace(tmp, store_path(state_dir))


def create_token(state_dir: str | Path, *, actor: str,
                 scopes: list[str], owner: str,
                 ttl_days: int) -> tuple[dict, str]:
    """Create a token; returns (stored_record, raw_token).

    The raw token is returned ONCE — only its sha256 is persisted.
    """
    unknown = set(scopes) - set(VALID_SCOPES)
    if unknown:
        raise ValueError(f"unknown scopes: {sorted(unknown)}")
    if not actor:
        raise ValueError("actor is required")
    if not owner:
        raise ValueError("owner is required ('*' for any daimon)")
    created = now_ms()
    raw_token = TOKEN_PREFIX + uuid.uuid4().hex
    record = {
        "schema": TOKEN_SCHEMA,
        "token_id": str(uuid.uuid4()),
        "sha256_of_token": hash_token(raw_token),
        "actor": actor,
        "scopes": sorted(set(scopes)),
        "owner": owner,
        "created_ms": created,
        "expires_ms": created + int(ttl_days * 86_400_000),
        "revoked": False,
    }
    tokens = _load_tokens(state_dir)
    tokens.append(record)
    _save_tokens(state_dir, tokens)
    return record, raw_token


def revoke_token(state_dir: str | Path, token_id: str) -> dict | None:
    """Revoke by token_id; effective on the very next request (the
    server's TokenStore reloads on mtime change). Returns the record."""
    tokens = _load_tokens(state_dir)
    found = None
    for rec in tokens:
        if rec.get("token_id") == token_id:
            rec["revoked"] = True
            found = rec
    if found is not None:
        _save_tokens(state_dir, tokens)
    return found


def list_tokens(state_dir: str | Path) -> list[dict]:
    """Metadata-only listing: NO hashes, NO token material."""
    return [
        {
            "token_id": rec.get("token_id"),
            "actor": rec.get("actor"),
            "scopes": rec.get("scopes"),
            "owner": rec.get("owner"),
            "created_ms": rec.get("created_ms"),
            "expires_ms": rec.get("expires_ms"),
            "revoked": rec.get("revoked", False),
        }
        for rec in _load_tokens(state_dir)
    ]


# --------------------------------------------------------------------------
# request-side resolution
# --------------------------------------------------------------------------

class TokenStore:
    """Server-side resolver with mtime-checked reload.

    Tokens are re-read from disk whenever tokens.json changes, so
    revocation and new tokens take effect WITHOUT a server restart
    (issue #18 acceptance criterion).
    """

    def __init__(self, state_dir: str | Path):
        self.state_dir = str(state_dir)
        self._mtime_ns: int | None = None
        self._tokens: list[dict] = []

    def _maybe_reload(self) -> None:
        path = store_path(self.state_dir)
        try:
            mtime = path.stat().st_mtime_ns
        except OSError:
            mtime = None
        if mtime != self._mtime_ns:
            self._tokens = _load_tokens(self.state_dir)
            self._mtime_ns = mtime

    def resolve(self, raw_token: str | None) -> dict | None:
        """Return the token record for ``raw_token`` or None.

        Constant-time digest compare against every record (no early
        exit) to avoid timing oracles on token prefixes.
        """
        if not raw_token:
            return None
        self._maybe_reload()
        digest = hash_token(raw_token)
        found = None
        for rec in self._tokens:
            if hmac.compare_digest(str(rec.get("sha256_of_token", "")), digest):
                found = rec
        return found


def authenticate(store: TokenStore, raw_token: str | None,
                 now: int | None = None) -> tuple[dict | None, str | None]:
    """Resolve + validate. Returns (record, None) or (None, reason)."""
    if not raw_token:
        return None, "missing-token"
    record = store.resolve(raw_token)
    if record is None:
        return None, "unknown-token"
    if record.get("revoked"):
        return None, "revoked-token"
    expires = record.get("expires_ms")
    if expires is not None and (now if now is not None else now_ms()) > expires:
        return None, "expired-token"
    return record, None


def has_scope(record: dict, required: str) -> bool:
    return required in (record.get("scopes") or [])


def instance_owner(state_dir: str | Path, name: str) -> str | None:
    """Read the declared spec's ``created_by`` (None if no spec)."""
    spec_path = Path(state_dir) / "instances" / f"{name}.yaml"
    if not spec_path.is_file():
        return None
    try:
        raw = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(raw, dict):
        return None
    owner = raw.get("created_by")
    return owner if isinstance(owner, str) and owner else None


# --------------------------------------------------------------------------
# rate limiting (per-token sliding window, in-memory)
# --------------------------------------------------------------------------

class RateLimiter:
    """Simple per-key sliding-window limiter (in-memory dict)."""

    def __init__(self, limit: int = MUTATION_RATE_LIMIT,
                 window_s: float = MUTATION_RATE_WINDOW_S):
        self.limit = limit
        self.window_s = window_s
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        hits = [t for t in self._hits.get(key, []) if now - t < self.window_s]
        if len(hits) >= self.limit:
            self._hits[key] = hits
            return False
        hits.append(now)
        self._hits[key] = hits
        return True
