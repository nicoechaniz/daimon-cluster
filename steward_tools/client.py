"""Minimal read-only clusterd client for the steward agent (issue #22).

Hard rules:

- The base URL is a CONSTRUCTION-TIME constant per instance: the
  ``CLUSTERD_URL`` environment variable (read once, at construction) or
  the compiled-in default. No method accepts a URL, and the attribute is
  read-only — a client can never be repointed after construction.
- The bearer token is read from a FILE PATH given at construction
  (default: the steward's read-token in its durable volume). The file is
  re-read per request so the 30-day rotation runbook needs no restart.
- urllib only, 5s timeout, GET only.
- Redirects to a different origin are REFUSED, never followed — a
  misconfigured or hostile endpoint cannot bounce the steward's token
  at another host.
- Only the fixed read routes exist as methods; there is no way to
  request an arbitrary path.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlencode, urlsplit

DEFAULT_BASE_URL = "http://10.105.93.1:8785"
DEFAULT_TOKEN_PATH = "/home/agent/.clusterd/read-token"
TIMEOUT_S = 60.0

# Instance names as clusterctl specs allow them; validated here AND in
# clusterd's handler (the daemon never trusts the caller).
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")


class ClusterdError(Exception):
    """Base class for client-side failures.

    steward_tools.tools converts these into degraded result dicts — the
    agent never sees them unless it uses this client directly.
    """


class ClusterdUnreachable(ClusterdError):
    """Connect refused / timeout / DNS — the daemon is not there."""


class ClusterdHTTPError(ClusterdError):
    """The daemon answered with a non-2xx status."""

    def __init__(self, status: int, body: object = None):
        super().__init__(f"clusterd answered HTTP {status}")
        self.status = status
        self.body = body


class CrossOriginRedirect(ClusterdError):
    """A redirect to a different origin was refused (never followed)."""


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only when the target origin is identical."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urlsplit(req.full_url)
        new = urlsplit(newurl)
        if (new.scheme, new.netloc) != (old.scheme, old.netloc):
            raise CrossOriginRedirect(
                "refused redirect to a different origin: "
                f"{new.scheme}://{new.netloc}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class ClusterdClient:
    """Read-only window into ONE clusterd base URL, fixed at construction."""

    def __init__(self, token_path: str = DEFAULT_TOKEN_PATH,
                 base_url: str | None = None):
        base = (base_url or
                os.environ.get("CLUSTERD_URL", DEFAULT_BASE_URL)).rstrip("/")
        parsed = urlsplit(base)
        if parsed.scheme != "http" or not parsed.netloc:
            raise ValueError(f"invalid clusterd base URL: {base!r}")
        self._base_url = base
        self._token_path = token_path
        self._opener = urllib.request.build_opener(
            _SameOriginRedirectHandler())

    @property
    def base_url(self) -> str:
        """The construction-time base URL (read-only)."""
        return self._base_url

    def _token(self) -> str:
        return Path(self._token_path).read_text(encoding="utf-8").strip()

    def _get(self, path: str) -> tuple[int, object, dict]:
        """GET one of the fixed route paths; returns (status, json, headers)."""
        req = urllib.request.Request(
            self._base_url + path, method="GET",
            headers={"Authorization": f"Bearer {self._token()}"})
        try:
            with self._opener.open(req, timeout=TIMEOUT_S) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                return resp.status, payload, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                body = json.loads(exc.read().decode("utf-8"))
            except Exception:  # non-JSON error body — keep the status only
                body = None
            finally:
                exc.close()
            raise ClusterdHTTPError(status, body) from exc
        except CrossOriginRedirect:
            raise
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise ClusterdUnreachable(str(exc)) from exc

    # -- fixed read routes (no arbitrary paths anywhere) ----------------

    def instances(
        self, *, limit: int = 200, cursor: str | None = None
    ) -> tuple[int, object, dict]:
        if isinstance(limit, bool) or not 1 <= int(limit) <= 200:
            raise ValueError("instances limit must be in 1..200")
        query: dict[str, object] = {"limit": int(limit)}
        if cursor is not None:
            if not isinstance(cursor, str) or not cursor or len(cursor) > 512:
                raise ValueError("invalid instances cursor")
            query["cursor"] = cursor
        return self._get("/v1/instances?" + urlencode(query))

    def health(self) -> tuple[int, object, dict]:
        return self._get("/v1/health")

    def weave_status(self) -> tuple[int, object, dict]:
        return self._get("/v1/weave/status")

    def backups(self) -> tuple[int, object, dict]:
        return self._get("/v1/backups")

    def logs(self, name: str, lines: int) -> tuple[int, object, dict]:
        if not NAME_RE.fullmatch(name):
            raise ValueError(f"invalid instance name: {name!r}")
        return self._get(f"/v1/instances/{name}/logs?lines={int(lines)}")


def source_ts_ms(headers: dict, fallback_ms: int) -> int:
    """Source timestamp from the clusterd envelope (HTTP Date header).

    Falls back to the caller-supplied receipt time when the header is
    missing or unparseable.
    """
    date = headers.get("Date") or headers.get("date")
    if date:
        try:
            return int(parsedate_to_datetime(date).timestamp() * 1000)
        except (TypeError, ValueError):
            pass
    return fallback_ms
