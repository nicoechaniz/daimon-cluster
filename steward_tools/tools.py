"""The steward's four read-only tools (issue #22).

Each tool is a thin function over ONE fixed clusterd read route. Every
result is a steward-tool-result/v1 dict::

    {schema, tool, ok, data, stale, degraded, source_ts_ms}

Design rules:

- A tool NEVER raises a transport failure to the agent: an unreachable
  daemon, an HTTP error, or a refused redirect becomes ``ok=False``
  with an explicit ``degraded`` reason and ``data=None`` (unknown state
  is data, not an exception). Invalid INPUT (a malformed instance name)
  is a programming error and raises ValueError before any I/O.
- ``stale`` flags data past its freshness contract (backups: newest
  manifest older than 26h — RPO is 6h + margin).
- ``degraded`` lists partial-failure reasons (which health subsystem is
  down, which backup manifest is unreadable, ...).
- ``source_ts_ms`` comes from the clusterd envelope (HTTP Date header),
  so the agent can tell how old the answer was AT THE SOURCE, not when
  it arrived.
"""

from __future__ import annotations

import re
import time

from .client import (
    NAME_RE,
    ClusterdClient,
    ClusterdError,
    ClusterdHTTPError,
    ClusterdUnreachable,
    source_ts_ms,
)

SCHEMA = "steward-tool-result/v1"

LOGS_DEFAULT_LINES = 50
LOGS_MAX_LINES = 200
BACKUP_STALE_MS = 26 * 3600 * 1000  # RPO 6h + margin


def _now_ms() -> int:
    return int(time.time() * 1000)


def _result(tool: str, ok: bool, data: object, stale: bool,
            degraded: list, ts_ms: int) -> dict:
    return {
        "schema": SCHEMA,
        "tool": tool,
        "ok": ok,
        "data": data,
        "stale": bool(stale),
        "degraded": list(degraded),
        "source_ts_ms": int(ts_ms),
    }


def _client(client: ClusterdClient | None) -> ClusterdClient:
    return client if client is not None else ClusterdClient()


def _call(tool: str, fn):
    """Run one client call.

    Returns ``(payload, headers, None)`` on success, or
    ``(None, None, failure_result)`` — every transport failure becomes
    an explicit degraded steward-tool-result, never an exception.
    """
    try:
        _status, payload, headers = fn()
        return payload, headers, None
    except ClusterdUnreachable:
        return None, None, _result(
            tool, False, None, False, ["clusterd-unreachable"], _now_ms())
    except ClusterdHTTPError as exc:
        return None, None, _result(
            tool, False, None, False, [f"clusterd-http-{exc.status}"],
            _now_ms())
    except ClusterdError as exc:
        return None, None, _result(
            tool, False, None, False,
            [f"clusterd-client-error:{type(exc).__name__}"], _now_ms())


def cluster_list(client: ClusterdClient | None = None) -> dict:
    """GET /v1/instances — per-daimon name/state/image/uptime."""
    tool = "cluster_list"
    payload, headers, err = _call(tool, lambda: _client(client).instances())
    if err is not None:
        return err
    records = payload if isinstance(payload, list) else []
    data = [{
        "name": rec.get("name"),
        "state": rec.get("state"),
        "image_version": rec.get("image_version"),
        "uptime_s": rec.get("uptime_s"),
    } for rec in records]
    return _result(tool, True, data, False, [],
                   source_ts_ms(headers, _now_ms()))


def cluster_health(client: ClusterdClient | None = None) -> dict:
    """GET /v1/health — status + audit_chain_ok + mirror_state.

    When the daemon reports anything but "ok", ``degraded`` names the
    failing subsystems so the agent knows WHAT is unknown/broken.
    """
    tool = "cluster_health"
    payload, headers, err = _call(tool, lambda: _client(client).health())
    if err is not None:
        return err
    degraded = []
    if not payload.get("clusterctl_reachable", False):
        degraded.append("clusterctl")
    if not payload.get("audit_chain_ok", False):
        degraded.append("audit-chain")
    if payload.get("mirror_state") == "failing":
        degraded.append("mirror")
    ok = payload.get("status") == "ok"
    return _result(tool, ok, payload, False, degraded,
                   source_ts_ms(headers, _now_ms()))


def cluster_backups(client: ClusterdClient | None = None) -> dict:
    """GET /v1/backups — per-daimon latest manifest summary + age_ms.

    ``stale=True`` when the NEWEST manifest across the fleet is older
    than 26h (RPO is 6h + margin) or no manifest exists at all.
    """
    tool = "cluster_backups"
    payload, headers, err = _call(tool, lambda: _client(client).backups())
    if err is not None:
        return err
    now = _now_ms()
    entries, degraded = [], []
    newest_ms = None
    records = payload if isinstance(payload, list) else []
    for entry in records:
        manifest = entry.get("manifest")
        manifest = manifest if isinstance(manifest, dict) else {}
        created_ms = manifest.get("created_ms")
        if not isinstance(created_ms, int):
            degraded.append(f"manifest-unreadable:{entry.get('name')}")
        else:
            newest_ms = created_ms if newest_ms is None \
                else max(newest_ms, created_ms)
        entries.append({
            "name": entry.get("name"),
            "snap_name": manifest.get("snap_name"),
            "created_ms": created_ms,
            "verified_readable": manifest.get("verified_readable"),
            "retention_class": manifest.get("retention_class"),
            "age_ms": (now - created_ms)
                      if isinstance(created_ms, int) else None,
        })
    if newest_ms is None:
        degraded.append("no-backup-manifests")
    stale = newest_ms is None or (now - newest_ms) > BACKUP_STALE_MS
    return _result(tool, True, entries, stale, degraded,
                   source_ts_ms(headers, now))


def cluster_logs(name: str, lines: int = LOGS_DEFAULT_LINES,
                 client: ClusterdClient | None = None) -> dict:
    """GET /v1/instances/{name}/logs?lines=N — bounded, redacted logs.

    ``name`` is validated against ^[a-z0-9][a-z0-9-]{0,30}$ (ValueError
    on anything else — before any I/O); ``lines`` is clamped to 1..200.
    Redaction itself is applied by clusterctl on the host before any
    bytes cross the wire.
    """
    if not NAME_RE.fullmatch(name):
        raise ValueError(f"invalid instance name: {name!r}")
    tool = "cluster_logs"
    n = max(1, min(int(lines), LOGS_MAX_LINES))
    payload, headers, err = _call(
        tool, lambda: _client(client).logs(name, n))
    if err is not None:
        return err
    return _result(tool, True, payload, False, [],
                   source_ts_ms(headers, _now_ms()))
