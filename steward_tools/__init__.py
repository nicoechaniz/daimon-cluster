"""steward_tools — the steward agent's safe, read-only window into the
fleet (issue #22).

Two modules:

- ``client`` — a minimal clusterd client pinned to ONE base URL at
  construction (CLUSTERD_URL env or the compiled-in default) and ONE
  token file; urllib only, GET only, 5s timeout, cross-origin redirects
  refused. There is no arbitrary-URL parameter anywhere: only the four
  fixed read routes exist.
- ``tools`` — the four steward tools. Each returns a
  steward-tool-result/v1 dict and NEVER raises a transport failure to
  the agent: unreachable daemon or an HTTP error becomes
  ``ok=False`` with an explicit ``degraded`` reason.

Everything here is read-only by construction: no shell, no mutation
verbs, no mutation-scoped token use.
"""

from .client import (
    ClusterdClient,
    ClusterdError,
    ClusterdHTTPError,
    ClusterdUnreachable,
    CrossOriginRedirect,
)
from .tools import (
    SCHEMA,
    cluster_backups,
    cluster_health,
    cluster_list,
    cluster_logs,
)

__all__ = [
    "ClusterdClient",
    "ClusterdError",
    "ClusterdHTTPError",
    "ClusterdUnreachable",
    "CrossOriginRedirect",
    "SCHEMA",
    "cluster_backups",
    "cluster_health",
    "cluster_list",
    "cluster_logs",
]
