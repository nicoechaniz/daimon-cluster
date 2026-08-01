"""steward_tools — the steward agent's safe window into the fleet.

Read path (issue #22):

- ``client`` — a minimal clusterd client pinned to ONE base URL at
  construction (CLUSTERD_URL env or the compiled-in default) and ONE
  token file; urllib only, GET only, 5s timeout, cross-origin redirects
  refused. There is no arbitrary-URL parameter anywhere: only the four
  fixed read routes exist.
- ``tools`` — the four steward read tools. Each returns a
  steward-tool-result/v1 dict and NEVER raises a transport failure to
  the agent: unreachable daemon or an HTTP error becomes
  ``ok=False`` with an explicit ``degraded`` reason.

Mutation path (issue #23):

- ``mutations`` — the gated two-phase flow. ``propose_<op>`` builds a
  steward-mutation-plan/v1 (no mutation ever happens at propose time);
  ``confirm_plan`` is the ONLY execution path and enforces digest
  integrity, single use, 120s expiry and typed-name confirmation for
  the destructive class — locally, before clusterd re-enforces its own
  rules. No free-form operation, URL, or assent-text parameter exists.

The read path (client.py, tools.py) is read-only by construction: no
shell, no mutation verbs. The mutation path (mutations.py) is gated by
construction: nothing executes without an explicit, unexpired,
single-use confirm call carrying the human-turn marker.
"""

from .client import (
    ClusterdClient,
    ClusterdError,
    ClusterdHTTPError,
    ClusterdUnreachable,
    CrossOriginRedirect,
)
from .mutations import (
    MutationClient,
    MutationPlan,
    confirm_plan,
    propose_destroy,
    propose_park,
    propose_restart,
    propose_snapshot,
    propose_start,
    propose_stop,
    propose_wake,
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
    "MutationClient",
    "MutationPlan",
    "SCHEMA",
    "cluster_backups",
    "cluster_health",
    "cluster_list",
    "cluster_logs",
    "confirm_plan",
    "propose_destroy",
    "propose_park",
    "propose_restart",
    "propose_snapshot",
    "propose_start",
    "propose_stop",
    "propose_wake",
]
