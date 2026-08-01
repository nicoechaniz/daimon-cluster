"""Read-only three-source reconciliation (issue #19, design §4).

Cross-checks the audit trail's declared mutations against the spec files
and incus reality, and reports discrepancies in a ``findings`` array
(empty = clean). STRICTLY read-only: nothing here writes to the state
dir or mutates incus.

Sources:

- **audit** — every ``audit-event/v1`` line with ``result == "ok"``
  (creates declare intent; lifecycle events give the per-target
  transition timeline).
- **specs** — ``<state_dir>/instances/<name>.yaml`` (instance-spec/v1).
- **incus** — ``adapter.list_instances()`` + ``adapter.list_volumes()``.

Finding kinds:

- ``untracked_container`` (warning): present in incus but the audit log
  has NO successful ``create`` for it — the fleet changed outside the
  audited control plane.
- ``untracked_volume`` (warning): a custom volume ``<name>-home`` with
  no spec for ``<name>``.
- ``impossible_transition`` (error): a successful lifecycle event the
  audit trail itself cannot explain (e.g. ``stop`` ok for an instance
  the audit never created).
- ``double_start`` (info): two successful ``start`` events for one
  target without an intervening ``stop`` — suspicious but possibly a
  replay artifact, so informational only.

The report also carries a ``drift_summary`` (from the declared-vs-actual
inventory reconcile): names classified ``missing`` / ``drifted`` /
``undeclared``.
"""

from __future__ import annotations

from . import audit, inventory
from .adapters import Adapter
from .config import Config

REPORT_SCHEMA = "clusterctl-reconcile-report/v1"

_CREATE_ACTIONS = {"create", "provision"}  # actions that declare a target
_LIFECYCLE_ACTIONS = {"start", "stop", "restart", "delete"}


def _finding(kind: str, severity: str, target: str, message: str) -> dict:
    return {"kind": kind, "severity": severity, "target": target,
            "message": message}


def run_reconcile(cfg: Config, adapter: Adapter) -> dict:
    """Build the reconciliation report (read-only; exit-code free)."""
    specs = inventory.load_specs(cfg.instances_dir)
    events = audit.read_events(cfg.state_dir)
    ok_events = [e for e in events if e.get("result") == "ok"]

    created_in_audit = {
        e.get("target") for e in ok_events
        if e.get("action") in _CREATE_ACTIONS and e.get("target")
    }

    actual = adapter.list_instances()
    actual_names = {inst["name"] for inst in actual}
    try:
        volumes = adapter.list_volumes()
    except Exception:
        volumes = []  # adapter cannot enumerate volumes — treat as unknown

    findings: list[dict] = []

    # (a) untracked containers: in incus, never in audit creates.
    for name in sorted(actual_names - created_in_audit):
        findings.append(_finding(
            "untracked_container", "warning", name,
            f"instance {name!r} exists in incus but the audit log has no "
            f"successful create for it"))

    # (b) untracked volumes: custom volume <name>-home without a spec.
    for vol in volumes:
        if vol.endswith("-home") and vol[:-len("-home")] not in specs:
            findings.append(_finding(
                "untracked_volume", "warning", vol,
                f"custom volume {vol!r} has no matching instance spec"))
        elif not vol.endswith("-home"):
            findings.append(_finding(
                "untracked_volume", "warning", vol,
                f"custom volume {vol!r} is not a managed <name>-home volume"))

    # (c) impossible / suspicious transitions in the audit timeline.
    timeline: dict[str, list[dict]] = {}
    for e in ok_events:
        if e.get("action") in _LIFECYCLE_ACTIONS and e.get("target"):
            timeline.setdefault(e["target"], []).append(e)
    for target in sorted(timeline):
        target_events = timeline[target]
        if target not in created_in_audit:
            findings.append(_finding(
                "impossible_transition", "error", target,
                f"audit shows {target_events[0].get('action')!r} ok for "
                f"{target!r} which the audit log never created"))
        last_start_seq: int | None = None
        stopped_since = True
        for e in sorted(target_events,
                        key=lambda ev: (ev.get("seq") is None, ev.get("seq") or 0)):
            action = e.get("action")
            if action == "start":
                if not stopped_since:
                    findings.append(_finding(
                        "double_start", "info", target,
                        f"two successful starts for {target!r} without an "
                        f"intervening stop"))
                stopped_since = False
                last_start_seq = e.get("seq")
            elif action in ("stop", "delete"):
                stopped_since = True

    # (d) drift summary from the declared-vs-actual inventory reconcile.
    records = inventory.reconcile(specs, adapter, cfg.host_id)
    drift_summary = {
        "missing": sorted(r["name"] for r in records if r["state"] == "missing"),
        "drifted": sorted(r["name"] for r in records if r["state"] == "drifted"),
        "undeclared": sorted(r["name"] for r in records if r["state"] == "undeclared"),
    }

    return {
        "schema": REPORT_SCHEMA,
        "host_id": cfg.host_id,
        "ts_ms": audit.now_ms(),
        "counts": {
            "audit_events": len(events),
            "specs": len(specs),
            "incus_instances": len(actual_names),
            "custom_volumes": len(volumes),
        },
        "drift_summary": drift_summary,
        "findings": findings,
    }


def render_human(report: dict) -> str:
    """Plain-text rendering of the report (one line per finding)."""
    lines = [
        f"reconcile ({report['schema']}) host={report['host_id']}",
        f"  audit_events={report['counts']['audit_events']} "
        f"specs={report['counts']['specs']} "
        f"incus={report['counts']['incus_instances']} "
        f"volumes={report['counts']['custom_volumes']}",
        f"  drift: missing={report['drift_summary']['missing']} "
        f"drifted={report['drift_summary']['drifted']} "
        f"undeclared={report['drift_summary']['undeclared']}",
    ]
    if not report["findings"]:
        lines.append("  findings: none (clean)")
    else:
        lines.append(f"  findings: {len(report['findings'])}")
        for f in report["findings"]:
            lines.append(f"    [{f['severity']}] {f['kind']} "
                         f"{f['target']}: {f['message']}")
    return "\n".join(lines)
