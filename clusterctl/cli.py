"""clusterctl command-line interface.

Read commands (side-effect free): ``list``, ``status <name>``,
``config-show`` — all with ``[--json]``.

Lifecycle mutations (issue #11): ``create``, ``start``, ``stop``,
``restart``, ``logs``, ``destroy-plan``. Mutations write to the state
dir (spec, idempotency store, locks, audit log) and apply admission,
idempotency, locking, and audit contracts — see
``clusterctl.lifecycle``.

Exit codes:
    0  success
    2  usage error (argparse)
    3  not found (unknown/undeclared instance name)
    6  conflict (duplicate name, idempotency-key reuse, lock held)
    10 internal error (config/spec/incus failures, bugs)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from . import audit, lifecycle
from .adapters import IncusAdapter, IncusError
from .config import Config, ConfigError, load_config
from .inventory import SpecError, find_record, load_specs, reconcile

EXIT_OK = 0
EXIT_NOT_FOUND = 3
EXIT_CONFLICT = 6
EXIT_INTERNAL = 10

DEFAULT_CONFIG_PATH = Path("configs/clusterctl.yaml")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clusterctl",
        description="daimon-cluster fleet state CLI",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="path to clusterctl-config/v1 YAML (default: %(default)s)",
    )
    parser.add_argument(
        "--state-dir",
        default=None,
        help="override state_dir from the config (used by tests)",
    )
    parser.add_argument(
        "--actor",
        default="clusterctl-cli",
        help="actor recorded in audit events (default: %(default)s)",
    )
    parser.add_argument(
        "--request-id",
        default=None,
        help="caller request id recorded in audit events (clusterd "
             "X-Request-Id passthrough, issue #19)",
    )
    parser.add_argument(
        "--action-digest",
        default=None,
        help="confirmation action digest recorded in audit events "
             "(clusterd cluster-confirmation/v1 passthrough, issue #19)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list all instances with reconciled state")
    p_list.add_argument("--json", action="store_true", help="emit JSON array of instance-status/v1 records")

    p_status = sub.add_parser("status", help="show one instance's reconciled status")
    p_status.add_argument("name", help="instance name")
    p_status.add_argument("--json", action="store_true", help="emit a single instance-status/v1 record")

    p_cfg = sub.add_parser("config-show", help="show the resolved clusterctl config")
    p_cfg.add_argument("--json", action="store_true", help="emit config as JSON")

    p_rec = sub.add_parser(
        "reconcile",
        help="cross-check audit trail vs specs vs incus (read-only, issue #19)")
    p_rec.add_argument("--json", action="store_true",
                       help="emit the clusterctl-reconcile-report/v1 JSON")

    def _mutation(name, help_text):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("name", help="instance name")
        p.add_argument("--idempotency-key", default=None,
                       help="uuid; retry with the same key replays the cached result")
        p.add_argument("--json", action="store_true", help="emit JSON")
        return p

    p_create = sub.add_parser("create", help="declare and create a new instance (stopped)")
    p_create.add_argument("name", help="instance name")
    p_create.add_argument("--species", required=True, help="species tag recorded in the spec")
    p_create.add_argument("--image", default=lifecycle.DEFAULT_IMAGE,
                          help="image alias (default: %(default)s)")
    p_create.add_argument("--idempotency-key", required=True,
                          help="uuid; retry with the same key replays the cached result")
    p_create.add_argument("--json", action="store_true", help="emit JSON")

    _mutation("start", "start a declared instance")
    p_stop = _mutation("stop", "stop a declared instance")
    p_stop.add_argument("--timeout", type=int, default=lifecycle.STOP_DEFAULT_TIMEOUT,
                        help="graceful stop timeout in seconds (default: %(default)s)")
    _mutation("restart", "restart a declared (running) instance")

    p_logs = sub.add_parser("logs", help="fetch instance logs (bounded, secrets redacted)")
    p_logs.add_argument("name", help="instance name")
    p_logs.add_argument("--lines", type=int, default=lifecycle.LOGS_DEFAULT_LINES,
                        help=f"max lines (default: %(default)s, max {lifecycle.LOGS_MAX_LINES})")
    p_logs.add_argument("--json", action="store_true", help="emit JSON")

    p_dp = sub.add_parser("destroy-plan", help="print the destroy plan for an instance (plan only)")
    p_dp.add_argument("name", help="instance name")
    p_dp.add_argument("--delete-volumes", action="store_true",
                      help="include volume deletion in the plan")
    p_dp.add_argument("--json", action="store_true", help="emit JSON")

    p_prov = sub.add_parser("provision", help="governed provisioning (issue #12)")
    prov_sub = p_prov.add_subparsers(dest="provision_command", required=True)
    p_prep = prov_sub.add_parser(
        "prepare",
        help="create container+volume+identity, emit confirmation token, then HALT")
    p_prep.add_argument("name", help="instance (daimon) name")
    p_prep.add_argument("--species", required=True, help="species tag recorded in the spec")
    p_prep.add_argument("--requested-by", required=True, dest="requested_by",
                        help="human requesting the provisioning (ADR D8)")
    p_prep.add_argument("--sponsor", required=True,
                        help="human sponsor; must differ from --requested-by")
    p_prep.add_argument("--seed-manifest", default=None, dest="seed_manifest",
                        help="optional seed-manifest/v1 YAML to stage")
    p_prep.add_argument("--idempotency-key", required=True,
                        help="uuid; retry with the same key replays the cached result")
    p_prep.add_argument("--json", action="store_true", help="emit JSON")
    p_conf = prov_sub.add_parser(
        "confirm",
        help="consume a provision-activate token (directory activation is governance's act)")
    p_conf.add_argument("--token", required=True, help="token emitted by provision prepare")
    p_conf.add_argument("--json", action="store_true", help="emit JSON")

    p_snap = sub.add_parser("snapshot", help="quiesced snapshots (issue #14)")
    snap_sub = p_snap.add_subparsers(dest="snapshot_command", required=True)
    p_sc = snap_sub.add_parser(
        "create",
        help="quiesce (park+checkpoint), capture, verify, then write backup manifest")
    p_sc.add_argument("name", help="instance (daimon) name")
    p_sc.add_argument("--timeout-s", type=int, default=30, dest="timeout_s",
                      help="quiesce timeout in seconds (default: %(default)s)")
    p_sc.add_argument("--idempotency-key", required=True,
                      help="uuid; retry with the same key replays the cached result")
    p_sc.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def _resolve_config(args) -> Config:
    cfg = load_config(args.config)
    if args.state_dir is not None:
        cfg = Config(
            host_id=cfg.host_id,
            incus_project=cfg.incus_project,
            managed_prefix=cfg.managed_prefix,
            profile=cfg.profile,
            state_dir=args.state_dir,
        )
    return cfg


def _adapter_for(cfg: Config):
    return IncusAdapter(
        profile=cfg.profile,
        managed_prefix=cfg.managed_prefix,
        project=cfg.incus_project,
    )


def _render_table(records: list[dict]) -> str:
    headers = ["NAME", "SPECIES", "STATE", "IMAGE_VERSION", "CPU", "MEM_MIB", "DISK_GIB", "UPTIME_S"]

    def cell(value) -> str:
        return "-" if value is None else str(value)

    rows = [
        [
            rec["name"],
            rec["species"],
            rec["state"],
            cell(rec["image_version"]),
            cell(rec["budgets"].get("cpu")),
            cell(rec["budgets"].get("memory_mib")),
            cell(rec["budgets"].get("disk_gib")),
            cell(rec.get("uptime_s")),
        ]
        for rec in records
    ]
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows)) if rows else len(headers[i])
        for i in range(len(headers))
    ]
    lines = ["  ".join(headers[i].ljust(widths[i]) for i in range(len(headers)))]
    for row in rows:
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))
    return "\n".join(lines)


def _reconcile(cfg: Config) -> list[dict]:
    specs = load_specs(cfg.instances_dir)
    records = reconcile(specs, _adapter_for(cfg), cfg.host_id)
    # Enrich with the last audit event per instance (read-only; the audit
    # log is append-only, reading it is side-effect free).
    for rec in records:
        rec["last_audit_event"] = audit.last_event_for(cfg.state_dir, rec["name"])
    return records


def run(argv=None, adapter=None) -> int:
    """Entry point. ``adapter`` may be injected (tests); None = live IncusAdapter."""
    args = _build_parser().parse_args(argv)
    try:
        cfg = _resolve_config(args)

        if args.command in ("create", "start", "stop", "restart", "logs",
                            "destroy-plan", "provision", "snapshot"):
            ad = adapter if adapter is not None else _adapter_for(cfg)
            return lifecycle.dispatch(args, cfg, ad)

        if args.command == "reconcile":
            # Read-only three-source cross-check (issue #19). Exit 0
            # always: discrepancies are data in the findings array.
            from .reconcile import render_human, run_reconcile
            ad = adapter if adapter is not None else _adapter_for(cfg)
            report = run_reconcile(cfg, ad)
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print(render_human(report))
            return EXIT_OK

        if args.command == "config-show":
            data = {
                "schema": "clusterctl-config/v1",
                "host_id": cfg.host_id,
                "incus_project": cfg.incus_project,
                "managed_prefix": cfg.managed_prefix,
                "profile": cfg.profile,
                "state_dir": cfg.state_dir,
            }
            if args.json:
                print(json.dumps(data, indent=2))
            else:
                print(yaml.safe_dump(data, sort_keys=False), end="")
            return EXIT_OK

        if adapter is not None:
            specs = load_specs(cfg.instances_dir)
            records = reconcile(specs, adapter, cfg.host_id)
            for rec in records:
                rec["last_audit_event"] = audit.last_event_for(cfg.state_dir, rec["name"])
        else:
            records = _reconcile(cfg)

        if args.command == "list":
            if args.json:
                print(json.dumps(records, indent=2))
            else:
                print(_render_table(records))
            return EXIT_OK

        # status <name>
        rec = find_record(records, args.name)
        if rec is None:
            print(f"clusterctl: instance {args.name!r} not found", file=sys.stderr)
            return EXIT_NOT_FOUND
        if args.json:
            print(json.dumps(rec, indent=2))
        else:
            print(_render_table([rec]))
            for entry in rec.get("drift") or []:
                print(f"drift: {entry['field']}: declared={entry['declared']} actual={entry['actual']}")
        return EXIT_OK

    except (ConfigError, SpecError, IncusError) as exc:
        print(f"clusterctl: error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    except Exception as exc:  # pragma: no cover - defensive
        print(f"clusterctl: internal error: {exc!r}", file=sys.stderr)
        return EXIT_INTERNAL


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
