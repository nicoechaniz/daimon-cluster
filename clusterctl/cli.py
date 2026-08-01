"""clusterctl command-line interface.

Commands: ``list [--json]``, ``status <name> [--json]``, ``config-show [--json]``.

Exit codes (clusterctl v0.1.0):
    0  success
    2  usage error (argparse)
    3  not found (``status`` of an unknown instance name)
    6  conflict (reserved; unused at this milestone)
    10 internal error (config/spec/incus failures, bugs)

Read commands are strictly side-effect free.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

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
        description="daimon-cluster fleet state CLI (read-only at v0.1.0)",
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
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list all instances with reconciled state")
    p_list.add_argument("--json", action="store_true", help="emit JSON array of instance-status/v1 records")

    p_status = sub.add_parser("status", help="show one instance's reconciled status")
    p_status.add_argument("name", help="instance name")
    p_status.add_argument("--json", action="store_true", help="emit a single instance-status/v1 record")

    p_cfg = sub.add_parser("config-show", help="show the resolved clusterctl config")
    p_cfg.add_argument("--json", action="store_true", help="emit config as JSON")
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
    return reconcile(specs, _adapter_for(cfg), cfg.host_id)


def run(argv=None, adapter=None) -> int:
    """Entry point. ``adapter`` may be injected (tests); None = live IncusAdapter."""
    args = _build_parser().parse_args(argv)
    try:
        cfg = _resolve_config(args)
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
