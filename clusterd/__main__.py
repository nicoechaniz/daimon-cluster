"""clusterd entry point: ``python -m clusterd`` / ``scripts/clusterd``.

Options:
    --bind HOST:PORT   listen address (default 127.0.0.1:8785)
    --config PATH      clusterctl-config/v1 YAML (default configs/clusterctl.yaml)
    --state-dir PATH   override clusterctl state_dir (tests)
    --dump-openapi [PATH]  write the generated OpenAPI doc and exit
                           (default docs/contracts/clusterd-openapi-v1.yaml)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, handlers, server
from .openapi import dump_openapi

DEFAULT_OPENAPI_OUT = "docs/contracts/clusterd-openapi-v1.yaml"


def _parse_bind(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise argparse.ArgumentTypeError(
            f"--bind must be HOST:PORT, got {value!r}")
    try:
        return host, int(port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"--bind port must be an integer, got {value!r}") from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="clusterd",
        description="thin HTTP API over clusterctl (issue #17)",
    )
    parser.add_argument("--bind", default=f"{server.DEFAULT_BIND}:{server.DEFAULT_PORT}",
                        help="listen address HOST:PORT (default: %(default)s)")
    parser.add_argument("--config", default="configs/clusterctl.yaml",
                        help="clusterctl-config/v1 YAML (default: %(default)s)")
    parser.add_argument("--state-dir", default=None,
                        help="override clusterctl state_dir (tests)")
    parser.add_argument("--dump-openapi", nargs="?", const=DEFAULT_OPENAPI_OUT,
                        default=None, metavar="PATH",
                        help=f"write the generated OpenAPI YAML and exit "
                             f"(default path: {DEFAULT_OPENAPI_OUT})")
    parser.add_argument("--version", action="version",
                        version=f"clusterd {__version__}")
    args = parser.parse_args(argv)

    if args.dump_openapi is not None:
        out = Path(args.dump_openapi)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(dump_openapi(), encoding="utf-8")
        print(f"wrote {out}")
        return 0

    bind, port = _parse_bind(args.bind)
    deps = handlers.Deps(config_path=args.config, state_dir=args.state_dir)
    server.serve(deps, bind, port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
