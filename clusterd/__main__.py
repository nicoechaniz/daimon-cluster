"""clusterd entry point: ``python -m clusterd`` / ``scripts/clusterd``.

Options:
    --bind HOST:PORT   listen address; REPEATABLE for multi-bind
                       (issue #21, e.g. --bind 127.0.0.1:8785
                       --bind 10.105.93.1:8785). All binds share one
                       state_dir, one token store, one rate limiter.
                       (default 127.0.0.1:8785)
    --config PATH      clusterctl-config/v1 YAML (default configs/clusterctl.yaml)
    --state-dir PATH   override clusterctl state_dir (tests)
    --dump-openapi [PATH]  write the generated OpenAPI doc and exit
                           (default docs/contracts/clusterd-openapi-v1.yaml)

Token management (issue #18):
    --token-create --actor A --scopes read,mutate --owner O --ttl-days N
                           create a token; the RAW token (dcd_<uuid4hex>)
                           is printed ONCE — only its sha256 is stored.
    --token-revoke --token-id ID
                           revoke immediately (effective next request,
                           no restart: the server reloads on mtime change).
    --token-list           metadata only (ids, actors, scopes, owners,
                           revoked) — never hashes, never token material.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from clusterctl.config import load_config
from clusterctl.matrix_host import matrix_client_factory

from . import __version__, auth, handlers, server
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
    parser.add_argument("--bind", action="append", type=_parse_bind,
                        default=None, metavar="HOST:PORT",
                        help=f"listen address; repeatable for multi-bind "
                             f"(issue #21); default "
                             f"{server.DEFAULT_BIND}:{server.DEFAULT_PORT}")
    parser.add_argument("--config", default="configs/clusterctl.yaml",
                        help="clusterctl-config/v1 YAML (default: %(default)s)")
    parser.add_argument("--state-dir", default=None,
                        help="override clusterctl state_dir (tests)")
    parser.add_argument("--dump-openapi", nargs="?", const=DEFAULT_OPENAPI_OUT,
                        default=None, metavar="PATH",
                        help=f"write the generated OpenAPI YAML and exit "
                             f"(default path: {DEFAULT_OPENAPI_OUT})")
    # token management (#18)
    parser.add_argument("--token-create", action="store_true",
                        help="create a bearer token; raw token printed ONCE")
    parser.add_argument("--token-revoke", action="store_true",
                        help="revoke --token-id immediately (no restart needed)")
    parser.add_argument("--token-list", action="store_true",
                        help="list token metadata (never hashes/material)")
    parser.add_argument("--token-id", default=None, help="token id to revoke")
    parser.add_argument("--actor", default=None, help="token actor identity")
    parser.add_argument("--scopes", default="read",
                        help="comma-separated scopes: read,mutate")
    parser.add_argument("--owner", default="*",
                        help="human identity owning daimons, or '*'")
    parser.add_argument("--ttl-days", type=int, default=30,
                        help="token time-to-live in days (default: %(default)s)")
    parser.add_argument("--version", action="version",
                        version=f"clusterd {__version__}")
    args = parser.parse_args(argv)

    if args.dump_openapi is not None:
        out = Path(args.dump_openapi)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(dump_openapi(), encoding="utf-8")
        print(f"wrote {out}")
        return 0

    state_dir = args.state_dir or load_config(args.config).state_dir

    if args.token_create:
        if not args.actor:
            parser.error("--token-create requires --actor")
        scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
        record, raw_token = auth.create_token(
            state_dir, actor=args.actor, scopes=scopes,
            owner=args.owner, ttl_days=args.ttl_days)
        # The raw token is printed exactly ONCE; only sha256 is stored.
        print(json.dumps({
            "schema": auth.TOKEN_SCHEMA,
            "token": raw_token,
            "token_id": record["token_id"],
            "actor": record["actor"],
            "scopes": record["scopes"],
            "owner": record["owner"],
            "created_ms": record["created_ms"],
            "expires_ms": record["expires_ms"],
            "note": "store this token now; it is shown only once",
        }, indent=2, sort_keys=True))
        return 0

    if args.token_revoke:
        if not args.token_id:
            parser.error("--token-revoke requires --token-id")
        record = auth.revoke_token(state_dir, args.token_id)
        if record is None:
            print(json.dumps({"error": f"unknown token_id {args.token_id}"}),
                  file=sys.stderr)
            return 3
        print(json.dumps({"revoked": True, "token_id": args.token_id}))
        return 0

    if args.token_list:
        print(json.dumps(auth.list_tokens(state_dir), indent=2, sort_keys=True))
        return 0

    binds = args.bind or [(server.DEFAULT_BIND, server.DEFAULT_PORT)]
    deps = handlers.Deps(
        config_path=args.config,
        state_dir=args.state_dir,
        matrix_client_factory=matrix_client_factory(state_dir),
    )
    server.serve(deps, binds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
