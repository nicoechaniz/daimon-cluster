"""Private subprocess for one closed exact DM-035 provider call."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from .reviewed_publication import (
    DM035ExecutorError,
    PinnedPublisherTransport,
    _canonical,
    _load_provider,
    _owner_directory,
    _provider_dispatch,
    _verify_git_checkout,
)


def _diagnostic(code: str, retryable: bool = False) -> None:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}", code) is None:
        code = "dm035_provider_failed"
        retryable = False
    value = {
        "schema": "dm.cluster.dm035-provider-diagnostic/v1",
        "code": code,
        "retryable": retryable,
    }
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-checkout", type=Path, required=True)
    parser.add_argument("--wiki-root", type=Path, required=True)
    parser.add_argument("--projection-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--hmk-checkout", type=Path, required=True)
    parser.add_argument("--hmk-base", type=Path, required=True)
    parser.add_argument("--fixed-clock-ms", type=int)
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read(18 * 1024 * 1024 + 1)
        if not raw or len(raw) > 18 * 1024 * 1024:
            raise DM035ExecutorError("dm035_provider_request_rejected")
        value = json.loads(raw)
        if (
            not isinstance(value, Mapping)
            or set(value) != {"schema", "operation", "document"}
            or value["schema"] != "dm.cluster.dm035-provider-call/v1"
            or value["operation"] not in PinnedPublisherTransport.OPERATIONS
            or not isinstance(value["document"], Mapping)
        ):
            raise DM035ExecutorError("dm035_provider_request_rejected")
        _verify_git_checkout(
            args.provider_checkout.resolve(),
            "cf56e9de703f68f44b85fdf21f503d55a5557984",
            (
                "matrix_publisher.py",
                "state_safety.py",
                "policies/matrix-publisher-v1.json",
            ),
            "dm035_provider_contract_mismatch",
        )
        _verify_git_checkout(
            args.hmk_checkout.resolve(),
            "f10fd5c3089c0962920314c97e14bc024feffa7a",
            ("scripts/memoryctl.py",),
            "dm035_hmk_contract_mismatch",
        )
        _owner_directory(args.wiki_root, owner_only=False)
        for root in (args.projection_root, args.runtime_root, args.hmk_base):
            _owner_directory(root)
        module = _load_provider(args.provider_checkout.resolve())
        clock = (
            None if args.fixed_clock_ms is None else lambda: int(args.fixed_clock_ms)
        )
        api = module.MatrixPublisher(
            wiki_root=args.wiki_root,
            projection_root=args.projection_root,
            runtime_root=args.runtime_root,
            hmk_root=args.hmk_checkout,
            hmk_base=args.hmk_base,
            policy_path=args.provider_checkout
            / "policies"
            / "matrix-publisher-v1.json",
            clock_ms=clock,
        )
        result = _provider_dispatch(
            module, api, str(value["operation"]), value["document"]
        )
        sys.stdout.buffer.write(_canonical(result, "dm035_provider_response_rejected"))
        sys.stdout.buffer.write(b"\n")
        return 0
    except DM035ExecutorError as exception:
        _diagnostic(exception.code, exception.retryable)
    except Exception as exception:
        code = exception.args[0] if exception.args else "dm035_provider_failed"
        provider_error = exception.__class__.__name__ in {
            "PublisherError",
            "PublisherBusy",
        }
        if not provider_error or not isinstance(code, str):
            code = "dm035_provider_failed"
        _diagnostic(code, exception.__class__.__name__ == "PublisherBusy")
    return 1


if __name__ == "__main__":
    # No inherited secret/config environment is required by the provider.
    os.environ.pop("HMK_DB_PATH", None)
    raise SystemExit(main())
