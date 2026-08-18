"""Run the exact release-candidate mypy boundary used by CI and docs."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

FILES = (
    "clusterctl/admission.py",
    "clusterctl/adapters.py",
    "clusterctl/embodiments.py",
    "clusterctl/fences.py",
    "clusterctl/idempotency.py",
    "clusterctl/inventory.py",
    "clusterctl/locks.py",
    "clusterctl/operation_journal.py",
    "clusterctl/production_fences.py",
    "clusterctl/matrix_host.py",
    "clusterctl/transfer.py",
    "clusterctl/rebirth.py",
    "clusterctl/rebirth_host.py",
    "clusterctl/recovery_rebirth.py",
    "clusterctl/cli.py",
    "clusterctl/distributed_rebirth.py",
    "clusterd/approvals.py",
    "clusterd/auth.py",
    "clusterd/confirm.py",
    "clusterd/routes.py",
    "steward_tools/mutations.py",
    "tests/test_human_approvals.py",
    "tests/test_admission.py",
    "tests/test_rebirth.py",
    "tests/test_recovery_rebirth.py",
    "tests/integration/recovery-rebirth/role.py",
    "tests/integration/test_recovery_rebirth_containers.py",
    "tools/build_physical_preflight.py",
    "tools/build_rc_manifest.py",
    "tools/qualify_offline.py",
    "tools/check_rc_types.py",
    "scripts/h3-volume-drill.py",
)


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "--follow-imports=skip",
            "--ignore-missing-imports",
            "--disable-error-code=import-untyped",
            *FILES,
        ],
        cwd=root,
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
