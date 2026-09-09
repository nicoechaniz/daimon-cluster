"""Offline unit runner: suppress only the historical Incus collection probe."""
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch


def main():
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    sys.path.insert(0, str(root))
    os.environ.pop("DAIMON_RUN_DOCKER_TESTS", None)
    os.environ.pop("DAIMON_RUN_DOCKER_RECOVERY_TESTS", None)
    original = subprocess.run

    def guarded_run(args, *a, **kw):
        if isinstance(args, (list, tuple)) and list(args) == ["sudo", "incus", "list"]:
            return subprocess.CompletedProcess(args, 127, stdout="", stderr="Offline qualification: live probe disabled")
        return original(args, *a, **kw)

    import pytest
    with patch("subprocess.run", side_effect=guarded_run):
        return pytest.main(sys.argv[1:] or ["tests", "-q", "-W", "error::ResourceWarning", "-W", "error::pytest.PytestUnraisableExceptionWarning"])


if __name__ == "__main__":
    raise SystemExit(main())
