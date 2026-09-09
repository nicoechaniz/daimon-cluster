"""Installed-line boundary: never upgrade the unrelated fleet implicitly."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLANNED = {
    "clusterctl/matrix_host.py", "requirements-weave.txt",
    "tests/test_matrix_host.py", "tests/test_matrix_host_process.py",
    ".github/workflows/tests.yml",
    "tests/test_clusterd.py", "tests/test_matrix_parity.py",
}


def test_installed_tree_preserved_outside_explicit_maintenance_boundary():
    baseline = json.loads((ROOT / "docs/verification/maintenance-baseline.json").read_text())
    for name, digest in baseline["sha256"].items():
        if name not in PLANNED:
            assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name


def test_only_declared_runtime_additions_and_exact_upstream_composition():
    baseline = json.loads((ROOT / "docs/verification/maintenance-baseline.json").read_text())
    old = {name for name in baseline["sha256"] if name.endswith(".py") and name.split("/")[0] in {"clusterctl", "clusterd", "steward_tools"}}
    current = {str(path.relative_to(ROOT)) for package in ("clusterctl", "clusterd", "steward_tools") for path in (ROOT / package).rglob("*.py")}
    assert current - old == {
        "clusterctl/matrix_fencing/__init__.py",
        "clusterctl/matrix_fencing/fences.py",
        "clusterctl/matrix_fencing/production_fences.py",
        "clusterctl/matrix_status_transition.py",
    }
    assert not old - current
    origins = json.loads((ROOT / "docs/verification/maintenance-origins.json").read_text())
    for name, origin in origins.items():
        candidate = (ROOT / name).read_bytes()
        # Preserve the historical frozen hashes: only these two origin members
        # intentionally repin the identical Matrix package to its merged commit.
        if name in {"clusterctl/matrix_host.py", "requirements-weave.txt"}:
            merged = b"8e7d8870609507e61eec1be769280dc33c487366"
            reviewed = b"0a80cc5c38d3c7f5cad98d440153f0cf9706686b"
            assert candidate.count(merged) == 1, name
            candidate = candidate.replace(merged, reviewed)
        assert hashlib.sha256(candidate).hexdigest() == origin["candidate_sha256"], name


def test_host_uses_private_fences_without_replacing_legacy_api():
    from clusterctl import fences, matrix_host
    assert matrix_host.ResourceFenceStore is not fences.ResourceFenceStore
    assert matrix_host.ResourceFenceStore.__module__ == "clusterctl.matrix_fencing.fences"
    assert matrix_host.MATRIX_CONTRACT_COMMIT == "8e7d8870609507e61eec1be769280dc33c487366"
