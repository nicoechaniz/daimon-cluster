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

# Additional test-only delta after the original seven-file maintenance boundary:
# explicitly close HTTPError responses, including on body decoding failure.
# Keep the historical baseline hashes and original PLANNED inventory unchanged.
HTTP_HELPER_CLEANUP = {"tests/test_auth.py", "tests/test_clusterd.py"}

# Owner-approved runtime exception: ONLY wrap the existing HTTPError catch
# read/translate block in a context manager. Undo exactly that addition before
# comparing historical hashes, so no other client changes are permitted.
HTTP_CLIENT_CLEANUP = {"steward_tools/client.py", "steward_tools/mutations.py"}


def _before_http_client_cleanup(name, candidate):
    suffix = " only" if name == "steward_tools/client.py" else ""
    original = (
        '            try:\n'
        '                body = json.loads(exc.read().decode("utf-8"))\n'
        '            except Exception:  # non-JSON error body — keep the status'
        + suffix + '\n'
        '                body = None\n'
        '            raise ClusterdHTTPError(exc.code, body) from exc\n'
    ).encode()
    wrapped = b"            with exc:\n" + b"".join(
        b"    " + line for line in original.splitlines(keepends=True)
    )
    assert candidate.count(wrapped) == 1, name
    return candidate.replace(wrapped, original)


# Separately authorized test-owned response: no whole-file exemption.
HTTP_UNATTENDED_TEST_CLEANUP = {"tests/test_steward_mutations.py"}


def _before_http_unattended_test_cleanup(name, candidate):
    original = (
        '    assert exc_info.value.code == 403\n'
        '    body = json.loads(exc_info.value.read().decode("utf-8"))\n'
        '    assert body["error"] == "unattended-steward-denied"\n'
        '    assert ad.mutation_log == []\n'
    ).encode()
    wrapped = b"    with exc_info.value:\n" + b"".join(
        b"    " + line for line in original.splitlines(keepends=True)
    )
    assert candidate.count(wrapped) == 1, name
    return candidate.replace(wrapped, original)


def test_installed_tree_preserved_outside_explicit_maintenance_boundary():
    baseline = json.loads((ROOT / "docs/verification/maintenance-baseline.json").read_text())
    for name, digest in baseline["sha256"].items():
        if name not in PLANNED | HTTP_HELPER_CLEANUP:
            candidate = (ROOT / name).read_bytes()
            if name in HTTP_CLIENT_CLEANUP:
                candidate = _before_http_client_cleanup(name, candidate)
            if name in HTTP_UNATTENDED_TEST_CLEANUP:
                candidate = _before_http_unattended_test_cleanup(name, candidate)
            assert hashlib.sha256(candidate).hexdigest() == digest, name


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
            merged = b"acb131f18c200bb028ee86fa3a8ef9a2f6c040a3"
            reviewed = b"0a80cc5c38d3c7f5cad98d440153f0cf9706686b"
            assert candidate.count(merged) == 1, name
            candidate = candidate.replace(merged, reviewed)
        assert hashlib.sha256(candidate).hexdigest() == origin["candidate_sha256"], name


def test_host_uses_private_fences_without_replacing_legacy_api():
    from clusterctl import fences, matrix_host
    assert matrix_host.ResourceFenceStore is not fences.ResourceFenceStore
    assert matrix_host.ResourceFenceStore.__module__ == "clusterctl.matrix_fencing.fences"
    assert matrix_host.MATRIX_CONTRACT_COMMIT == "acb131f18c200bb028ee86fa3a8ef9a2f6c040a3"
