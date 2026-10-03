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


# Issues114/116: exact scoped registry/fleet-status delta; historical hashes remain.
REGISTRY_MUTATION_UPDATE = {
    "clusterctl/embodiments.py": "297d52439d967a6f04a710d6c79db21f13288e0d73d3c57fcef21701d6bf6cdd",
    "tests/test_embodiments.py": "f99b43ff17353b6ca1b8720a285d4c57ab310851c7e8eec73c5e5374e0afa7b9",
    "clusterd/handlers.py": "429d31321b530fd4650c6d7d19adeb458e4b96b96d45ec61fe1e8727eea865de",
    "tests/test_matrix_status.py": "624b88bc4e7e9f0d31f67c255aeb572c85bb4eaff3103b4c2e09add710823707",
}


def test_installed_tree_preserved_outside_explicit_maintenance_boundary():
    baseline = json.loads((ROOT / "docs/verification/maintenance-baseline.json").read_text())
    for name, digest in baseline["sha256"].items():
        if name in REGISTRY_MUTATION_UPDATE:
            assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == REGISTRY_MUTATION_UPDATE[name], name
            continue
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
        "clusterctl/owner_body_reader.py",
        "clusterctl/owner_runtime.py",
    }
    assert not old - current
    origins = json.loads((ROOT / "docs/verification/maintenance-origins.json").read_text())
    for name, origin in origins.items():
        candidate = (ROOT / name).read_bytes()
        # Preserve the historical frozen hashes: only these two origin members
        # intentionally repin the identical Matrix package to its merged commit.
        if name in {"clusterctl/matrix_host.py", "requirements-weave.txt"}:
            merged = b"95216a1227a2bafd09db975bd2caf415e3e163cc"
            reviewed = b"0a80cc5c38d3c7f5cad98d440153f0cf9706686b"
            assert candidate.count(merged) == 1, name
            candidate = candidate.replace(merged, reviewed)
        assert hashlib.sha256(candidate).hexdigest() == origin["candidate_sha256"], name


def test_host_uses_private_fences_without_replacing_legacy_api():
    from clusterctl import fences, matrix_host
    assert matrix_host.ResourceFenceStore is not fences.ResourceFenceStore
    assert matrix_host.ResourceFenceStore.__module__ == "clusterctl.matrix_fencing.fences"
    assert matrix_host.MATRIX_CONTRACT_COMMIT == "95216a1227a2bafd09db975bd2caf415e3e163cc"
