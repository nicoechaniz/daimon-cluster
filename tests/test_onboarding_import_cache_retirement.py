"""Explicit cache maintenance cannot hide changed or missing SDK source."""
import hashlib
import py_compile

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_sdk import _retire_import_bytecode


@pytest.fixture
def tree(tmp_path):
    root = tmp_path/'imports'
    root.mkdir(mode=0o700)
    source = root/'example.py'
    source.write_text('value = 42\n')
    source.chmod(0o600)
    cache = py_compile.compile(str(source), doraise=True)
    from pathlib import Path
    cache = Path(cache)
    cache.parent.chmod(0o700)
    cache.chmod(0o600)
    return root, source, cache, {'example.py': hashlib.sha256(source.read_bytes()).hexdigest()}


def test_retirement_preserves_wheel_bytes_and_only_removes_verified_cache(tree):
    root, source, cache, files = tree
    original = source.read_bytes()
    _retire_import_bytecode(root, files)
    assert source.read_bytes() == original and not cache.exists() and not cache.parent.exists()


@pytest.mark.parametrize('fault', ['changed-source', 'missing-source', 'unknown-file', 'symlink'])
def test_retirement_refuses_before_any_cache_deletion(tree, fault):
    root, source, cache, files = tree
    if fault == 'changed-source':
        source.write_text('value = 43\n')
    elif fault == 'missing-source':
        source.unlink()
    elif fault == 'unknown-file':
        (root/'unqualified.py').write_text('unexpected = True\n')
    else:
        (root/'link').symlink_to(source)
    with pytest.raises((OnboardingError, ValueError), match='qualified_runtime_imports_required|seed_symlink_path_refused'):
        _retire_import_bytecode(root, files)
    assert cache.exists()
