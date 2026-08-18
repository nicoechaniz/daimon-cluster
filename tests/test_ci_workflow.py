"""Executable checks for security-sensitive inline CI preparation logic."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest


def _private_inventory() -> Any:
    workflow = Path(__file__).parents[1] / ".github/workflows/tests.yml"
    raw = workflow.read_text(encoding="utf-8")
    step = raw.index("Harden and record the trusted qualification interpreter")
    marker = "          python - <<'PY'\n"
    start = raw.index(marker, step) + len(marker)
    end = raw.index("          PY\n", start)
    source = "\n".join(
        line.removeprefix("          ") for line in raw[start:end].splitlines()
    )
    parsed = ast.parse(source)
    names = {"digest_file", "inventory", "normalised_mode"}
    functions = [
        node
        for node in parsed.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    assert {node.name for node in functions} == names
    namespace = {
        "Path": Path,
        "hashlib": hashlib,
        "json": json,
        "os": os,
        "stat": stat,
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), workflow, "exec"), namespace)
    return namespace["inventory"]


def test_private_ci_prefix_inventory_rejects_writable_member(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private-prefix"
    private.mkdir(mode=0o700)
    member = private / "module.py"
    member.write_bytes(b"VALUE = 1\n")
    member.chmod(0o620)

    inventory = _private_inventory()
    with pytest.raises(AssertionError):
        inventory(private, private=True)

    member.chmod(0o600)
    assert inventory(private, private=True) == [
        ["directory", ".", 0o700],
        ["file", "module.py", 0o600, 10, hashlib.sha256(b"VALUE = 1\n").hexdigest()],
    ]


def test_private_ci_prefix_inventory_rejects_writable_directory(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private-prefix"
    private.mkdir(mode=0o700)
    package = private / "package"
    package.mkdir(mode=0o720)

    inventory = _private_inventory()
    with pytest.raises(AssertionError):
        inventory(private, private=True)

    package.chmod(0o700)
    assert inventory(private, private=True) == [
        ["directory", ".", 0o700],
        ["directory", "package", 0o700],
    ]


def test_ci_sandbox_preflight_is_hosted_runner_only_and_preserves_isolation() -> None:
    workflow = (
        Path(__file__).parents[1] / ".github/workflows/tests.yml"
    ).read_text(encoding="utf-8")
    start = workflow.index(
        "      - name: Prove the disposable runner supports the qualification sandbox"
    )
    end = workflow.index("      - run: python -m pip install", start)
    step = workflow[start:end]

    assert 'test "${RUNNER_ENVIRONMENT:-}" = github-hosted' in step
    assert "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0" in step
    assert "--unshare-all" in step
    assert "--clearenv" in step
    assert "--ro-bind / /" not in step
    assert "--share-net" not in step
    assert 'test "$(readlink /proc/self/ns/net)" != "$HOST_NET_NAMESPACE"' in step
    assert 'test "$(wc -l < /proc/net/route)" -eq 1' in step
    assert "test ! -e /home/runner" in step
    assert "test ! -e /run/docker.sock" in step
