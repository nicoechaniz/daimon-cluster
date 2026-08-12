"""Repository-level invariants for administrative and production boundaries."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE_ROOTS = (
    ROOT / "clusterctl",
    ROOT / "clusterd",
    ROOT / "configs",
    ROOT / "scripts",
    ROOT / "steward_tools",
)
ADMIN_SSH_ROOT = re.compile(
    r"/(?:root|home/(?:root|debian|nicolas))/\.ssh(?:/|\b)", re.IGNORECASE
)
ADMIN_SSH_MUTATION = re.compile(
    r"\b(?:cp|install|mv|rm|sed|tee|truncate|unlink)\b[^\n]*"
    r"/(?:root|home/(?:root|debian|nicolas))/\.ssh(?:/|\b)|"
    r">{1,2}\s*[\"']?/(?:root|home/(?:root|debian|nicolas))/\.ssh(?:/|\b)|"
    r"/(?:root|home/(?:root|debian|nicolas))/\.ssh(?:/|\b)[^\n]*"
    r"\.write_(?:text|bytes)\(",
    re.IGNORECASE,
)


def _repository_assets() -> list[Path]:
    return sorted(
        path
        for root in EXECUTABLE_ROOTS
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    )


def test_executable_assets_do_not_target_administrative_ssh_or_mona() -> None:
    violations: list[str] = []
    for path in _repository_assets():
        body = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)
        if "authorized_keys" in body.lower():
            violations.append(f"{relative}: references authorized_keys")
        if re.search(r"\bmona(?:\.altermundi\.net)?\b", body, re.IGNORECASE):
            violations.append(f"{relative}: references excluded production host Mona")
        for line_number, line in enumerate(body.splitlines(), start=1):
            if ADMIN_SSH_ROOT.search(line) and ADMIN_SSH_MUTATION.search(line):
                violations.append(
                    f"{relative}:{line_number}: mutates an administrative SSH root"
                )
    assert not violations, "\n".join(violations)


def test_operating_rules_persist_the_incident_boundaries() -> None:
    rules = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    normalized_rules = " ".join(rules.split())
    required = (
        "must not modify an existing administrative login path",
        "content-addressed preflight",
        "timed automatic rollback",
        "second fresh session",
        "mona.altermundi.net",
        "Do not connect to it for discovery or verification",
        "containers or purpose-created disposable hosts",
    )
    for phrase in required:
        assert phrase in normalized_rules

    incident = ROOT / "docs/incidents/2026-08-11-ssh-authorized-keys-lockout.md"
    assert incident.is_file()
