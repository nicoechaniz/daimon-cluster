"""Stable runtime must not retain a Tribe Bridge operational dependency."""

from pathlib import Path

from clusterctl.cli import _build_parser
from clusterctl.lifecycle import DEFAULT_IMAGE

ROOT = Path(__file__).resolve().parents[1]
ACTIVE_ROOTS = ("clusterctl", "clusterd", "configs", "scripts")
BANNED = (
    b"tribe-bridge",
    b".tribe-bridge",
    b"tribe-base",
    b"tribe-agent",
    b"tribe_client_v1",
    b"tribe_crypto_v1",
    b"tribe_protocol_v1",
    b"bridge-outbox",
    b"force-outbox",
    b"tcp dport 8685",
)


def test_active_runtime_assets_have_no_bridge_dependency():
    findings = []
    for relative in ACTIVE_ROOTS:
        for path in sorted((ROOT / relative).rglob("*")):
            if not path.is_file() or path.suffix == ".pyc":
                continue
            content = path.read_bytes().lower()
            for marker in BANNED:
                if marker.lower() in content:
                    findings.append((path.relative_to(ROOT).as_posix(), marker.decode()))
    assert findings == []


def test_removed_bridge_provision_command_is_not_parseable():
    parser = _build_parser()
    subcommands = next(
        action.choices
        for action in parser._actions
        if getattr(action, "choices", None)
    )
    assert "provision" not in subcommands


def test_native_defaults_do_not_select_legacy_bridge_assets():
    assert DEFAULT_IMAGE == "daimon-base/latest"
    assert "profile: daimon-agent" in (ROOT / "configs/clusterctl.yaml").read_text()
    assert (ROOT / "configs/daimon-agent-profile.yaml").is_file()
    assert not (ROOT / "configs/tribe-agent-profile.yaml").exists()
