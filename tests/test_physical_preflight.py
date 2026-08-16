from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tools.build_physical_preflight import (
    PhysicalPreflightError,
    build_preflight,
    main,
)


def _plan() -> dict:
    components = {
        name: {"commit": digit * 40, "tree": digit * 40}
        for name, digit in (
            ("daimon-matrix", "1"),
            ("daimon-cluster", "2"),
            ("tribe-bridge", "3"),
        )
    }
    hosts = [
        {
            "role": role,
            "host_ref": f"rc-{role}.invalid",
            "purpose_built": True,
            "production": False,
        }
        for role in ("source", "target", "backup")
    ]
    stages = (
        "preflight",
        "backup-export",
        "volume-transfer",
        "restore",
        "start-reboot",
        "loss-fence",
        "rollback",
    )
    return {
        "schema": "dm.cluster.physical-rehearsal-plan/v1",
        "execution_authorized": False,
        "components": components,
        "artifacts": [
            {"name": f"artifact-{index}", "sha256": str(index) * 64}
            for index in (4, 5, 6)
        ],
        "hosts": hosts,
        "steps": [
            {
                "sequence": index,
                "stage": stage,
                "host_role": "source" if index < 3 else "target",
                "argv": ["fixture-command", stage],
                "effects": [f"bounded effect {stage}"],
                "success": [f"verified result {stage}"],
                "rollback_argv": ["fixture-rollback", stage],
            }
            for index, stage in enumerate(stages, 1)
        ],
        "gates": {
            "exact_go_required": True,
            "external_contact_approved": False,
            "live_custody_approved": False,
        },
        "limitations": [
            "synthetic evidence is not physical singleton evidence",
            "host selection and execution remain external gates",
        ],
    }


def test_preflight_is_deterministic_closed_and_unauthorized() -> None:
    first = build_preflight(_plan())
    second = build_preflight(_plan())
    assert first == second
    assert first["execution_authorized"] is False
    assert first["required_go"] == f"GO {first['plan_sha256']}"
    assert len(first["plan_sha256"]) == 64


@pytest.mark.parametrize(
    "change,code",
    [
        (lambda value: value.update(execution_authorized=True), "unauthorized"),
        (lambda value: value["hosts"][1].update(production=True), "purpose_built"),
        (lambda value: value["hosts"][1].update(purpose_built=False), "purpose_built"),
        (lambda value: value["steps"].pop(), "steps_incomplete"),
        (lambda value: value["steps"][2].update(rollback_argv=[]), "rollback"),
        (
            lambda value: value["steps"][2].update(argv=["bash", "-c", "true"]),
            "step_invalid",
        ),
        (
            lambda value: value["gates"].update(live_custody_approved=True),
            "gate_widening",
        ),
    ],
)
def test_preflight_rejects_incomplete_or_widened_plan(change, code) -> None:
    value = copy.deepcopy(_plan())
    change(value)
    with pytest.raises(PhysicalPreflightError, match=code):
        build_preflight(value)


def test_cli_refuses_noncanonical_input_and_existing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = tmp_path / "plan.json"
    output = tmp_path / "preflight.json"
    plan.write_text(json.dumps(_plan(), indent=2), encoding="utf-8")
    plan.chmod(0o600)
    monkeypatch.setattr(
        "sys.argv",
        ["build_physical_preflight", "--plan", str(plan), "--output", str(output)],
    )
    with pytest.raises(PhysicalPreflightError, match="canonical"):
        main()

    plan.write_text(
        json.dumps(_plan(), sort_keys=True, separators=(",", ":")), encoding="ascii"
    )
    assert main() == 0
    assert output.stat().st_mode & 0o077 == 0
    with pytest.raises(PhysicalPreflightError, match="output_rejected"):
        main()


def test_cli_rejects_mutable_or_linked_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = tmp_path / "plan.json"
    linked = tmp_path / "linked.json"
    output = tmp_path / "preflight.json"
    plan.write_text(
        json.dumps(_plan(), sort_keys=True, separators=(",", ":")), encoding="ascii"
    )
    plan.chmod(0o640)
    monkeypatch.setattr(
        "sys.argv",
        ["build_physical_preflight", "--plan", str(plan), "--output", str(output)],
    )
    with pytest.raises(PhysicalPreflightError, match="plan_file_rejected"):
        main()

    plan.chmod(0o600)
    linked.symlink_to(plan)
    monkeypatch.setattr(
        "sys.argv",
        ["build_physical_preflight", "--plan", str(linked), "--output", str(output)],
    )
    with pytest.raises(PhysicalPreflightError, match="plan_file_rejected"):
        main()


def test_cli_rejects_linked_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = tmp_path / "plan.json"
    occupied = tmp_path / "occupied.json"
    output = tmp_path / "preflight.json"
    plan.write_text(
        json.dumps(_plan(), sort_keys=True, separators=(",", ":")), encoding="ascii"
    )
    plan.chmod(0o600)
    occupied.write_text("do not replace", encoding="ascii")
    output.symlink_to(occupied)
    monkeypatch.setattr(
        "sys.argv",
        ["build_physical_preflight", "--plan", str(plan), "--output", str(output)],
    )
    with pytest.raises(PhysicalPreflightError, match="output_rejected"):
        main()
    assert occupied.read_text(encoding="ascii") == "do not replace"


def test_cli_rejects_writable_output_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = tmp_path / "plan.json"
    output_root = tmp_path / "mutable"
    output_root.mkdir(mode=0o777)
    output_root.chmod(0o777)
    output = output_root / "preflight.json"
    plan.write_text(
        json.dumps(_plan(), sort_keys=True, separators=(",", ":")), encoding="ascii"
    )
    plan.chmod(0o600)
    monkeypatch.setattr(
        "sys.argv",
        ["build_physical_preflight", "--plan", str(plan), "--output", str(output)],
    )
    with pytest.raises(PhysicalPreflightError, match="output_rejected"):
        main()
    assert not output.exists()
