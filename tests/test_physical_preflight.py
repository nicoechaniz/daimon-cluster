from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from tools.build_physical_preflight import (
    PhysicalPreflightError,
    build_preflight,
    main,
)


def _manifest() -> dict:
    components = {
        name: {
            "archive_bytes": index,
            "archive_sha256": digit * 64,
            "commit": digit * 40,
            "tree": digit * 40,
        }
        for index, (name, digit) in enumerate(
            (
                ("daimon-matrix", "1"),
                ("daimon-cluster", "2"),
                ("tribe-bridge", "3"),
            ),
            1,
        )
    }
    artifacts = {
        "daimon-matrix": [
            {
                "bytes": 1,
                "kind": kind,
                "name": name,
                "path": path,
                "sha256": digit * 64,
            }
            for kind, name, path, digit in (
                ("git-bundle", "source-bundle", "daimon-matrix.bundle", "4"),
                ("python-wheel", "wheel", "daimon-matrix.whl", "5"),
                ("python-sdist", "sdist", "daimon-matrix.tar.gz", "6"),
                ("wheelhouse", "wheelhouse", "matrix-wheelhouse.tar", "f"),
                (
                    "install-evidence",
                    "install-evidence",
                    "daimon-matrix-install.json",
                    "c",
                ),
            )
        ],
        "daimon-cluster": [
            {
                "bytes": 2,
                "kind": "matrix-git-bundle",
                "name": "matrix-source-bundle",
                "path": "cluster-matrix.bundle",
                "sha256": "4" * 64,
            },
            {
                "bytes": 2,
                "kind": "wheelhouse",
                "name": "wheelhouse",
                "path": "cluster-wheelhouse.tar",
                "sha256": "f" * 64,
            },
            {
                "bytes": 2,
                "kind": "git-archive",
                "name": "source-archive",
                "path": "daimon-cluster.tar",
                "sha256": "7" * 64,
            },
            {
                "bytes": 2,
                "kind": "install-evidence",
                "name": "install-evidence",
                "path": "daimon-cluster-install.json",
                "sha256": "d" * 64,
            },
        ],
        "tribe-bridge": [
            {
                "bytes": 3,
                "kind": "wheelhouse",
                "name": "wheelhouse",
                "path": "tribe-wheelhouse.tar",
                "sha256": "f" * 64,
            },
            {
                "bytes": 3,
                "kind": "git-archive",
                "name": "source-archive",
                "path": "tribe-bridge.tar",
                "sha256": "8" * 64,
            },
            {
                "bytes": 3,
                "kind": "install-evidence",
                "name": "install-evidence",
                "path": "tribe-bridge-install.json",
                "sha256": "e" * 64,
            },
        ],
    }
    evidence = {
        name: [{"path": "README.md", "sha256": digit * 64}]
        for name, digit in (
            ("daimon-matrix", "9"),
            ("daimon-cluster", "a"),
            ("tribe-bridge", "b"),
        )
    }
    receipts = {}
    for name in components:
        receipts[name] = {
            "schema": "daimon-artifact-qualification/v1",
            "commit": components[name]["commit"],
            "tree": components[name]["tree"],
            "source_artifact": (
                "source-bundle" if name == "daimon-matrix" else "source-archive"
            ),
            "artifacts": [
                {"name": row["name"], "sha256": row["sha256"]}
                for row in sorted(artifacts[name], key=lambda item: item["name"])
            ],
            "installations": [
                {
                    "python": "3.13",
                    "network": "disabled",
                    "result": "passed",
                    "source": (
                        "vcs-direct-url" if name == "daimon-matrix" else "git-archive"
                    ),
                    "installed_commit": components[name]["commit"],
                    "installed_tree": components[name]["tree"],
                    "evidence_ref": {
                        "artifact": "install-evidence",
                        "sha256": next(
                            row["sha256"]
                            for row in artifacts[name]
                            if row["kind"] == "install-evidence"
                        ),
                    },
                }
            ],
        }
    return {
        "schema": "daimon-release-candidate/v1",
        "baseline": {},
        "components": components,
        "cross_repository": {},
        "qualification": {
            "schema": "daimon-release-qualification/v2",
            "release": "0.1.0rc1",
            "supported_python": {name: ["3.13"] for name in components},
            "artifacts": artifacts,
            "artifact_receipts": receipts,
            "tests": {
                name: [
                    {"name": "full", "python": "3.13", "passed": 1, "skipped": 0}
                ]
                for name in components
            },
            "evidence": evidence,
            "limitations": ["fixture"],
            "human_gates": ["fixture"],
        },
    }


def _plan(manifest=None) -> dict:
    manifest = _manifest() if manifest is None else manifest
    components = {
        name: {"commit": row["commit"], "tree": row["tree"]}
        for name, row in manifest["components"].items()
    }
    manifest_raw = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii") + b"\n"
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
        "rc_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "components": components,
        "artifacts": [
            {"name": f"{component}:{row['name']}", "sha256": row["sha256"]}
            for component in sorted(manifest["qualification"]["artifacts"])
            for row in manifest["qualification"]["artifacts"][component]
        ],
        "hosts": hosts,
        "steps": [
            {
                "sequence": index,
                "stage": stage,
                "host_role": (
                    "backup"
                    if stage == "backup-export"
                    else "target"
                    if stage in {"restore", "start-reboot", "loss-fence"}
                    else "source"
                ),
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
    manifest = _manifest()
    first = build_preflight(_plan(manifest), manifest)
    second = build_preflight(_plan(manifest), manifest)
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
            lambda value: value["steps"][2].update(
                argv=["/usr/bin/env", "bash", "-c", "true"]
            ),
            "step_invalid",
        ),
        (
            lambda value: value["steps"][2].update(
                argv=["/usr/bin/env", "--split-string=bash -c 'true'"]
            ),
            "step_invalid",
        ),
        (
            lambda value: value["gates"].update(live_custody_approved=True),
            "gate_widening",
        ),
    ],
)
def test_preflight_rejects_incomplete_or_widened_plan(change, code) -> None:
    manifest = _manifest()
    value = copy.deepcopy(_plan(manifest))
    change(value)
    with pytest.raises(PhysicalPreflightError, match=code):
        build_preflight(value, manifest)


def test_preflight_is_bound_to_manifest_components_artifacts_and_backup() -> None:
    manifest = _manifest()

    wrong_component = _plan(manifest)
    wrong_component["components"]["daimon-cluster"]["commit"] = "a" * 40
    with pytest.raises(PhysicalPreflightError, match="component_manifest_mismatch"):
        build_preflight(wrong_component, manifest)

    numeric_component = _plan(manifest)
    numeric_component["components"]["daimon-cluster"]["commit"] = int("2" * 40)
    with pytest.raises(PhysicalPreflightError, match="component_hash_invalid"):
        build_preflight(numeric_component, manifest)

    wrong_artifact = _plan(manifest)
    wrong_artifact["artifacts"][0]["sha256"] = "f" * 64
    with pytest.raises(PhysicalPreflightError, match="artifact_manifest_mismatch"):
        build_preflight(wrong_artifact, manifest)

    no_backup_step = _plan(manifest)
    no_backup_step["steps"][1]["host_role"] = "source"
    with pytest.raises(PhysicalPreflightError, match="step_invalid"):
        build_preflight(no_backup_step, manifest)

    boolean_sequence = _plan(manifest)
    boolean_sequence["steps"][0]["sequence"] = True
    with pytest.raises(PhysicalPreflightError, match="step_invalid"):
        build_preflight(boolean_sequence, manifest)

    wrong_manifest_digest = _plan(manifest)
    wrong_manifest_digest["rc_manifest_sha256"] = "0" * 64
    with pytest.raises(PhysicalPreflightError, match="rc_manifest_mismatch"):
        build_preflight(wrong_manifest_digest, manifest)
    partial = copy.deepcopy(manifest)
    partial["qualification"] = {"artifacts": partial["qualification"]["artifacts"]}
    with pytest.raises(PhysicalPreflightError, match="rc_manifest_malformed"):
        build_preflight(_plan(partial), partial)

    missing_sdist = copy.deepcopy(manifest)
    missing_sdist["qualification"]["artifacts"]["daimon-matrix"] = [
        row
        for row in missing_sdist["qualification"]["artifacts"]["daimon-matrix"]
        if row["kind"] != "python-sdist"
    ]
    with pytest.raises(PhysicalPreflightError, match="rc_artifacts_incomplete"):
        build_preflight(_plan(missing_sdist), missing_sdist)

    receipt_lie = copy.deepcopy(manifest)
    receipt_lie["qualification"]["artifact_receipts"]["daimon-matrix"][
        "installations"
    ][0]["evidence_ref"]["sha256"] = "0" * 64
    with pytest.raises(PhysicalPreflightError, match="rc_manifest_malformed"):
        build_preflight(_plan(receipt_lie), receipt_lie)


@pytest.mark.parametrize(
    ("component", "kind"),
    [
        ("daimon-matrix", "wheelhouse"),
        ("daimon-cluster", "wheelhouse"),
        ("daimon-cluster", "matrix-git-bundle"),
        ("tribe-bridge", "wheelhouse"),
    ],
)
def test_physical_preflight_requires_every_offline_replay_input(
    component: str, kind: str
) -> None:
    manifest = _manifest()
    manifest["qualification"]["artifacts"][component] = [
        row
        for row in manifest["qualification"]["artifacts"][component]
        if row["kind"] != kind
    ]
    with pytest.raises(PhysicalPreflightError, match="rc_artifacts_incomplete"):
        build_preflight(_plan(manifest), manifest)


def test_cli_refuses_noncanonical_input_and_existing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_value = _manifest()
    manifest = tmp_path / "rc-manifest.json"
    plan = tmp_path / "plan.json"
    output = tmp_path / "preflight.json"
    manifest.write_text(
        json.dumps(manifest_value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    manifest.chmod(0o600)
    plan.write_text(json.dumps(_plan(manifest_value), indent=2), encoding="utf-8")
    plan.chmod(0o600)
    monkeypatch.setattr(
        "sys.argv",
        [
            "build_physical_preflight",
            "--plan",
            str(plan),
            "--rc-manifest",
            str(manifest),
            "--output",
            str(output),
        ],
    )
    with pytest.raises(PhysicalPreflightError, match="canonical"):
        main()

    plan.write_text(
        json.dumps(_plan(manifest_value), sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    assert main() == 0
    assert output.stat().st_mode & 0o077 == 0
    with pytest.raises(PhysicalPreflightError, match="output_rejected"):
        main()


def test_cli_rejects_mutable_or_linked_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_value = _manifest()
    manifest = tmp_path / "rc-manifest.json"
    plan = tmp_path / "plan.json"
    linked = tmp_path / "linked.json"
    output = tmp_path / "preflight.json"
    manifest.write_text(
        json.dumps(manifest_value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    manifest.chmod(0o600)
    plan.write_text(
        json.dumps(_plan(manifest_value), sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    plan.chmod(0o640)
    monkeypatch.setattr(
        "sys.argv",
        [
            "build_physical_preflight",
            "--plan",
            str(plan),
            "--rc-manifest",
            str(manifest),
            "--output",
            str(output),
        ],
    )
    with pytest.raises(PhysicalPreflightError, match="plan_file_rejected"):
        main()

    plan.chmod(0o600)
    linked.symlink_to(plan)
    monkeypatch.setattr(
        "sys.argv",
        [
            "build_physical_preflight",
            "--plan",
            str(linked),
            "--rc-manifest",
            str(manifest),
            "--output",
            str(output),
        ],
    )
    with pytest.raises(PhysicalPreflightError, match="plan_file_rejected"):
        main()


def test_cli_rejects_linked_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_value = _manifest()
    manifest = tmp_path / "rc-manifest.json"
    plan = tmp_path / "plan.json"
    occupied = tmp_path / "occupied.json"
    output = tmp_path / "preflight.json"
    manifest.write_text(
        json.dumps(manifest_value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    manifest.chmod(0o600)
    plan.write_text(
        json.dumps(_plan(manifest_value), sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    plan.chmod(0o600)
    occupied.write_text("do not replace", encoding="ascii")
    output.symlink_to(occupied)
    monkeypatch.setattr(
        "sys.argv",
        [
            "build_physical_preflight",
            "--plan",
            str(plan),
            "--rc-manifest",
            str(manifest),
            "--output",
            str(output),
        ],
    )
    with pytest.raises(PhysicalPreflightError, match="output_rejected"):
        main()
    assert occupied.read_text(encoding="ascii") == "do not replace"


def test_cli_rejects_writable_output_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_value = _manifest()
    manifest = tmp_path / "rc-manifest.json"
    plan = tmp_path / "plan.json"
    output_root = tmp_path / "mutable"
    output_root.mkdir(mode=0o777)
    output_root.chmod(0o777)
    output = output_root / "preflight.json"
    manifest.write_text(
        json.dumps(manifest_value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    manifest.chmod(0o600)
    plan.write_text(
        json.dumps(_plan(manifest_value), sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    plan.chmod(0o600)
    monkeypatch.setattr(
        "sys.argv",
        [
            "build_physical_preflight",
            "--plan",
            str(plan),
            "--rc-manifest",
            str(manifest),
            "--output",
            str(output),
        ],
    )
    with pytest.raises(PhysicalPreflightError, match="output_rejected"):
        main()
    assert not output.exists()
