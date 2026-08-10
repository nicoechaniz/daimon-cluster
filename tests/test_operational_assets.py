"""Regression coverage for the deployed release and backup boundary."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _executable(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _backup_fixture(tmp_path: Path, *, fail_backup: bool = False) -> tuple[dict[str, str], Path, Path]:
    state = tmp_path / "state"
    deploy = tmp_path / "deploy"
    matrix_etc = tmp_path / "matrix-etc"
    units = tmp_path / "units"
    pool = tmp_path / "pool"
    for path in (state / "instances", deploy, matrix_etc, units, pool):
        path.mkdir(parents=True)
    (state / "instances" / "steward.yaml").write_text("name: steward\n")
    (pool / "default_steward-home").mkdir()
    for name in (
        "clusterd.service",
        "daimon-matrix-compaii.service",
        "restic-backup.service",
        "restic-backup.timer",
    ):
        (units / name).write_text("fixture\n")

    systemctl_log = tmp_path / "systemctl.log"
    restic_log = tmp_path / "restic.log"
    fake_systemctl = _executable(
        tmp_path / "systemctl",
        """#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$SYSTEMCTL_LOG"
case "$1" in
  list-units) printf '%s\n' 'daimon-matrix-compaii.service loaded active running fixture' ;;
  is-active) exit 0 ;;
  stop|start) exit 0 ;;
  *) exit 64 ;;
esac
""",
    )
    fake_restic = _executable(
        tmp_path / "restic",
        f"""#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$RESTIC_LOG"
[[ "$1" == backup ]] && exit {9 if fail_backup else 0}
exit 0
""",
    )
    env = {
        **os.environ,
        "DAIMON_CLUSTER_STATE_DIR": str(state),
        "DAIMON_CLUSTER_DEPLOY_DIR": str(deploy),
        "DAIMON_MATRIX_ETC_DIR": str(matrix_etc),
        "SYSTEMD_UNIT_DIR": str(units),
        "INCUS_POOL_DIR": str(pool),
        "RESTIC_REPOSITORY": str(state / "restic-repo"),
        "RESTIC_PASSWORD": "fixture-only",
        "SYSTEMCTL_BIN": str(fake_systemctl),
        "RESTIC_BIN": str(fake_restic),
        "SYSTEMCTL_LOG": str(systemctl_log),
        "RESTIC_LOG": str(restic_log),
    }
    return env, systemctl_log, restic_log


def test_backup_quiesces_complete_boundary_and_resumes_in_order(tmp_path: Path) -> None:
    env, systemctl_log, restic_log = _backup_fixture(tmp_path)
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/restic-backup.sh")],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    calls = systemctl_log.read_text().splitlines()
    assert calls.index("stop daimon-matrix-compaii.service") < calls.index(
        "stop clusterd.service"
    )
    assert calls.index("start clusterd.service") < calls.index(
        "start daimon-matrix-compaii.service"
    )
    restic = restic_log.read_text()
    assert f"backup {env['DAIMON_CLUSTER_STATE_DIR']}" in restic
    assert env["DAIMON_CLUSTER_DEPLOY_DIR"] in restic
    assert env["DAIMON_MATRIX_ETC_DIR"] in restic
    assert f"--exclude {env['RESTIC_REPOSITORY']}" in restic
    assert f"--exclude {env['DAIMON_CLUSTER_STATE_DIR']}/backup-keys" in restic
    assert "forget --keep-daily 7 --keep-weekly 4 --prune" in restic
    assert restic.rstrip().endswith("check")


def test_backup_failure_still_resumes_previously_active_services(tmp_path: Path) -> None:
    env, systemctl_log, _restic_log = _backup_fixture(tmp_path, fail_backup=True)
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/restic-backup.sh")],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 9
    calls = systemctl_log.read_text().splitlines()
    assert calls[-2:] == [
        "start clusterd.service",
        "start daimon-matrix-compaii.service",
    ]


def test_check_only_accepts_password_file_without_stopping_services(
    tmp_path: Path,
) -> None:
    env, systemctl_log, restic_log = _backup_fixture(tmp_path)
    env.pop("RESTIC_PASSWORD")
    password = tmp_path / "password"
    password.write_text("fixture-only\n")
    env["RESTIC_PASSWORD_FILE"] = str(password)
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/restic-backup.sh"), "--check-only"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not systemctl_log.exists()
    assert restic_log.read_text().splitlines() == ["snapshots --latest 1"]


def test_deploy_and_unit_assets_pin_the_final_release_boundary() -> None:
    runbook = (ROOT / "docs/runbooks/clusterd-deploy.md").read_text()
    install = next(line for line in runbook.splitlines() if "sudo rsync" in line)
    for asset in ("clusterd", "clusterctl", "configs", "scripts", "steward_tools"):
        assert asset in install
    assert "Never copy or rename a prepared virtualenv" in runbook
    assert "#!/opt/daimon-cluster/venv/bin/python" in runbook

    unit = (ROOT / "configs/restic-backup.service").read_text()
    assert "ExecStart=/opt/daimon-cluster/scripts/restic-backup.sh" in unit
    assert "RESTIC_PASSWORD_FILE=" in unit
    assert "/home/" not in unit

    subprocess.run(
        ["bash", "-n", str(ROOT / "scripts/restic-backup.sh")], check=True
    )
