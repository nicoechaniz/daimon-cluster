"""Regression coverage for the deployed release and backup boundary."""

from __future__ import annotations

import os
import json
import re
import subprocess
import sys
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

    clusterd_unit = (ROOT / "configs/clusterd.service").read_text()
    assert (
        "ExecStartPre=/usr/bin/python3 "
        "/opt/daimon-cluster/scripts/wait-private-bind.py "
        "--address 10.105.93.1 --timeout 30"
    ) in clusterd_unit


def test_rebirth_unit_preserves_admission_and_credential_boundaries() -> None:
    unit = (ROOT / "configs/daimon-matrix-rebirth@.service").read_text()

    assert "User=clusterd" in unit
    assert "Group=clusterd" in unit
    assert (
        "LoadCredential=matrix-password:"
        "/etc/daimon-matrix/rebirth/%i.password"
    ) in unit
    assert "-m clusterctl.rebirth_host" in unit
    assert '--embodiment-id "$1"' in unit
    assert "--password-fd 3" in unit
    assert "--production-fence-verifier" in unit
    assert '3<"$CREDENTIALS_DIRECTORY/matrix-password"' in unit
    assert "Requires=clusterd.service" in unit

    for boundary in (
        "UMask=0077",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ReadOnlyPaths=/opt/daimon-cluster",
        "ReadWritePaths=/var/lib/daimon-cluster",
        "RestrictSUIDSGID=true",
        "LockPersonality=true",
    ):
        assert boundary in unit

    assert "EnvironmentFile=" not in unit
    assert "--password " not in unit
    assert "-m clusterctl.matrix_host" not in unit
    assert "daimon-matrixd" not in unit


def _mirror_fixture(tmp_path: Path) -> tuple[dict[str, str], Path, str]:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    receipts = tmp_path / "receipts"
    credentials = tmp_path / "credentials"
    for path in (
        source / "data",
        source / "index",
        source / "keys",
        source / "locks",
        source / "snapshots" / "ab",
        destination,
        receipts,
        credentials,
    ):
        path.mkdir(parents=True, exist_ok=True)
    destination.chmod(0o700)
    (source / "config").write_text("synthetic encrypted repo\n")
    (source / "data" / "payload").write_bytes(b"ciphertext")
    snapshot_id = "ab" + ("c" * 62)
    (source / "snapshots" / "ab" / ("c" * 62)).write_bytes(b"snapshot")
    key = credentials / "source-key"
    key.write_text("fixture-private-key\n")
    key.chmod(0o600)
    (credentials / "source-known-hosts").write_text(
        "source.example ssh-ed25519 AAAAfixture\n"
    )
    fake_rsync = _executable(
        tmp_path / "rsync",
        """#!/usr/bin/env bash
set -eu
printf 'RSH=%s\nARGS=%s\n' "$RSYNC_RSH" "$*" > "$MIRROR_RSYNC_LOG"
if [[ "${MIRROR_RSYNC_FAIL:-0}" == 1 ]]; then exit 9; fi
dest="${!#}"
cp -a "$MIRROR_FIXTURE_SOURCE/." "$dest"
""",
    )
    env = {
        **os.environ,
        "MIRROR_SOURCE": "mirror@source.example",
        "MIRROR_DEST": str(destination),
        "MIRROR_RECEIPT": str(receipts / "source.json"),
        "MIRROR_CREDENTIALS_DIR": str(credentials),
        "MIRROR_FIXTURE_SOURCE": str(source),
        "MIRROR_RSYNC_LOG": str(tmp_path / "rsync.log"),
        "RSYNC_BIN": str(fake_rsync),
        "SSH_BIN": "/usr/bin/ssh",
    }
    return env, destination, snapshot_id


def test_mirror_pull_is_read_only_pinned_and_content_addressed(tmp_path: Path) -> None:
    env, destination, snapshot_id = _mirror_fixture(tmp_path)
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/restic-mirror-pull.sh")],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    receipt = json.loads(Path(env["MIRROR_RECEIPT"]).read_text())
    assert receipt["schema"] == "dm.cluster-mirror-receipt/v1"
    assert receipt["latest_snapshot_id"] == snapshot_id
    assert receipt["status"] == "ok"
    assert receipt["file_count"] == 3
    assert receipt["byte_count"] > 0
    assert len(receipt["tree_sha256"]) == 64
    assert (destination / "data" / "payload").read_bytes() == b"ciphertext"

    rsync = Path(env["MIRROR_RSYNC_LOG"]).read_text()
    assert "--delete-delay" in rsync
    assert "--delay-updates" in rsync
    assert "--partial-dir=.rsync-partial" in rsync
    assert f"--link-dest={destination}" in rsync
    assert "mirror@source.example:/" in rsync
    assert f"-i {env['MIRROR_CREDENTIALS_DIR']}/source-key" in rsync
    assert "StrictHostKeyChecking=yes" in rsync
    assert "UserKnownHostsFile=" in rsync


def test_mirror_failure_preserves_last_good_receipt_and_marks_error(tmp_path: Path) -> None:
    env, _destination, _snapshot_id = _mirror_fixture(tmp_path)
    receipt = Path(env["MIRROR_RECEIPT"])
    receipt.write_text('{"status":"previous-ok"}\n')
    env["MIRROR_RSYNC_FAIL"] = "1"
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/restic-mirror-pull.sh")],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 9
    assert json.loads(receipt.read_text()) == {"status": "previous-ok"}
    error = json.loads(Path(f"{receipt}.last-error").read_text())
    assert error == {
        "schema": "dm.cluster-mirror-error/v1",
        "status": "failed",
        "exit_code": 9,
    }


def test_mirror_rejects_unsafe_key_and_mirrored_symlink(tmp_path: Path) -> None:
    env, destination, _snapshot_id = _mirror_fixture(tmp_path)
    key = Path(env["MIRROR_CREDENTIALS_DIR"]) / "source-key"
    key.chmod(0o644)
    unsafe_key = subprocess.run(
        ["bash", str(ROOT / "scripts/restic-mirror-pull.sh")],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert unsafe_key.returncode == 2
    assert unsafe_key.stderr == "mirror_key_permissions_unsafe\n"
    assert not Path(env["MIRROR_RSYNC_LOG"]).exists()

    key.chmod(0o600)
    source = Path(env["MIRROR_FIXTURE_SOURCE"])
    (source / "data" / "escape").symlink_to("/etc/passwd")
    unsafe_tree = subprocess.run(
        ["bash", str(ROOT / "scripts/restic-mirror-pull.sh")],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert unsafe_tree.returncode == 3
    assert "mirror_repository_symlink_rejected" in unsafe_tree.stderr
    assert not (destination / "data" / "escape").exists()


def test_mirror_systemd_assets_are_unprivileged_and_secret_free() -> None:
    service = (ROOT / "configs/daimon-restic-mirror@.service").read_text()
    timer = (ROOT / "configs/daimon-restic-mirror@.timer").read_text()
    assert "User=daimon-backup" in service
    assert "Group=daimon-backup" in service
    assert "LoadCredential=source-key:" in service
    assert "LoadCredential=source-known-hosts:" in service
    assert "ReadWritePaths=/srv/daimon-backups" in service
    assert "CapabilityBoundingSet=" in service
    assert "RESTIC_PASSWORD" not in service
    assert "PrivateDevices=true" in service
    assert "Persistent=true" in timer
    subprocess.run(
        ["bash", "-n", str(ROOT / "scripts/restic-mirror-pull.sh")], check=True
    )


def test_executable_assets_cannot_mutate_administrative_ssh_access() -> None:
    protected_roots = (
        "/root/.ssh",
        "/home/root/.ssh",
        "/home/debian/.ssh",
        "/home/nicolas/.ssh",
    )
    executable_roots = (
        ROOT / "scripts",
        ROOT / "configs",
        ROOT / "clusterctl",
        ROOT / "clusterd",
        ROOT / "steward_tools",
    )

    for directory in executable_roots:
        for path in directory.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            assert "authorized_keys" not in content, path
            for line in content.splitlines():
                if not any(protected in line for protected in protected_roots):
                    continue
                assert re.search(r"(?<![012])>(?!&)", line) is None, (path, line)
                for mutation in (
                    "tee ",
                    "sed -i",
                    "cp ",
                    "mv ",
                    "install ",
                    "chmod ",
                    "chown ",
                    "truncate ",
                ):
                    assert mutation not in line, (path, line)

    rules = " ".join((ROOT / "AGENTS.md").read_text().split())
    assert "must not modify an existing administrative login path" in rules
    assert "timed automatic rollback" in rules
    assert "second fresh session" in rules

    runbook = (ROOT / "docs/runbooks/second-offhost-mirror.md").read_text()
    assert "dedicated `daimon-backup-export` identity" in runbook
    assert "must never add, remove, rewrite" in runbook
    assert "contains no authorized installer" in runbook


def test_private_bind_wait_is_bounded_and_disclosure_safe() -> None:
    script = ROOT / "scripts/wait-private-bind.py"
    ready = subprocess.run(
        [
            sys.executable,
            str(script),
            "--address",
            "127.0.0.1",
            "--timeout",
            "0.1",
            "--interval",
            "0.01",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert ready.returncode == 0, ready.stderr

    missing = subprocess.run(
        [
            sys.executable,
            str(script),
            "--address",
            "192.0.2.1",
            "--timeout",
            "0.05",
            "--interval",
            "0.01",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert missing.returncode == 1
    assert missing.stdout == ""
    assert missing.stderr == "bind_address_unavailable\n"
