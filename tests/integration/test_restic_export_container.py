"""Adversarial disposable-host proof for the dedicated backup exporter."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(
    os.environ.get("DAIMON_RUN_DOCKER_TESTS") != "1",
    reason="set DAIMON_RUN_DOCKER_TESTS=1 for the disposable Docker proof",
)


def _run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, text=True, capture_output=True, **kwargs)


def _ssh_arguments(key: Path, known_hosts: Path, port: str) -> list[str]:
    return [
        "ssh",
        "-F",
        "/dev/null",
        "-i",
        str(key),
        "-p",
        port,
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "ConnectTimeout=5",
    ]


def _admin_login(ssh: list[str], container: str) -> None:
    result = _run([*ssh, "admin-test@127.0.0.1", "printf admin-ok"], check=False)
    if result.returncode != 0:
        logs = _run(["docker", "logs", container], check=False)
        pytest.fail(f"{result.stderr}\ncontainer logs:\n{logs.stdout}\n{logs.stderr}")
    assert result.stdout == "admin-ok"


def test_export_identity_failure_cannot_change_admin_access(tmp_path: Path) -> None:
    test_id = uuid.uuid4().hex[:12]
    image = f"daimon-restic-export-test:{test_id}"
    container = f"daimon-restic-export-test-{test_id}"
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    admin_key = tmp_path / "admin-key"
    export_key = tmp_path / "export-key"
    for key in (admin_key, export_key):
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
    shutil.copyfile(admin_key.with_suffix(".pub"), fixture / "admin.pub")

    bundle = fixture / "bundle"
    rendered = _run(
        [
            "python3",
            str(ROOT / "scripts/restic-export-preflight.py"),
            "render",
            "--public-key",
            str(export_key.with_suffix(".pub")),
            "--output",
            str(bundle),
        ],
        check=False,
    )
    assert rendered.returncode == 0, rendered.stderr
    bundle_sha256 = rendered.stdout.strip().removeprefix("bundle_sha256=")

    repository = fixture / "repository"
    repository.mkdir()
    (repository / "config").write_text("synthetic encrypted config\n")
    (repository / "payload").write_bytes(b"synthetic ciphertext\n")
    (repository / "snapshot").write_bytes(b"synthetic snapshot\n")

    try:
        built = _run(
            [
                "docker",
                "build",
                "--tag",
                image,
                "--file",
                str(ROOT / "tests/integration/restic-export/Dockerfile"),
                str(ROOT),
            ],
            check=False,
        )
        assert built.returncode == 0, built.stderr
        started = _run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                container,
                "--publish",
                "127.0.0.1::2222",
                "--env",
                "DAIMON_DISPOSABLE_TEST_ONLY=yes",
                "--env",
                f"EXPORT_BUNDLE_SHA256={bundle_sha256}",
                "--volume",
                f"{fixture}:/fixture:ro",
                image,
            ],
            check=False,
        )
        assert started.returncode == 0, started.stderr
        port_result = _run(
            ["docker", "port", container, "2222/tcp"], check=False
        )
        assert port_result.returncode == 0, port_result.stderr
        port = port_result.stdout.strip().rsplit(":", maxsplit=1)[1]
        known_hosts = tmp_path / "known-hosts"
        for _attempt in range(50):
            scanned = _run(
                ["ssh-keyscan", "-p", port, "127.0.0.1"], check=False
            )
            if scanned.returncode == 0 and scanned.stdout:
                known_hosts.write_text(scanned.stdout)
                break
            time.sleep(0.1)
        else:
            logs = _run(["docker", "logs", container], check=False)
            pytest.fail(f"disposable sshd did not start:\n{logs.stdout}\n{logs.stderr}")

        admin_ssh = _ssh_arguments(admin_key, known_hosts, port)
        export_ssh = _ssh_arguments(export_key, known_hosts, port)
        _admin_login(admin_ssh, container)
        original_admin_hash = _run(
            [
                "docker",
                "exec",
                container,
                "sha256sum",
                "/etc/daimon-test/admin-test-keys",
            ],
            check=True,
        ).stdout.split()[0]

        effective = _run(
            [
                "docker",
                "exec",
                container,
                "/usr/sbin/sshd",
                "-T",
                "-f",
                "/etc/ssh/sshd_config",
                "-C",
                "user=daimon-backup-export,host=localhost,addr=127.0.0.1",
            ],
            check=True,
        ).stdout
        assert "forcecommand /opt/daimon-cluster/scripts/restic-export-command.sh" in effective
        assert "authorizedkeysfile /etc/daimon-backup/export-keys" in effective
        assert "disableforwarding yes" in effective
        assert "permittty no" in effective

        destination = tmp_path / "mirror"
        destination.mkdir()
        rsync_rsh = " ".join(export_ssh)
        pulled = _run(
            [
                "rsync",
                "--archive",
                "--rsh",
                rsync_rsh,
                "daimon-backup-export@127.0.0.1:/",
                f"{destination}/",
            ],
            check=False,
        )
        assert pulled.returncode == 0, pulled.stderr
        assert (destination / "data/payload").read_bytes() == b"synthetic ciphertext\n"

        shell = _run(
            [*export_ssh, "daimon-backup-export@127.0.0.1", "id"], check=False
        )
        assert shell.returncode != 0
        tty = _run(
            [
                *export_ssh,
                "-tt",
                "daimon-backup-export@127.0.0.1",
                "id",
            ],
            check=False,
        )
        assert tty.returncode != 0
        forwarding = _run(
            [
                *export_ssh,
                "-W",
                "127.0.0.1:22",
                "daimon-backup-export@127.0.0.1",
            ],
            check=False,
        )
        assert forwarding.returncode != 0
        upload_source = tmp_path / "upload"
        upload_source.write_text("must not arrive\n")
        upload = _run(
            [
                "rsync",
                "--archive",
                "--rsh",
                rsync_rsh,
                str(upload_source),
                "daimon-backup-export@127.0.0.1:/incoming",
            ],
            check=False,
        )
        assert upload.returncode != 0
        escaped = _run(
            [
                "rsync",
                "--archive",
                "--rsh",
                rsync_rsh,
                "daimon-backup-export@127.0.0.1:/../etc/",
                f"{tmp_path / 'escape'}/",
            ],
            check=False,
        )
        assert escaped.returncode != 0

        revoked = _run(
            [
                "docker",
                "exec",
                container,
                "install",
                "-o",
                "root",
                "-g",
                "daimon-backup-export",
                "-m",
                "0640",
                "/dev/null",
                "/etc/daimon-backup/export-keys",
            ],
            check=False,
        )
        assert revoked.returncode == 0, revoked.stderr
        _admin_login(admin_ssh, container)
        assert _run(
            [*export_ssh, "daimon-backup-export@127.0.0.1", "id"], check=False
        ).returncode != 0

        restored = _run(
            [
                "docker",
                "exec",
                container,
                "install",
                "-o",
                "root",
                "-g",
                "daimon-backup-export",
                "-m",
                "0640",
                "/fixture/bundle/export-keys",
                "/etc/daimon-backup/export-keys",
            ],
            check=False,
        )
        assert restored.returncode == 0, restored.stderr
        deleted = _run(
            ["docker", "exec", container, "userdel", "daimon-backup-export"],
            check=False,
        )
        assert deleted.returncode == 0, deleted.stderr
        _admin_login(admin_ssh, container)
        assert _run(
            [*export_ssh, "daimon-backup-export@127.0.0.1", "id"], check=False
        ).returncode != 0

        final_admin_hash = _run(
            [
                "docker",
                "exec",
                container,
                "sha256sum",
                "/etc/daimon-test/admin-test-keys",
            ],
            check=True,
        ).stdout.split()[0]
        assert final_admin_hash == original_admin_hash
        assert original_admin_hash == hashlib.sha256(
            (fixture / "admin.pub").read_bytes()
        ).hexdigest()
        evidence = {
            "schema": "dm.restic-export-disposable-proof/v1",
            "bundle_sha256": bundle_sha256,
            "admin_key_sha256": original_admin_hash,
            "read_only_pull": "ok",
            "shell": "denied",
            "tty": "denied",
            "forwarding": "denied",
            "upload": "denied",
            "path_escape": "denied",
            "revocation_admin_login": "ok",
            "account_deletion_admin_login": "ok",
        }
        print(json.dumps(evidence, sort_keys=True))
    finally:
        _run(["docker", "rm", "--force", container], check=False)
        _run(["docker", "image", "rm", "--force", image], check=False)
