"""Install a qualified Matrix wheelhouse offline into a body's private venv.

No seed code, account credentials, identity keys or model calls are involved.
The wheelhouse is covered by the receiving release's content digest.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from . import being_seed, onboarding_release
from .onboarding import OnboardingError, digest, private_directory

SCHEMA = "cluster-onboarding-sdk/v1"
MATRIX_COMMIT = "ca1570aae24cadd2b9fee42bee65be5a4c06e664"
PREVIOUS_MATRIX_COMMIT = "196ec7219f954cf4e514a1f61ae72eb3451d851e"


def wheel(path: Path, *, uid: int) -> dict:
    raw = onboarding_release.regular(path, uid=uid)
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or len(names) > 10000:
            raise OnboardingError("invalid_onboarding_sdk_wheel")
        for name in names:
            parts = PurePosixPath(name).parts
            if (not parts or name.startswith("/") or ".." in parts or "\\" in name
                    or any(part.endswith(".data") for part in parts)):
                raise OnboardingError("invalid_onboarding_sdk_wheel")
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise OnboardingError("invalid_onboarding_sdk_wheel")
        message = BytesParser().parsebytes(archive.read(metadata[0]))
        name, version = message.get("Name", ""), message.get("Version", "")
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", version)
            or not re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", path.name)):
        raise OnboardingError("invalid_onboarding_sdk_wheel")
    return dict(filename=path.name, distribution=re.sub(r"[-_.]+", "-", name).lower(),
                version=version, sha256=hashlib.sha256(raw).hexdigest())


def requirement_lines(rows: list[dict]) -> bytes:
    return "".join(f"{row['distribution']}=={row['version']} --hash=sha256:{row['sha256']}\n"
                   for row in rows).encode()


def verify(code: Path, *, uid: int, matrix_commit: str = MATRIX_COMMIT) -> dict:
    root = code / "sdk"
    value = json.loads(onboarding_release.regular(root / "sdk.json", uid=uid))
    if (not isinstance(value, dict) or set(value) != {"schema", "matrix_commit", "wheels"}
            or matrix_commit not in {MATRIX_COMMIT, PREVIOUS_MATRIX_COMMIT}
            or value["schema"] != SCHEMA or value["matrix_commit"] != matrix_commit
            or not isinstance(value["wheels"], list) or not 1 <= len(value["wheels"]) <= 100):
        raise OnboardingError("invalid_onboarding_sdk")
    found = [wheel(path, uid=uid) for path in sorted((root / "wheels").iterdir())]
    if (value["wheels"] != found or len({row["distribution"] for row in found}) != len(found)
            or sum(row["distribution"] == "daimon-matrix" for row in found) != 1
            or onboarding_release.regular(root / "requirements.txt", uid=uid) != requirement_lines(found)):
        raise OnboardingError("onboarding_sdk_digest_mismatch")
    return value


def _run(argv: list[str]) -> str:
    try:
        result = subprocess.run(argv, capture_output=True, timeout=180, check=False, umask=0o077,
                                env={"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
                                     "PIP_CONFIG_FILE": os.devnull, "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                                     "LD_LIBRARY_PATH": str(Path(sys.base_prefix) / "lib")})
        if result.returncode:
            raise OnboardingError("native_onboarding_sdk_refused")
        return result.stdout.decode()
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        raise OnboardingError("native_onboarding_sdk_refused") from None


def installed(venv: Path, code: Path, value: dict, *, code_uid: int) -> None:
    # Query only stdlib metadata in the isolated interpreter. Do not import an
    # unverified installed SDK, dependency, .pth hook or sitecustomize.
    probe = ("import sys,sysconfig; print(sysconfig.get_path('purelib', scheme='venv', "
             "vars={'base':sys.argv[1], 'platbase':sys.argv[1]}))")
    site = Path(_run([str(venv / "bin/python"), "-I", "-S", "-c", probe, str(venv)]).strip())
    if not site.is_relative_to(venv):
        raise OnboardingError("private_onboarding_sdk_required")
    for row in value["wheels"]:
        path = code / "sdk/wheels" / row["filename"]
        # Recheck artifact ownership/hash before matching each installed byte.
        if wheel(path, uid=code_uid) != row:
            raise OnboardingError("onboarding_sdk_digest_mismatch")
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.is_dir() or member.filename.endswith(".dist-info/RECORD"):
                    continue
                actual = onboarding_release.regular(site / member.filename, uid=os.geteuid())
                if hashlib.sha256(actual).digest() != hashlib.sha256(archive.read(member)).digest():
                    raise OnboardingError("installed_onboarding_sdk_changed")
    _run([str(venv / "bin/python"), "-I", "-m", "pip", "check"])


def observe(home: Path, code: Path, *, code_uid: int = 0,
            matrix_commit: str = MATRIX_COMMIT) -> Path:
    value = verify(code, uid=code_uid, matrix_commit=matrix_commit)
    root = home / ".local/share/daimon-matrix/sdk" / digest(value)
    private_directory(root)
    expected = dict(schema="cluster-onboarding-sdk-installation/v1", sdk_digest=digest(value),
                    matrix_commit=value['matrix_commit'], wheel_count=len(value["wheels"]))
    if being_seed._read(root / "installation.json") != expected:
        raise OnboardingError("installed_onboarding_sdk_changed")
    installed(root / "venv", code, value, code_uid=code_uid)
    return root / "venv"


def install(home: Path, code: Path, release_digest: str, *, code_uid: int = 0,
            matrix_commit: str = MATRIX_COMMIT) -> Path:
    onboarding_release.verify(code, release_digest, uid=code_uid)
    value = verify(code, uid=code_uid, matrix_commit=matrix_commit)
    private_directory(home)
    parent = home / ".local/share/daimon-matrix/sdk"
    current = home
    for part in parent.relative_to(home).parts:
        current /= part
        private_directory(current, create=True)
    root = parent / digest(value)
    private_directory(root, create=True)
    receipt = root / "installation.json"
    venv = root / "venv"
    with being_seed._locked(root):
        expected = dict(schema="cluster-onboarding-sdk-installation/v1", sdk_digest=digest(value),
                        matrix_commit=value['matrix_commit'], wheel_count=len(value["wheels"]))
        if receipt.exists():
            if being_seed._read(receipt) != expected:
                raise OnboardingError("installed_onboarding_sdk_changed")
            installed(venv, code, value, code_uid=code_uid)
            return venv
        if venv.exists():
            private_directory(venv)
        # Before completion only dependency installation may be replayed. No
        # runtime/custody is created in this directory and completed SDK bytes
        # are never repaired by overwriting them.
        _run([sys.executable, "-I", "-m", "venv", str(venv)])
        venv.chmod(0o700)
        _run([str(venv / "bin/python"), "-I", "-m", "pip", "install", "--no-index",
              "--no-deps", "--require-hashes", "--only-binary=:all:", "--no-cache-dir",
              "--force-reinstall", "--find-links", str(code / "sdk/wheels"),
              "--requirement", str(code / "sdk/requirements.txt")])
        installed(venv, code, value, code_uid=code_uid)
        being_seed._write(receipt, expected)
        return venv
