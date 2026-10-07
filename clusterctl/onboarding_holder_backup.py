"""One holder's native encrypted backup, restore and typed signature witness.

Invoked in a separate protected process. It never opens another role's holder,
exports a private seed, or includes the unlock path in the encrypted backup.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
from pathlib import Path

from . import being_seed
from .onboarding import OnboardingError, digest, private_directory, validate_plan
from .onboarding_custody import document

BACKUP_SCHEMA = "cluster-onboarding-holder-backup/v1"
FILES = ("holder.json", "descriptor.json", ".holder.json.highwater", ".holder.json.lock")


def private_bytes(path: Path) -> bytes:
    being_seed._path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size > 16 * 1024**2):
            raise OnboardingError("private_onboarding_custody_required")
        return stream.read()


def inventory(path: Path) -> dict[str, str]:
    private_directory(path)
    for item in path.iterdir():
        if item.name not in FILES:
            # Native atomic-write remnants are preserved after a killed child;
            # they are not portable package members. Never admit an unlock or
            # unrelated file into a qualified holder backup.
            if not re.fullmatch(r"\.(?:holder\.json|descriptor\.json|\.holder\.json\.highwater)\.tmp-[0-9a-f]{24}", item.name):
                raise OnboardingError("onboarding_holder_backup_conflict")
            private_bytes(item)
    if private_bytes(path / ".holder.json.lock") != b"":
        raise OnboardingError("onboarding_holder_backup_conflict")
    return {name: hashlib.sha256(private_bytes(path / name)).hexdigest() for name in FILES}


def backup_restore(root: Path, role: str, reader) -> dict:
    from daimon_matrix import canonical, keystore, operator_genesis

    if role not in {"root", "recovery"}:
        raise OnboardingError("invalid_onboarding_holder_role")
    private_directory(root)
    plan = validate_plan(being_seed._read(root / "plan.json"))
    if root.name != digest(plan):
        raise OnboardingError("onboarding_custody_plan_conflict")
    source = private_directory(root / role)
    backup = private_directory(root / ("backup-" + role), create=True)
    restored = private_directory(root / ("restore-" + role), create=True)
    original = inventory(source)
    descriptor = document(source / "descriptor.json")
    if descriptor.get("role") != role or descriptor.get("schema") != operator_genesis.HOLDER_SCHEMA:
        raise OnboardingError("onboarding_holder_backup_conflict")
    store = keystore.EncryptedKeystore(source / "holder.json")
    contents = store.open(reader, minimum_counter=1, required_control_head=operator_genesis.PENDING_CONTROL_HEAD)
    if contents.counter != 1:
        raise OnboardingError("onboarding_holder_backup_conflict")

    def unchanged_or_write(path: Path, data: bytes) -> None:
        # The parent job/custody lock owns this new tree. Existing ciphertext or
        # rollback state is never replaced to make a retry pass.
        if path.exists() or path.is_symlink():
            if private_bytes(path) != data:
                raise OnboardingError("onboarding_holder_backup_conflict")
        else:
            keystore._atomic_write(path, data)

    if not (backup / "holder.json").exists():
        store.backup(backup / "holder.json", reader, minimum_counter=1)
    if private_bytes(backup / "holder.json") != private_bytes(source / "holder.json"):
        raise OnboardingError("onboarding_holder_backup_conflict")
    for name in FILES[1:]:
        unchanged_or_write(backup / name, private_bytes(source / name))
    if inventory(backup) != original:
        raise OnboardingError("onboarding_holder_backup_conflict")
    if not (restored / "holder.json").exists():
        keystore.EncryptedKeystore.restore(backup / "holder.json", restored / "holder.json", reader,
            public_counter=1, public_control_head=operator_genesis.PENDING_CONTROL_HEAD)
    if private_bytes(restored / "holder.json") != private_bytes(backup / "holder.json"):
        raise OnboardingError("onboarding_holder_backup_conflict")
    # Native restore recreates rollback state; a crash before that publication
    # may leave it missing. Reconcile only the independently preserved exact
    # counter metadata, never a lower or different high-water.
    for name in FILES[1:]:
        unchanged_or_write(restored / name, private_bytes(backup / name))
    if inventory(restored) != original:
        raise OnboardingError("onboarding_holder_backup_conflict")
    def publish(path: Path, value: dict) -> None:
        if path.exists():
            if document(path) != value:
                raise OnboardingError("onboarding_holder_backup_conflict")
        else:
            keystore._atomic_write(path, canonical.canonical_bytes(value))
    witness = operator_genesis.create_holder_share(document(root / "intent.json"), restored, reader)
    publish(root / ("restored-" + role + "-share.json"), witness)
    result = {"schema": BACKUP_SCHEMA, "plan_digest": digest(plan), "role": role,
              "key_id": descriptor["key"]["key_id"], "counter": 1,
              "control_head": operator_genesis.PENDING_CONTROL_HEAD, "files": original,
              "witness_digest": digest(witness)}
    publish(root / (role + "-backup-receipt.json"), result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ceremony-root", type=Path, required=True)
    parser.add_argument("--role", choices=("root", "recovery"), required=True)
    parser.add_argument("--password-fd", type=int, required=True)
    args = parser.parse_args(argv)
    password = bytearray()
    try:
        from .matrix_host import _matrix_api
        from daimon_matrix import operator_genesis

        _matrix_api()
        password = operator_genesis._password(args.password_fd)
        backup_restore(args.ceremony_root, args.role, operator_genesis._reader(password))
        return 0
    except Exception:
        # The parent gets only the exit code; no key, schema or path diagnostics.
        return 1
    finally:
        password[:] = b"\0" * len(password)


if __name__ == "__main__":
    raise SystemExit(main())
