#!/usr/bin/env python3
"""Explicit, selective installation of skill bytes from an immutable Git commit.

No networking, subprocess shell, harness launch, policy change or memory access.
Fetch the reviewed commit separately through the repository's authorized remote.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path, PurePosixPath

REPOSITORY = "AlterMundi/Skills"
MAX_FILES = 512
MAX_BYTES = 8 * 1024 * 1024
NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


class Conflict(ValueError):
    pass


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def closed(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError("invalid_document_fields")
    return value


def path_name(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError("invalid_package_name")
    return value


def relative(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("invalid_relative_path")
    p = PurePosixPath(value)
    if p.is_absolute() or str(p) != value or any(x in {".", ".."} for x in p.parts):
        raise ValueError("invalid_relative_path")
    return value


def read_json(path):
    if Path(path).is_symlink():
        raise ValueError("symlink_document")

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate_json_key")
            out[key] = value
        return out

    return json.loads(Path(path).read_bytes(), object_pairs_hook=pairs)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_dir(path):
    path = Path(path).absolute()
    # Check existing ancestors before mkdir can follow a substituted link.
    for parent in reversed((path, *path.parents)):
        if parent.is_symlink():
            raise ValueError("symlink_directory")
    for parent in reversed((path, *path.parents)):
        if not parent.exists():
            parent.mkdir(mode=0o700)
            sync_dir(parent.parent)
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError("unsafe_directory")
    return path


def write_json(path, value):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("symlink_state")
    temp = path.parent / (".write-" + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_dir(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL
    )


def remote_repository(repo):
    url = git(repo, "config", "--get", "remote.origin.url").decode().strip()
    allowed = {
        "https://github.com/AlterMundi/Skills.git",
        "https://github.com/AlterMundi/Skills",
        "git@github.com:AlterMundi/Skills.git",
        "ssh://git@github.com/AlterMundi/Skills.git",
    }
    if url not in allowed:
        raise ValueError("repository_mismatch")


def source_package(repo, commit, name):
    path_name(name)
    prefix = f"skills/{name}/"
    rows = git(repo, "ls-tree", "-rz", commit, "--", prefix).split(b"\0")
    files, blobs, total = {}, {}, 0
    for row in rows:
        if not row:
            continue
        meta, rawpath = row.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        sourcepath = rawpath.decode("utf-8")
        if (
            not sourcepath.startswith(prefix)
            or kind != "blob"
            or mode not in {"100644", "100755"}
        ):
            raise ValueError("unsafe_git_entry")
        rel = relative(sourcepath[len(prefix) :])
        size = int(git(repo, "cat-file", "-s", oid).decode())
        total += size
        if total > MAX_BYTES or len(files) >= MAX_FILES:
            raise ValueError("package_limit_exceeded")
        raw = git(repo, "cat-file", "blob", oid)
        files[rel] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": size,
            "executable": mode == "100755",
        }
        blobs[rel] = raw
    if "SKILL.md" not in files or "package.json" not in files:
        raise ValueError("missing_package_metadata")
    metadata = json.loads(blobs["package.json"])
    closed(metadata, {"schema", "name", "version", "auxiliary_skills"})
    if metadata["schema"] != "altermundi.skill-package/v1" or metadata["name"] != name:
        raise ValueError("package_metadata_mismatch")
    if not isinstance(metadata["version"], str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+", metadata["version"]
    ):
        raise ValueError("invalid_version")
    if not isinstance(metadata["auxiliary_skills"], list):
        raise TypeError("invalid_auxiliary_skills")
    for auxiliary in metadata["auxiliary_skills"]:
        if relative(auxiliary) not in files or not auxiliary.endswith("/SKILL.md"):
            raise ValueError("missing_auxiliary_skill")
    return {"name": name, "version": metadata["version"], "files": files}, blobs


def describe(repo, commit, names):
    if (
        not isinstance(commit, str)
        or not COMMIT.fullmatch(commit)
        or not names
        or len(set(names)) != len(names)
    ):
        raise ValueError("invalid_selection")
    remote_repository(repo)
    if git(repo, "rev-parse", commit + "^{commit}").decode().strip() != commit:
        raise ValueError("commit_mismatch")
    packages = [source_package(repo, commit, name)[0] for name in sorted(names)]
    return {
        "schema": "altermundi.skill-update/v1",
        "repository": REPOSITORY,
        "commit": commit,
        "packages": packages,
    }


def validate_descriptor(repo, value):
    closed(value, {"schema", "repository", "commit", "packages"})
    if (
        value["schema"] != "altermundi.skill-update/v1"
        or value["repository"] != REPOSITORY
    ):
        raise ValueError("descriptor_repository_mismatch")
    if not isinstance(value["packages"], list) or not 1 <= len(value["packages"]) <= 32:
        raise ValueError("invalid_package_selection")
    for package in value["packages"]:
        closed(package, {"name", "version", "files"})
        path_name(package["name"])
    expected = describe(repo, value["commit"], [x["name"] for x in value["packages"]])
    if canonical(expected) != canonical(value):
        raise ValueError("descriptor_content_mismatch")


def snapshot(path):
    path = Path(path)
    if path.is_symlink():
        raise Conflict("local_symlink")
    if not path.exists():
        return None
    if not path.is_dir():
        raise Conflict("local_not_directory")
    files, total = {}, 0
    for folder, dirs, names in os.walk(path, followlinks=False):
        for name in dirs + names:
            entry = Path(folder) / name
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode) or not (
                stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
            ):
                raise Conflict("local_unsafe_entry")
            if stat.S_ISDIR(info.st_mode):
                continue
            total += info.st_size
            if total > MAX_BYTES or len(files) >= MAX_FILES:
                raise Conflict("local_package_limit_exceeded")
            raw = entry.read_bytes()
            files[entry.relative_to(path).as_posix()] = {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
                "executable": bool(info.st_mode & 0o111),
            }
    return files


@contextlib.contextmanager
def locked(state):
    state = private_dir(state)
    if state.stat().st_mode & 0o077:
        raise ValueError("state_not_private")
    fd = os.open(state / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield state
    finally:
        os.close(fd)


def record(state, name):
    path = state / (path_name(name) + ".json")
    if path.is_symlink():
        raise ValueError("symlink_state")
    return read_json(path) if path.exists() else None


def _validate_reconciliation(repo, baseline):
    """Reconcile only known managed files, never unmanaged/private additions."""
    conflicts = baseline["conflicts"]
    if not conflicts or any(item["reason"] != "local_changes" for item in conflicts):
        raise Conflict("reviewed_baseline_unsupported")
    for package in baseline["descriptor"]["packages"]:
        name = package["name"]
        previous = baseline["previous_records"][name]
        if previous is None:
            raise Conflict("reviewed_baseline_unmanaged")
        closed(previous, {"transaction", "root", "descriptor", "files"})
        validate_descriptor(repo, previous["descriptor"])
        retained = next(
            (row for row in previous["descriptor"]["packages"] if row["name"] == name),
            None,
        )
        before = baseline["expected"][name]
        if (
            previous["root"] != baseline["root"]
            or retained is None
            or retained["files"] != previous["files"]
            or before is None
            or any(
                path not in previous["files"] and entry != package["files"].get(path)
                for path, entry in before.items()
            )
        ):
            raise Conflict("reviewed_baseline_unsafe")


def prepare(
    repo, descriptor, root, state_path, adopt_existing=False, reviewed_plan_sha256=None
):
    validate_descriptor(repo, descriptor)
    root = private_dir(root)
    with locked(state_path) as state:
        expected, records, conflicts = {}, {}, []
        for package in descriptor["packages"]:
            name = package["name"]
            before, previous = snapshot(root / name), record(state, name)
            expected[name], records[name] = before, previous
            if previous is not None and previous["root"] != str(root):
                conflicts.append({"package": name, "reason": "state_root_mismatch"})
            elif previous is not None and before != previous["files"]:
                conflicts.append({"package": name, "reason": "local_changes"})
            elif before is not None and previous is None and not adopt_existing:
                conflicts.append(
                    {"package": name, "reason": "unmanaged_existing_package"}
                )
        plan = {
            "schema": "altermundi.skill-install-plan/v1",
            "descriptor": descriptor,
            "root": str(root),
            "state": str(state),
            "expected": expected,
            "previous_records": records,
            "conflicts": conflicts,
        }
        if reviewed_plan_sha256 is not None:
            if digest(plan) != reviewed_plan_sha256:
                raise Conflict("reviewed_baseline_drift")
            _validate_reconciliation(repo, plan)
            plan = {
                **plan,
                "schema": "altermundi.skill-install-plan/v2",
                "conflicts": [],
                "reconciliation": {
                    "reviewed_plan_sha256": reviewed_plan_sha256,
                    "original_conflicts": conflicts,
                },
            }
        return plan


def journal_path(state, transaction):
    if not re.fullmatch(r"[0-9a-f]{32}", transaction):
        raise ValueError("invalid_transaction")
    return state / ("transaction-" + transaction + ".json")


def save_journal(state, journal):
    write_json(journal_path(state, journal["transaction"]), journal)


def transaction_dir(root, transaction):
    # Harnesses may recursively discover every SKILL.md below root, including
    # hidden folders. Keep staged and historical skills entirely outside it.
    history = private_dir(root.parent / ("." + root.name + "-update-history"))
    if history.stat().st_dev != root.stat().st_dev:
        raise Conflict("history_filesystem_mismatch")
    return private_dir(history / transaction)


def restore(state, journal):
    """Restore only exactly recognized before/after bytes; preserve unexpected edits."""
    root = private_dir(journal["root"])
    tx = transaction_dir(root, journal["transaction"])
    # Validate every participant before moving any; then preserve after bytes.
    for package in journal["descriptor"]["packages"]:
        name = package["name"]
        current, backup = snapshot(root / name), snapshot(tx / "before" / name)
        expected = journal["expected"][name]
        if backup is not None and backup != expected:
            raise Conflict("backup_drift")
        if current not in (expected, package["files"], None):
            raise Conflict("recovery_local_changes")
        if expected is not None and current != expected and backup != expected:
            raise Conflict("missing_backup")
    journal["status"] = "rolling_back"
    save_journal(state, journal)
    private_dir(tx / "retained")
    for package in reversed(journal["descriptor"]["packages"]):
        name = package["name"]
        live, backup = root / name, tx / "before" / name
        if snapshot(live) != journal["expected"][name]:
            if live.exists():
                os.replace(live, tx / "retained" / name)
            if backup.exists():
                os.replace(backup, live)
            sync_dir(root)
            sync_dir(tx / "before")
            sync_dir(tx / "retained")
        previous = journal["previous_records"][name]
        if previous is None:
            (state / (name + ".json")).unlink(missing_ok=True)
            sync_dir(state)
        else:
            write_json(state / (name + ".json"), previous)
    journal["status"] = "rolled_back"
    save_journal(state, journal)
    return {"outcome": "rolled_back", "transaction": journal["transaction"]}


def recover(root, state_path):
    root = private_dir(root)
    with locked(state_path) as state:
        results = []
        for path in sorted(state.glob("transaction-*.json")):
            journal = read_json(path)
            if journal["root"] == str(root) and journal["status"] in {
                "applying",
                "rolling_back",
            }:
                results.append(restore(state, journal))
        return {"outcome": "recovered", "transactions": results}


def apply(repo, plan, plan_sha256):
    reconciled = plan.get("schema") == "altermundi.skill-install-plan/v2"
    closed(
        plan,
        {
            "schema",
            "descriptor",
            "root",
            "state",
            "expected",
            "previous_records",
            "conflicts",
        }
        | ({"reconciliation"} if reconciled else set()),
    )
    if (
        plan["schema"]
        not in {"altermundi.skill-install-plan/v1", "altermundi.skill-install-plan/v2"}
        or digest(plan) != plan_sha256
    ):
        raise ValueError("plan_digest_mismatch")
    if plan["conflicts"]:
        raise Conflict("plan_has_conflicts")
    validate_descriptor(repo, plan["descriptor"])
    if reconciled:
        review = closed(
            plan["reconciliation"], {"reviewed_plan_sha256", "original_conflicts"}
        )
        baseline = {
            key: value for key, value in plan.items() if key != "reconciliation"
        }
        baseline.update(
            schema="altermundi.skill-install-plan/v1",
            conflicts=review["original_conflicts"],
        )
        if digest(baseline) != review["reviewed_plan_sha256"]:
            raise Conflict("reviewed_baseline_drift")
        _validate_reconciliation(repo, baseline)
    root = private_dir(plan["root"])
    with locked(plan["state"]) as state:
        for path in state.glob("transaction-*.json"):
            pending = read_json(path)
            if pending["root"] == str(root) and pending["status"] in {
                "applying",
                "rolling_back",
            }:
                raise Conflict("pending_recovery")
        names = [p["name"] for p in plan["descriptor"]["packages"]]
        if set(plan["expected"]) != set(names) or set(plan["previous_records"]) != set(
            names
        ):
            raise ValueError("plan_selection_mismatch")
        current_records = {name: record(state, name) for name in names}
        if all(
            snapshot(root / p["name"]) == p["files"]
            and current_records[p["name"]] is not None
            and current_records[p["name"]]["root"] == str(root)
            and current_records[p["name"]]["descriptor"] == plan["descriptor"]
            and current_records[p["name"]]["files"] == p["files"]
            for p in plan["descriptor"]["packages"]
        ):
            return {
                "outcome": "unchanged",
                "descriptor_sha256": digest(plan["descriptor"]),
                "packages": names,
            }
        for name in names:
            if (
                snapshot(root / name) != plan["expected"][name]
                or record(state, name) != plan["previous_records"][name]
            ):
                raise Conflict("plan_baseline_drift")
        transaction = uuid.uuid4().hex
        tx = transaction_dir(root, transaction)
        private_dir(tx / "before")
        private_dir(tx / "after")
        for package in plan["descriptor"]["packages"]:
            name = package["name"]
            _, blobs = source_package(repo, plan["descriptor"]["commit"], name)
            staged = private_dir(tx / "after" / name)
            for rel, raw in blobs.items():
                destination = staged / rel
                private_dir(destination.parent)
                with open(destination, "xb") as stream:
                    os.chmod(
                        destination,
                        0o700 if package["files"][rel]["executable"] else 0o600,
                    )
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                sync_dir(destination.parent)
            if snapshot(staged) != package["files"]:
                raise ValueError("staged_content_mismatch")
        for name in names:
            if (
                snapshot(root / name) != plan["expected"][name]
                or record(state, name) != plan["previous_records"][name]
            ):
                raise Conflict("plan_baseline_drift")
        journal = {
            "transaction": transaction,
            "root": str(root),
            "status": "applying",
            "descriptor": plan["descriptor"],
            "expected": plan["expected"],
            "previous_records": plan["previous_records"],
        }
        if reconciled:
            journal["reconciliation"] = plan["reconciliation"]
        save_journal(state, journal)
        try:
            for package in plan["descriptor"]["packages"]:
                name = package["name"]
                if (root / name).exists():
                    os.replace(root / name, tx / "before" / name)
                    sync_dir(root)
                    sync_dir(tx / "before")
                os.replace(tx / "after" / name, root / name)
                sync_dir(root)
                sync_dir(tx / "after")
            for package in plan["descriptor"]["packages"]:
                if snapshot(root / package["name"]) != package["files"]:
                    raise Conflict("installed_content_mismatch")
                write_json(
                    state / (package["name"] + ".json"),
                    {
                        "transaction": transaction,
                        "root": str(root),
                        "descriptor": plan["descriptor"],
                        "files": package["files"],
                    },
                )
            journal["status"] = "applied"
            save_journal(state, journal)
        except BaseException:
            # Includes a handled SIGINT. SIGKILL/power loss leaves an explicit
            # applying journal; `recover` performs the same exact-byte rollback.
            restore(state, journal)
            raise
        return {
            "outcome": "applied",
            "transaction": transaction,
            "descriptor_sha256": digest(plan["descriptor"]),
            "packages": names,
        }


def status(root, state_path, names):
    root = private_dir(root)
    with locked(state_path) as state:
        results = []
        for name in names:
            previous = record(state, path_name(name))
            current = snapshot(root / name)
            results.append(
                {
                    "package": name,
                    "outcome": "unmanaged"
                    if previous is None
                    else "installed"
                    if previous["root"] == str(root) and current == previous["files"]
                    else "drifted",
                    "commit": previous["descriptor"]["commit"] if previous else None,
                    "version": next(
                        p["version"]
                        for p in previous["descriptor"]["packages"]
                        if p["name"] == name
                    )
                    if previous
                    else None,
                    "content_sha256": digest(current),
                }
            )
        return {"packages": results}


def rollback(root, state_path, transaction):
    root = private_dir(root)
    with locked(state_path) as state:
        journal = read_json(journal_path(state, transaction))
        if journal["root"] != str(root):
            raise Conflict("rollback_root_mismatch")
        if journal["status"] == "rolled_back":
            return {"outcome": "unchanged", "transaction": transaction}
        if journal["status"] != "applied":
            raise Conflict("pending_recovery")
        for package in journal["descriptor"]["packages"]:
            previous = record(state, package["name"])
            if previous is None or previous["transaction"] != transaction:
                raise Conflict("superseded_transaction")
            if snapshot(root / package["name"]) != package["files"]:
                raise Conflict("rollback_local_changes")
        return restore(state, journal)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    desc = commands.add_parser("describe")
    desc.add_argument("--repository", type=Path, required=True)
    desc.add_argument("--commit", required=True)
    desc.add_argument("--skill", action="append", required=True)
    desc.add_argument("--out", type=Path, required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("--repository", type=Path, required=True)
    prep.add_argument("--descriptor", type=Path, required=True)
    prep.add_argument("--adopt-existing", action="store_true")
    prep.add_argument("--reviewed-plan-sha256")
    prep.add_argument("--out", type=Path, required=True)
    run = commands.add_parser("apply")
    run.add_argument("--repository", type=Path, required=True)
    run.add_argument("--plan", type=Path, required=True)
    run.add_argument("--plan-sha256", required=True)
    for cmd in (
        prep,
        commands.add_parser("status"),
        commands.add_parser("recover"),
        commands.add_parser("rollback"),
    ):
        cmd.add_argument("--root", type=Path, default=Path.home() / ".agents/skills")
        cmd.add_argument(
            "--state",
            type=Path,
            default=Path.home() / ".local/state/altermundi-skill-updates",
        )
        if cmd.prog.endswith(" status"):
            cmd.add_argument("--skill", action="append", required=True)
        if cmd.prog.endswith(" rollback"):
            cmd.add_argument("--transaction", required=True)
    args = parser.parse_args()
    try:
        if args.command == "describe":
            value = describe(args.repository, args.commit, args.skill)
            write_json(args.out, value)
            result = {
                "descriptor_sha256": digest(value),
                "commit": args.commit,
                "packages": [p["name"] for p in value["packages"]],
            }
        elif args.command == "prepare":
            value = prepare(
                args.repository,
                read_json(args.descriptor),
                args.root,
                args.state,
                args.adopt_existing,
                args.reviewed_plan_sha256,
            )
            write_json(args.out, value)
            result = {"plan_sha256": digest(value), "conflicts": value["conflicts"]}
        elif args.command == "apply":
            result = apply(args.repository, read_json(args.plan), args.plan_sha256)
        elif args.command == "status":
            result = status(args.root, args.state, args.skill)
        elif args.command == "recover":
            result = recover(args.root, args.state)
        else:
            result = rollback(args.root, args.state, args.transaction)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (
        ValueError,
        OSError,
        subprocess.CalledProcessError,
        TypeError,
        KeyError,
        AttributeError,
    ) as error:
        # Do not echo paths, content, Git subprocess stderr or private local data.
        code = (
            str(error)
            if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]+", str(error))
            else type(error).__name__
        )
        print(
            json.dumps(
                {
                    "outcome": "conflicted"
                    if isinstance(error, Conflict)
                    else "failed",
                    "code": code,
                }
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
