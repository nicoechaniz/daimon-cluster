"""Owner-local home provisioning with commit-pinned maintained skill updates.

No model, inbox, identity creation or administrative login mutation. The host
places a reviewed private declaration in an accepted body's home and invokes
this code as that body's existing UID. It does not copy another body's context.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import uuid


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_mode & 0o022
        ):
            raise ValueError("owned_home_file_required")
        return stream.read()


def directory(path, home, *, strict=True):
    if (
        not path.is_relative_to(home)
        or any(p.is_symlink() for p in (path, *path.parents))
        or ".." in path.parts
    ):
        raise ValueError("receiving_home_path_required")
    current = home
    for part in path.relative_to(home).parts:
        current /= part
        if not current.exists():
            current.mkdir(mode=0o700)
    if (
        not path.is_dir()
        or path.stat().st_uid != os.geteuid()
        or strict
        and path.stat().st_mode & 0o077
    ):
        raise ValueError("owned_home_directory_required")


def replace(path, raw, *, previous, home, backups, executable=False):
    # Preserve existing owner-local config/bin/context directory permissions.
    # The file still needs ownership, no symlink, exact prior bytes and CAS.
    directory(path.parent, home, strict=False)
    if path.exists() or path.is_symlink():
        existing = regular(path)
        if existing == raw:
            return False
        if sha(existing) != previous:
            raise ValueError("existing_home_file_preserved")
        backup = backups / (
            sha(str(path.relative_to(home)).encode()) + "-" + sha(existing)
        )
        if not backup.exists():
            descriptor = os.open(
                backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(existing)
                stream.flush()
                os.fsync(stream.fileno())
    elif previous is not None:
        raise ValueError("home_predecessor_missing")
    temporary = path.with_name(".home-" + uuid.uuid4().hex)
    descriptor = os.open(
        temporary,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
        0o700 if executable else 0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Recheck the exact predecessor after durable staging.
        if path.exists() and sha(regular(path)) != previous:
            raise ValueError("concurrent_home_file_change")
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def owner_pointer(original, public_url):
    start = "\n# Artifact home binding\n"
    paragraph = (
        start
        + "\nYour artifact home is "
        + public_url
        + ". Use the installed daimon-home skill and "
        "command for selected ideas, files, experiments and project links. Its receiving binding is "
        "~/.config/daimon-home/binding.json. All homes use the same Matrix resource-access contract "
        "and shared permission authority. Public, dedicated-VPN and authenticated audiences are "
        "available only as reported by the receiving adapter; never weaken a selection to publish. "
        "Publication and browser approval respond to explicit human requests. This pointer creates "
        "no automatic publication, inbox attention or model wakeup. Preserve each artifact's chosen audience.\n"
    )
    text = original.decode()
    if start in text:
        offset = text.index(start)
        rest = text[offset + len(start) :]
        if not rest.startswith("\nYour artifact home is "):
            raise ValueError("custom_home_pointer_preserved")
        end = rest.find("\n", 1)
        if end < 0:
            raise ValueError("custom_home_pointer_preserved")
        return (text[:offset] + paragraph + rest[end + 1 :]).encode()
    return original + paragraph.encode()


def initialize_source(home, repository, bundle):
    """An offline source cache retains the maintained installer's provenance."""
    home, repository, bundle = map(Path, (home, repository, bundle))
    if repository != home / ".local/state/daimon-home/skills-source":
        raise ValueError("dedicated_home_source_cache_required")
    regular(bundle)
    directory(repository, home, strict=False)
    subprocess.run(["git", "init", str(repository)], check=True, capture_output=True)
    origin = subprocess.run(
        ["git", "-C", str(repository), "config", "--get", "remote.origin.url"],
        capture_output=True,
        text=True,
    )
    expected = "https://github.com/AlterMundi/Skills.git"
    if origin.returncode == 1:
        subprocess.run(
            ["git", "-C", str(repository), "remote", "add", "origin", expected],
            check=True,
            capture_output=True,
        )
    elif origin.returncode != 0 or origin.stdout.strip() != expected:
        raise ValueError("existing_home_source_origin_preserved")
    heads = (
        subprocess.check_output(["git", "bundle", "list-heads", str(bundle)])
        .decode()
        .splitlines()
    )
    if len(heads) != 1:
        raise ValueError("selected_home_bundle_reference_required")
    fields = heads[0].split()
    if (
        len(fields) != 2
        or not re.fullmatch("[a-f0-9]{40}", fields[0])
        or not re.fullmatch("refs/daimon-home/bundle-[a-f0-9]{32}", fields[1])
    ):
        raise ValueError("selected_home_bundle_reference_required")
    subprocess.run(
        ["git", "-C", str(repository), "fetch", str(bundle), fields[1]],
        check=True,
        capture_output=True,
        timeout=60,
    )


def install_skill(repository, commit, home, state):
    if not re.fullmatch("[a-f0-9]{40}", commit):
        raise ValueError("immutable_home_skill_commit_required")
    repository = Path(repository)
    raw = subprocess.run(
        ["git", "-C", str(repository), "show", commit + ":scripts/skills_update.py"],
        check=True,
        capture_output=True,
    ).stdout
    installer = state / ("installer-" + sha(raw) + ".py")
    if not installer.exists():
        descriptor = os.open(
            installer, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
    if regular(installer) != raw:
        raise ValueError("home_installer_integrity_required")

    def run(*args):
        return subprocess.run(
            [sys.executable, str(installer), *map(str, args)],
            check=True,
            capture_output=True,
            timeout=120,
        ).stdout

    descriptor = state / "descriptor.json"
    run(
        "describe",
        "--repository",
        repository,
        "--commit",
        commit,
        "--skill",
        "daimon-home",
        "--out",
        descriptor,
    )
    plan = state / "skill-plan.json"
    prepared = json.loads(
        run(
            "prepare",
            "--repository",
            repository,
            "--descriptor",
            descriptor,
            "--root",
            home / ".agents/skills",
            "--state",
            home / ".local/state/altermundi-skill-updates",
            "--out",
            plan,
        )
    )
    value = json.loads(regular(plan))
    if value.get("conflicts"):
        raise ValueError("existing_home_skill_preserved")
    # The maintained installer owns package succession and compatible rollback.
    from_digest = prepared["plan_sha256"]
    run(
        "apply",
        "--repository",
        repository,
        "--plan",
        plan,
        "--plan-sha256",
        from_digest,
    )
    return commit


def provision(home, declaration, *, repository, install=install_skill):
    home = Path(home).absolute()
    if (
        home.is_symlink()
        or home.stat().st_uid != os.geteuid()
        or set(declaration) != {"schema", "binding", "skills_commit", "previous"}
        or declaration["schema"] != "dm.home.receiving/v1"
        or not isinstance(declaration["binding"], dict)
        or not isinstance(declaration["previous"], dict)
    ):
        raise ValueError("invalid_home_receiving_declaration")
    binding = declaration["binding"]
    human_reader = binding.get('schema') == 'dm.home-human-client/v1'
    if not human_reader:
        store = Path(binding["store"])
        if (
            not store.is_absolute()
            or ".." in store.parts
            or any(p.is_symlink() for p in (store, *store.parents))
        ):
            raise ValueError("owned_artifact_store_required")
        if store.is_relative_to(home):
            directory(store, home)
        elif (
            not store.is_dir()
            or store.stat().st_uid != os.geteuid()
            or store.stat().st_mode & 0o077
        ):
            # Reuse an explicitly configured durable external store; an owner-local
            # bootstrap cannot allocate an unknown external host resource.
            raise ValueError("existing_owned_artifact_store_required")
    # Use the published helper's existing receiving contract after installation;
    # it validates URLs, ports/store and public ring selection.
    state = home / ".local/state/daimon-home/provision"
    directory(state, home)
    backups = state / "previous"
    directory(backups, home)
    with (state / "writer.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        commit = install(repository, declaration["skills_commit"], home, state)
        helper = home / ".agents/skills/daimon-home/scripts/home.py"
        binding_raw = (json.dumps(binding, sort_keys=True, indent=2) + "\n").encode()
        candidate = state / "binding.candidate.json"
        temporary = candidate.with_name(".binding-" + uuid.uuid4().hex)
        with temporary.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(binding_raw)
        os.replace(temporary, candidate)
        result = subprocess.run(
            [sys.executable, str(helper), "--binding", str(candidate), "status"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        if json.loads(result.stdout)["public_url"] != binding["public_url"]:
            raise ValueError("home_binding_integrity_required")
        targets = {
            "binding": (home / ".config/daimon-home/binding.json", binding_raw, False),
            "wrapper": (
                home / ".local/bin/daimon-home",
                (
                    "#!/bin/sh\nexec python3 " + shlex.quote(str(helper)) + ' "$@"\n'
                ).encode(),
                True,
            ),
        }
        pointer = home / ".codex/AGENTS.md"
        if pointer.exists() and not human_reader:
            targets["pointer"] = (
                pointer,
                owner_pointer(regular(pointer), binding["public_url"]),
                False,
            )
        for name, (path, raw, executable) in targets.items():
            replace(
                path,
                raw,
                previous=declaration["previous"].get(name),
                home=home,
                backups=backups,
                executable=executable,
            )
        receipt = {
            "schema": "dm.home.provisioned/v1",
            "skills_commit": commit,
            "declaration_digest": sha(
                json.dumps(declaration, sort_keys=True, separators=(",", ":")).encode()
            ),
            "files": {
                name: sha(regular(path)) for name, (path, _, _) in targets.items()
            },
        }
        receipt_raw = (json.dumps(receipt, sort_keys=True) + "\n").encode()
        path = state / "receipt.json"
        replace(
            path,
            receipt_raw,
            previous=sha(regular(path)) if path.exists() else None,
            home=home,
            backups=backups,
        )
        return receipt


def prepare_human_client_home(home, uid, gid):
    """Create only the client directory; retain the protected config parent."""
    home = Path(home)
    parent = home / '.config'
    info = parent.lstat()
    if (home.is_symlink() or home.stat().st_uid != uid
            or not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid)
            or info.st_mode & 0o022):
        raise ValueError('owned_client_home_required')
    before = (info.st_uid, info.st_gid, info.st_mode, info.st_ino)
    target = parent / 'daimon-home'
    if not target.exists() and not target.is_symlink():
        target.mkdir(mode=0o700)
        os.chown(target, uid, gid)
    info = target.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
        raise ValueError('private_human_client_directory_required')
    info = parent.lstat()
    if (info.st_uid, info.st_gid, info.st_mode, info.st_ino) != before:
        raise ValueError('existing_config_parent_preserved')


def install_service(
    candidate,
    previous,
    *,
    system_dir=Path("/etc/systemd/system"),
    state_dir=Path("/var/lib/daimon-home-service"),
):
    raw = regular(candidate)
    if (
        b"User=agent\n" not in raw
        or b"ExecStart=/home/agent/.local/bin/daimon-home serve\n" not in raw
        or b"[Install]\nWantedBy=multi-user.target\n" not in raw
    ):
        raise ValueError("qualified_home_service_required")
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (
        state_dir.is_symlink()
        or state_dir.stat().st_uid != os.geteuid()
        or state_dir.stat().st_mode & 0o077
    ):
        raise ValueError("private_home_service_state_required")
    target = system_dir / "daimon-home.service"
    return replace(target, raw, previous=previous, home=system_dir, backups=state_dir)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path)
    parser.add_argument("--declaration", type=Path)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--unit-file", type=Path)
    parser.add_argument("--prepare-human-client", action="store_true")
    parser.add_argument("--source-bundle", type=Path)
    parser.add_argument("--previous-unit-sha256")
    args = parser.parse_args()
    try:
        if args.prepare_human_client:
            import pwd
            if os.geteuid() != 0 or args.home != Path('/home/agent'):
                raise ValueError('human_client_operator_required')
            account = pwd.getpwnam('agent')
            if account.pw_uid != 1000:
                raise ValueError('qualified_guest_owner_required')
            prepare_human_client_home(args.home, account.pw_uid, account.pw_gid)
            print(json.dumps({'status': 'client-directory-ready'}))
            return
        if args.source_bundle:
            if not args.home or not args.repository:
                raise ValueError("complete_home_source_selection_required")
            initialize_source(args.home, args.repository, args.source_bundle)
            print(json.dumps({"status": "source-ready"}))
            return
        if args.unit_file:
            if os.geteuid() != 0:
                raise ValueError("home_service_operator_required")
            changed = install_service(args.unit_file, args.previous_unit_sha256)
            print(json.dumps({"status": "service-installed", "changed": changed}))
            return
        if not all((args.home, args.declaration, args.repository)):
            raise ValueError("complete_home_placement_required")
        value = json.loads(regular(args.declaration))
        provision(args.home, value, repository=args.repository)
        print(json.dumps({"status": "provisioned"}))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print(
            json.dumps(
                {"status": "refused", "reason": "home_receiving_integrity_required"}
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
