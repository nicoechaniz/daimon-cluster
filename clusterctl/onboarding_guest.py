"""Typed receiving context and native HMK installation inside one owned home.

This is maintained receiving code. It never executes scripts from the seed,
creates Matrix identity, opens account/bot credentials or launches a model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import shlex
import subprocess
import sys
import uuid
from collections import Counter
from contextlib import closing
from pathlib import Path

from . import being_seed, onboarding_input, onboarding_release, onboarding_sdk
from .onboarding import Observation, OnboardingError, digest, private_directory, validate_plan


def checksum(path: Path) -> str:
    return onboarding_input.owned_digest(path, uid=os.geteuid())[0]


def mkdir_chain(root: Path, target: Path) -> None:
    if not target.is_relative_to(root):
        raise OnboardingError("receiving_home_path_required")
    private_directory(root)
    current = root
    for part in target.relative_to(root).parts:
        current /= part
        private_directory(current, create=True)


def new_bytes(path: Path, raw: bytes, *, executable: bool = False) -> None:
    being_seed._path(path)
    if path.exists():
        if (checksum(path) != hashlib.sha256(raw).hexdigest()
                or bool(path.stat().st_mode & 0o100) != executable):
            raise OnboardingError("existing_receiving_file_preserved")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700 if executable else 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def reconcile_context_copy(home, incoming, plan):
    """Recover only a strict input prefix before context activation.

    Self-contained for host dispatch against an immutable receiving generation.
    The interrupted bytes remain in a durable journal; replacements are copied
    from the bound read-only input and published only after complete verification.
    """
    import fcntl
    import hashlib
    import json
    import os
    import re
    import stat
    import uuid
    from pathlib import Path, PurePosixPath

    def refuse():
        raise ValueError('existing_receiving_file_preserved')

    def owned(path, directory=False):
        if any(p.is_symlink() for p in (path, *path.parents)):
            refuse()
        info = path.stat()
        if (info.st_uid != os.geteuid() or info.st_mode & 0o077
                or (not stat.S_ISDIR(info.st_mode) if directory else
                    not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)):
            refuse()
        return info

    def mkdir(path):
        if path.exists():
            owned(path, True)
            return
        mkdir(path.parent)
        path.mkdir(mode=0o700)

    def sync(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def fingerprint(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def checksum(path):
        owned(path)
        h = hashlib.sha256()
        with path.open('rb') as stream:
            while chunk := stream.read(1024 * 1024):
                h.update(chunk)
        return h.hexdigest()

    home, incoming = Path(home), Path(incoming)
    owned(home, True)
    if (not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,30}', plan.get('name', ''))
            or not incoming.is_relative_to(home)):
        refuse()
    state = home / '.local/state/daimon-onboarding' / plan['name']
    if (state / 'context.json').exists() or (state / 'memory.json').exists():
        return {'recovered': 0}
    manifest_file = incoming / 'manifest.json'
    if owned(manifest_file).st_size > 16 * 1024**2:
        refuse()
    manifest = json.loads(manifest_file.read_bytes())
    if manifest.get('schema') != 'cluster-onboarding-input/v1' or fingerprint(manifest) != plan['seed_digest']:
        refuse()
    received = home / '.agents/memory' / plan['name'] / 'received'
    if not received.exists():
        return {'recovered': 0}
    owned(received, True)
    root = state / 'copy-recovery'
    mkdir(root)
    lock = os.open(root / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    recovered = 0
    try:
        owned(root / 'lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for row in manifest['files']:
            relative = PurePosixPath(row['path'])
            if relative.is_absolute() or any(p in ('', '.', '..') for p in row['path'].split('/')) or '\\' in row['path']:
                refuse()
            target, source = received / row['path'], incoming / 'received' / row['path']
            journal = root / fingerprint(row)
            # The usual full copy remains owned by the pinned installer. A
            # journal also resumes a lost acknowledgement after quarantine.
            if not journal.exists() and (not target.exists() or owned(target).st_size == row['size']):
                continue
            mkdir(journal)
            partial = journal / 'interrupted'
            intent = {'schema': 'cluster-context-copy-recovery/v1', 'plan_digest': fingerprint(plan), 'file': row}
            record = journal / 'intent.json'
            if record.exists():
                owned(record)
                if json.loads(record.read_bytes()) != intent:
                    refuse()
            else:
                if not target.exists():
                    refuse()
                fd = os.open(record, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(json.dumps(intent, sort_keys=True).encode())
                    stream.flush()
                    os.fsync(stream.fileno())
                sync(journal)
            probe = partial if partial.exists() else target
            before = owned(probe)
            if not 0 <= before.st_size < row['size'] or owned(source).st_size != row['size']:
                refuse()
            with probe.open('rb') as a, source.open('rb') as b:
                while chunk := a.read(1024 * 1024):
                    if b.read(len(chunk)) != chunk:
                        refuse()
            after = owned(probe)
            if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                refuse()
            if partial.exists():
                if target.exists():
                    if owned(target).st_size != row['size'] or checksum(target) != row['sha256']:
                        refuse()
                    continue
            else:
                if checksum(source) != row['sha256']:
                    refuse()
                os.rename(target, partial)
                sync(target.parent)
                sync(journal)
            temporary = journal / ('copy-' + uuid.uuid4().hex)
            h = hashlib.sha256()
            size = 0
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as output, source.open('rb') as stream:
                while chunk := stream.read(1024 * 1024):
                    h.update(chunk)
                    size += len(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if (size, h.hexdigest()) != (row['size'], row['sha256']) or target.exists():
                refuse()
            os.rename(temporary, target)
            sync(target.parent)
            sync(journal)
            recovered += 1
        return {'recovered': recovered}
    finally:
        os.close(lock)


class Receiver:
    def __init__(self, home: Path, incoming: Path, code: Path, plan: dict, *, code_uid: int = 0):
        self.plan = validate_plan(plan)
        self.code_uid = code_uid
        self.home, self.incoming, self.code = home.absolute(), incoming.absolute(), code.absolute()
        private_directory(self.home)
        if not self.incoming.is_relative_to(self.home) or self.code.is_relative_to(self.incoming):
            raise OnboardingError("isolated_receiving_paths_required")
        self.manifest = onboarding_input.verify(self.incoming, plan["seed_digest"])
        self.release = onboarding_release.verify(self.code, plan["release_digest"], uid=code_uid)
        self.profile = self.release["profile"]
        self.state = self.home / ".local/state/daimon-onboarding" / plan["name"]
        self.received = self.home / ".agents/memory" / plan["name"] / "received"
        if self.received.is_relative_to(self.incoming) or self.incoming.is_relative_to(self.received):
            raise OnboardingError("isolated_receiving_paths_required")
        self.preparation = being_seed._read(self.incoming / "received/preparation.json")
        if (self.preparation.get("schema") != "dm.being-receiving-preparation/v1"
                or self.preparation.get("ready_for_context_install") is not True):
            raise OnboardingError("prepared_receiving_context_required")
        self.memory = self.preparation["selection"]["memory"]
        if not isinstance(self.memory, list):
            raise OnboardingError("invalid_receiving_memory")
        for row in self.memory:
            if (not isinstance(row, dict) or not isinstance(row.get("name"), str)
                    or not being_seed.NAME.fullmatch(row["name"]) or row.get("database") != "library.db"):
                raise OnboardingError("invalid_receiving_memory")
        if len({row["name"] for row in self.memory}) != len(self.memory):
            raise OnboardingError("invalid_receiving_memory")
        self.primary = self.profile["primary_store"]
        if self.primary is not None and self.primary not in {row["name"] for row in self.memory}:
            raise OnboardingError("selected_receiving_memory_missing")

    def _marker(self, stage: str) -> dict | None:
        path = self.state / (stage + ".json")
        if not path.exists():
            return None
        value = being_seed._read(path)
        if (value.get("schema") != "cluster-receiving-" + stage + "/v1"
                or value.get("plan_digest") != digest(self.plan)):
            raise OnboardingError("receiving_stage_conflict")
        return value

    def _publish(self, stage: str, **fields) -> None:
        mkdir_chain(self.home, self.state)
        value = {"schema": "cluster-receiving-" + stage + "/v1", "plan_digest": digest(self.plan), **fields}
        new_bytes(self.state / (stage + ".json"), json.dumps(value, sort_keys=True).encode())
        descriptor = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _copy_input(self) -> None:
        reconcile_context_copy(self.home, self.incoming, self.plan)
        mkdir_chain(self.home, self.received)
        for directory in sorted(path for path in (self.incoming / "received").rglob("*") if path.is_dir()):
            mkdir_chain(self.home, self.received / directory.relative_to(self.incoming / "received"))
        for row in self.manifest["files"]:
            target = self.received / onboarding_input.relative(row["path"])
            mkdir_chain(self.home, target.parent)
            if target.exists():
                if checksum(target) != row["sha256"]:
                    raise OnboardingError("existing_receiving_file_preserved")
                continue
            found, size = onboarding_input.owned_digest(self.incoming / "received" / row["path"],
                                                       uid=os.geteuid(), copy=target)
            if (found, size) != (row["sha256"], row["size"]):
                raise OnboardingError("receiving_input_changed")

    def _wrapper(self, store: str) -> bytes:
        memory = self.received / "memory" / store
        return f'''"""Human-requested HMK for one preserved working store."""
import os
import sys
from pathlib import Path
if (len(sys.argv) < 2 or Path(sys.argv[1]).name != sys.argv[1]
        or not sys.argv[1].endswith(".py") or ".." in sys.argv[1]):
    raise SystemExit("native_script_basename_required")
os.environ["HMK_AGENT_MEMORY_BASE"] = {str(memory)!r}
os.environ["HERMES_AGENT_MEMORY_BASE"] = {str(memory)!r}
os.environ["HMK_DB_PATH"] = {str(memory / "library.db")!r}
os.environ["HMK_ENV_FILE"] = {str(self.state / "hmk.env")!r}
os.environ["HMK_WORKSPACE_ROOT"] = {str(self.home / "Projects/being")!r}
os.environ["HMK_HERMES_HOME"] = {str(self.state)!r}
script = Path({str(self.code / "hmk/scripts")!r}) / sys.argv[1]
if not script.is_file() or script.is_symlink():
    raise SystemExit("native_script_unavailable")
os.chdir({str(self.home / "Projects/being")!r})
os.execv({sys.executable!r}, [{sys.executable!r}, "-B", str(script), *sys.argv[2:]])
'''.encode()

    def install_context(self) -> None:
        observed = self.observe_context()
        if observed.state == "complete":
            return
        if observed.state != "absent":
            raise OnboardingError("existing_receiving_file_preserved")
        if (self.code / "sdk").exists():
            onboarding_sdk.install(self.home, self.code, self.plan["release_digest"], code_uid=self.code_uid)
        self._copy_input()
        mkdir_chain(self.home, self.state)
        mkdir_chain(self.home, self.home / "Projects/being")
        new_bytes(self.state / "hmk.env", b"# No inherited source dotenv or provider configuration.\n")
        access = ["Memory belongs to this continuing being. Read only on human request.\n",
                  "Do not prefetch at startup/turn boundaries or add Matrix attention hooks.\n",
                  "Source originals, private histories and provenance remain in the receiving continuity index.\n",
                  "Keep the separate stores and their origins; do not silently merge them.\n"]
        for row in self.memory:
            command = self.state / ("hmk-" + row["name"] + ".py")
            new_bytes(command, self._wrapper(row["name"]))
            access.append(f"Store {row['name']}: {sys.executable} {command} memoryctl.py hybrid-pack --query <human-requested-query> --budget 1500 --limit 5\n")
        if self.primary:
            mkdir_chain(self.home, self.home / ".local/bin")
            wrapper = (f"#!/bin/sh\nexec {shlex.quote(sys.executable)} "
                       f"{shlex.quote(str(self.state / ('hmk-' + self.primary + '.py')))} \"$@\"\n").encode()
            new_bytes(self.home / ".local/bin/hmk", wrapper, executable=True)
        new_bytes(self.state / "MEMORY-ACCESS.md", "".join(access).encode())
        # Preserve the original personal SOUL. Selected lineage is a separate
        # attributed context surface, not a replacement of autobiography.
        new_bytes(self.state / "INHERITANCE.md", (self.code / "inheritance.md").read_bytes())
        for name in self.profile["skills"]:
            source = self.code / "skills" / name
            target = self.home / ".agents/skills" / name
            mkdir_chain(self.home, target)
            for path in sorted(source.rglob("*")):
                output = target / path.relative_to(source)
                if path.is_dir():
                    mkdir_chain(self.home, output)
                else:
                    mkdir_chain(self.home, output.parent)
                    new_bytes(output, path.read_bytes(), executable=bool(path.stat().st_mode & 0o100))
        codex_home = self.home / ".codex"
        mkdir_chain(self.home, codex_home)
        being_seed.tool("install_codex_identity", ["--codex-home", str(codex_home),
            "--identity-file", str(self.received / "context/IDENTITY.md"),
            "--soul", str(self.received / "context/SOUL.md"),
            "--foundation", str(self.state / "INHERITANCE.md"),
            "--memory-access", str(self.state / "MEMORY-ACCESS.md"),
            "--model", self.profile["model"], "--reasoning", self.profile["reasoning"],
            "--approval", self.profile["approval"], "--sandbox", self.profile["sandbox"], "--apply"])
        self._publish("context", agents_sha256=checksum(codex_home / "AGENTS.md"),
                      config_sha256=checksum(codex_home / "config.toml"), skills=len(self.profile["skills"]))

    def observe_context(self) -> Observation:
        marker = self._marker("context")
        if marker is None:
            return Observation("absent", safe_to_execute=True)
        if (self.code / "sdk").exists():
            onboarding_sdk.observe(self.home, self.code, code_uid=self.code_uid)
        if (checksum(self.home / ".codex/AGENTS.md") != marker["agents_sha256"]
                or checksum(self.home / ".codex/config.toml") != marker["config_sha256"]):
            return Observation("conflict", reason="observed_state_conflict")
        # Reconcile actual copied commons against qualified code, not a count.
        for row in self.release["files"]:
            if row["path"].startswith("skills/") and checksum(self.home / ".agents" / row["path"]) != row["sha256"]:
                return Observation("conflict", reason="observed_state_conflict")
        return Observation("complete", {"verified": True, "context_verified": True, "skills": marker["skills"]})

    def _database(self, store: str):
        path = self.received / "memory" / store / "library.db"
        being_seed._path(path)
        return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)

    def _native(self, store: str, args: list[str]) -> dict:
        # Native output contains private material and stays inside this process.
        try:
            result = subprocess.run([sys.executable, "-B", str(self.state / ("hmk-" + store + ".py")),
                                     "memoryctl.py", *args], capture_output=True, timeout=120, check=False)
            value = json.loads(result.stdout)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            raise OnboardingError("native_hmk_verification_failed") from None
        if result.returncode or not isinstance(value, dict):
            raise OnboardingError("native_hmk_verification_failed")
        return value

    def verify_memory(self) -> None:
        if self.observe_memory().state == "complete":
            return
        if self.observe_context().state != "complete":
            raise OnboardingError("receiving_context_required")
        backups = self.state / "backups"
        mkdir_chain(self.home, backups)
        evidence = []
        for row in self.memory:
            store = row["name"]
            with closing(self._database(store)) as database:
                if database.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    raise OnboardingError("receiving_memory_integrity_failed")
                database.row_factory = sqlite3.Row
                chapters = [dict(r) for r in database.execute("SELECT id,title,raw FROM chapters ORDER BY id")]
                backup = backups / (store + ".db")
                if not backup.exists():
                    # A killed backup leaves only an unpublished derived file.
                    # No native mutation starts until the complete snapshot is
                    # durable. Retrying never trusts an empty final filename.
                    temporary = backups / (store + "." + uuid.uuid4().hex + ".partial")
                    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    os.close(descriptor)
                    with closing(sqlite3.connect(temporary)) as snapshot:
                        database.backup(snapshot)
                        if snapshot.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                            raise OnboardingError("receiving_memory_backup_failed")
                    descriptor = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    # Publication without replacement; ambiguous old bytes stay.
                    os.link(temporary, backup, follow_symlinks=False)
                    temporary.unlink()
                else:
                    # Reconcile a crash between no-replace publication and
                    # unlinking its one known derived snapshot name.
                    info = backup.stat()
                    if info.st_nlink == 2:
                        links = [path for path in backups.glob(store + ".*.partial")
                                 if not path.is_symlink() and path.stat().st_uid == os.geteuid()
                                 and (path.stat().st_dev, path.stat().st_ino) == (info.st_dev, info.st_ino)]
                        if len(links) != 1:
                            raise OnboardingError("receiving_memory_backup_failed")
                        links[0].unlink()
                    checksum(backup)
                with closing(sqlite3.connect(backup.as_uri() + "?mode=ro", uri=True)) as snapshot:
                    if snapshot.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                        raise OnboardingError("receiving_memory_backup_failed")
                descriptor = os.open(backup, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                descriptor = os.open(backups, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            # stats may perform a supported native schema upgrade. The verified
            # snapshot above precedes it; no init/bootstrap or re-embedding call.
            result = self._native(store, ["stats"])
            expected = self.received / "memory" / store / "library.db"
            if result.get("db_path") != str(expected) or result.get("chapters") != len(chapters):
                raise OnboardingError("native_hmk_wrong_binding_or_counts")
            witnesses = []
            for chapter in ([chapters[0], chapters[-1]] if chapters else []):
                recalled = self._native(store, ["expand", "--id", str(chapter["id"])])
                if any(recalled.get(key) != chapter[key] for key in ("id", "title", "raw")):
                    raise OnboardingError("native_hmk_retrieval_mismatch")
                witnesses.append({"id": chapter["id"], "digest": digest(chapter)})
            self._preserved_rows(store, backup)
            evidence.append({"name": store, "chapters": len(chapters), "witnesses": witnesses,
                             "backup_sha256": checksum(backup)})
        self._publish("memory", stores=evidence)

    def _preserved_rows(self, store: str, backup: Path) -> None:
        """Every original row/column survives additive native upgrades.

        FTS internals are derived indexes. Native expand legitimately updates
        only access counters; neither exception permits lost content, vectors,
        relationships, source metadata, revisions or query history.
        """
        with closing(sqlite3.connect(backup.as_uri() + "?mode=ro", uri=True)) as original, closing(self._database(store)) as current:
            tables = original.execute("SELECT name,sql FROM sqlite_master WHERE type='table'").fetchall()
            for name, sql in tables:
                if name.startswith("sqlite_") or name.startswith("chapters_fts") or "VIRTUAL TABLE" in (sql or "").upper():
                    continue
                # Quote SQLite identifiers, never interpolate seed SQL.
                quoted = '"' + name.replace('"', '""') + '"'
                columns = [row[1] for row in original.execute("PRAGMA table_info(" + quoted + ")")]
                if name == "chapters":
                    columns = [column for column in columns if column not in {"last_access", "access_count"}]
                selected = ",".join('"' + column.replace('"', '""') + '"' for column in columns)
                old = Counter(original.execute("SELECT " + selected + " FROM " + quoted))
                remaining = old.copy()
                for row in current.execute("SELECT " + selected + " FROM " + quoted):
                    if remaining[row] > 0:
                        remaining[row] -= 1
                if any(remaining.values()):
                    raise OnboardingError("receiving_memory_original_rows_changed")

    def observe_memory(self) -> Observation:
        marker = self._marker("memory")
        if marker is None:
            return Observation("absent", safe_to_execute=True)
        if {row["name"] for row in marker["stores"]} != {row["name"] for row in self.memory}:
            return Observation("conflict", reason="observed_state_conflict")
        count = 0
        for row in marker["stores"]:
            with closing(self._database(row["name"])) as database:
                if database.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                    return Observation("conflict", reason="verification_failed")
                found = database.execute("SELECT COUNT(*) FROM chapters").fetchone()[0]
                if found < row["chapters"]:
                    return Observation("conflict", reason="observed_state_conflict")
                database.row_factory = sqlite3.Row
                for witness in row["witnesses"]:
                    chapter = database.execute("SELECT id,title,raw FROM chapters WHERE id=?", (witness["id"],)).fetchone()
                    if chapter is None or digest(dict(chapter)) != witness["digest"]:
                        return Observation("conflict", reason="observed_state_conflict")
                count += found
        return Observation("complete", {"verified": True, "memory_stores": len(self.memory), "memory_chapters": count})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("observe", "execute"))
    parser.add_argument("stage", choices=("context", "memory"))
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--code", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receiver = Receiver(args.home, args.input, args.code, being_seed._read(args.plan))
        if args.action == "execute":
            (receiver.install_context if args.stage == "context" else receiver.verify_memory)()
        observation = (receiver.observe_context if args.stage == "context" else receiver.observe_memory)()
        print(json.dumps(dict(state=observation.state, facts=observation.facts,
                              reason=observation.reason, safe_to_execute=observation.safe_to_execute)))
        return 0
    except Exception:
        print(json.dumps({"state": "conflict", "facts": {}, "reason": "verification_failed", "safe_to_execute": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
