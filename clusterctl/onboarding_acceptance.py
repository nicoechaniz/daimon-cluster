"""Owner witnesses and independent, read-only hosted acceptance evidence.

This collection does not finish a job. Human reports remain witnesses; native
metadata proves only the checks it actually observes. Missing technical adapters
stay visible until they supply their own observed evidence.
"""

from __future__ import annotations

import inspect
import json
import os
import re
import sqlite3
import time
import uuid
from pathlib import Path

from . import being_seed
from .onboarding import (
    JobStore,
    Observation,
    OnboardingError,
    digest,
    private_directory,
)
from .onboarding_progress import Progress
from .onboarding_release import regular

SCHEMA = "cluster-onboarding-hosted-checks/v1"
REPORT = "cluster-onboarding-hosted-witness/v1"
RESULTS = {"passed", "failed", "missing", "not-checked"}
TECHNICAL = (
    "identity_verified",
    "provider_verified",
    "memory_verified",
    "memory_write_verified",
    "ssh_verified",
    "telegram_verified",
    "topics_verified",
    "steering_verified",
    "restart_verified",
    "cli_resume_verified",
    "matrix_delivery_verified",
)
CHECKS = {
    "own_identity": "In the hosted Codex conversation, confirm your own identity and history are loaded.",
    "ssh_codex": "Use the dedicated SSH access shown here and open native Codex in the existing being workspace.",
    "permanent_finals": "After a reply finishes, reopen the Telegram topic and confirm the final reply is still visible.",
    "steering_outcome": "While Codex is working, send a correction in the same topic. Confirm the result follows it.",
    "topic_independence": "Complete a conversation in each of two Telegram topics. Confirm they keep separate conversations.",
    "restart_continuity": "After the host continuity test, continue both existing topics and confirm they retain their conversations.",
    "cli_resume": "Through dedicated SSH, use codex resume with an existing hosted thread shown here; confirm its prior conversation continues.",
}
BROWSER = "In the hosted browser, verify the supported browser session works."


def memory_write_probe(home, plan, store, native_runner=None):
    """Finite native write/read/delete; preserve original rows and crash state.

    Dispatched as the receiving user. This self-contained stdlib program never
    restores a database, reads credentials or calls an embedding provider.
    """
    import contextlib
    import collections
    import fcntl
    import hashlib
    import json
    import os
    import re
    import sqlite3
    import stat
    import subprocess
    import sys
    import uuid
    from pathlib import Path

    def refuse():
        raise ValueError('native_memory_write_verification_failed')

    def owned(path):
        if any(p.is_symlink() for p in (path, *path.parents)):
            refuse()
        info = path.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            refuse()

    def read(path):
        owned(path)
        if path.stat().st_size > 65536:
            refuse()
        value = json.loads(path.read_bytes())
        if not isinstance(value, dict):
            refuse()
        return value

    def publish(path, value):
        raw = json.dumps(value, sort_keys=True).encode()
        temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    if (not isinstance(plan, dict) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,30}', plan.get('name', ''))
            or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,30}', store)):
        refuse()
    fingerprint = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    home = Path(home)
    state = home / '.local/state/daimon-onboarding' / plan['name']
    marker = read(state / 'memory.json')
    if marker.get('plan_digest') != fingerprint or store not in {r['name'] for r in marker['stores']}:
        refuse()
    root = state / 'memory-write' / store
    if any(p.is_symlink() for p in (root, *root.parents)):
        refuse()
    for path in (root.parent, root):
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.stat()
        if not path.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            refuse()
    lock = os.open(root / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        owned(root / 'lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        schema = 'cluster-native-memory-write-proof/v1'
        if (root / 'proof.json').exists():
            proof = read(root / 'proof.json')
            if (set(proof) != {'schema', 'plan_digest', 'store', 'verified', 'backup_sha256', 'probe_sha256'}
                    or proof['schema'] != schema or proof['plan_digest'] != fingerprint
                    or proof['store'] != store or proof['verified'] is not True
                    or any(not re.fullmatch('[0-9a-f]{64}', proof[k]) for k in ('backup_sha256', 'probe_sha256'))):
                refuse()
            return proof
        database = home / '.agents/memory' / plan['name'] / 'received/memory' / store / 'library.db'
        owned(database)
        backup = root / 'backup.db'
        if not backup.exists():
            temporary = root / (uuid.uuid4().hex + '.partial')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            with contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as source:
                with contextlib.closing(sqlite3.connect(temporary)) as snapshot:
                    source.backup(snapshot)
                    if snapshot.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                        refuse()
            fd = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(temporary, backup)
        owned(backup)
        with contextlib.closing(sqlite3.connect(backup.as_uri() + '?mode=ro', uri=True)) as snapshot:
            if snapshot.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                refuse()
        if not (root / 'intent.json').exists():
            publish(root / 'intent.json', dict(plan_digest=fingerprint, nonce=str(uuid.uuid4()), read_verified=False))
        intent = read(root / 'intent.json')
        if (set(intent) != {'plan_digest', 'nonce', 'read_verified'} or intent['plan_digest'] != fingerprint
                or str(uuid.UUID(intent['nonce'])) != intent['nonce'] or type(intent['read_verified']) is not bool):
            refuse()
        title = 'Onboarding native memory verification ' + intent['nonce']
        raw = 'Temporary native write/read verification; original history remains preserved. ' + intent['nonce']
        wrapper = state / ('hmk-' + store + '.py')
        owned(wrapper)

        def native(arguments):
            if native_runner is not None:
                return native_runner(arguments)
            result = subprocess.run([sys.executable, '-B', str(wrapper), 'memoryctl.py', *arguments],
                capture_output=True, timeout=120)
            if result.returncode:
                refuse()
            return json.loads(result.stdout)

        def candidate():
            with contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as current:
                rows = current.execute('SELECT id,raw FROM chapters WHERE title=?', (title,)).fetchall()
            if len(rows) > 1 or rows and rows[0][1] != raw:
                refuse()
            return rows[0][0] if rows else None

        stats = native(['stats'])
        if stats.get('db_path') != str(database):
            refuse()
        chapter = candidate()
        if chapter is None and not intent['read_verified']:
            native(['add-text', '--shelf', 'evidence', '--title', title, '--raw', raw,
                '--actor', 'cluster-onboarding-verification'])
            chapter = candidate()
            if chapter is None:
                refuse()
        if not intent['read_verified']:
            recalled = native(['expand', '--id', str(chapter)])
            if recalled.get('id') != chapter or recalled.get('title') != title or recalled.get('raw') != raw:
                refuse()
            intent['read_verified'] = True
            publish(root / 'intent.json', intent)
        if chapter is not None:
            native(['delete', '--id', str(chapter)])
        if candidate() is not None:
            refuse()
        # Preserve every original row, including variants, vectors and history.
        # Native expand legitimately changes only chapter access counters.
        with contextlib.closing(sqlite3.connect(backup.as_uri() + '?mode=ro', uri=True)) as original:
            with contextlib.closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as current:
                if original.execute('PRAGMA integrity_check').fetchall() != [('ok',)] or current.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                    refuse()
                for name, sql in original.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"):
                    if name.startswith(('sqlite_', 'chapters_fts')) or 'VIRTUAL TABLE' in (sql or '').upper():
                        continue
                    quoted = '"' + name.replace('"', '""') + '"'
                    columns = [r[1] for r in original.execute('PRAGMA table_info(' + quoted + ')')]
                    if name == 'chapters':
                        columns = [c for c in columns if c not in {'last_access', 'access_count'}]
                    selection = ','.join('"' + c.replace('"', '""') + '"' for c in columns)
                    remaining = collections.Counter(original.execute('SELECT ' + selection + ' FROM ' + quoted))
                    for row in current.execute('SELECT ' + selection + ' FROM ' + quoted):
                        if remaining[row] > 0:
                            remaining[row] -= 1
                    if any(remaining.values()):
                        refuse()
        checksum = hashlib.sha256()
        with backup.open('rb') as stream:
            while chunk := stream.read(1024 * 1024):
                checksum.update(chunk)
        proof = dict(schema=schema, plan_digest=fingerprint, store=store, verified=True,
            backup_sha256=checksum.hexdigest(), probe_sha256=hashlib.sha256(raw.encode()).hexdigest())
        publish(root / 'proof.json', proof)
        return proof
    finally:
        os.close(lock)


def _uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def snapshot(connection: sqlite3.Connection, human: int) -> dict:
    """Read metadata for the configured human only; never retrieve chat text."""
    connection.execute("BEGIN")
    try:
        instance = connection.execute(
            "SELECT instance_id FROM app_instance_lock WHERE key='main'"
        ).fetchone()
        sessions = []
        for sid, topic, native in connection.execute(
            "SELECT id,thread_id,codex_thread_id FROM sessions WHERE chat_id=? AND creator_user_id=? ORDER BY id LIMIT 32",
            (human, human),
        ):
            if native is None:
                continue
            turns = [
                list(row)
                for row in connection.execute(
                    "SELECT t.id,t.completed_at,(SELECT i.instance_id FROM incoming_updates i WHERE i.turn_id=t.id AND i.status='settled' ORDER BY i.update_id LIMIT 1) FROM turns t WHERE t.session_id=? AND t.from_user_id=? AND t.status='completed' AND EXISTS(SELECT 1 FROM incoming_updates i WHERE i.turn_id=t.id AND i.status='settled') ORDER BY t.id DESC LIMIT 16",
                    (sid, human),
                )
            ]
            if turns:
                sessions.append(
                    dict(topic_id=topic, codex_thread_id=native, turns=turns)
                )
        completed = {turn[0] for session in sessions for turn in session["turns"]}
        steered = []
        # The maintained listener records this audit only after a native steer
        # acknowledgement. Multiple settled inputs alone cannot prove steering.
        for (turn,) in connection.execute(
            "SELECT json_extract(details_json,'$.turn_id') FROM audit_log WHERE action='turn_steered' AND actor_user_id=? AND json_extract(details_json,'$.chat_id')=? ORDER BY id DESC LIMIT 64",
            (human, human),
        ):
            if turn in completed and turn not in steered:
                steered.append(turn)
        return dict(
            instance_id=instance[0] if instance else None,
            sessions=sessions,
            steered_turns=steered,
        )
    finally:
        connection.rollback()


def validate_snapshot(value: object) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != {"instance_id", "sessions", "steered_turns"}
        or value["instance_id"] is not None
        and not _uuid(value["instance_id"])
        or not isinstance(value["sessions"], list)
        or len(value["sessions"]) > 32
        or not isinstance(value["steered_turns"], list)
        or len(value["steered_turns"]) > 64
    ):
        raise OnboardingError("invalid_hosted_check_evidence")
    topics, threads, turns = set(), set(), set()
    for row in value["sessions"]:
        if (
            not isinstance(row, dict)
            or set(row) != {"topic_id", "codex_thread_id", "turns"}
            or type(row["topic_id"]) is not int
            or row["topic_id"] < 0
            or not _uuid(row["codex_thread_id"])
            or not isinstance(row["turns"], list)
            or not 1 <= len(row["turns"]) <= 16
            or row["topic_id"] in topics
            or row["codex_thread_id"] in threads
        ):
            raise OnboardingError("invalid_hosted_check_evidence")
        topics.add(row["topic_id"])
        threads.add(row["codex_thread_id"])
        for item in row["turns"]:
            if (
                not isinstance(item, list)
                or len(item) != 3
                or type(item[0]) is not int
                or item[0] <= 0
                or item[0] in turns
                or not isinstance(item[1], str)
                or len(item[1]) > 64
                or not re.fullmatch(r"[0-9T:.+Z-]{20,64}", item[1])
                or not _uuid(item[2])
            ):
                raise OnboardingError("invalid_hosted_check_evidence")
            turns.add(item[0])
    if any(
        type(turn) is not int or turn not in turns for turn in value["steered_turns"]
    ):
        raise OnboardingError("invalid_hosted_check_evidence")
    return value


def validate(value: object) -> dict:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema",
            "name",
            "owner",
            "request_id",
            "plan_digest",
            "created_ms",
            "updated_ms",
            "browser",
            "technical",
            "native",
            "restart_baseline",
        }
        or value["schema"] != SCHEMA
        or any(
            not isinstance(value[key], str) or not being_seed.NAME.fullmatch(value[key])
            for key in ("name", "owner")
        )
        or not isinstance(value["plan_digest"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["plan_digest"])
        or value["request_id"]
        != str(uuid.uuid5(uuid.NAMESPACE_URL, SCHEMA + ":" + value["plan_digest"]))
        or type(value["created_ms"]) is not int
        or value["created_ms"] < 0
        or type(value["updated_ms"]) is not int
        or value["updated_ms"] < value["created_ms"]
        or type(value["browser"]) is not bool
        or not isinstance(value["technical"], dict)
        or set(value["technical"]) != set(TECHNICAL)
        or any(type(result) is not bool for result in value["technical"].values())
    ):
        raise OnboardingError("invalid_hosted_checks")
    validate_snapshot(value["native"])
    validate_snapshot(value["restart_baseline"])
    return value


class Requests(Progress):
    suffix = ".hosted-checks.json"
    validate = staticmethod(validate)


def _checks(request: dict) -> dict:
    return {**CHECKS, **({"browser": BROWSER} if request["browser"] else {})}


def validate_report(request: dict, value: object) -> dict:
    if (
        not isinstance(value, dict)
        or set(value)
        != {"schema", "request_id", "plan_digest", "checked_at_ms", "checks"}
        or value["schema"] != REPORT
        or value["request_id"] != request["request_id"]
        or value["plan_digest"] != request["plan_digest"]
        or type(value["checked_at_ms"]) is not int
        or value["checked_at_ms"] < request["created_ms"]
        or value["checked_at_ms"] > int(time.time() * 1000) + 300000
        or not isinstance(value["checks"], dict)
        or set(value["checks"]) != set(_checks(request))
        or any(
            not isinstance(result, str) or result not in RESULTS
            for result in value["checks"].values()
        )
    ):
        raise being_seed.SeedError("invalid_hosted_witness")
    return value


def _directory(state: Path, request: dict, *, create=False) -> Path:
    parent = being_seed._path(state / "hosted-witnesses")
    root = being_seed._path(parent / request["name"])
    if create:
        private_directory(parent, create=True)
        private_directory(root, create=True)
    return root


def _report(request: dict, reader, root: Path) -> dict | None:
    try:
        pointer = reader(root / "latest.json")
    except FileNotFoundError:
        return None
    if (
        not isinstance(pointer, dict)
        or set(pointer) != {"report_digest"}
        or not isinstance(pointer["report_digest"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", pointer["report_digest"])
    ):
        raise OnboardingError("invalid_hosted_witness")
    value = reader(root / (pointer["report_digest"] + ".json"))
    if digest(value) != pointer["report_digest"]:
        raise OnboardingError("invalid_hosted_witness")
    if (
        value.get("request_id") != request["request_id"]
        or value.get("plan_digest") != request["plan_digest"]
    ):
        return None
    return validate_report(request, value)


def read(state: Path, request: dict) -> dict:
    request = validate(request)
    witness = _report(request, being_seed._read, _directory(state, request))
    # Historical baseline is worker evidence, not participant-facing content.
    return {
        key: value for key, value in request.items() if key != "restart_baseline"
    } | {
        "checks": _checks(request),
        "report": witness,
        "hosted_acceptance": False,
        "response_path": "/v1/seeds/" + request["name"] + "/onboarding/checks",
        "evidence_scope": "Native metadata is independently collected. Owner results are witnesses; a report does not activate the body.",
        "instructions": [
            "Use this existing hosted body, dedicated SSH and Telegram bot; do not re-export, reinstall or resubmit account or bot data.",
            "Report only checks you actually completed. Missing and failed results are useful.",
            "Use separate real Telegram topics, not /new in one topic. Keep existing native thread bindings.",
            "The host handles the service restart and remaining technical proofs. Do not restart during active work.",
            "Keep credentials and conversation contents private. No transcript or memory corpus is requested.",
        ],
    }


def submit(state: Path, request: dict, value: object) -> dict:
    request = validate(request)
    value = validate_report(request, value)
    being_seed.status(state, request["name"], owner=request["owner"])
    root = _directory(state, request, create=True)
    with being_seed._locked(root):
        previous = _report(request, being_seed._read, root)
        fingerprint = digest(value)
        destination = root / (fingerprint + ".json")
        if destination.exists():
            if being_seed._read(destination) != value:
                raise being_seed.SeedError("existing_hosted_witness_preserved", 409)
        else:
            if len(list(root.glob("*.json"))) >= 129:
                raise being_seed.SeedError("hosted_witness_limit", 409)
            being_seed._write(destination, value)
        if previous is None or value["checked_at_ms"] > previous["checked_at_ms"]:
            being_seed._write(root / "latest.json", {"report_digest": fingerprint})
        elif value["checked_at_ms"] == previous["checked_at_ms"] and value != previous:
            raise being_seed.SeedError("hosted_witness_timestamp_conflict", 409)
    return read(state, request)


def worker_report(state: Path, request: dict, *, intake_uid: int) -> dict | None:
    root = _directory(state, request)
    if not root.exists():
        return None
    for path in (state, root.parent, root):
        being_seed._path(path)
        info = path.stat()
        if not path.is_dir() or info.st_uid != intake_uid or info.st_mode & 0o077:
            raise OnboardingError("private_hosted_witness_required")

    def read_private(path):
        raw = regular(path, uid=intake_uid, limit=65536)
        if path.stat().st_mode & 0o077:
            raise OnboardingError("private_hosted_witness_required")
        return json.loads(raw)

    return _report(request, read_private, root)


class MemoryWrites(Progress):
    suffix = '.memory-write.json'

    @staticmethod
    def validate(value):
        if (not isinstance(value, dict) or set(value) != {'schema', 'name', 'owner', 'plan_digest', 'stores'}
                or value['schema'] != 'cluster-hosted-memory-write/v1'
                or any(not isinstance(value[k], str) or not being_seed.NAME.fullmatch(value[k]) for k in ('name', 'owner'))
                or not isinstance(value['plan_digest'], str) or not re.fullmatch('[0-9a-f]{64}', value['plan_digest'])
                or not isinstance(value['stores'], list) or len(value['stores']) > 200):
            raise OnboardingError('invalid_hosted_memory_write_evidence')
        stores = set()
        for proof in value['stores']:
            if (not isinstance(proof, dict) or set(proof) != {'schema', 'plan_digest', 'store', 'verified', 'backup_sha256', 'probe_sha256'}
                    or proof['schema'] != 'cluster-native-memory-write-proof/v1'
                    or proof['plan_digest'] != value['plan_digest'] or proof['verified'] is not True
                    or not isinstance(proof['store'], str) or not being_seed.NAME.fullmatch(proof['store'])
                    or proof['store'] in stores
                    or any(not isinstance(proof[k], str) or not re.fullmatch('[0-9a-f]{64}', proof[k]) for k in ('backup_sha256', 'probe_sha256'))):
                raise OnboardingError('invalid_hosted_memory_write_evidence')
            stores.add(proof['store'])
        return value


class HostedChecks:
    def __init__(self, backend):
        self.backend = backend

    def _memory_stores(self, plan):
        config = self.backend.config
        if config.inputs is None:
            raise OnboardingError('prepared_onboarding_input_required')
        report = json.loads(regular(config.inputs / plan['name'] / 'received/preparation.json',
            uid=os.geteuid(), limit=being_seed.MAX_PREPARATION))
        stores = [row['name'] for row in report['selection']['memory']]
        if len(set(stores)) != len(stores) or any(not being_seed.NAME.fullmatch(s) for s in stores):
            raise OnboardingError('prepared_onboarding_input_required')
        return stores

    def memory_write_observe(self, plan):
        config = self.backend.config
        proofs = MemoryWrites(config.progress, worker_uid=os.geteuid())
        try:
            value = proofs.read(plan['name'], owner=plan['owner'])
        except FileNotFoundError:
            return Observation('absent', safe_to_execute=True)
        if (value['plan_digest'] != digest(plan)
                or {r['store'] for r in value['stores']} != set(self._memory_stores(plan))):
            raise OnboardingError('existing_hosted_checks_preserved')
        return Observation('complete', {'verified': True})

    def verify_memory_write(self, plan):
        if self.memory_write_observe(plan).state == 'complete':
            return
        config = self.backend.config
        job = JobStore(config.jobs)._load(plan['name'])
        if job['plan'] != plan or job['steps']['memory']['state'] != 'complete':
            raise OnboardingError('receiving_context_required')
        program = ('import json,sys;\n' + inspect.getsource(memory_write_probe)
            + '\nprint(json.dumps(memory_write_probe("/home/agent",json.loads(sys.argv[1]),sys.argv[2])))')
        stores = []
        for store in self._memory_stores(plan):
            result = self.backend._dispatch(plan, ['exec', self.backend.instance(plan), '--user', '1000',
                '--group', '1000', '--', 'python3', '-B', '-I', '-c', program, json.dumps(plan), store])
            stores.append(json.loads(result))
        # No store is created for an explicitly empty-history seed.
        MemoryWrites(config.progress, worker_uid=os.geteuid()).publish(dict(
            schema='cluster-hosted-memory-write/v1', name=plan['name'], owner=plan['owner'],
            plan_digest=digest(plan), stores=stores))

    def observe(self, plan: dict) -> Observation:
        config = self.backend.config
        if (
            config.progress is None
            or config.consent_state is None
            or config.consent_uid is None
        ):
            return Observation("waiting", reason="backend_unavailable")
        supplied = self.backend._telegram_connections(plan)
        if supplied is None:
            return Observation("waiting", reason="connection_data_required")
        human = supplied["telegram_chat_id"]
        # Host-only stdlib program: the qualified receiving SDK/context is not
        # replaced. SQLite uses a read-only connection and a consistent snapshot.
        program = (
            "import sqlite3,json,sys;\n"
            + inspect.getsource(snapshot)
            + '\nc=sqlite3.connect("file:/home/agent/.local/state/daimon-onboarding/telegram/telegram.sqlite3?mode=ro",uri=True);'
            + "print(json.dumps(snapshot(c,int(sys.argv[1]))))"
        )
        native = validate_snapshot(
            json.loads(
                self.backend._dispatch(
                    plan,
                    [
                        "exec",
                        self.backend.instance(plan),
                        "--user",
                        "1000",
                        "--group",
                        "1000",
                        "--",
                        "python3",
                        "-B",
                        "-I",
                        "-c",
                        program,
                        str(human),
                    ],
                )
            )
        )
        requests = Requests(config.progress, worker_uid=os.geteuid())
        now = int(time.time() * 1000)
        try:
            previous = requests.read(plan["name"], owner=plan["owner"])
            if previous["plan_digest"] != digest(plan):
                raise OnboardingError("existing_hosted_checks_preserved")
        except FileNotFoundError:
            previous = None
        baseline = previous["restart_baseline"] if previous else native
        # Keep the first qualified two-topic mapping until a real instance
        # successor has continued both exact native threads.
        if len(baseline["sessions"]) < 2 and len(native["sessions"]) >= 2:
            baseline = native
        restarted = False
        if baseline["instance_id"] is not None and native["instance_id"] not in {
            None,
            baseline["instance_id"],
        }:
            restarted = len(baseline["sessions"]) >= 2 and all(
                any(
                    current["topic_id"] == old["topic_id"]
                    and current["codex_thread_id"] == old["codex_thread_id"]
                    and any(
                        turn[0] > max(item[0] for item in old["turns"])
                        and turn[2] == native["instance_id"]
                        for turn in current["turns"]
                    )
                    for current in native["sessions"]
                )
                for old in baseline["sessions"]
            )
        job = JobStore(config.jobs)._load(plan["name"])
        if job["plan"] != plan:
            raise OnboardingError("existing_hosted_checks_preserved")
        technical = dict.fromkeys(TECHNICAL, False)
        technical.update(
            identity_verified=True,
            provider_verified=job["steps"]["access"]["facts"].get("provider_verified")
            is True,
            memory_verified=job["steps"]["memory"]["state"] == "complete",
            telegram_verified=bool(native["sessions"]),
            topics_verified=len(native["sessions"]) >= 2,
            steering_verified=bool(native["steered_turns"]),
            restart_verified=restarted,
        )
        try:
            memory_proof = MemoryWrites(config.progress, worker_uid=os.geteuid()).read(plan['name'], owner=plan['owner'])
        except FileNotFoundError:
            memory_proof = None
        if memory_proof is not None:
            technical['memory_write_verified'] = self.memory_write_observe(plan).state == 'complete'
        if previous and previous["technical"]["restart_verified"]:
            # Historical continuation evidence survives later normal restarts.
            technical["restart_verified"] = True
        value = dict(
            schema=SCHEMA,
            name=plan["name"],
            owner=plan["owner"],
            plan_digest=digest(plan),
            request_id=str(uuid.uuid5(uuid.NAMESPACE_URL, SCHEMA + ":" + digest(plan))),
            created_ms=previous["created_ms"] if previous else now,
            updated_ms=now,
            browser=plan["browser"],
            technical=technical,
            native=native,
            restart_baseline=baseline,
        )
        requests.publish(value)
        witness = worker_report(
            config.consent_state, value, intake_uid=config.consent_uid
        )
        # Remaining SSH/CLI, reversible memory write and native Matrix delivery
        # adapters must still provide observations. All-passed witnesses cannot
        # promote this collection to a complete hosted acceptance.
        reason = (
            "human_contact_required"
            if witness is None
            or any(result != "passed" for result in witness["checks"].values())
            else "hosted_checks_required"
        )
        return Observation("waiting", reason=reason)
