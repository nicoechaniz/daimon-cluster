"""Owner witnesses and independent, read-only hosted acceptance evidence.

Human reports remain witnesses; native metadata proves only observed checks.
Completion requires both the full owner witness and every native technical
proof. Missing evidence stays visible and never activates a body.
"""

from __future__ import annotations

import inspect
import base64
import hashlib
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


def acceptance_facts(request, witness):
    """Neither an owner report nor native readiness alone completes acceptance."""
    from .onboarding import ACCEPTANCE
    if witness is None:
        return None
    validate_report(request, witness)
    if (any(value != 'passed' for value in witness['checks'].values())
            or any(request['technical'].get(key) is not True for key in TECHNICAL)):
        return None
    facts = {'verified': True, **dict.fromkeys(ACCEPTANCE, True)}
    if request['browser']:
        facts['browser_verified'] = True
    return facts


def accepted_progress(progress, request, worker_uid):
    """Only the Root worker's committed complete job projects activation."""
    try:
        value = Progress(progress, worker_uid=worker_uid).read(request['name'], owner=request['owner'])
    except FileNotFoundError:
        return False
    if value['plan_digest'] != request['plan_digest']:
        raise OnboardingError('existing_hosted_checks_preserved')
    return value['active'] is True


def read(state: Path, request: dict, *, progress=None, worker_uid=0) -> dict:
    request = validate(request)
    witness = _report(request, being_seed._read, _directory(state, request))
    # Historical baseline is worker evidence, not participant-facing content.
    return {
        key: value for key, value in request.items() if key != "restart_baseline"
    } | {
        "checks": _checks(request),
        "report": witness,
        "hosted_acceptance": bool(progress is not None and acceptance_facts(request, witness) is not None
            and accepted_progress(progress, request, worker_uid)),
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


def ssh_login_snapshot(entries, fingerprint, since_ms, now_ms):
    """Only trusted sshd authentication for the configured owner's key counts."""
    import re

    authenticated = None
    pattern = r'Accepted publickey for agent from \S+ port [0-9]+ ssh2: [A-Za-z0-9-]+ (SHA256:[A-Za-z0-9+/]{43})'
    if (not isinstance(fingerprint, str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fingerprint)
            or type(since_ms) is not int or type(now_ms) is not int or since_ms > now_ms):
        raise ValueError('invalid_ssh_login_evidence')
    for entry in entries:
        if (not isinstance(entry, dict) or entry.get('_SYSTEMD_UNIT') != 'daimon-onboarding-ssh.service'
                or entry.get('_UID') != '0' or entry.get('_COMM') not in ('sshd', 'sshd-session')):
            continue
        message = entry.get('MESSAGE')
        match = re.fullmatch(pattern, message) if isinstance(message, str) else None
        stamp = entry.get('__REALTIME_TIMESTAMP', '')
        if not match or match[1] != fingerprint or not isinstance(stamp, str) or not stamp.isdecimal():
            continue
        when = int(stamp) // 1000
        if since_ms <= when <= now_ms + 300000:
            authenticated = max(authenticated or when, when)
    return {'verified': authenticated is not None, 'authenticated_at_ms': authenticated}


class SSHLogins(Progress):
    suffix = '.ssh-login.json'

    @staticmethod
    def validate(value):
        if (not isinstance(value, dict)
                or set(value) != {'schema', 'name', 'owner', 'plan_digest', 'key_digest', 'verified', 'authenticated_at_ms'}
                or value['schema'] != 'cluster-hosted-ssh-login/v1'
                or any(not isinstance(value[k], str) or not being_seed.NAME.fullmatch(value[k]) for k in ('name', 'owner'))
                or any(not isinstance(value[k], str) or not re.fullmatch('[0-9a-f]{64}', value[k]) for k in ('plan_digest', 'key_digest'))
                or value['verified'] is not True or type(value['authenticated_at_ms']) is not int
                or value['authenticated_at_ms'] < 0):
            raise OnboardingError('invalid_ssh_login_evidence')
        return value


def matrix_delivery_result(response, send_id):
    """Native intake receipts prove transport, never a conscious agent read."""
    import hashlib
    import json
    import uuid

    if not isinstance(response, dict):
        return {'verified': False}
    value = response.get('result')
    if (response.get('ok') is not True or response.get('error') is not None
            or not isinstance(value, dict) or value.get('send_id') != send_id
            or value.get('phase') != 'message' or value.get('transport_status') != 'recipient-intake'
            or value.get('ambiguous') is not False or value.get('retryable') is not False
            or not isinstance(value.get('stages'), list) or len(value['stages']) != 2):
        return {'verified': False}
    for stage, phase in zip(value['stages'], ('evidence', 'message'), strict=True):
        if not isinstance(stage, dict) or stage.get('phase') != phase or stage.get('transport_status') != 'recipient-intake':
            return {'verified': False}
        try:
            if str(uuid.UUID(stage['attempt_id'])) != stage['attempt_id']:
                return {'verified': False}
        except (KeyError, TypeError, ValueError, AttributeError):
            return {'verified': False}
    return {'verified': True, 'agent_read': False,
        'native_receipt_sha256': hashlib.sha256(json.dumps(response, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}


def matrix_delivery_probe(payload, parameters, recipient, send=False):
    """Use the receiving body's issued native helper; custody stays in daemon.

    The finite technical test is attributed to its human-directed operator.
    It does not load a runtime, read an inbox, or request an autonomous reply.
    """
    import asyncio
    import json
    from pathlib import Path
    from daimon_matrix.agent_chat import bridge, load_binding, call
    from daimon_matrix.client import ClientConfig
    from daimon_matrix.messaging_config import protected_read

    root = Path(payload['home']) / payload['state_relative']
    chat = payload['chat']
    attachment = Path(chat['attachment'])
    binding = load_binding(attachment / 'binding.json')
    assert binding == dict(schema='dm.agent-chat.binding/v1', socket=chat['socket'],
        client_config=str(Path(chat['application']) / 'client.json'),
        client_key=str(Path(chat['application']) / 'client.key'),
        request_dir=str(attachment / 'requests'), incoming_channels=['peer-in'], outgoing_channels=['peer-out'])
    native = ClientConfig.load(root / 'runtime/client.json', protected_read(root / 'runtime/client.key', size=32))
    client = bridge(binding).client
    assert client.config.expected_server == native.expected_server and client.config.runtime_id == native.runtime_id
    assert all(native.expected_server[k] == v for k, v in payload['origin'].items())
    application = json.loads(protected_read(Path(chat['application']) / 'application.json'))
    assert application['outgoing']['recipient_being_ref'] == recipient
    assert application['incoming']['recipient_being_ref'] == payload['being_ref']
    assert parameters['channel_id'] == 'peer-out'
    query = dict(channel_id='peer-out', send_id=parameters['send_id'])
    observed = asyncio.run(call(binding, 'messaging_delivery', query, timeout=45))
    result = matrix_delivery_result(observed, parameters['send_id'])
    if not result['verified'] and send:
        # Exact persisted arguments and native request journal own retry safety.
        # A lost send ACK is reconciled by delivery on the next invocation.
        asyncio.run(call(binding, 'messaging_send', parameters, timeout=45))
        observed = asyncio.run(call(binding, 'messaging_delivery', query, timeout=45))
        result = matrix_delivery_result(observed, parameters['send_id'])
    return result


class MatrixIntents(Progress):
    suffix = '.matrix-intent.json'

    @staticmethod
    def validate(value):
        fields = {'schema', 'name', 'owner', 'plan_digest', 'sender_being_ref', 'recipient_being_ref', 'parameters'}
        if (not isinstance(value, dict) or set(value) != fields or value['schema'] != 'cluster-hosted-matrix-intent/v1'
                or any(not isinstance(value[k], str) or not being_seed.NAME.fullmatch(value[k]) for k in ('name', 'owner'))
                or not isinstance(value['plan_digest'], str) or not re.fullmatch('[0-9a-f]{64}', value['plan_digest'])
                or any(not isinstance(value[k], str) or not re.fullmatch(r'dm:being:v1:[A-Za-z0-9_-]{43}', value[k])
                       for k in ('sender_being_ref', 'recipient_being_ref'))):
            raise OnboardingError('invalid_matrix_delivery_evidence')
        params = value['parameters']
        if (not isinstance(params, dict) or set(params) != {'channel_id', 'send_id', 'thread_id', 'text'}
                or params['channel_id'] != 'peer-out' or not isinstance(params['text'], str) or not 1 <= len(params['text']) <= 4096):
            raise OnboardingError('invalid_matrix_delivery_evidence')
        for key in ('send_id', 'thread_id'):
            try:
                if str(uuid.UUID(params[key])) != params[key]:
                    raise ValueError
            except (ValueError, TypeError, AttributeError):
                raise OnboardingError('invalid_matrix_delivery_evidence') from None
        return value


class MatrixDeliveries(Progress):
    suffix = '.matrix-delivery.json'

    @staticmethod
    def validate(value):
        if (not isinstance(value, dict) or set(value) != {'schema', 'name', 'owner', 'plan_digest', 'intent', 'probe'}
                or value['schema'] != 'cluster-hosted-matrix-delivery/v1'):
            raise OnboardingError('invalid_matrix_delivery_evidence')
        intent = MatrixIntents.validate(value['intent'])
        if any(value[k] != intent[k] for k in ('name', 'owner', 'plan_digest')):
            raise OnboardingError('invalid_matrix_delivery_evidence')
        probe = value['probe']
        if (not isinstance(probe, dict) or set(probe) != {'verified', 'agent_read', 'native_receipt_sha256'}
                or probe['verified'] is not True or probe['agent_read'] is not False
                or not isinstance(probe['native_receipt_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', probe['native_receipt_sha256'])):
            raise OnboardingError('invalid_matrix_delivery_evidence')
        return value


def telegram_listener_snapshot(home, owner, runner=None):
    """Observe the running listener's own current native lease, without writes."""
    import json
    import os
    import subprocess
    import sys
    import time
    import uuid
    from pathlib import Path

    run = runner or subprocess.run
    command = ['systemctl', 'show', 'daimon-onboarding-telegram.service',
        '--property=MainPID', '--property=ActiveState', '--property=ExecMainStartTimestampMonotonic']

    def status():
        result = run(command, capture_output=True, text=True, timeout=30, check=True)
        return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)

    before = status()
    try:
        pid = int(before['MainPID'])
        start = int(before['ExecMainStartTimestampMonotonic']) / 1000000
        if before['ActiveState'] != 'active' or pid <= 0 or not 0 < start <= time.monotonic():
            return {'ready': False}
        os.kill(pid, 0)
        if Path('/proc', str(pid)).stat().st_uid != owner:
            return {'ready': False}
    except (KeyError, ValueError, OSError):
        return {'ready': False}
    started_at = time.time() - (time.monotonic() - start)
    program = ('import sqlite3,json,sys;from pathlib import Path;from contextlib import closing;'
        'from datetime import datetime;\n'
        'with closing(sqlite3.connect(Path(sys.argv[1]).as_uri()+"?mode=ro",uri=True)) as c:\n'
        ' r=c.execute("SELECT instance_id,heartbeat_at,acquired_at FROM app_instance_lock WHERE key=\'main\'").fetchone()\n'
        'print(json.dumps({"instance":r[0],"heartbeat":datetime.fromisoformat(r[1]).timestamp(),'
        '"acquired":datetime.fromisoformat(r[2]).timestamp()} if r else None))')
    database = Path(home) / '.local/state/daimon-onboarding/telegram/telegram.sqlite3'
    result = run([sys.executable, '-B', '-I', '-c', program, str(database)],
        user=owner, group=owner, extra_groups=[] if os.geteuid() == 0 else None, umask=0o077,
        env={'HOME': str(home), 'PATH': os.defpath, 'LANG': 'C.UTF-8'},
        capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        return {'ready': False}
    try:
        lease = json.loads(result.stdout)
        if (not isinstance(lease, dict) or set(lease) != {'instance', 'heartbeat', 'acquired'}
                or str(uuid.UUID(lease['instance'])) != lease['instance']
                or any(type(lease[k]) not in (int, float) for k in ('heartbeat', 'acquired'))):
            return {'ready': False}
        now = time.time()
        # The selected native listener heartbeats every 30 seconds. The lease
        # must have been acquired by this process, not its stopped predecessor.
        if not started_at - .1 <= lease['acquired'] <= lease['heartbeat'] <= now + 5 or now - lease['heartbeat'] > 45:
            return {'ready': False}
        if status() != before:
            return {'ready': False}
        os.kill(pid, 0)
    except (TypeError, ValueError, OSError):
        return {'ready': False}
    return {'ready': True}


def wait_telegram_listener(home, owner, runner=None, sleeper=None, elapsed=None, timeout=180):
    """A finite startup wait; do not restart a live or cooling-down listener."""
    import time
    sleep = sleeper or time.sleep
    clock = elapsed or time.monotonic
    deadline = clock() + timeout
    while True:
        if telegram_listener_snapshot(home, owner, runner)['ready']:
            return True
        if clock() >= deadline:
            return False
        sleep(min(2, max(0, deadline - clock())))


def cli_admission_guard(home, owner):
    """Hold the receiving user's SQLite writer lock until admission stops."""
    import json
    import os
    import select
    import subprocess
    import sys
    from pathlib import Path

    database = Path(home) / '.local/state/daimon-onboarding/telegram/telegram.sqlite3'
    program = ('import sqlite3,json,sys;'
        'c=sqlite3.connect(sys.argv[1],timeout=20);c.execute("BEGIN IMMEDIATE");'
        'idle=c.execute("SELECT COUNT(*) FROM sessions WHERE busy!=0").fetchone()[0]==0 '
        'and c.execute("SELECT COUNT(*) FROM turns WHERE status=\'running\'").fetchone()[0]==0;'
        'print(json.dumps({"idle":idle}),flush=True);sys.stdin.buffer.read(1);c.rollback();c.close()')
    process = subprocess.Popen([sys.executable, '-B', '-I', '-c', program, str(database)],
        user=owner, group=owner, extra_groups=[] if os.geteuid() == 0 else None, umask=0o077,
        env={'HOME': str(home), 'PATH': os.defpath, 'LANG': 'C.UTF-8'},
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        if not select.select([process.stdout], [], [], 30)[0]:
            raise ValueError('cli_admission_lock_unavailable')
        value = json.loads(process.stdout.readline())
        if set(value) != {'idle'} or type(value['idle']) is not bool:
            raise ValueError('cli_admission_lock_unavailable')
        yield value['idle']
    finally:
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        if process.stdout is not None:
            process.stdout.close()


def cli_resume_probe(home, plan, thread, model, reasoning, runner=None,
                     journal_root=None, unit_root=None, codex_path=None):
    """One bounded CLI resume; keep history, offsets and uncertain output.

    Runs as guest root. Only the dedicated Telegram/native services pause,
    after idle checks. Native inference runs as the receiving user. An uncertain
    inference is never repeated; recovery consumes its original private stream.
    """
    import fcntl
    import hashlib
    import json
    import os
    import re
    import shutil
    import stat
    import subprocess
    import sys
    import uuid
    from pathlib import Path
    from contextlib import contextmanager

    run = runner or subprocess.run
    coordinator = os.geteuid()
    if runner is None and coordinator != 0:
        raise PermissionError('guest_root_required')
    owner = 1000 if runner is None else coordinator
    home = Path(home)
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,30}', plan.get('name', '')) or str(uuid.UUID(thread)) != thread:
        raise ValueError('invalid_cli_resume_probe')
    fingerprint = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    root = Path(journal_root) if journal_root else Path('/var/lib/daimon-onboarding-checks') / plan['name'] / 'cli-resume' / thread
    units = Path(unit_root or '/etc/systemd/system')
    names = ['daimon-onboarding-telegram.service', 'daimon-onboarding-codex.service']

    def owned(path, uid, private=True):
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('private_cli_resume_probe_required')
        info = path.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
                or info.st_mode & (0o077 if private else 0o022)):
            raise ValueError('private_cli_resume_probe_required')
        return info

    def hash_file(path, length=None):
        h = hashlib.sha256()
        with path.open('rb') as stream:
            left = length
            while left is None or left > 0:
                chunk = stream.read(1024 * 1024 if left is None else min(left, 1024 * 1024))
                if not chunk:
                    break
                h.update(chunk)
                if left is not None:
                    left -= len(chunk)
        if left not in (None, 0):
            raise ValueError('original_cli_history_changed')
        return h.hexdigest()

    def publish(path, value):
        temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(json.dumps(value, sort_keys=True).encode())
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def read(path):
        if owned(path, coordinator).st_size > 65536:
            raise ValueError('invalid_cli_resume_probe')
        return json.loads(path.read_bytes())

    def system(action, selected):
        return run(['systemctl', action, *selected], capture_output=True, text=True, timeout=40, check=True)

    def metadata():
        # SQLite read marks stay owned by the receiving user, including SHM.
        code = ('import sqlite3,json,sys;from pathlib import Path;from contextlib import closing;'
            'h=Path(sys.argv[1]);\n'
            'with closing(sqlite3.connect((h/".local/state/daimon-onboarding/telegram/telegram.sqlite3").as_uri()+"?mode=ro",uri=True)) as c:\n'
            ' idle=c.execute("SELECT COUNT(*) FROM sessions WHERE busy!=0").fetchone()[0]==0 and c.execute("SELECT COUNT(*) FROM turns WHERE status=\'running\'").fetchone()[0]==0\n'
            'with closing(sqlite3.connect((h/".codex/state_5.sqlite").as_uri()+"?mode=ro",uri=True)) as c:\n'
            ' row=c.execute("SELECT rollout_path FROM threads WHERE id=? AND archived=0",(sys.argv[2],)).fetchone()\n'
            'print(json.dumps({"idle":idle,"rollout":row[0] if row else None}))')
        result = run([sys.executable, '-B', '-I', '-c', code, str(home), thread],
            user=owner, group=owner, extra_groups=[], umask=0o077,
            env={'HOME': str(home), 'PATH': os.defpath, 'LANG': 'C.UTF-8'},
            capture_output=True, text=True, timeout=30, check=True)
        value = json.loads(result.stdout)
        if set(value) != {'idle', 'rollout'} or type(value['idle']) is not bool:
            raise ValueError('invalid_cli_resume_probe')
        return value

    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != coordinator or root.stat().st_mode & 0o077:
        raise ValueError('private_cli_resume_probe_required')
    fd = os.open(root / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        owned(root / 'lock', coordinator)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        executable = Path(codex_path or shutil.which('codex')).resolve(strict=True)
        owned(executable, coordinator, False)
        unit_hashes = {name: hash_file(units / name) for name in names if owned(units / name, coordinator, False)}
        binding = {'plan_digest': fingerprint, 'thread_id': thread, 'model': model, 'reasoning': reasoning,
                   'cli_sha256': hash_file(executable), 'units': unit_hashes}
        intent_path = root / 'intent.json'
        intent = read(intent_path) if intent_path.exists() else None
        if intent is not None and intent['binding'] != binding:
            raise ValueError('existing_cli_resume_probe_preserved')
        # Do not restore/restart underneath a CLI left alive by a lost caller.
        for process in Path('/proc').iterdir():
            if not process.name.isdecimal():
                continue
            try:
                argv = (process / 'cmdline').read_bytes().split(b'\0')
                if thread.encode() in argv and b'resume' in argv:
                    return {'verified': False, 'waiting': True}
            except OSError:
                pass
        stopped = False
        try:
            if (root / 'proof.json').exists():
                proof = read(root / 'proof.json')
                if proof['plan_digest'] != fingerprint or proof['thread_id'] != thread or proof['cli_sha256'] != binding['cli_sha256']:
                    raise ValueError('existing_cli_resume_probe_preserved')
                history = Path(intent['history'])
                owned(history, owner)
                if hash_file(history, intent['history_size']) != intent['history_sha256']:
                    raise ValueError('original_cli_history_changed')
                return proof
            if intent is None:
                if not metadata()['idle']:
                    return {'verified': False, 'waiting': True}
                system('is-active', names)
                # Native Telegram marks busy before provider dispatch. Hold its
                # writer lock while stopping admission so no new turn can start
                # between the idle observation and service shutdown.
                if runner is None:
                    admission = contextmanager(cli_admission_guard)(home, owner)
                else:
                    @contextmanager
                    def fixture_admission():
                        yield metadata()['idle']
                    admission = fixture_admission()
                with admission as idle:
                    if not idle:
                        return {'verified': False, 'waiting': True}
                    stopped = True
                    system('stop', names[:1])
                information = metadata()
                if not information['idle']:
                    return {'verified': False, 'waiting': True}
                system('stop', names[1:])
                history = Path(information['rollout'])
                if not history.is_relative_to(home / '.codex'):
                    raise ValueError('owned_cli_thread_required')
                info = owned(history, owner)
                old_hash = hash_file(history)
                original = root / ('original-history-' + uuid.uuid4().hex + '.jsonl')
                with history.open('rb') as source, original.open('xb') as output:
                    os.chmod(original, 0o600)
                    shutil.copyfileobj(source, output)
                    output.flush()
                    os.fsync(output.fileno())
                if hash_file(original) != old_hash:
                    raise ValueError('original_cli_history_changed')
                intent = {'binding': binding, 'history': str(history), 'history_size': info.st_size,
                    'history_sha256': old_hash, 'nonce': 'CLI_RESUME_OK_' + uuid.uuid4().hex}
                publish(intent_path, intent)
                # Intent is durable before dispatch. No retry creates inference.
                output_path = root / 'native-output.jsonl'
                output_fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                error_fd = os.open(root / 'native-errors.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(output_fd, 'wb') as output, os.fdopen(error_fd, 'wb') as errors:
                    run([str(executable), '-c', 'cli_auth_credentials_store="file"',
                        '-c', 'approval_policy="never"', '-c', 'sandbox_mode="read-only"',
                        '-c', 'model_reasoning_effort=' + json.dumps(reasoning), 'exec', 'resume',
                        '--ephemeral', '--json', '--skip-git-repo-check', '--model', model, thread, '-'],
                        input=('Technical CLI continuity verification, requested by Nicolas and operated by Source. '
                            'Do not use tools, read memory or Matrix, change files or reveal conversation content. '
                            'Reply with exactly: ' + intent['nonce']).encode(),
                        env={'HOME': str(home), 'CODEX_HOME': str(home / '.codex'),
                             'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                        cwd=home / 'Projects/being', user=owner, group=owner, extra_groups=[], umask=0o077,
                        stdout=output, stderr=errors, timeout=240, check=False)
                    output.flush()
                    os.fsync(output.fileno())
                    errors.flush()
                    os.fsync(errors.fileno())
            history = Path(intent['history'])
            owned(history, owner)
            if hash_file(history, intent['history_size']) != intent['history_sha256']:
                raise ValueError('original_cli_history_changed')
            output_path = root / 'native-output.jsonl'
            if not output_path.exists() or owned(output_path, coordinator).st_size > 16 * 1024**2:
                return {'verified': False, 'uncertain': True}
            try:
                events = [json.loads(line) for line in output_path.read_bytes().splitlines() if line.strip()]
            except ValueError:
                return {'verified': False, 'uncertain': True}
            if (not any(e.get('type') == 'thread.started' and e.get('thread_id') == thread for e in events)
                    or not any(e.get('type') == 'turn.completed' for e in events)
                    or any(e.get('type') in {'error', 'turn.failed'} for e in events)
                    or any(e.get('type', '').startswith('item.') and e.get('item', {}).get('type')
                           not in {'agent_message', 'reasoning'} for e in events)
                    or not any(e.get('type') == 'item.completed' and e.get('item', {}).get('type') == 'agent_message'
                           and e['item'].get('text', '').strip() == intent['nonce'] for e in events)):
                return {'verified': False, 'uncertain': True}
            proof = {'schema': 'cluster-native-cli-resume/v1', 'plan_digest': fingerprint, 'thread_id': thread,
                'verified': True, 'original_history_sha256': intent['history_sha256'],
                'cli_sha256': binding['cli_sha256'], 'provider_stream_sha256': hash_file(output_path)}
            owned(executable, coordinator, False)
            if hash_file(executable) != binding['cli_sha256']:
                raise ValueError('existing_cli_resume_probe_preserved')
            publish(root / 'proof.json', proof)
            return proof
        finally:
            if stopped or intent is not None:
                for name in unit_hashes:
                    owned(units / name, coordinator, False)
                if any(hash_file(units / name) != expected for name, expected in unit_hashes.items()):
                    raise ValueError('foreign_cli_service_state_preserved')
                # Software/services only. Never restore history, SQLite or offsets.
                system('start', names[1:])
                system('start', names[:1])
                system('is-active', names)
                if not wait_telegram_listener(home, owner, runner):
                    raise ValueError('telegram_listener_not_ready')
    finally:
        os.close(fd)


class CLIResumes(Progress):
    suffix = '.cli-resume.json'

    @staticmethod
    def validate(value):
        if (not isinstance(value, dict) or set(value) != {'schema', 'name', 'owner', 'plan_digest', 'probe'}
                or value['schema'] != 'cluster-hosted-cli-resume/v1'
                or any(not isinstance(value[k], str) or not being_seed.NAME.fullmatch(value[k]) for k in ('name', 'owner'))
                or not isinstance(value['plan_digest'], str) or not re.fullmatch('[0-9a-f]{64}', value['plan_digest'])):
            raise OnboardingError('invalid_cli_resume_evidence')
        probe = value['probe']
        if (not isinstance(probe, dict) or set(probe) != {'schema', 'plan_digest', 'thread_id', 'verified',
                'original_history_sha256', 'cli_sha256', 'provider_stream_sha256'}
                or probe['schema'] != 'cluster-native-cli-resume/v1' or probe['plan_digest'] != value['plan_digest']
                or probe['verified'] is not True
                or any(not isinstance(probe[k], str) or not re.fullmatch('[0-9a-f]{64}', probe[k])
                       for k in ('original_history_sha256', 'cli_sha256', 'provider_stream_sha256'))):
            raise OnboardingError('invalid_cli_resume_evidence')
        try:
            if str(uuid.UUID(probe['thread_id'])) != probe['thread_id']:
                raise ValueError
        except (TypeError, ValueError, AttributeError):
            raise OnboardingError('invalid_cli_resume_evidence') from None
        return value


class HostedChecks:
    def __init__(self, backend):
        self.backend = backend

    def _matrix_context(self, plan):
        from .onboarding_managed import ManagedRuntime
        from .onboarding_owner_client import OwnerClient
        from .onboarding_peer_host import PeerHost
        expected = ManagedRuntime(self.backend)._expected(plan)
        payload = OwnerClient(self.backend)._payload(plan, expected, install=False)
        if 'chat' not in payload or self.backend._target_call(plan, 'sdk-observe').get('ready') is not True:
            raise OnboardingError('backend_unavailable')
        return payload, PeerHost(self.backend).settings['source_being_ref']

    def prepare_matrix_intent(self, plan, parameters=None):
        """Freeze an approved technical send, or adopt its exact existing intent."""
        payload, recipient = self._matrix_context(plan)
        intents = MatrixIntents(self.backend.config.progress, worker_uid=os.geteuid())
        try:
            existing = intents.read(plan['name'], owner=plan['owner'])
        except FileNotFoundError:
            existing = None
        if parameters is None and existing is not None:
            parameters = existing['parameters']
        if parameters is None:
            parameters = dict(channel_id='peer-out',
                send_id=str(uuid.uuid5(uuid.NAMESPACE_URL, 'cluster-hosted-matrix-intent/v1:send:' + digest(plan))),
                thread_id=str(uuid.uuid5(uuid.NAMESPACE_URL, 'cluster-hosted-matrix-intent/v1:thread:' + digest(plan))),
                text='Technical Matrix delivery verification requested by Nicolas, operated by Source on this hosted body. '
                    'This checks native transport; no automatic agent reply is requested.')
        value = MatrixIntents.validate(dict(schema='cluster-hosted-matrix-intent/v1', name=plan['name'],
            owner=plan['owner'], plan_digest=digest(plan), sender_being_ref=payload['being_ref'],
            recipient_being_ref=recipient, parameters=parameters))
        if existing is not None:
            if existing != value:
                raise OnboardingError('existing_hosted_checks_preserved')
        else:
            intents.publish(value)
        return value, payload

    def _matrix_probe(self, plan, intent, payload, *, send=False):
        program = ('import json,sys;\n' + inspect.getsource(matrix_delivery_result) + '\n'
            + inspect.getsource(matrix_delivery_probe)
            + '\np=json.loads(sys.argv[1]);print(json.dumps(matrix_delivery_probe(p["payload"],'
            + 'p["parameters"],p["recipient"],p["send"])))')
        request = dict(payload=payload, parameters=intent['parameters'], recipient=intent['recipient_being_ref'], send=send)
        result = json.loads(self.backend._dispatch(plan, ['exec', self.backend.instance(plan),
            '--user', '1000', '--group', '1000', '--env', 'HOME=/home/agent', '--',
            payload['python'], '-B', '-I', '-c', program, json.dumps(request)]))
        if result == {'verified': False}:
            return False
        receipt = MatrixDeliveries.validate(dict(schema='cluster-hosted-matrix-delivery/v1',
            name=plan['name'], owner=plan['owner'], plan_digest=digest(plan), intent=intent, probe=result))
        MatrixDeliveries(self.backend.config.progress, worker_uid=os.geteuid()).publish(receipt)
        return True

    def adopt_matrix_delivery(self, plan, path):
        """Import a worker-owned historical native receipt, never owner input.

        A completed delivery is historical evidence. Reinspection can require a
        renewed transport carrier; importing an already authenticated Root
        record preserves the observed effect without another transmission.
        """
        intent, payload = self.prepare_matrix_intent(plan)
        path = Path(path)
        record = json.loads(regular(path, uid=os.geteuid(), limit=65536))
        if (path.stat().st_mode & 0o037
                or not isinstance(record, dict)
                or set(record) != {'schema', 'plan_digest', 'commit', 'send_id', 'thread_id', 'delivered', 'agent_read', 'response'}
                or record['schema'] != 'cluster-owner-requested-message-verification-result/v1'
                or record['plan_digest'] != digest(plan) or record['delivered'] is not True or record['agent_read'] is not False
                or not isinstance(record['commit'], str) or not re.fullmatch('[0-9a-f]{40}', record['commit'])
                or any(record[key] != intent['parameters'][key] for key in ('send_id', 'thread_id'))):
            raise OnboardingError('invalid_matrix_delivery_evidence')
        response = record['response']
        if (not isinstance(response, dict) or response.get('schema') != 'dm.local.response/v1'
                or not isinstance(response.get('server'), dict)
                or any(response['server'].get(key) != value for key, value in payload['origin'].items())):
            raise OnboardingError('invalid_matrix_delivery_evidence')
        probe = matrix_delivery_result(response, intent['parameters']['send_id'])
        receipt = MatrixDeliveries.validate(dict(schema='cluster-hosted-matrix-delivery/v1',
            name=plan['name'], owner=plan['owner'], plan_digest=digest(plan), intent=intent, probe=probe))
        try:
            previous = MatrixDeliveries(self.backend.config.progress, worker_uid=os.geteuid()).read(plan['name'], owner=plan['owner'])
        except FileNotFoundError:
            previous = None
        if previous is not None:
            if previous != receipt:
                raise OnboardingError('existing_hosted_checks_preserved')
        else:
            MatrixDeliveries(self.backend.config.progress, worker_uid=os.geteuid()).publish(receipt)

    def matrix_delivery_observe(self, plan):
        proofs = MatrixDeliveries(self.backend.config.progress, worker_uid=os.geteuid())
        try:
            proof = proofs.read(plan['name'], owner=plan['owner'])
        except FileNotFoundError:
            proof = None
        try:
            intent = MatrixIntents(self.backend.config.progress, worker_uid=os.geteuid()).read(plan['name'], owner=plan['owner'])
        except FileNotFoundError:
            if proof is not None:
                raise OnboardingError('existing_hosted_checks_preserved')
            return Observation('absent', safe_to_execute=True)
        current, payload = self.prepare_matrix_intent(plan)
        if current != intent or proof is not None and proof['intent'] != intent:
            raise OnboardingError('existing_hosted_checks_preserved')
        if proof is not None or self._matrix_probe(plan, intent, payload):
            return Observation('complete', {'verified': True, 'matrix_delivery_verified': True})
        return Observation('absent', safe_to_execute=True)

    def verify_matrix_delivery(self, plan):
        if self.matrix_delivery_observe(plan).state == 'complete':
            return
        intent, payload = self.prepare_matrix_intent(plan)
        self._matrix_probe(plan, intent, payload, send=True)

    def _memory_stores(self, plan):
        config = self.backend.config
        if config.inputs is None:
            raise OnboardingError('prepared_onboarding_input_required')
        report = json.loads(regular(config.inputs / plan['name'] / 'received/preparation.json',
            uid=os.geteuid(), limit=being_seed.MAX_PREPARATION))
        stores = [row['name'] for row in report['selection']['memory']]
        if not stores:
            from . import onboarding_input, onboarding_release
            manifest = onboarding_input.verify(config.inputs / plan['name'], plan['seed_digest'])
            if manifest.get('seed_mode') == 'new':
                profile = onboarding_release.verify(config.code, plan['release_digest'], uid=os.geteuid())['profile']
                stores = [onboarding_input.new_memory_store(manifest, stores, profile['primary_store'])]
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

    def ssh_login_observe(self, plan, job):
        config = self.backend.config
        key = self.backend._ssh_key(plan)
        if key is None or job['steps']['access']['state'] != 'complete':
            return False
        from .onboarding_ssh import public_key
        canonical = public_key(key)
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(
            base64.b64decode(canonical.split()[1], validate=True)).digest()).decode().rstrip('=')
        key_digest = hashlib.sha256(canonical).hexdigest()
        if not self.backend._ssh_command(plan, 'observe', key)['installed']:
            return False
        logins = SSHLogins(config.progress, worker_uid=os.geteuid())
        try:
            receipt = logins.read(plan['name'], owner=plan['owner'])
        except FileNotFoundError:
            receipt = None
        if receipt is not None:
            if (receipt['plan_digest'] != digest(plan) or receipt['key_digest'] != key_digest
                    or receipt['authenticated_at_ms'] < job['created_ms']):
                raise OnboardingError('existing_hosted_checks_preserved')
            return True
        # Journal fields are collected as guest root from the dedicated unit.
        # Never return IP addresses, messages, key comments or unrelated logs.
        program = ('import json,subprocess,sys;\n' + inspect.getsource(ssh_login_snapshot)
            + '\np=json.loads(sys.argv[1]);r=subprocess.run(["journalctl",'
            + '"--unit=daimon-onboarding-ssh.service","--output=json","--no-pager",'
            + '"--grep=^Accepted publickey for agent ",'
            + '"--lines=512","--since=@"+str(p["since_ms"]//1000)],'
            + 'capture_output=True,text=True,timeout=30,check=False);'
            + 'assert r.returncode==0 or (r.returncode==1 and not r.stdout and not r.stderr);'
            + 'print(json.dumps(ssh_login_snapshot([json.loads(line) for line in r.stdout.splitlines()],'
            + 'p["fingerprint"],p["since_ms"],p["now_ms"])))')
        parameters = {'fingerprint': fingerprint, 'since_ms': job['created_ms'], 'now_ms': int(time.time() * 1000)}
        result = json.loads(self.backend._dispatch(plan, ['exec', self.backend.instance(plan), '--',
            'python3', '-B', '-I', '-c', program, json.dumps(parameters)]))
        if (not isinstance(result, dict) or set(result) != {'verified', 'authenticated_at_ms'}
                or type(result['verified']) is not bool
                or (result['verified'] and (type(result['authenticated_at_ms']) is not int
                    or not parameters['since_ms'] <= result['authenticated_at_ms'] <= parameters['now_ms'] + 300000))
                or (not result['verified'] and result['authenticated_at_ms'] is not None)):
            raise OnboardingError('invalid_ssh_login_evidence')
        if result['verified']:
            logins.publish(dict(schema='cluster-hosted-ssh-login/v1', name=plan['name'], owner=plan['owner'],
                plan_digest=digest(plan), key_digest=key_digest, **result))
        return result['verified']

    def cli_resume_observe(self, plan):
        try:
            receipt = CLIResumes(self.backend.config.progress, worker_uid=os.geteuid()).read(plan['name'], owner=plan['owner'])
        except FileNotFoundError:
            try:
                request = Requests(self.backend.config.progress, worker_uid=os.geteuid()).read(plan['name'], owner=plan['owner'])
            except FileNotFoundError:
                return Observation('waiting', reason='human_contact_required')
            if request['plan_digest'] != digest(plan):
                raise OnboardingError('existing_hosted_checks_preserved')
            return (Observation('absent', safe_to_execute=True) if request['native']['sessions']
                    else Observation('waiting', reason='human_contact_required'))
        if receipt['plan_digest'] != digest(plan):
            raise OnboardingError('existing_hosted_checks_preserved')
        return Observation('complete', {'verified': True})

    def verify_cli_resume(self, plan):
        if self.cli_resume_observe(plan).state != 'absent':
            return
        config = self.backend.config
        job = JobStore(config.jobs)._load(plan['name'])
        if job['plan'] != plan or any(job['steps'][stage]['state'] != 'complete' for stage in ('access', 'memory', 'telegram')):
            raise OnboardingError('receiving_context_required')
        request = Requests(config.progress, worker_uid=os.geteuid()).read(plan['name'], owner=plan['owner'])
        profile = self.backend.config.code
        from .onboarding_release import verify
        settings = verify(profile, plan['release_digest'], uid=os.geteuid())['profile']
        thread = request['native']['sessions'][0]['codex_thread_id']
        program = ('import json,sys;\n' + inspect.getsource(telegram_listener_snapshot)
            + '\n' + inspect.getsource(wait_telegram_listener)
            + '\n' + inspect.getsource(cli_admission_guard) + '\n' + inspect.getsource(cli_resume_probe)
            + '\np=json.loads(sys.argv[1]);print(json.dumps(cli_resume_probe("/home/agent",'
            + 'p["plan"],p["thread"],p["model"],p["reasoning"])))')
        payload = {'plan': plan, 'thread': thread, 'model': settings['model'], 'reasoning': settings['reasoning']}
        result = json.loads(self.backend._dispatch(plan, ['exec', self.backend.instance(plan), '--',
            'python3', '-B', '-I', '-c', program, json.dumps(payload)]))
        if result.get('waiting') is True and result.get('verified') is False:
            return
        if result.get('uncertain') is True and result.get('verified') is False:
            raise OnboardingError('uncertain_external_effect')
        if result.get('thread_id') != thread:
            raise OnboardingError('invalid_cli_resume_evidence')
        CLIResumes(config.progress, worker_uid=os.geteuid()).publish(dict(
            schema='cluster-hosted-cli-resume/v1', name=plan['name'], owner=plan['owner'],
            plan_digest=digest(plan), probe=result))

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
        if hasattr(self.backend, '_ssh_key'):
            technical['ssh_verified'] = self.ssh_login_observe(plan, job)
        try:
            memory_proof = MemoryWrites(config.progress, worker_uid=os.geteuid()).read(plan['name'], owner=plan['owner'])
        except FileNotFoundError:
            memory_proof = None
        if memory_proof is not None:
            technical['memory_write_verified'] = self.memory_write_observe(plan).state == 'complete'
        try:
            cli_proof = CLIResumes(config.progress, worker_uid=os.geteuid()).read(plan['name'], owner=plan['owner'])
        except FileNotFoundError:
            cli_proof = None
        if cli_proof is not None:
            technical['cli_resume_verified'] = self.cli_resume_observe(plan).state == 'complete'
        if getattr(config, 'peer', None) is not None:
            technical['matrix_delivery_verified'] = self.matrix_delivery_observe(plan).state == 'complete'
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
        facts = acceptance_facts(value, witness)
        if facts is not None:
            return Observation('complete', facts)
        reason = (
            "human_contact_required"
            if witness is None
            or any(result != "passed" for result in witness["checks"].values())
            else "hosted_checks_required"
        )
        return Observation("waiting", reason=reason)
