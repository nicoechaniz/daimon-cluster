"""Witnesses stay private; native metadata proves only observed acceptance."""

import dataclasses
import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing, contextmanager
import time
import uuid
from types import SimpleNamespace

import pytest

from clusterctl import being_seed, onboarding_acceptance as checks
from clusterctl.cli import run
from clusterctl.onboarding import OnboardingError, digest
from tests.test_being_seed import KEY, http_server
from tests.test_onboarding import advance, plan, setup


def test_ssh_login_requires_real_unit_owner_key_and_current_job_time():
    fingerprint = 'SHA256:' + 'A' * 43
    entry = {'_SYSTEMD_UNIT': 'daimon-onboarding-ssh.service', '_UID': '0', '_COMM': 'sshd',
        'MESSAGE': 'Accepted publickey for agent from 192.0.2.5 port 2000 ssh2: ED25519 ' + fingerprint,
        '__REALTIME_TIMESTAMP': '1500000'}
    assert checks.ssh_login_snapshot([entry], fingerprint, 1000, 2000) == {
        'verified': True, 'authenticated_at_ms': 1500}
    for invalid in ({'_SYSTEMD_UNIT': 'ssh.service'}, {'_UID': '1000'}, {'_COMM': 'logger'},
                    {'__REALTIME_TIMESTAMP': '999000'}, {'__REALTIME_TIMESTAMP': '302001000'},
                    {'MESSAGE': entry['MESSAGE'].replace('agent from', 'root from')},
                    {'MESSAGE': entry['MESSAGE'].replace(fingerprint, 'SHA256:' + 'B' * 43)},
                    {'MESSAGE': ['invalid journal value']}):
        assert checks.ssh_login_snapshot([{**entry, **invalid}], fingerprint, 1000, 2000) == {
            'verified': False, 'authenticated_at_ms': None}


def test_ssh_login_adapter_binds_native_evidence_and_keeps_owner_isolation(tmp_path):
    value = plan()
    store, fixture = setup(tmp_path, value)
    advance(store, fixture, count=7)
    job = store._load('eko')
    progress = tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    key = 'ssh-ed25519 ' + base64.b64encode(b'fixture public owner key bytes32!!').decode()
    calls = []
    result = {'verified': False, 'authenticated_at_ms': None}
    installed = True

    def dispatch(plan, argv):
        calls.append(argv)
        assert argv[:4] == ['exec', 'dm-eko', '--', 'python3']
        compile(argv[-2], '<captured-ssh-journal-probe>', 'exec')
        parameters = json.loads(argv[-1])
        assert parameters['since_ms'] == job['created_ms']
        return json.dumps(result)

    backend = SimpleNamespace(config=SimpleNamespace(progress=progress), _ssh_key=lambda plan:key,
        _ssh_command=lambda *args:{'installed': installed}, instance=lambda plan:'dm-eko', _dispatch=dispatch)
    adapter = checks.HostedChecks(backend)
    assert adapter.ssh_login_observe(value, job) is False
    assert not (progress / 'eko.ssh-login.json').exists()
    result = {'verified': True, 'authenticated_at_ms': job['created_ms']}
    assert adapter.ssh_login_observe(value, job) is True
    receipt = checks.SSHLogins(progress, worker_uid=os.geteuid()).read('eko', owner='sai')
    assert receipt['key_digest'] == hashlib.sha256((key + '\n').encode()).hexdigest()
    assert set(receipt) == {'schema', 'name', 'owner', 'plan_digest', 'key_digest', 'verified', 'authenticated_at_ms'}
    assert adapter.ssh_login_observe(value, job) is True and len(calls) == 2
    installed = False
    assert adapter.ssh_login_observe(value, job) is False
    installed = True
    with pytest.raises(OnboardingError, match='onboarding_job_not_found'):
        checks.SSHLogins(progress, worker_uid=os.geteuid()).read('eko', owner='ani')
    with pytest.raises(OnboardingError, match='existing_hosted_checks_preserved'):
        adapter.ssh_login_observe({**value, 'browser': not value['browser']}, job)


def test_empty_native_ssh_journal_is_missing_proof_and_command_errors_are_not_accepted(tmp_path, monkeypatch, capsys):
    value = plan()
    store, fixture = setup(tmp_path, value)
    advance(store, fixture, count=7)
    job = store._load('eko')
    progress = tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    key = 'ssh-ed25519 ' + base64.b64encode(b'fixture public owner key bytes32!!').decode()
    journal_result = SimpleNamespace(returncode=1, stdout='', stderr='')
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs:journal_result)

    def dispatch(plan, argv):
        monkeypatch.setattr(sys, 'argv', ['native-probe', argv[-1]])
        exec(compile(argv[-2], '<captured-native-ssh-probe>', 'exec'), {})
        return capsys.readouterr().out

    backend = SimpleNamespace(config=SimpleNamespace(progress=progress), _ssh_key=lambda plan:key,
        _ssh_command=lambda *args:{'installed': True}, instance=lambda plan:'dm-eko', _dispatch=dispatch)
    assert checks.HostedChecks(backend).ssh_login_observe(value, job) is False
    journal_result = SimpleNamespace(returncode=1, stdout='', stderr='fixture journal error')
    with pytest.raises(AssertionError):
        checks.HostedChecks(backend).ssh_login_observe(value, job)
    assert not (progress / 'eko.ssh-login.json').exists()


def test_native_cli_admission_lock_prevents_turn_start_and_releases_without_row_changes(tmp_path):
    database = tmp_path / '.local/state/daimon-onboarding/telegram/telegram.sqlite3'
    database.parent.mkdir(parents=True)
    with closing(sqlite3.connect(database)) as connection:
        connection.executescript('CREATE TABLE sessions(busy INTEGER);INSERT INTO sessions VALUES(0);'
            'CREATE TABLE turns(status TEXT);')
    guard = contextmanager(checks.cli_admission_guard)
    with guard(tmp_path, os.geteuid()) as idle:
        assert idle is True
        with closing(sqlite3.connect(database, timeout=0)) as competing:
            with pytest.raises(sqlite3.OperationalError, match='locked'):
                competing.execute('UPDATE sessions SET busy=1')
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute('SELECT busy FROM sessions').fetchone() == (0,)
        connection.execute('UPDATE sessions SET busy=1')
        connection.commit()
    with guard(tmp_path, os.geteuid()) as idle:
        assert idle is False
    with closing(sqlite3.connect(database, timeout=0)) as connection:
        connection.execute('UPDATE sessions SET busy=0')
        connection.commit()


def cli_fixture(tmp_path):
    home = tmp_path / 'home'
    history = home / '.codex/sessions/selected.jsonl'
    history.parent.mkdir(parents=True)
    history.write_bytes(b'original selected conversation\n')
    history.chmod(0o600)
    executable = tmp_path / 'codex'
    executable.write_bytes(b'qualified native test executable\n')
    executable.chmod(0o755)
    units = tmp_path / 'units'
    units.mkdir()
    states = {name: True for name in ('daimon-onboarding-telegram.service', 'daimon-onboarding-codex.service')}
    for name in states:
        (units / name).write_bytes(b'qualified dedicated unit\n')
        (units / name).chmod(0o644)
    thread = str(uuid.uuid4())
    options = {'idle': [True, True, True], 'output': 'complete', 'lost_ack': False, 'changed_history': False, 'changed_unit': False}
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        if argv[0] == 'systemctl':
            action = argv[1]
            for name in argv[2:]:
                assert name in states
                if action in {'start', 'stop'}:
                    states[name] = action == 'start'
                else:
                    assert action == 'is-active' and states[name]
            return SimpleNamespace(returncode=0, stdout='active\n')
        if argv[0] == sys.executable:
            compile(argv[4], '<captured-owner-metadata>', 'exec')
            return SimpleNamespace(returncode=0, stdout=json.dumps({'idle': options['idle'].pop(0), 'rollout': str(history)}))
        assert argv[0] == str(executable)
        assert argv[-2:] == [thread, '-'] and '--ephemeral' in argv and 'resume' in argv
        assert not any(states.values()) and kwargs['timeout'] == 240
        token = kwargs['input'].decode().rsplit(': ', 1)[1]
        events = [{'type': 'thread.started', 'thread_id': thread if options['output'] != 'other-thread' else str(uuid.uuid4())},
            {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': token}}, {'type': 'turn.completed'}]
        kwargs['stdout'].write(b'{"partial":' if options['output'] == 'partial'
                                else b'\n'.join(json.dumps(e).encode() for e in events))
        if options['changed_history']:
            history.write_bytes(b'different original history')
        if options['changed_unit']:
            (units / next(iter(states))).write_bytes(b'unrelated successor unit')
        if options['lost_ack']:
            raise OSError('fixture lost acknowledgement after completed inference')
        return SimpleNamespace(returncode=0)

    def probe():
        return checks.cli_resume_probe(home, plan(), thread, 'gpt-6.1', 'medium', runner,
            journal_root=tmp_path / 'journal', unit_root=units, codex_path=executable)
    return probe, history, states, options, calls


def test_cli_resume_keeps_original_history_restores_services_and_recovers_completed_lost_ack(tmp_path):
    probe, history, states, options, calls = cli_fixture(tmp_path)
    original = history.read_bytes()
    options['lost_ack'] = True
    with pytest.raises(OSError, match='lost acknowledgement'):
        probe()
    assert all(states.values()) and history.read_bytes() == original
    proof = probe()
    assert proof['verified'] is True
    assert proof['original_history_sha256'] == hashlib.sha256(original).hexdigest()
    assert len([call for call in calls if call[0] != 'systemctl' and call[0] != sys.executable]) == 1
    history.write_bytes(original + b'new receiving work\n')
    # Recover a crash after proof publication but before listener restoration.
    for name in states:
        states[name] = False
    assert probe() == proof and all(states.values())
    assert history.read_bytes() == original + b'new receiving work\n'
    assert [p.read_bytes() for p in (tmp_path / 'journal').glob('original-history-*')] == [original]


@pytest.mark.parametrize('race', [False, True])
def test_cli_resume_waits_for_idle_and_restores_admission_after_a_turn_race(tmp_path, race):
    probe, history, states, options, calls = cli_fixture(tmp_path)
    options['idle'] = [True, False] if race else [False]
    assert probe() == {'verified': False, 'waiting': True}
    assert all(states.values()) and history.read_bytes() == b'original selected conversation\n'
    assert not (tmp_path / 'journal/intent.json').exists()
    assert not any(call[0] == str(tmp_path / 'codex') for call in calls)


@pytest.mark.parametrize('stream', ['partial', 'other-thread'])
def test_uncertain_or_wrong_thread_cli_output_never_repeats_inference(tmp_path, stream):
    probe, history, states, options, calls = cli_fixture(tmp_path)
    options['output'] = stream
    assert probe() == {'verified': False, 'uncertain': True}
    assert probe() == {'verified': False, 'uncertain': True}
    assert all(states.values())
    assert len([call for call in calls if call[0] == str(tmp_path / 'codex')]) == 1
    assert not (tmp_path / 'journal/proof.json').exists()


def test_cli_resume_detects_history_loss_and_preserves_foreign_service_successor(tmp_path):
    probe, history, states, options, calls = cli_fixture(tmp_path)
    options['changed_history'] = True
    with pytest.raises(ValueError, match='original_cli_history_changed'):
        probe()
    assert all(states.values())
    assert [p.read_bytes() for p in (tmp_path / 'journal').glob('original-history-*')] == [b'original selected conversation\n']
    assert not (tmp_path / 'journal/proof.json').exists()
    # A different plan/executable/service binding cannot adopt old progress.
    unit = tmp_path / 'units/daimon-onboarding-telegram.service'
    unit.write_bytes(b'unrelated successor unit')
    before = list(calls)
    with pytest.raises(ValueError, match='existing_cli_resume_probe_preserved'):
        probe()
    assert calls == before and unit.read_bytes() == b'unrelated successor unit'


def memory_fixture(tmp_path):
    home = tmp_path / 'home'
    state = home / '.local/state/daimon-onboarding/eko'
    state.mkdir(mode=0o700, parents=True)
    value = plan()
    being_seed._write(state / 'memory.json', dict(plan_digest=digest(value), stores=[{'name': 'store-001'}]))
    wrapper = state / 'hmk-store-001.py'
    wrapper.write_text('# Explicit native test transport.\n')
    wrapper.chmod(0o600)
    database = home / '.agents/memory/eko/received/memory/store-001/library.db'
    database.parent.mkdir(mode=0o700, parents=True)
    with closing(sqlite3.connect(database)) as db:
        db.executescript('CREATE TABLE chapters(id INTEGER PRIMARY KEY,title TEXT,raw TEXT,access_count INTEGER DEFAULT 0); CREATE TABLE original_vectors(id INTEGER PRIMARY KEY,value BLOB);')
        db.execute('INSERT INTO chapters(title,raw) VALUES (?,?)', ('Own older memory', 'preserved original'))
        db.execute('INSERT INTO original_vectors VALUES (?,?)', (1, b'original vector'))
        db.commit()
    database.chmod(0o600)
    calls = []
    def native(args):
        calls.append(args[0])
        with closing(sqlite3.connect(database)) as db:
            if args[0] == 'stats':
                result = {'db_path': str(database)}
            elif args[0] == 'add-text':
                title, raw = args[args.index('--title') + 1], args[args.index('--raw') + 1]
                db.execute('INSERT INTO chapters(title,raw) VALUES (?,?)', (title, raw))
                result = {}
            elif args[0] == 'expand':
                cid = int(args[2])
                row = db.execute('SELECT id,title,raw FROM chapters WHERE id=?', (cid,)).fetchone()
                result = dict(zip(('id', 'title', 'raw'), row))
                db.execute('UPDATE chapters SET access_count=access_count+1 WHERE id=?', (cid,))
            else:
                assert args[0] == 'delete'
                db.execute('DELETE FROM chapters WHERE id=?', (int(args[2]),))
                result = {}
            db.commit()
        return result
    return home, value, database, state, native, calls


@pytest.mark.parametrize('interruption', ['add-text', 'delete'])
def test_native_memory_write_resumes_lost_ack_preserves_originals_and_new_writes(tmp_path, interruption):
    home, value, database, state, native, calls = memory_fixture(tmp_path)
    def lost_ack(args):
        result = native(args)
        if args[0] == interruption:
            raise OSError('fixture acknowledgement interrupted after native commit')
        return result
    with pytest.raises(OSError):
        checks.memory_write_probe(home, value, 'store-001', lost_ack)
    # Another receiving writer is legitimate and must never be rolled back.
    with closing(sqlite3.connect(database)) as db:
        db.execute('INSERT INTO chapters(title,raw) VALUES (?,?)', ('New work', 'receiving write'))
        db.commit()
    proof = checks.memory_write_probe(home, value, 'store-001', native)
    assert proof['verified'] is True and proof['plan_digest'] == digest(value)
    assert calls.count('add-text') == calls.count('expand') == calls.count('delete') == 1
    with closing(sqlite3.connect(database)) as db:
        assert db.execute('SELECT title,raw FROM chapters ORDER BY id').fetchall() == [
            ('Own older memory', 'preserved original'), ('New work', 'receiving write')]
        assert db.execute('SELECT value FROM original_vectors').fetchone() == (b'original vector',)
    assert checks.memory_write_probe(home, value, 'store-001', lambda args:pytest.fail('completed probe repeated')) == proof
    backup = state / 'memory-write/store-001/backup.db'
    assert backup.stat().st_mode & 0o077 == 0
    with closing(sqlite3.connect(backup)) as db:
        assert db.execute('SELECT COUNT(*) FROM chapters').fetchone()[0] == 1


def test_native_memory_write_requires_verified_backup_and_refuses_loss_of_history(tmp_path):
    home, value, database, state, native, calls = memory_fixture(tmp_path)
    root = state / 'memory-write/store-001'
    root.parent.mkdir(mode=0o700)
    root.mkdir(mode=0o700)
    backup = root / 'backup.db'
    backup.write_bytes(b'invalid SQLite')
    backup.chmod(0o600)
    with pytest.raises(sqlite3.DatabaseError):
        checks.memory_write_probe(home, value, 'store-001', native)
    assert not calls
    backup.unlink()
    def corrupt_original(args):
        result = native(args)
        if args[0] == 'delete':
            with closing(sqlite3.connect(database)) as db:
                db.execute('DELETE FROM original_vectors')
                db.commit()
        return result
    with pytest.raises(ValueError, match='native_memory_write_verification_failed'):
        checks.memory_write_probe(home, value, 'store-001', corrupt_original)
    assert not (root / 'proof.json').exists()
    with closing(sqlite3.connect(backup)) as db:
        assert db.execute('SELECT value FROM original_vectors').fetchone() == (b'original vector',)


def test_host_executes_finite_guest_memory_probe_and_reuses_root_owned_evidence(tmp_path):
    home, value, database, state, runner, native_calls = memory_fixture(tmp_path)
    store, fixture = setup(tmp_path, value)
    advance(store, fixture, count=7)
    inputs, progress = tmp_path / 'inputs', tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    received = inputs / 'eko/received'
    received.mkdir(mode=0o700, parents=True)
    being_seed._write(received / 'preparation.json', {'selection': {'memory': [{'name': 'store-001'}]}})
    calls = []
    def dispatch(plan, argv):
        calls.append(argv)
        assert argv[:7] == ['exec', 'dm-eko', '--user', '1000', '--group', '1000', '--']
        assert json.loads(argv[-2]) == value and argv[-1] == 'store-001'
        compile(argv[-3], '<captured-host-probe>', 'exec')
        return json.dumps(checks.memory_write_probe(home, value, 'store-001', runner))
    backend = SimpleNamespace(config=SimpleNamespace(inputs=inputs, progress=progress, jobs=store.root),
        instance=lambda plan:'dm-eko', _dispatch=dispatch)
    adapter = checks.HostedChecks(backend)
    assert adapter.memory_write_observe(value).safe_to_execute
    adapter.verify_memory_write(value)
    assert adapter.memory_write_observe(value).state == 'complete'
    adapter.verify_memory_write(value)
    assert len(calls) == 1 and native_calls == ['stats', 'add-text', 'expand', 'delete']
    record = checks.MemoryWrites(progress, worker_uid=os.geteuid()).read('eko', owner='sai')
    assert record['stores'][0]['verified'] is True
    with pytest.raises(OnboardingError, match='onboarding_job_not_found'):
        checks.MemoryWrites(progress, worker_uid=os.geteuid()).read('eko', owner='ani')
    with pytest.raises(OnboardingError, match='existing_hosted_checks_preserved'):
        adapter.memory_write_observe({**value, 'browser': not value['browser']})


def test_memory_probe_refuses_other_store_binding_before_any_write(tmp_path):
    home, value, database, state, runner, calls = memory_fixture(tmp_path)
    def wrong_binding(args):
        assert args == ['stats']
        return {'db_path': '/another/being/library.db'}
    with pytest.raises(ValueError, match='native_memory_write_verification_failed'):
        checks.memory_write_probe(home, value, 'store-001', wrong_binding)
    assert not calls
    assert not (state / 'memory-write/store-001/proof.json').exists()
    with closing(sqlite3.connect(database)) as db:
        assert db.execute('SELECT COUNT(*) FROM chapters').fetchone()[0] == 1


def native(instance=None, topics=1, steered=False, first=1):
    instance = instance or str(uuid.uuid4())
    return dict(
        instance_id=instance,
        sessions=[
            dict(
                topic_id=number,
                codex_thread_id=str(
                    uuid.uuid5(uuid.NAMESPACE_URL, "fixture-topic-" + str(number))
                ),
                turns=[[first + number, "2026-10-08T01:04:30.156+00:00", instance]],
            )
            for number in range(topics)
        ],
        steered_turns=[first] if steered else [],
    )


def request(browser=False):
    fingerprint = digest(plan(browser=browser))
    return dict(
        schema=checks.SCHEMA,
        name="eko",
        owner="sai",
        plan_digest=fingerprint,
        request_id=str(
            uuid.uuid5(uuid.NAMESPACE_URL, checks.SCHEMA + ":" + fingerprint)
        ),
        created_ms=int(time.time() * 1000) - 1000,
        updated_ms=int(time.time() * 1000),
        browser=browser,
        technical=dict.fromkeys(checks.TECHNICAL, False),
        native=native(),
        restart_baseline=native(),
    )


def witness(task, result="passed", stamp=None):
    return dict(
        schema=checks.REPORT,
        request_id=task["request_id"],
        plan_digest=task["plan_digest"],
        checked_at_ms=stamp or int(time.time() * 1000),
        checks={key: result for key in checks._checks(task)},
    )


def test_cli_resume_adapter_requires_selected_thread_and_owner_bound_proof(tmp_path, monkeypatch):
    from clusterctl import onboarding_release

    value = plan(browser=False)
    store, fixture = setup(tmp_path, value)
    advance(store, fixture, count=7)
    progress = tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    task = request()
    calls = []
    result = {'schema': 'cluster-native-cli-resume/v1', 'plan_digest': digest(value),
        'thread_id': str(uuid.uuid4()), 'verified': True,
        'original_history_sha256': '3' * 64, 'cli_sha256': '4' * 64,
        'provider_stream_sha256': '5' * 64}

    def dispatch(plan, argv):
        calls.append(argv)
        assert argv[:4] == ['exec', 'dm-eko', '--', 'python3']
        compile(argv[-2], '<captured-native-cli-probe>', 'exec')
        parameters = json.loads(argv[-1])
        assert parameters == {'plan': value, 'thread': task['native']['sessions'][0]['codex_thread_id'],
            'model': 'existing-qualified-model', 'reasoning': 'high'}
        return json.dumps(result)

    monkeypatch.setattr(onboarding_release, 'verify', lambda *args, **kwargs: {
        'profile': {'model': 'existing-qualified-model', 'reasoning': 'high'}})
    backend = SimpleNamespace(config=SimpleNamespace(progress=progress, jobs=store.root, code=tmp_path / 'code'),
        instance=lambda plan:'dm-eko', _dispatch=dispatch)
    adapter = checks.HostedChecks(backend)
    assert adapter.cli_resume_observe(value).state == 'waiting'
    checks.Requests(progress, worker_uid=os.geteuid()).publish(task)
    assert adapter.cli_resume_observe(value).state == 'absent'
    with pytest.raises(OnboardingError, match='invalid_cli_resume_evidence'):
        adapter.verify_cli_resume(value)
    assert not (progress / 'eko.cli-resume.json').exists()
    result['thread_id'] = task['native']['sessions'][0]['codex_thread_id']
    adapter.verify_cli_resume(value)
    assert adapter.cli_resume_observe(value).state == 'complete'
    adapter.verify_cli_resume(value)
    assert len(calls) == 2
    with pytest.raises(OnboardingError, match='onboarding_job_not_found'):
        checks.CLIResumes(progress, worker_uid=os.geteuid()).read('eko', owner='ani')
    with pytest.raises(OnboardingError, match='existing_hosted_checks_preserved'):
        adapter.cli_resume_observe({**value, 'browser': True})


def test_owner_scoped_http_cli_reports_preserve_retries_without_activation(
    tmp_path, capsys
):
    state, progress = tmp_path / "state", tmp_path / "progress"
    progress.mkdir(mode=0o750)
    task = request()
    publisher = checks.Requests(progress, worker_uid=os.geteuid())
    publisher.publish(task)
    state.mkdir(mode=0o700)
    being_seed.create(
        state, dict(name="eko", label="Eko", mode="import"), owner="sai", key=KEY
    )
    endpoint = "/v1/seeds/eko/onboarding/checks"
    with http_server(state) as (server, http):
        server.deps = dataclasses.replace(
            server.deps,
            seed_only=True,
            onboarding_progress=str(progress),
            onboarding_worker_uid=os.geteuid(),
        )
        assert http(endpoint, owner="ani")[0] == 404
        assert http(endpoint, owner="reader")[0] == 403
        assert http(endpoint, extra={"Authorization": ""})[0] == 401
        code, headers, data = http(endpoint, owner="sai")
        assert code == 200 and headers["Cache-Control"] == "no-store"
        assert data["request"]["hosted_acceptance"] is False
        assert "restart_baseline" not in data["request"]
        value = witness(task)
        assert http(endpoint, "POST", value, owner="ani")[0] == 404
        first = http(endpoint, "POST", value, owner="sai")[2]
        assert first["request"]["report"] == value
        assert first["request"]["hosted_acceptance"] is False
        assert http(endpoint, "POST", value, owner="sai")[2] == first
        later = witness(task, result="failed", stamp=value["checked_at_ms"] + 1)
        assert http(endpoint, "POST", later, owner="sai")[0] == 200
        assert (
            http(endpoint, "POST", value, owner="sai")[2]["request"]["report"] == later
        )
        conflict = {**later, "checks": value["checks"]}
        assert http(endpoint, "POST", conflict, owner="sai")[0] == 409
        for invalid in (
            {**value, "checked_at_ms": True},
            {**value, "plan_digest": "0" * 64},
            {**value, "checked_at_ms": int(time.time() * 1000) + 400000},
            {**value, "checks": {**value["checks"], "identity_context": "passed"}},
            {**value, "password": "never accepted"},
        ):
            assert http(endpoint, "POST", invalid, owner="sai")[0] == 400
        assert "hosted-checks-section" in http("/v1/onboarding")[2]
        guide = http("/v1/onboarding?format=json")[2]
        assert guide["requests"]["hosted_witness"]["body"]["schema"] == checks.REPORT
        assert "/v1/seeds/{seed}/onboarding/checks" in guide["api"]["paths"]
    assert checks.worker_report(state, task, intake_uid=os.geteuid()) == later
    with pytest.raises(OnboardingError, match="private_hosted_witness_required"):
        checks.worker_report(state, task, intake_uid=os.geteuid() + 1)
    stored = state / "hosted-witnesses/eko"
    assert all(path.stat().st_mode & 0o077 == 0 for path in stored.glob("*.json"))
    assert not list(state.rglob("custody.json"))
    args = ["--state-dir", str(state), "seed", "--owner", "sai"]
    assert (
        run(
            [
                *args,
                "checks",
                "eko",
                "--progress",
                str(progress),
                "--worker-uid",
                str(os.geteuid()),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["report"] == later
    file = tmp_path / "report.json"
    newest = witness(task, stamp=later["checked_at_ms"] + 1)
    file.write_text(json.dumps(newest))
    assert (
        run(
            [
                *args,
                "witness",
                "eko",
                "--progress",
                str(progress),
                "--worker-uid",
                str(os.geteuid()),
                "--file",
                str(file),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["report"] == newest
    assert checks.read(state, task)["hosted_acceptance"] is False
    next_task = request(browser=True)
    publisher.publish(next_task)
    assert checks.read(state, next_task)["report"] is None
    with pytest.raises(being_seed.SeedError, match="invalid_hosted_witness"):
        checks.submit(state, next_task, newest)
    assert checks.read(state, task)["report"] == newest


def test_native_read_only_snapshot_filters_human_acknowledgements_and_steering(
    tmp_path,
):
    database = tmp_path / "native.sqlite"
    connection = sqlite3.connect(database)
    connection.executescript("""
        CREATE TABLE sessions(id INTEGER,chat_id INTEGER,creator_user_id INTEGER,thread_id INTEGER,codex_thread_id TEXT);
        CREATE TABLE turns(id INTEGER,session_id INTEGER,from_user_id INTEGER,status TEXT,completed_at TEXT,prompt TEXT,assistant_text TEXT);
        CREATE TABLE incoming_updates(update_id INTEGER,turn_id INTEGER,status TEXT,instance_id TEXT,payload_json TEXT);
        CREATE TABLE audit_log(id INTEGER,actor_user_id INTEGER,action TEXT,details_json TEXT);
        CREATE TABLE app_instance_lock(key TEXT,instance_id TEXT);
    """)
    instance = str(uuid.uuid4())
    timestamp = "2026-10-08T01:04:30.156+00:00"
    for number, human in enumerate((123, 123, 456), start=1):
        connection.execute(
            "INSERT INTO sessions VALUES(?,?,?,?,?)",
            (number, human, human, number, str(uuid.uuid4())),
        )
        connection.execute(
            "INSERT INTO turns VALUES(?,?,?,?,?,?,?)",
            (
                number,
                number,
                human,
                "completed",
                timestamp,
                "PRIVATE-CONVERSATION-SENTINEL",
                "PRIVATE-REPLY-SENTINEL",
            ),
        )
        connection.execute(
            "INSERT INTO incoming_updates VALUES(?,?,?,?,?)",
            (number, number, "settled", instance, "PRIVATE-PAYLOAD-SENTINEL"),
        )
    # Two inputs in one completed turn do not prove an acknowledged steer.
    connection.execute(
        "INSERT INTO incoming_updates VALUES(?,?,?,?,?)",
        (4, 1, "settled", instance, "PRIVATE-PAYLOAD-SENTINEL"),
    )
    connection.execute("INSERT INTO app_instance_lock VALUES(?,?)", ("main", instance))
    connection.commit()
    before = database.read_bytes()
    readonly = sqlite3.connect("file:" + str(database) + "?mode=ro", uri=True)
    value = checks.validate_snapshot(checks.snapshot(readonly, 123))
    assert len(value["sessions"]) == 2 and not value["steered_turns"]
    assert "PRIVATE-" not in json.dumps(value)
    assert database.read_bytes() == before
    connection.execute(
        "INSERT INTO audit_log VALUES(?,?,?,?)",
        (1, 123, "turn_steered", json.dumps(dict(chat_id=123, turn_id=1))),
    )
    connection.execute(
        "INSERT INTO audit_log VALUES(?,?,?,?)",
        (2, 456, "turn_steered", json.dumps(dict(chat_id=123, turn_id=2))),
    )
    connection.commit()
    assert checks.snapshot(readonly, 123)["steered_turns"] == [1]
    connection.execute(
        "UPDATE incoming_updates SET status='undetermined' WHERE turn_id=1"
    )
    connection.commit()
    assert checks.snapshot(readonly, 123)["steered_turns"] == []
    readonly.close()
    connection.close()


def test_worker_collects_real_structure_preserves_baseline_and_never_trusts_report_as_completion(
    tmp_path,
):
    value = plan(browser=False)
    store, fixture = setup(tmp_path, value)
    advance(store, fixture, count=7)
    state, progress = tmp_path / "state", tmp_path / "progress"
    progress.mkdir(mode=0o750)
    state.mkdir(mode=0o700)
    being_seed.create(
        state, dict(name="eko", label="Eko", mode="import"), owner="sai", key=KEY
    )
    observed = native(topics=2)
    calls = []

    def dispatch(plan, argv):
        calls.append(argv)
        assert argv[:2] == ["exec", "dm-eko"]
        assert argv[-1] == "123"
        assert "?mode=ro" in argv[-2] and "payload_json" not in argv[-2]
        return json.dumps(observed)

    backend = SimpleNamespace(
        config=SimpleNamespace(
            progress=progress,
            consent_state=state,
            consent_uid=os.geteuid(),
            jobs=store.root,
        ),
        _telegram_connections=lambda _: {"telegram_chat_id": 123},
        _dispatch=dispatch,
        instance=lambda _: "dm-eko",
    )
    adapter = checks.HostedChecks(backend)
    assert adapter.observe(value).reason == "human_contact_required"
    requests = checks.Requests(progress, worker_uid=os.geteuid())
    first = requests.read("eko", owner="sai")
    assert (
        first["technical"]["topics_verified"]
        and first["technical"]["telegram_verified"]
    )
    assert (
        not first["technical"]["steering_verified"]
        and not first["technical"]["restart_verified"]
    )
    checks.submit(state, first, witness(first))
    assert adapter.observe(value).reason == "hosted_checks_required"
    assert store._load("eko")["state"] != "complete"
    # An instance change cannot relabel turns completed BEFORE the restart as
    # continuity proof; completed inputs must belong to the successor instance.
    successor = str(uuid.uuid4())
    observed["instance_id"] = successor
    for row in observed["sessions"]:
        row["turns"][0][0] += 10
    adapter.observe(value)
    assert not requests.read("eko", owner="sai")["technical"]["restart_verified"]
    for row in observed["sessions"]:
        row["turns"][0][2] = successor
    observed["steered_turns"] = [observed["sessions"][0]["turns"][0][0]]
    adapter.observe(value)
    latest = requests.read("eko", owner="sai")
    assert (
        latest["technical"]["restart_verified"]
        and latest["technical"]["steering_verified"]
    )
    assert (
        latest["created_ms"] == first["created_ms"]
        and latest["request_id"] == first["request_id"]
    )
    assert latest["restart_baseline"] == first["restart_baseline"]
    assert checks.read(state, latest)["report"]["checks"] == witness(first)["checks"]
    assert not latest["technical"]["matrix_delivery_verified"]
    assert not latest["technical"]["cli_resume_verified"]
    assert not latest["technical"]["ssh_verified"]
    assert not latest["technical"]["memory_write_verified"]
    with pytest.raises(OnboardingError, match="existing_hosted_checks_preserved"):
        adapter.observe({**value, "browser": True})
    assert len(calls) >= 4


def test_untrusted_request_and_native_metadata_are_rejected(tmp_path):
    value = request()
    for changed in (
        {**value, "technical": {**value["technical"], "custody": True}},
        {**value, "request_id": str(uuid.uuid4())},
        {**value, "owner": "../sai"},
        {**value, "browser": "false"},
        {**value, "updated_ms": False},
    ):
        with pytest.raises(OnboardingError):
            checks.validate(changed)
    for changed in (
        {**value["native"], "instance_id": "foreign"},
        {**value["native"], "steered_turns": [999]},
        {**value["native"], "sessions": value["native"]["sessions"] * 2},
    ):
        with pytest.raises(OnboardingError):
            checks.validate_snapshot(changed)
    progress = tmp_path / "progress"
    progress.mkdir(mode=0o750)
    publisher = checks.Requests(progress, worker_uid=os.geteuid())
    publisher.publish(value)
    (progress / ("eko" + publisher.suffix)).chmod(0o666)
    with pytest.raises(OnboardingError, match="trusted_onboarding_progress_required"):
        publisher.read("eko", owner="sai")
