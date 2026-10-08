"""Witnesses stay private; native metadata proves only observed acceptance."""

import dataclasses
import json
import os
import sqlite3
import time
import uuid
from types import SimpleNamespace

import pytest

from clusterctl import being_seed, onboarding_acceptance as checks
from clusterctl.cli import run
from clusterctl.onboarding import OnboardingError, digest
from tests.test_being_seed import KEY, http_server
from tests.test_onboarding import advance, plan, setup


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
