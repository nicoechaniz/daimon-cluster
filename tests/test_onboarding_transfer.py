"""Real owner-scoped protected intake, restart/partial retry and preserved history."""

import io
import json
import os
import sqlite3
from contextlib import closing

import pytest

from clusterctl import being_seed as seeds
from clusterctl import onboarding_transfer as transfer

KEY = "11111111-1111-4111-8111-111111111111"
ROOT = "dm:being:v1:" + "a" * 43


@pytest.fixture(autouse=True)
def staging(monkeypatch):
    original = seeds.shutil.disk_usage
    monkeypatch.setattr(
        seeds.shutil, "disk_usage", lambda p: original(p)._replace(free=30 * 1024**3)
    )


def slot(tmp_path):
    seeds.create(
        tmp_path, dict(name="oliva", label="Oliva", mode="import"), owner="ani", key=KEY
    )
    return transfer.request(tmp_path, "oliva", owner="ani", expected_being_ref=ROOT)


def exported(tmp_path, public):
    source = tmp_path / "history"
    source.mkdir(mode=0o700)
    (source / "SOUL.md").write_text("I am Oliva, preserving my own identity.\n")
    credential = "sk-" + "fixture" * 6
    with closing(sqlite3.connect(source / "library.db")) as db:
        db.execute("CREATE TABLE chapters(id INTEGER, text TEXT)")
        db.executemany(
            "INSERT INTO chapters VALUES(?,?)",
            [(1, "older memory"), (2, credential), (3, "recent memory")],
        )
        db.commit()
    (source / "session.json").write_text(json.dumps(dict(historical=credential)))
    packet = tmp_path / "recipient.json"
    seeds._write(packet, public["recipient"])
    plan, archive = tmp_path / "export-plan.json", tmp_path / "oliva.dm-protected"
    seeds.tool(
        "export_being",
        [
            "discover",
            "--being",
            "Oliva",
            "--memory-root",
            str(source),
            "--output",
            str(plan),
        ],
    )
    result = seeds.tool(
        "export_being",
        [
            "export",
            "--plan",
            str(plan),
            "--output",
            str(archive),
            "--writers-stopped",
            "--recipient",
            str(packet),
            "--recipient-sha256",
            public["recipient_sha256"],
        ],
    )
    return archive.read_bytes(), result["sha256"], credential


def test_durable_recipient_is_private_bound_and_reused_after_restart(tmp_path):
    public = slot(tmp_path)
    directory = tmp_path / "being-seeds/oliva/transfer"
    original = {p.name: p.read_bytes() for p in directory.iterdir()}
    assert transfer.read(tmp_path, "oliva", owner="ani") == public
    assert (
        transfer.request(tmp_path, "oliva", owner="ani", expected_being_ref=ROOT)
        == public
    )
    assert public["recipient"]["expected_being_ref"] == ROOT
    assert "private.key" not in json.dumps(public)
    assert public["recipient"]["name"] == "oliva"
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == original
    for path in [directory, *directory.iterdir()]:
        assert path.stat().st_mode & 0o077 == 0
    with pytest.raises(seeds.SeedError, match="seed_not_found"):
        transfer.read(tmp_path, "oliva", owner="sai")
    with pytest.raises(seeds.SeedError, match="recipient_preserved"):
        transfer.request(tmp_path, "oliva", owner="ani", expected_being_ref=None)
    (directory / "private.key").chmod(0o644)
    with pytest.raises(ValueError, match="private_protection_file_required"):
        transfer.read(tmp_path, "oliva", owner="ani")


def test_protected_upload_partial_retry_and_preparation_keep_receiving_writes(tmp_path):
    public = slot(tmp_path)
    raw, digest, credential = exported(tmp_path, public)
    with pytest.raises(seeds.SeedError, match="incomplete_seed_upload"):
        seeds.upload(
            tmp_path,
            "oliva",
            owner="ani",
            stream=io.BytesIO(raw[:37]),
            length=len(raw),
            sha256=digest,
        )
    assert seeds.status(tmp_path, "oliva", owner="ani")["upload_retryable"]
    partial = next((tmp_path / "being-seeds/oliva").glob("*.partial"))
    assert (
        transfer.request(tmp_path, "oliva", owner="ani", expected_being_ref=ROOT)
        == public
    )
    status = seeds.upload(
        tmp_path,
        "oliva",
        owner="ani",
        stream=io.BytesIO(raw),
        length=len(raw),
        sha256=digest,
    )
    assert status["protected_history"] and status["phase"] == "uploaded"
    assert partial.read_bytes() == raw[:37]
    selection = seeds.discovery(tmp_path, "oliva", owner="ani")
    assert selection["discovery"]["protected_transport"]["authenticated"]
    selection["memory_coverage"] = "complete-authorized"
    result = seeds.prepare(tmp_path, "oliva", selection, owner="ani")
    assert result["phase"] == "prepared" and not result["active"]
    directory = tmp_path / "being-seeds/oliva"
    assert (directory / "source.archive").read_bytes() == raw
    assert (directory / "received/source.archive").read_bytes() == raw
    memory = directory / "received/memory/store-001/library.db"
    with closing(sqlite3.connect(memory)) as db:
        assert db.execute("SELECT text FROM chapters ORDER BY id").fetchall() == [
            ("older memory",),
            (credential,),
            ("recent memory",),
        ]
        db.execute("INSERT INTO chapters VALUES(4,'receiving write')")
        db.commit()
    written = memory.read_bytes()
    assert seeds.prepare(tmp_path, "oliva", selection, owner="ani") == result
    assert (
        seeds.upload(
            tmp_path,
            "oliva",
            owner="ani",
            stream=io.BytesIO(b""),
            length=len(raw),
            sha256=digest,
        )
        == result
    )
    assert memory.read_bytes() == written
    from clusterctl import onboarding_input

    frozen = tmp_path / "worker-input"
    onboarding_input.capture(directory / "received", frozen, source_uid=os.geteuid())
    assert (frozen / "manifest.json").exists()
    assert not list(frozen.rglob("private.key"))
    assert not list(frozen.glob(".verify-transfer-*"))
    assert memory.read_bytes() == written
    with pytest.raises(seeds.SeedError, match="seed_not_found"):
        seeds.discovery(tmp_path, "oliva", owner="sai")


def test_wrong_recipient_and_tamper_never_produce_prepared_marker(tmp_path):
    public = slot(tmp_path)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    foreign = slot(other)
    raw, digest, _ = exported(tmp_path, foreign)
    seeds.upload(
        tmp_path,
        "oliva",
        owner="ani",
        stream=io.BytesIO(raw),
        length=len(raw),
        sha256=digest,
    )
    with pytest.raises(seeds.SeedError, match="verification_or_preparation_refused"):
        seeds.discovery(tmp_path, "oliva", owner="ani")
    assert not (tmp_path / "being-seeds/oliva/received/preparation.json").exists()
    assert transfer.read(tmp_path, "oliva", owner="ani") == public
    assert (tmp_path / "being-seeds/oliva/source.archive").read_bytes() == raw


def test_actual_http_transfer_keeps_owner_scopes_and_never_returns_private_key(
    tmp_path,
):
    from tests.test_being_seed import http_server

    state = tmp_path / "state"
    with http_server(state) as (_, request):
        assert (
            request(
                "/v1/seeds",
                "POST",
                dict(name="oliva", label="Oliva", mode="import"),
                extra={"Idempotency-Key": KEY},
            )[0]
            == 200
        )
        path = "/v1/seeds/oliva/transfer"
        assert request(path, "POST", {}, owner="sai")[0] == 404
        assert request(path, "POST", {}, owner="reader")[0] == 403
        assert request(path, "POST", {"expected_being_ref": ROOT})[0] == 400
        code, headers, public = request(path, "POST", {})
        assert code == 200 and headers["Cache-Control"] == "no-store"
        assert public["recipient"]["expected_being_ref"] is None
        private = (state / "being-seeds/oliva/transfer/private.key").read_bytes()
        assert transfer.protection().encoded(private) not in json.dumps(public)
        assert request(path, "POST", {})[2] == public
        assert request(path)[2] == public
        assert request(path, owner="sai")[0] == 404
        assert request(path, owner="reader")[0] == 403
        raw, digest, _ = exported(tmp_path, public)
        code, _, status = request(
            "/v1/seeds/oliva/archive", "POST", raw, extra={"X-Archive-SHA256": digest}
        )
        assert code == 200 and status["protected_history"]
        code, _, selection = request("/v1/seeds/oliva/selection")
        assert code == 200
        selection["memory_coverage"] = "complete-authorized"
        code, _, prepared = request(
            "/v1/seeds/oliva/prepare", "POST", {"selection": selection}
        )
        assert code == 200 and prepared["phase"] == "prepared"
        assert not prepared["active"]


def test_interrupted_recipient_publication_preserves_candidates_without_replacing_pair(
    tmp_path, monkeypatch
):
    seeds.create(
        tmp_path, dict(name="oliva", label="Oliva", mode="import"), owner="ani", key=KEY
    )
    rename = transfer.os.rename
    with monkeypatch.context() as change:
        change.setattr(
            transfer.os,
            "rename",
            lambda *_: (_ for _ in ()).throw(OSError("fixture crash")),
        )
        with pytest.raises(OSError):
            transfer.request(tmp_path, "oliva", owner="ani", expected_being_ref=ROOT)
    directory = tmp_path / "being-seeds/oliva"
    candidate = next(directory.glob(".transfer-*"))
    preserved = {p.name: p.read_bytes() for p in candidate.iterdir()}
    assert not (directory / "transfer").exists()
    public = transfer.request(tmp_path, "oliva", owner="ani", expected_being_ref=ROOT)
    assert {p.name: p.read_bytes() for p in candidate.iterdir()} == preserved
    assert transfer.read(tmp_path, "oliva", owner="ani") == public
    assert rename is os.rename
    raw, digest, _ = exported(tmp_path, public)
    with pytest.raises(seeds.SeedError, match="incomplete_seed_upload"):
        seeds.upload(
            tmp_path,
            "oliva",
            owner="ani",
            stream=io.BytesIO(raw[:20]),
            length=len(raw),
            sha256=digest,
        )
    assert seeds.status(tmp_path, "oliva", owner="ani")["upload_retryable"]
    assert (
        seeds.upload(
            tmp_path,
            "oliva",
            owner="ani",
            stream=io.BytesIO(raw),
            length=len(raw),
            sha256=digest,
        )["phase"]
        == "uploaded"
    )
    assert {p.name: p.read_bytes() for p in candidate.iterdir()} == preserved


@pytest.mark.parametrize("tamper", ["proof", "plaintext"])
def test_worker_independently_refuses_forged_preparation_without_publishing_input(
    tmp_path, tamper
):
    from clusterctl import onboarding_input
    from clusterctl.onboarding import OnboardingError

    public = slot(tmp_path)
    raw, digest, _ = exported(tmp_path, public)
    seeds.upload(
        tmp_path,
        "oliva",
        owner="ani",
        stream=io.BytesIO(raw),
        length=len(raw),
        sha256=digest,
    )
    selection = seeds.discovery(tmp_path, "oliva", owner="ani")
    selection["memory_coverage"] = "complete-authorized"
    seeds.prepare(tmp_path, "oliva", selection, owner="ani")
    directory = tmp_path / "being-seeds/oliva"
    received = directory / "received"
    if tamper == "proof":
        report = seeds._read(received / "preparation.json")
        report["protected_transport"]["plaintext_sha256"] = "0" * 64
        seeds._write(received / "preparation.json", report)
    else:
        archive = received / "plaintext.archive"
        original = archive.read_bytes()
        archive.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    frozen = tmp_path / "worker-input"
    with pytest.raises(OnboardingError, match="protected_onboarding_input_mismatch"):
        onboarding_input.capture(received, frozen, source_uid=os.geteuid())
    assert not (frozen / "manifest.json").exists()
    assert not list(frozen.rglob("private.key"))
    assert not list(frozen.glob(".verify-transfer-*"))
    assert (directory / "source.archive").read_bytes() == raw
