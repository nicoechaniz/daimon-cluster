"""Real standardized archives, private HTTP uploads and preserved receiving writes."""
import hashlib
import io
import json
import socket
import sqlite3
import threading
import urllib.error
import urllib.request
from contextlib import closing, contextmanager

import pytest

from clusterctl import being_seed as seeds
from clusterctl import browser
from clusterctl.cli import run
from clusterd import auth, handlers, seed_handlers
from clusterd.server import make_server

KEY = "11111111-1111-4111-8111-111111111111"


@pytest.fixture(autouse=True)
def staging_volume(monkeypatch):
    # /tmp may be a small tmpfs. Qualify archive behavior with a declared
    # staging-volume capacity; exercise real storage refusal separately.
    original = seeds.shutil.disk_usage
    monkeypatch.setattr(seeds.shutil, "disk_usage", lambda path: original(path)._replace(free=30 * 1024**3))


@pytest.fixture
def packet(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SOUL.md").write_text("I am Fixture, with a history and a human.\n")
    memory = source / "agent-memory"
    memory.mkdir()
    with closing(sqlite3.connect(memory / "library.db")) as database:
        database.execute("CREATE TABLE chapters(id INTEGER PRIMARY KEY, text TEXT)")
        database.execute("INSERT INTO chapters VALUES(1, 'A remembered encounter')")
        database.commit()
    skill = source / "skills/listening"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: listening\n---\nUseful historical behavior.\n")
    (source / "sessions").mkdir()
    (source / "sessions/old.jsonl").write_text('{"origin":"hermes","text":"old work"}\n')
    plan, archive = tmp_path / "plan.json", tmp_path / "fixture.tgz"
    seeds.tool("export_being", ["discover", "--being", "Fixture", "--hermes-root", str(source), "--output", str(plan)])
    result = seeds.tool("export_being", ["export", "--plan", str(plan), "--output", str(archive), "--writers-stopped"])
    return archive, result["sha256"]


def imported(state, packet, owner="ani", name="fixture"):
    archive, digest = packet
    seeds.create(state, {"name": name, "label": "Fixture", "mode": "import", "browser": True}, owner=owner, key=KEY)
    with archive.open("rb") as stream:
        seeds.upload(state, name, owner=owner, stream=stream, length=archive.stat().st_size, sha256=digest)
    return seeds.discovery(state, name, owner=owner)


def test_real_receiving_selection_retry_and_memory_isolation(tmp_path, packet):
    state = tmp_path / "state"
    selection = imported(state, packet)
    selection["memory_coverage"] = "complete-authorized"
    result = seeds.prepare(state, "fixture", selection, owner="ani")
    assert result["phase"] == "prepared"
    assert result["memory_stores"] == result["memory_chapters"] == result["skills"] == 1
    assert result["memory_coverage"] == "complete-authorized"
    assert result["active"] is False
    root = state / "being-seeds/fixture/received"
    working = root / "memory/store-001/library.db"
    with closing(sqlite3.connect(working)) as db:
        db.execute("INSERT INTO chapters VALUES (2,'New receiving memory')")
        db.commit()
    assert seeds.prepare(state, "fixture", selection, owner="ani") == result
    with closing(sqlite3.connect(working)) as db:
        assert db.execute("SELECT COUNT(*) FROM chapters").fetchone()[0] == 2
    original = next((root / "originals").rglob("library.db"))
    with closing(sqlite3.connect(original)) as db:
        assert db.execute("SELECT COUNT(*) FROM chapters").fetchone()[0] == 1
    assert (root / "source.archive").read_bytes() == packet[0].read_bytes()
    assert "not_imported" in (root / "continuity-index.json").read_text()
    for path in (state / "being-seeds").rglob("*"):
        assert path.stat().st_mode & 0o077 == 0


def test_new_seed_goes_through_same_export_and_receive(tmp_path):
    spec = {"name": "new-friend", "label": "New Friend", "mode": "new", "soul": "I am a new companion for this family."}
    seeds.create(tmp_path, spec, owner="family", key=KEY)
    result = seeds.prepare(tmp_path, "new-friend", None, owner="family")
    assert result["phase"] == "prepared"
    assert result["memory_coverage"] == "empty-new"
    assert result["memory_chapters"] == 0
    assert result["active"] is False
    assert seeds.prepare(tmp_path, "new-friend", None, owner="family") == result
    assert seeds.create(tmp_path, spec, owner="family", key=KEY) == result
    with pytest.raises(seeds.SeedError, match="idempotency_key_reuse"):
        seeds.create(tmp_path, {**spec, "name": "another"}, owner="family", key=KEY)


def test_private_connections_are_not_in_read_model(tmp_path):
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    token = "123456789:" + "a" * 40
    result = seeds.connections(tmp_path, "one", {"telegram_bot_token": token, "telegram_chat_id": -1234}, owner="ani")
    assert token not in json.dumps(result)
    assert token not in json.dumps(seeds.list_seeds(tmp_path))
    assert token in (tmp_path / "being-seeds/one/connections.json").read_text()
    assert result["telegram"] == "data supplied; not accepted"
    assert not seeds.list_seeds(tmp_path, owner="sai")
    with pytest.raises(seeds.SeedError, match="seed_not_found"):
        seeds.connections(tmp_path, "one", {"telegram_chat_id": 1234}, owner="sai")


def test_failed_upload_preserves_partial_and_blocks_overwrite(tmp_path):
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    with pytest.raises(seeds.SeedError, match="incomplete"):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(b"short"), length=20, sha256="0" * 64)
    assert seeds.status(tmp_path, "one")["phase"] == "attention-required"
    assert len(list((tmp_path / "being-seeds/one").glob("*.partial"))) == 1
    with pytest.raises(seeds.SeedError, match="already_present"):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(b"short"), length=5, sha256="0" * 64)


def test_storage_shortage_rejects_before_consuming_archive(tmp_path, monkeypatch):
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    original = seeds.shutil.disk_usage(tmp_path)
    monkeypatch.setattr(seeds.shutil, "disk_usage", lambda _path: original._replace(free=1024))
    stream = io.BytesIO(b"data")
    with pytest.raises(seeds.SeedError, match="staging_storage_required"):
        seeds.upload(tmp_path, "one", owner="ani", stream=stream, length=4, sha256="0" * 64)
    assert stream.tell() == 0
    assert seeds.status(tmp_path, "one")["phase"] == "awaiting-upload"


def test_published_archive_survives_metadata_failure_and_conflicting_retry(tmp_path, monkeypatch):
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    original_write = seeds._write
    def crash(path, value):
        if path.name == "record.json" and value.get("phase") == "uploaded":
            raise OSError("fixture metadata write failure")
        return original_write(path, value)
    with monkeypatch.context() as change:
        change.setattr(seeds, "_write", crash)
        with pytest.raises(OSError):
            seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(b"first"), length=5,
                         sha256=hashlib.sha256(b"first").hexdigest())
    assert seeds.status(tmp_path, "one")["phase"] == "attention-required"
    with pytest.raises(seeds.SeedError):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(b"other"), length=5,
                     sha256=hashlib.sha256(b"other").hexdigest())
    assert (tmp_path / "being-seeds/one/source.archive").read_bytes() == b"first"


def test_bad_archive_and_source_soul_credentials_never_prepare(tmp_path):
    spec = {"name": "one", "label": "One", "mode": "new", "soul": "Secret: 123456789:" + "a" * 40}
    seeds.create(tmp_path, spec, owner="ani", key=KEY)
    with pytest.raises(seeds.SeedError, match="requires_attention"):
        seeds.prepare(tmp_path, "one", None, owner="ani")
    assert not (tmp_path / "being-seeds/one/received/preparation.json").exists()


def test_symlink_paths_and_changed_pinned_tool_fail_closed(tmp_path, monkeypatch):
    alias = tmp_path / "alias"
    real = tmp_path / "real"
    real.mkdir()
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(seeds.SeedError, match="symlink"):
        seeds.list_seeds(alias)
    monkeypatch.setitem(seeds.TOOL_HASHES, "export_being.py", "0" * 64)
    with pytest.raises(seeds.SeedError, match="pinned_seed_tool_mismatch"):
        seeds.tool("export_being", ["--help"])


@contextmanager
def http_server(state):
    credentials = {}
    for owner, scopes in [("ani", ["fleet:read", "seed:write"]), ("sai", ["fleet:read", "seed:write"]), ("reader", ["fleet:read"])]:
        _, credentials[owner] = auth.create_token(state, actor=owner, scopes=scopes, owner=owner, ttl_days=1)
    server = make_server(handlers.Deps("configs/clusterctl.yaml", state_dir=str(state)), "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def request(path, method="GET", body=None, owner="ani", extra=None):
        headers = {"Authorization": "Bearer " + credentials[owner], **(extra or {})}
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"http://127.0.0.1:{server.server_address[1]}{path}", data=body, method=method, headers=headers)
        try:
            response = urllib.request.urlopen(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read()
            return response.status, dict(response.headers), json.loads(data) if response.headers["Content-Type"] == "application/json" else data.decode()
    try:
        yield server, request
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_web_upload_full_workflow_owner_isolation_and_no_secret_echo(tmp_path, packet):
    with http_server(tmp_path / "state") as (_server, request):
        spec = {"name": "one", "label": "Fixture", "mode": "import", "browser": True}
        assert request("/v1/seeds", "POST", spec, extra={"Idempotency-Key": KEY})[0] == 200
        assert request("/v1/seeds", "POST", spec, owner="reader", extra={"Idempotency-Key": KEY})[0] == 403
        archive, digest = packet
        assert request("/v1/seeds/one/archive", "POST", archive.read_bytes(), owner="sai", extra={"X-Archive-SHA256": digest})[0] == 404
        assert request("/v1/seeds/one/archive", "POST", archive.read_bytes(), extra={"X-Archive-SHA256": digest})[0] == 200
        code, _, selection = request("/v1/seeds/one/selection")
        assert code == 200
        code, _, result = request("/v1/seeds/one/prepare", "POST", {"selection": selection})
        assert code == 200 and result["phase"] == "prepared"
        assert request("/v1/seeds", owner="sai")[2]["items"] == []
        assert len(request("/v1/seeds")[2]["items"]) == 1
        token = "123456789:" + "x" * 40
        code, headers, data = request("/v1/seeds/one/connections", "POST", {"telegram_bot_token": token, "telegram_chat_id": 1234})
        assert code == 200 and token not in json.dumps(data)
        assert headers["Cache-Control"] == "no-store"
        code, headers, html = request("/v1/onboarding")
        assert code == 200
        assert "default-src 'none'" in headers["Content-Security-Policy"]
        assert "https://" not in html and "sessionStorage" not in html
        assert hashlib.sha256(seed_handlers.SCRIPT.encode()).digest()


def test_upload_unauthenticated_rejected_without_reading_body(tmp_path):
    with http_server(tmp_path) as (server, _request):
        with socket.create_connection(server.server_address, timeout=3) as connection:
            connection.sendall(b"POST /v1/seeds/no/archive HTTP/1.1\r\nHost: localhost\r\nContent-Length: 99999999\r\n\r\n")
            assert b"401" in connection.recv(8192)


def test_seed_cli_never_contacts_incus(tmp_path, capsys):
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"name": "one", "label": "One", "mode": "new", "soul": "A new friend"}))
    assert run(["--state-dir", str(tmp_path / "state"), "seed", "--owner", "ani", "create", "--spec", str(spec), "--idempotency-key", KEY]) == 0
    assert run(["--state-dir", str(tmp_path / "state"), "seed", "--owner", "ani", "prepare", "one"]) == 0
    assert '"phase": "prepared"' in capsys.readouterr().out


def test_seed_only_mode_has_no_fleet_or_matrix_surface(tmp_path):
    deps = handlers.Deps("configs/clusterctl.yaml", state_dir=str(tmp_path), seed_only=True)
    server = make_server(deps, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        with urllib.request.urlopen(base + "/v1/health") as response:
            assert json.load(response)["service"] == "seed-intake"
        with pytest.raises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(base + "/v1/instances")
        with raised.value as response:
            assert response.status == 404
        with urllib.request.urlopen(base + "/v1/onboarding") as response:
            assert response.status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_unverified_bad_archive_preserves_context_and_redacts_failure(tmp_path):
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    data = b"private text that is not an archive"
    seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(data), length=len(data), sha256=hashlib.sha256(data).hexdigest())
    with pytest.raises(seeds.SeedError) as error:
        seeds.discovery(tmp_path, "one", owner="ani")
    assert "private text" not in str(error.value)
    assert (tmp_path / "being-seeds/one/source.archive").read_bytes() == data


def test_conflicting_retry_never_replaces_prepared_state(tmp_path, packet):
    selection = imported(tmp_path, packet)
    seeds.prepare(tmp_path, "fixture", selection, owner="ani")
    selection["memory_coverage"] = "complete-authorized"
    with pytest.raises(seeds.SeedError, match="preserves_existing_attempt"):
        seeds.prepare(tmp_path, "fixture", selection, owner="ani")
    assert seeds.status(tmp_path, "fixture")["memory_coverage"] == "owner-selected"


def test_browser_preparation_copies_code_only_and_preserves_profile(tmp_path, monkeypatch):
    monkeypatch.setattr(browser.shutil, "which", lambda _program: "/fixture/program")
    daemon = tmp_path / "daemon"
    daemon.write_bytes(b"code artifact")
    extension = tmp_path / "extension"
    extension.mkdir()
    (extension / "manifest.json").write_text('{"version":"fixture"}')
    home = tmp_path / "owner-home"
    home.mkdir()
    digest = hashlib.sha256(daemon.read_bytes()).hexdigest()
    extension_hash = browser.extension_digest(extension)[0]
    args = (daemon, digest, extension, extension_hash, home)
    assert browser.prepare(*args, apply=False)["applied"] is False
    assert not (home / ".kimi-webbridge").exists()
    browser.prepare(*args, apply=True)
    profile = home / ".kimi-webbridge/chromium-profile"
    profile.mkdir()
    (profile / "history").write_text("Receiving user's own history")
    browser.prepare(*args, apply=True)
    assert (profile / "history").read_text() == "Receiving user's own history"
    (home / ".kimi-webbridge/extension/manifest.json").write_text("changed code")
    with pytest.raises(ValueError, match="installed_browser_code_changed"):
        browser.prepare(*args, apply=True)


def test_browser_private_state_and_symlink_are_never_imported(tmp_path, monkeypatch):
    monkeypatch.setattr(browser.shutil, "which", lambda _program: "/fixture/program")
    extension = tmp_path / "extension"
    extension.mkdir()
    (extension / "manifest.json").symlink_to(tmp_path / "outside")
    with pytest.raises(ValueError, match="symlink"):
        browser.extension_digest(extension)
