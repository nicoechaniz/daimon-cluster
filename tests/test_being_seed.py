"""Real standardized archives, private HTTP uploads and preserved receiving writes."""
import hashlib
import io
import json
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import closing, contextmanager
from concurrent.futures import ThreadPoolExecutor

import pytest

from clusterctl import being_seed as seeds
from clusterctl import browser
from clusterctl.cli import run
from clusterd import auth, handlers, seed_handlers
from clusterd.server import make_server

KEY = "11111111-1111-4111-8111-111111111111"


def test_portable_exporter_pin_accepts_reference_and_reports_remaining_history_boundary(tmp_path):
    from pathlib import Path
    from clusterd.seed_ui import agent_guide, agent_markdown
    root = Path(__file__).resolve().parents[1]
    provenance = json.loads((root / 'support/being-seed-tools/PROVENANCE.json').read_bytes())
    assert provenance['commit'] == seeds.TOOL_COMMIT
    assert provenance['files'] == seeds.TOOL_HASHES
    source = tmp_path / 'source'
    source.mkdir()
    content = b'api_key = provider_configuration.resolve_active_provider_key\n'
    (source / 'provider.py').write_bytes(content)
    plan, archive, restored = tmp_path / 'plan.json', tmp_path / 'reference.tgz', tmp_path / 'restored'
    seeds.tool('export_being', ['discover', '--being', 'Fixture', '--context-root', str(source), '--output', str(plan)])
    result = seeds.tool('export_being', ['export', '--plan', str(plan), '--output', str(archive), '--writers-stopped'])
    seeds.tool('export_being', ['unpack', '--archive', str(archive), '--sha256', result['sha256'], '--destination', str(restored)])
    assert (restored / 'payload/context-001/provider.py').read_bytes() == content
    assert (source / 'provider.py').read_bytes() == content
    guide = agent_guide()
    assert guide['preservation_tools_commit'] == seeds.TOOL_COMMIT
    assert seeds.TOOL_COMMIT[:7] in guide['portable_tools']
    assert guide['exporter_status']['credential_bearing_history'] == 'recipient-bound-protected-transfer'
    assert 'redacted native API' in agent_markdown()


@pytest.mark.parametrize("first", ["handlers", "seed_handlers"])
def test_http_handler_import_orders(first):
    # A fresh process catches partial module initialization hidden by pytest's
    # imports. Both standalone intake and the full server load these modules.
    subprocess.run([sys.executable, "-c",
                    f"from clusterd import {first}; "
                    "from clusterd import seed_handlers; "
                    "assert seed_handlers.seed_ui(None, None).status == 200"],
                   check=True, capture_output=True, text=True)


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


def test_large_receiving_index_queues_native_preparation_and_preserves_later_memory(tmp_path, packet):
    state = tmp_path / "state"
    selection = imported(state, packet)
    # A preserved package may index hundreds of historical skills. Discovery
    # notes are intentionally ignored by native selection verification.
    selection['discovery']['soul_candidates'] += ['payload/project-%03d/templates/SOUL.md' % i
                                                for i in range(2500)]
    assert len(json.dumps(selection).encode()) > seeds.MAX_RECORD
    directory = state / 'being-seeds/fixture'
    seeds._write(directory / 'discovery.json', selection, limit=seeds.MAX_SELECTION)
    assert seeds.discovery(state, 'fixture', owner='ani') == selection
    with http_server(state) as (_, http):
        code, _, result = http('/v1/seeds/fixture/prepare', 'POST',
            {'selection': selection, 'defer': True})
        assert code == 200
        assert http('/v1/seeds/fixture/prepare', 'POST',
            {'selection': selection, 'defer': True}, owner='sai')[0] == 404
        # The larger body allowance applies only to receiving selections.
        assert http('/v1/seeds/fixture/connections', 'POST',
            {'unused': 'x' * seeds.MAX_RECORD})[0] == 413
    assert result['preparation_queued'] and result['phase'] == 'uploaded'
    assert not (directory / 'received').exists()
    assert seeds.queue_prepare(state, 'fixture', selection, owner='ani') == result
    with pytest.raises(seeds.SeedError, match='preserves_existing_attempt'):
        seeds.queue_prepare(state, 'fixture', {**selection, 'memory': []}, owner='ani')
    prepared = seeds.process_preparation(state, 'fixture', owner='ani')
    assert prepared['phase'] == 'prepared' and not prepared['preparation_queued']
    assert (directory / 'received/preparation.json').stat().st_size > seeds.MAX_RECORD
    working = directory / 'received/memory/store-001/library.db'
    with closing(sqlite3.connect(working)) as db:
        db.execute("INSERT INTO chapters VALUES (2,'New receiving memory')")
        db.commit()
    assert seeds.process_preparation(state, 'fixture', owner='ani') == prepared
    with closing(sqlite3.connect(working)) as db:
        assert db.execute('SELECT COUNT(*) FROM chapters').fetchone()[0] == 2
    with pytest.raises(seeds.SeedError, match='seed_not_found'):
        seeds.process_preparation(state, 'fixture', owner='sai')
    # Large records remain refused outside the explicit receiving documents.
    with pytest.raises(seeds.SeedError, match='private_seed_record_required'):
        seeds._read(directory / 'discovery.json')


def test_queued_preparation_refuses_changed_archive_and_does_not_infer_soul(tmp_path, packet):
    state = tmp_path / 'state'
    selection = imported(state, packet)
    with pytest.raises(seeds.SeedError, match='explicit_receiving_selection_required'):
        seeds.queue_prepare(state, 'fixture', {**selection, 'soul': None}, owner='ani')
    seeds.queue_prepare(state, 'fixture', selection, owner='ani')
    path = state / 'being-seeds/fixture/preparation-request.json'
    value = seeds._read(path)
    seeds._write(path, {**value, 'archive_sha256': '0' * 64})
    with pytest.raises(seeds.SeedError, match='invalid_seed_preparation_request'):
        seeds.process_preparation(state, 'fixture', owner='ani')
    assert not (path.parent / 'received').exists()


def test_queued_preparation_reconciles_marker_after_metadata_crash(tmp_path, packet, monkeypatch):
    state = tmp_path / 'state'
    selection = imported(state, packet)
    seeds.queue_prepare(state, 'fixture', selection, owner='ani')
    original_write = seeds._write
    def crash(path, value, **options):
        if path.name == 'record.json' and value.get('phase') == 'prepared':
            raise OSError('fixture final metadata interruption')
        return original_write(path, value, **options)
    with monkeypatch.context() as change:
        change.setattr(seeds, '_write', crash)
        with pytest.raises(seeds.SeedError, match='requires_attention'):
            seeds.process_preparation(state, 'fixture', owner='ani')
    directory = state / 'being-seeds/fixture'
    working = directory / 'received/memory/store-001/library.db'
    with closing(sqlite3.connect(working)) as db:
        db.execute("INSERT INTO chapters VALUES (2,'Receiving write after marker')")
        db.commit()
    with monkeypatch.context() as change:
        change.setattr(seeds, 'tool', lambda *_a, **_k: pytest.fail('completed native tool was repeated'))
        result = seeds.process_preparation(state, 'fixture', owner='ani')
    assert result['phase'] == 'prepared'
    with closing(sqlite3.connect(working)) as db:
        assert db.execute('SELECT COUNT(*) FROM chapters').fetchone()[0] == 2


def test_queued_preparation_retries_unpublished_context_without_discarding_partial_bytes(tmp_path, packet, monkeypatch):
    state = tmp_path / 'state'
    selection = imported(state, packet)
    seeds.queue_prepare(state, 'fixture', selection, owner='ani')
    directory = state / 'being-seeds/fixture'
    original = seeds.tool
    def interrupted(name, arguments, **options):
        if name == 'receive_being' and arguments[0] == 'prepare':
            assert options['timeout'] == seeds.PREPARATION_TIMEOUT
            partial = directory / 'received'
            partial.mkdir(mode=0o700)
            (partial / 'preserved-evidence').write_bytes(b'partial original bytes')
            raise seeds.SeedError('seed_tool_incomplete', 409)
        return original(name, arguments, **options)
    with monkeypatch.context() as change:
        change.setattr(seeds, 'tool', interrupted)
        with pytest.raises(seeds.SeedError, match='requires_attention'):
            seeds.process_preparation(state, 'fixture', owner='ani')
    result = seeds.process_preparation(state, 'fixture', owner='ani')
    assert result['phase'] == 'prepared'
    assert [p.read_bytes() for p in directory.glob('uncompleted-receiving-*/preserved-evidence')] == [b'partial original bytes']
    assert (directory / 'received/preparation.json').exists()
    assert seeds._read(directory / 'record.json')['preparation_attempts'] == 2


def test_interrupted_preparation_keeps_foreign_selection_and_caps_retries(tmp_path, packet, monkeypatch):
    state = tmp_path / 'state'
    selection = imported(state, packet)
    seeds.queue_prepare(state, 'fixture', selection, owner='ani')
    directory = state / 'being-seeds/fixture'
    record = seeds._read(directory / 'record.json')
    seeds._write(directory / 'record.json', {**record, 'phase': 'preparing',
        'preparation_fingerprint': seeds._fingerprint({'selection': selection}), 'preparation_attempts': 3})
    (directory / 'received').mkdir(mode=0o700)
    evidence = directory / 'received/keep'
    evidence.write_bytes(b'unchanged')
    with pytest.raises(seeds.SeedError, match='preserves_existing_attempt'):
        seeds.prepare(state, 'fixture', {**selection, 'skills': []}, owner='ani')
    with pytest.raises(seeds.SeedError, match='retry_limit'):
        seeds.process_preparation(state, 'fixture', owner='ani')
    assert evidence.read_bytes() == b'unchanged'


def test_new_seed_queued_preparation_keeps_generated_archive_on_retry(tmp_path):
    seeds.create(tmp_path, {'name': 'new-friend', 'label': 'New Friend', 'mode': 'new',
        'soul': 'I am a new companion for this family.'}, owner='family', key=KEY)
    seeds.queue_prepare(tmp_path, 'new-friend', None, owner='family')
    result = seeds.process_preparation(tmp_path, 'new-friend', owner='family')
    archive = tmp_path / 'being-seeds/new-friend/source.archive'
    before = archive.read_bytes()
    assert result['phase'] == 'prepared' and result['memory_coverage'] == 'empty-new'
    assert seeds.process_preparation(tmp_path, 'new-friend', owner='family') == result
    assert archive.read_bytes() == before


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


def test_failed_upload_preserves_partial_and_blocks_different_archive(tmp_path):
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    with pytest.raises(seeds.SeedError, match="incomplete"):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(b"short"), length=20, sha256="0" * 64)
    assert seeds.status(tmp_path, "one")["phase"] == "attention-required"
    assert len(list((tmp_path / "being-seeds/one").glob("*.partial"))) == 1
    assert seeds.status(tmp_path, "one")["upload_retryable"] is True
    with pytest.raises(seeds.SeedError, match="requires_same_archive"):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(b"short"), length=5, sha256="0" * 64)


def test_resume_uses_longest_legacy_partial_and_survives_another_interruption(tmp_path, packet):
    raw, digest = packet[0].read_bytes(), packet[1]
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    seeds.connections(tmp_path, "one", {"telegram_chat_id": 1234}, owner="ani")
    directory = tmp_path / "being-seeds/one"
    for count in (30, 10):
        with pytest.raises(seeds.SeedError, match="incomplete"):
            seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(raw[:count]), length=len(raw), sha256=digest)
    connections = (directory / "connections.json").read_bytes()
    progress = seeds.upload_progress(tmp_path, "one", owner="ani")
    assert progress == dict(complete=False, offset=30, size=len(raw), sha256=digest,
                           prefix_sha256=hashlib.sha256(raw[:30]).hexdigest())
    with pytest.raises(seeds.SeedError, match="incomplete"):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(raw[30:50]),
                     length=len(raw)-30, sha256=digest, offset=30, total=len(raw),
                     prefix_sha256=progress["prefix_sha256"])
    progress = seeds.upload_progress(tmp_path, "one", owner="ani")
    assert progress["offset"] == 50
    result = seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(raw[50:]),
                          length=len(raw)-50, sha256=digest, offset=50, total=len(raw),
                          prefix_sha256=progress["prefix_sha256"])
    assert result["phase"] == "uploaded"
    assert (directory / "source.archive").read_bytes() == raw
    assert (directory / "connections.json").read_bytes() == connections
    assert [p.read_bytes() for p in directory.glob("*.partial")] == [raw[:10]]
    assert seeds.upload_progress(tmp_path, "one", owner="ani")["complete"] is True
    assert seeds.discovery(tmp_path, "one", owner="ani")["schema"]


@pytest.mark.parametrize("change", ["offset", "total", "prefix_sha256", "sha256"])
def test_resume_refuses_changed_identity_or_stale_prefix_before_reading(tmp_path, change):
    raw = b"a preserved original archive"
    digest = hashlib.sha256(raw).hexdigest()
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    with pytest.raises(seeds.SeedError):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(raw[:8]), length=len(raw), sha256=digest)
    original = next((tmp_path / "being-seeds/one").glob("*.partial"))
    args = dict(offset=8, total=len(raw), prefix_sha256=hashlib.sha256(raw[:8]).hexdigest(), sha256=digest)
    args[change] = args[change]+1 if change in {"offset", "total"} else "0"*64
    stream = io.BytesIO(raw[args["offset"]:])
    with pytest.raises(seeds.SeedError):
        seeds.upload(tmp_path, "one", owner="ani", stream=stream,
                     length=args["total"]-args["offset"], **args)
    assert stream.tell() == 0
    assert original.read_bytes() == raw[:8]


def test_resume_finalize_complete_partial_after_publication_failure(tmp_path, monkeypatch):
    raw = b"complete bytes received before publication"
    digest = hashlib.sha256(raw).hexdigest()
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    link = seeds.os.link
    def interrupted(*args):
        raise OSError("publication interrupted")
    monkeypatch.setattr(seeds.os, "link", interrupted)
    with pytest.raises(OSError):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(raw), length=len(raw), sha256=digest)
    progress = seeds.upload_progress(tmp_path, "one", owner="ani")
    assert not progress["complete"] and progress["offset"] == len(raw)
    monkeypatch.setattr(seeds.os, "link", link)
    assert seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(b""), length=0,
                        sha256=digest, offset=len(raw), total=len(raw), prefix_sha256=digest)["phase"] == "uploaded"


def test_resume_full_checksum_mismatch_never_publishes(tmp_path):
    raw = b"the same original bytes"
    digest = hashlib.sha256(raw).hexdigest()
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    with pytest.raises(seeds.SeedError):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(raw[:5]), length=len(raw), sha256=digest)
    with pytest.raises(seeds.SeedError, match="hash_mismatch"):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(b"x"*(len(raw)-5)),
                     length=len(raw)-5, sha256=digest, offset=5, total=len(raw),
                     prefix_sha256=hashlib.sha256(raw[:5]).hexdigest())
    assert not (tmp_path / "being-seeds/one/source.archive").exists()
    assert seeds.upload_progress(tmp_path, "one", owner="ani")["offset"] == 0


@pytest.mark.parametrize("legacy", [False, True])
def test_interrupted_upload_retry_preserves_partial_and_connections(tmp_path, packet, legacy):
    archive, digest = packet
    raw = archive.read_bytes()
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    seeds.connections(tmp_path, "one", {"telegram_chat_id": 1234}, owner="ani")
    with pytest.raises(seeds.SeedError, match="incomplete"):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(raw[:20]), length=len(raw), sha256=digest)
    directory = tmp_path / "being-seeds/one"
    partial = next(directory.glob("*.partial"))
    connections = (directory / "connections.json").read_bytes()
    if legacy:
        record = seeds._read(directory / "record.json")
        record.pop("upload_sha256")
        record.pop("upload_size")
        seeds._write(directory / "record.json", record)
    with pytest.raises(seeds.SeedError, match="not_found"):
        seeds.upload(tmp_path, "one", owner="sai", stream=io.BytesIO(raw), length=len(raw), sha256=digest)
    assert seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(raw), length=len(raw), sha256=digest)["phase"] == "uploaded"
    assert partial.read_bytes() == raw[:20]
    assert (directory / "connections.json").read_bytes() == connections
    assert (directory / "source.archive").read_bytes() == raw
    assert not seeds.status(tmp_path, "one")["upload_retryable"]
    assert seeds.discovery(tmp_path, "one", owner="ani")["schema"]


@pytest.mark.parametrize("marker", ["source.archive", "received", "discovery.json"])
def test_upload_retry_refuses_published_or_preparation_state(tmp_path, marker):
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    with pytest.raises(seeds.SeedError):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(b"x"), length=2, sha256="0" * 64)
    directory = tmp_path / "being-seeds/one"
    (directory / marker).write_bytes(b"preserved")
    assert not seeds.status(tmp_path, "one")["upload_retryable"]
    stream = io.BytesIO(b"xx")
    with pytest.raises(seeds.SeedError, match="already_present"):
        seeds.upload(tmp_path, "one", owner="ani", stream=stream, length=2, sha256="0" * 64)
    assert stream.tell() == 0
    assert (directory / marker).read_bytes() == b"preserved"


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
    for owner, scopes in [("ani", ["fleet:read", "seed:write"]), ("sai", ["fleet:read", "seed:write"]), ("reader", ["fleet:read"]), ("operator", ["fleet:read", "seed:write"])]:
        _, credentials[owner] = auth.create_token(state, actor=owner, scopes=scopes, owner="*" if owner == "operator" else owner, ttl_days=1)
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
            media = response.headers["Content-Type"]
            value = json.loads(data) if media == "application/json" else data if media == "application/zip" else data.decode()
            return response.status, dict(response.headers), value
    try:
        yield server, request
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_real_http_resume_client_owner_isolation_and_download(tmp_path, packet, monkeypatch, capsys):
    from tools import resume_seed_upload as client
    raw, digest = packet[0].read_bytes(), packet[1]
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    with pytest.raises(seeds.SeedError):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(raw[:30]), length=len(raw), sha256=digest)
    _, token = auth.create_token(tmp_path, actor="ani", scopes=["seed:write"], owner="ani", ttl_days=1)
    with http_server(tmp_path) as (server, request):
        path = "/v1/seeds/one/archive"
        assert request(path, owner="sai")[0] == 404
        assert request(path, owner="reader")[0] == 403
        code, _, progress = request(path)
        assert code == 200 and progress["offset"] == 30
        directory = tmp_path / "being-seeds/one"
        with seeds._locked(directory):
            assert request(path)[0] == 409
        assert request(path, "POST", raw[30:], extra={"X-Archive-SHA256": digest,
                       "X-Archive-Offset": "30"})[0] == 400
        connection = client.http.client.HTTPConnection
        monkeypatch.setattr(client.http.client, "HTTPSConnection",
                            lambda host, port, timeout: connection("127.0.0.1", server.server_address[1], timeout=timeout))
        value = client.upload("https://fixture.invalid", "one", packet[0], digest, token)
        assert value["phase"] == "uploaded"
        assert (directory / "source.archive").read_bytes() == raw
        assert client.upload("https://fixture.invalid", "one", packet[0], digest, token)["complete"]
        output = capsys.readouterr().out
        assert "Continuing from 30" in output and token not in output
        code, _, download = request("/v1/onboarding/local-body/tools/resume_seed_upload.py")
        assert code == 200 and "def upload(" in download


def test_resume_client_rejects_local_prefix_disagreement(tmp_path, packet, monkeypatch):
    from tools import resume_seed_upload as client
    raw, digest = packet[0].read_bytes(), packet[1]
    seeds.create(tmp_path, {"name": "one", "label": "One", "mode": "import"}, owner="ani", key=KEY)
    with pytest.raises(seeds.SeedError):
        seeds.upload(tmp_path, "one", owner="ani", stream=io.BytesIO(b"x"*30), length=len(raw), sha256=digest)
    _, token = auth.create_token(tmp_path, actor="ani", scopes=["seed:write"], owner="ani", ttl_days=1)
    with http_server(tmp_path) as (server, _):
        connection = client.http.client.HTTPConnection
        monkeypatch.setattr(client.http.client, "HTTPSConnection",
                            lambda host, port, timeout: connection("127.0.0.1", server.server_address[1], timeout=timeout))
        with pytest.raises(client.UploadError, match="prefix_disagrees_no_bytes_sent"):
            client.upload("https://fixture.invalid", "one", packet[0], digest, token)
    assert next((tmp_path / "being-seeds/one").glob("*.partial")).read_bytes() == b"x"*30


def test_resume_guide_documents_exact_post_protocol_and_browser_remaining_slice():
    from clusterd.seed_ui import SCRIPT, agent_guide, agent_markdown
    resume = agent_guide()["requests"]["upload"]["resume"]
    assert set(resume["headers"]) == {"X-Archive-Offset", "X-Archive-Size", "X-Archive-Prefix-SHA256"}
    assert "resume instead of restarting from zero" in agent_markdown()
    assert "file.slice(offset)" in SCRIPT and "body instanceof Blob" in SCRIPT


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
        assert "https://" not in html.replace("https://auth.openai.com/codex/device", "") and "sessionStorage" not in html
        assert hashlib.sha256(seed_handlers.SCRIPT.encode()).digest()


def test_http_disconnected_upload_can_retry_same_packet(tmp_path, packet):
    state = tmp_path / "state"
    archive, digest = packet
    raw = archive.read_bytes()
    with http_server(state) as (server, request):
        spec = {"name": "one", "label": "Fixture", "mode": "import"}
        assert request("/v1/seeds", "POST", spec, extra={"Idempotency-Key": KEY})[0] == 200
        _, token = auth.create_token(state, actor="ani", scopes=["seed:write"], owner="ani", ttl_days=1)
        with socket.create_connection(server.server_address, timeout=3) as connection:
            headers = ("POST /v1/seeds/one/archive HTTP/1.1\r\nHost: localhost\r\n"
                       f"Authorization: Bearer {token}\r\nContent-Length: {len(raw)}\r\n"
                       f"X-Archive-SHA256: {digest}\r\n\r\n")
            connection.sendall(headers.encode() + raw[:20])
            connection.shutdown(socket.SHUT_WR)
            connection.recv(4096)
        for _ in range(20):
            progress = request("/v1/seeds")[2]["items"][0]
            if progress["phase"] == "attention-required":
                break
            time.sleep(0.05)
        assert progress["upload_retryable"] is True
        partial = next((state / "being-seeds/one").glob("*.partial"))
        assert request("/v1/seeds/one/archive", "POST", raw, extra={"X-Archive-SHA256": digest})[0] == 200
        assert partial.read_bytes() == raw[:20]
        assert request("/v1/seeds/one/selection")[0] == 200


def test_upload_unauthenticated_rejected_without_reading_body(tmp_path):
    with http_server(tmp_path) as (server, _request):
        with socket.create_connection(server.server_address, timeout=3) as connection:
            connection.sendall(b"POST /v1/seeds/no/archive HTTP/1.1\r\nHost: localhost\r\nContent-Length: 99999999\r\n\r\n")
            assert b"401" in connection.recv(8192)


def test_same_entrypoint_machine_formats_are_public_metadata_only(tmp_path):
    with http_server(tmp_path) as (_server, request):
        spec = {"name": "private-fixture", "label": "PrivateFixture", "mode": "new",
                "soul": "Private autobiography unique to this fixture"}
        assert request("/v1/seeds", "POST", spec, extra={"Idempotency-Key": KEY})[0] == 200
        token = "123456789:" + "x" * 40
        assert request("/v1/seeds/private-fixture/connections", "POST",
                       {"telegram_bot_token": token, "telegram_chat_id": 1234})[0] == 200
        for media, suffix in [("text/markdown", "markdown"), ("application/json", "json")]:
            code, headers, body = request("/v1/onboarding", extra={"Authorization": "", "Accept": media})
            assert code == 200 and headers["Content-Type"].startswith(media)
            assert headers["Vary"] == "Accept" and headers["Cache-Control"] == "no-store"
            assert 'rel="alternate"' in headers["Link"]
            assert request("/v1/onboarding?format=" + suffix, extra={"Authorization": ""})[2] == body
            serialized = json.dumps(body)
            for private in [spec["name"], spec["label"], spec["soul"], token, str(tmp_path)]:
                assert private not in serialized
        code, _, guide = request("/v1/onboarding?format=json", extra={"Authorization": ""})
        assert code == 200 and guide["schema"] == "cluster-onboarding-guide/v1"
        assert guide["completion"]["active"] is False
        assert guide["completion"]["automatic_runtime_activation"] is False
        assert guide["api"]["servers"] == [{"url": "/", "description": "This HTTPS origin"}]
        assert set(guide["api"]["paths"]) == {
            "/v1/onboarding", "/v1/seed-access", "/v1/seeds", "/v1/seeds/{seed}/archive",
            "/v1/seeds/{seed}/transfer", "/v1/seeds/{seed}/selection", "/v1/seeds/{seed}/prepare", "/v1/seeds/{seed}/connections", "/v1/seeds/{seed}/onboarding",
            "/v1/seed-access-requests", "/v1/seed-access-requests/{request_id}",
            "/v1/seed-access-requests/{request_id}/claim", "/v1/seed-session",
            "/v1/seeds/{seed}/onboarding/review", "/v1/seeds/{seed}/onboarding/action",
            "/v1/seeds/{seed}/onboarding/access", "/v1/seeds/{seed}/onboarding/checks", "/v1/onboarding/local-body",
            "/v1/onboarding/local-body/{seed}", "/v1/onboarding/local-body/tools/{tool}",
            "/v1/onboarding/local-body/{seed}/diagnostic", "/v1/onboarding/local-body/{seed}/enrollment"}
        assert request("/v1/seeds", extra={"Authorization": ""})[0] == 401
        assert request("/v1/seeds/private-fixture/selection", owner="sai")[0] == 404


def test_machine_media_preferences_and_explicit_format_override(tmp_path):
    with http_server(tmp_path) as (_server, request):
        def get(path="/v1/onboarding", accept=""):
            return request(path, extra={"Authorization": "", "Accept": accept})
        assert get(accept="text/html;q=0.5, text/markdown;q=1")[1]["Content-Type"].startswith("text/markdown")
        assert get(accept="text/markdown;q=0, text/html;q=1")[1]["Content-Type"].startswith("text/html")
        assert get(accept="application/json, text/markdown")[1]["Content-Type"] == "application/json"
        assert get("/v1/onboarding?format=html", "application/json")[1]["Content-Type"].startswith("text/html")
        assert get(accept="*/*")[1]["Content-Type"].startswith("text/html")
        assert get("/v1/onboarding?format=")[1]["Content-Type"].startswith("text/html")
        for query in ["format=xml", "format=json&format=markdown"]:
            assert get("/v1/onboarding?" + query)[0] == 400


def test_public_access_request_requires_exact_human_approval_and_private_proof(tmp_path):
    key = "a" * 64
    spec = {"owner": "fresh-human", "proof_sha256": auth.hash_token(key)}
    with http_server(tmp_path) as (_server, request):
        public = {"Authorization": ""}
        code, _, pending = request("/v1/seed-access-requests", "POST", spec, extra=public)
        assert code == 200 and pending["phase"] == "pending"
        assert "proof_sha256" not in pending and "token" not in pending
        assert request("/v1/seed-access-requests", "POST", spec, extra=public)[2] == pending
        assert request("/v1/seed-access-requests", "POST", {**spec, "owner": "other-human"}, extra=public)[0] == 409
        assert request("/v1/seed-access-requests", "POST", {**spec, "owner": "*"}, extra=public)[0] == 400
        assert request("/v1/seed-access-requests", "POST", {**spec, "scopes": ["destroy:write"]}, extra=public)[0] == 400
        path = "/v1/seed-access-requests/" + pending["request_id"]
        proof = {**public, "X-Access-Request-Key": key}
        assert request(path, extra=public)[0] == 404
        assert request(path, extra={**public, "X-Access-Request-Key": "b" * 64})[0] == 404
        assert request(path + "/claim", "POST", {}, extra=proof)[0] == 409
        with pytest.raises(seeds.SeedError, match="owner_or_code_mismatch"):
            auth.approve_seed_access(tmp_path, owner="other-human", code=pending["verification_code"])
        assert auth.list_tokens(tmp_path)[-1]["actor"] == "operator"
        assert auth.approve_seed_access(tmp_path, owner=spec["owner"], code=pending["verification_code"])["phase"] == "approved"
        code, headers, granted = request(path + "/claim", "POST", {}, extra=proof)
        assert code == 200 and headers["Cache-Control"] == "no-store"
        record, reason = auth.authenticate(auth.TokenStore(tmp_path), granted["token"])
        assert reason is None and record["owner"] == spec["owner"]
        assert record["scopes"] == ["fleet:read", "seed:write"]
        assert request(path + "/claim", "POST", {}, extra=proof)[0] == 409
        assert request(path, extra=proof)[2]["phase"] == "claimed"
        for file in tmp_path.rglob("*.json"):
            assert key not in file.read_text() and granted["token"] not in file.read_text()


def test_browser_access_cookie_is_private_intake_only_and_requires_same_origin(tmp_path):
    key = "c" * 64
    with http_server(tmp_path) as (server, request):
        public = {"Authorization": ""}
        spec = {"owner": "browser-human", "proof_sha256": auth.hash_token(key)}
        pending = request("/v1/seed-access-requests", "POST", spec, extra=public)[2]
        auth.approve_seed_access(tmp_path, owner=spec["owner"], code=pending["verification_code"])
        code, headers, granted = request("/v1/seed-access-requests/" + pending["request_id"] + "/claim",
                                         "POST", {}, extra={**public, "X-Access-Request-Key": key,
                                                            "X-Access-Delivery": "browser"})
        assert code == 200 and "token" not in granted
        assert all(flag in headers["Set-Cookie"] for flag in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/v1"])
        cookie = {**public, "Cookie": headers["Set-Cookie"].split(";")[0]}
        assert request("/v1/seed-session", extra=cookie)[2]["owner"] == spec["owner"]
        assert request("/v1/instances", extra=cookie)[0] == 401
        assert request("/v1/seed-access", "POST", {"owner": "other"}, extra=cookie)[0] == 401
        assert request("/v1/seeds", extra={**cookie, "Authorization": "Bearer wrong"})[0] == 401
        seed_spec = {"name": "private", "label": "Private", "mode": "new", "soul": "My beginning"}
        write = {**cookie, "Idempotency-Key": KEY}
        for origin in [None, "https://elsewhere.invalid", "http://["]:
            extra = write if origin is None else {**write, "Origin": origin}
            assert request("/v1/seeds", "POST", seed_spec, extra=extra)[0] == 403
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        assert request("/v1/seeds", "POST", seed_spec, extra={**write, "Origin": origin})[0] == 200
        from clusterctl.onboarding_local_body import Requests
        from tests.test_onboarding_local_body import request as local_request, report as local_report
        import dataclasses
        import os
        progress = tmp_path / 'progress'
        progress.mkdir(mode=0o750)
        task = local_request('private', spec['owner'])
        Requests(progress, worker_uid=os.geteuid()).publish(task)
        server.deps = dataclasses.replace(server.deps, onboarding_progress=str(progress),
            onboarding_worker_uid=os.geteuid())
        local_path = '/v1/onboarding/local-body/private'
        assert request(local_path, extra=cookie)[0] == 200
        assert request(local_path, 'POST', local_report(task), extra=cookie)[0] == 403
        assert request(local_path, 'POST', local_report(task), extra={**cookie, 'Origin': origin})[0] == 200
        assert request("/v1/seeds", owner="sai")[2]["items"] == []
        code, headers, result = request("/v1/seed-session", "DELETE", extra={**cookie, "Origin": origin})
        assert code == 200 and result["signed_out"] is True and "Max-Age=0" in headers["Set-Cookie"]
        assert request("/v1/seed-session", extra=cookie)[0] == 401


def test_access_request_bounds_expiry_and_concurrent_claim(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "MAX_ACCESS_REQUESTS", 2)
    key = "d" * 64
    first = auth.request_seed_access(tmp_path, {"owner": "one", "proof_sha256": auth.hash_token(key)})
    auth.request_seed_access(tmp_path, {"owner": "two", "proof_sha256": auth.hash_token("e" * 64)})
    with pytest.raises(seeds.SeedError, match="capacity"):
        auth.request_seed_access(tmp_path, {"owner": "three", "proof_sha256": auth.hash_token("f" * 64)})
    auth.approve_seed_access(tmp_path, owner="one", code=first["verification_code"])
    def claim(_):
        try:
            return auth.claim_seed_access(tmp_path, first["request_id"], key)
        except seeds.SeedError:
            return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(claim, range(8)))
    assert sum(result is not None for result in results) == len(auth.list_tokens(tmp_path)) == 1
    monkeypatch.setattr(auth, "now_ms", lambda: first["expires_ms"] + 1)
    assert auth.seed_access_request_status(tmp_path, first["request_id"], key)["phase"] == "expired"
    with pytest.raises(seeds.SeedError, match="expired"):
        auth.claim_seed_access(tmp_path, first["request_id"], key)
    assert auth.request_seed_access(tmp_path, {"owner": "three", "proof_sha256": auth.hash_token("f" * 64)})["phase"] == "pending"


def test_access_approval_cli_exposes_only_the_confirmed_request_metadata(tmp_path, capsys):
    from clusterd.__main__ import main

    key = "9" * 64
    pending = auth.request_seed_access(tmp_path, {"owner": "ani", "proof_sha256": auth.hash_token(key)})
    args = ["--state-dir", str(tmp_path)]
    assert main([*args, "--access-pending"]) == 0
    listed = capsys.readouterr().out
    assert pending["verification_code"] in listed and key not in listed and "token" not in listed
    assert main([*args, "--access-approve", pending["verification_code"], "--owner", "sai"]) == 2
    capsys.readouterr()
    assert main([*args, "--access-approve", pending["verification_code"], "--owner", "ani"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["phase"] == "approved" and "token" not in result and key not in str(result)


def test_operator_web_access_issuer_cannot_be_used_by_participants(tmp_path):
    with http_server(tmp_path) as (_server, request):
        assert request("/v1/seed-access", "POST", {"owner": "new-human"})[0] == 403
        assert request("/v1/seed-access", "POST", {"owner": "*"}, owner="operator")[0] == 400
        code, headers, issued = request("/v1/seed-access", "POST", {"owner": "new-human"}, owner="operator")
        assert code == 200 and headers["Cache-Control"] == "no-store"
        record, reason = auth.authenticate(auth.TokenStore(tmp_path), issued["token"])
        assert reason is None
        assert record["owner"] == record["actor"] == "new-human"
        assert record["scopes"] == ["fleet:read", "seed:write"]
        assert issued["token"] not in (tmp_path / "auth/tokens.json").read_text()


def test_concurrent_private_access_issuance_keeps_every_token(tmp_path):
    def issue(number):
        return auth.create_token(tmp_path, actor=f"human-{number}", owner=f"human-{number}",
                                 scopes=["fleet:read", "seed:write"], ttl_days=3)
    with ThreadPoolExecutor(max_workers=8) as pool:
        issued = list(pool.map(issue, range(20)))
    store = auth.TokenStore(tmp_path)
    assert len(auth.list_tokens(tmp_path)) == 20
    for record, token in issued:
        assert auth.authenticate(store, token)[0]["token_id"] == record["token_id"]


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
