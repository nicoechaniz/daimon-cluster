"""Receiving continuity, native routing, retry and full-row preservation."""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tomllib
from contextlib import closing
from pathlib import Path

import pytest

from clusterctl import being_seed, onboarding_guest, onboarding_input, onboarding_release
from clusterctl.onboarding import OnboardingError
from tests.test_onboarding import plan
from tests import test_onboarding_input as input_fixtures

packet = input_fixtures.packet
staging_volume = input_fixtures.staging_volume
prepared = input_fixtures.prepared

ROOT = Path(__file__).resolve().parents[1]
NATIVE = '''import json, os, sqlite3, sys
from pathlib import Path
path = os.environ['HMK_DB_PATH']
db = sqlite3.connect(path)
db.row_factory = sqlite3.Row
if sys.argv[1] == 'stats':
    assert list(Path(os.environ['HMK_HERMES_HOME']).joinpath('backups').glob('*.db'))
    columns = {r[1] for r in db.execute('PRAGMA table_info(chapters)')}
    if 'migrated' not in columns:
        db.execute('ALTER TABLE chapters ADD COLUMN migrated INTEGER DEFAULT 1')
    db.commit()
    value = {'db_path': path, 'chapters': db.execute('SELECT count(*) FROM chapters').fetchone()[0]}
else:
    value = dict(db.execute('SELECT * FROM chapters WHERE id=?', (int(sys.argv[-1]),)).fetchone())
    db.execute('UPDATE chapters SET access_count=access_count+1 WHERE id=?', (int(sys.argv[-1]),))
    db.commit()
db.close()
print(json.dumps(value))
'''


def artifact(root, script=NATIVE):
    root.mkdir(mode=0o755)
    for path in (ROOT / 'support/being-seed-tools').rglob('*'):
        if path.is_file() and '__pycache__' not in path.parts:
            target = root / path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    scripts = root / 'hmk/scripts'
    scripts.mkdir(parents=True)
    (scripts / 'memoryctl.py').write_text(script)
    (scripts / 'native_records.py').write_text('# Synthetic contract fixture.\n')
    skill = root / 'skills/listening'
    skill.mkdir(parents=True)
    (skill / 'SKILL.md').write_text('---\nname: listening\n---\nApproved shared behavior.\n')
    (root / 'inheritance.md').write_bytes((ROOT / 'support/source-inheritance.md').read_bytes())
    profile = dict(schema=onboarding_release.PROFILE, model='gpt-6.1', reasoning='medium',
                   approval='never', sandbox='danger-full-access', skills=['listening'], primary_store='store-001')
    for path in root.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)
    return onboarding_release.seal(root, profile)


def receiving(tmp_path, packet, script=NATIVE):
    source, destination = prepared(tmp_path, packet)
    with closing(sqlite3.connect(source / 'memory/store-001/library.db')) as db:
        db.execute('ALTER TABLE chapters ADD COLUMN title TEXT')
        db.execute('ALTER TABLE chapters ADD COLUMN raw TEXT')
        db.execute('ALTER TABLE chapters ADD COLUMN access_count INTEGER DEFAULT 0')
        db.execute("UPDATE chapters SET title='Old memory',raw=text")
        db.execute("INSERT INTO chapters VALUES(2,'Recent encounter','Recent memory','Recent encounter',0)")
        db.execute('CREATE TABLE old_query_history(id INTEGER PRIMARY KEY, query TEXT)')
        db.execute("INSERT INTO old_query_history VALUES(1,'Private original history')")
        db.commit()
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    frozen = home / 'incoming'
    captured = onboarding_input.capture(source, frozen, source_uid=os.geteuid())
    code = tmp_path / 'code'
    fingerprint = artifact(code, script)
    value = {**plan(name='fixture', owner='ani'), 'seed_digest': captured['seed_digest'], 'release_digest': fingerprint}
    receiver = onboarding_guest.Receiver(home, frozen, code, value, code_uid=os.geteuid())
    return receiver


@pytest.mark.parametrize('lost_ack', [None, 'quarantine', 'publication'])
def test_torn_input_copy_recovers_without_losing_interrupted_bytes(tmp_path, packet, monkeypatch, lost_ack):
    receiver = receiving(tmp_path, packet)
    receiver._copy_input()
    target = receiver.received / 'source.archive'
    original = target.read_bytes()
    partial = original[:len(original) // 2]
    target.write_bytes(partial)
    original_rename = os.rename
    disconnected = False

    def rename(source, destination):
        nonlocal disconnected
        result = original_rename(source, destination)
        boundary = 'quarantine' if Path(destination).name == 'interrupted' else 'publication'
        if not disconnected and lost_ack == boundary:
            disconnected = True
            raise RuntimeError('fixture lost acknowledgement')
        return result

    with monkeypatch.context() as patch:
        patch.setattr(os, 'rename', rename)
        if lost_ack:
            with pytest.raises(RuntimeError, match='lost acknowledgement'):
                onboarding_guest.reconcile_context_copy(receiver.home, receiver.incoming, receiver.plan)
        else:
            onboarding_guest.reconcile_context_copy(receiver.home, receiver.incoming, receiver.plan)
    receiver.install_context()
    assert receiver.observe_context().state == 'complete'
    assert target.read_bytes() == original
    assert [p.read_bytes() for p in (receiver.state / 'copy-recovery').glob('*/interrupted')] == [partial]
    receiver.verify_memory()
    # Context activation ends copy recovery; real subsequent memory writes stay.
    with closing(sqlite3.connect(receiver.received / 'memory/store-001/library.db')) as database:
        database.execute("INSERT INTO old_query_history VALUES(2,'New receiving history')")
        database.commit()
    onboarding_guest.reconcile_context_copy(receiver.home, receiver.incoming, receiver.plan)
    with closing(receiver._database('store-001')) as database:
        assert database.execute('SELECT COUNT(*) FROM old_query_history').fetchone()[0] == 2


@pytest.mark.parametrize('foreign', ['different-prefix', 'longer', 'symlink', 'owner', 'wrong-plan'])
def test_copy_recovery_preserves_files_without_exact_prefix_and_owner_binding(tmp_path, packet, monkeypatch, foreign):
    receiver = receiving(tmp_path, packet)
    receiver._copy_input()
    target = receiver.received / 'source.archive'
    original = target.read_bytes()
    target.write_bytes(b'X' + original[1:len(original) // 2] if foreign == 'different-prefix'
                       else original + b'extra' if foreign == 'longer' else original[:len(original) // 2])
    value = dict(receiver.plan)
    if foreign == 'symlink':
        elsewhere = receiver.home / 'unrelated-original'
        target.rename(elsewhere)
        target.symlink_to(elsewhere)
    elif foreign == 'owner':
        monkeypatch.setattr(os, 'geteuid', lambda: os.getuid() + 1)
    elif foreign == 'wrong-plan':
        value['seed_digest'] = 'f' * 64
    before = target.read_bytes()
    with pytest.raises(ValueError, match='existing_receiving_file_preserved'):
        onboarding_guest.reconcile_context_copy(receiver.home, receiver.incoming, value)
    assert target.read_bytes() == before
    assert not list((receiver.state / 'copy-recovery').glob('*/interrupted'))


def test_installs_own_soul_selected_inheritance_and_native_manual_memory_without_touching_auth_history(tmp_path, packet):
    receiver = receiving(tmp_path, packet)
    codex = receiver.home / '.codex'
    codex.mkdir(mode=0o700)
    onboarding_guest.new_bytes(codex / 'auth.json', b'private account fixture')
    onboarding_guest.new_bytes(codex / 'history.jsonl', b'own native history')
    onboarding_guest.new_bytes(codex / 'config.toml', b'[shell_environment_policy]\ninherit="core"\n')
    receiver.install_context()
    agents = (codex / 'AGENTS.md').read_text()
    assert (receiver.incoming / 'received/context/SOUL.md').read_text() in agents
    assert '/me.inherits Source' in agents
    assert 'human request' in agents
    assert tomllib.loads((codex / 'config.toml').read_text())['shell_environment_policy']['inherit'] == 'core'
    assert (codex / 'auth.json').read_bytes() == b'private account fixture'
    assert (codex / 'history.jsonl').read_bytes() == b'own native history'
    assert receiver.observe_context().state == 'complete'
    assert not list(receiver.code.rglob('__pycache__'))
    original = onboarding_input.inventory(receiver.incoming / 'received', uid=os.geteuid())
    receiver.verify_memory()
    assert receiver.observe_memory().facts['memory_chapters'] == 2
    assert original == onboarding_input.inventory(receiver.incoming / 'received', uid=os.geteuid())
    assert not list(receiver.code.rglob('__pycache__'))
    for backup in (receiver.state / 'backups').glob('*.db'):
        with closing(sqlite3.connect(backup)) as db:
            assert 'migrated' not in {r[1] for r in db.execute('PRAGMA table_info(chapters)')}
            assert db.execute('SELECT SUM(access_count) FROM chapters').fetchone()[0] == 0
    # The wrapper wins over inherited Source/machine bindings.
    environment = dict(os.environ, HMK_DB_PATH='/unrelated/private-source.db', HMK_ENV_FILE='/unrelated/private.env')
    result = subprocess.run([sys.executable, '-B', str(receiver.state / 'hmk-store-001.py'), 'memoryctl.py', 'stats'],
                            env=environment, capture_output=True, check=True)
    assert json.loads(result.stdout)['db_path'] == str(receiver.received / 'memory/store-001/library.db')
    with closing(receiver._database('store-001')) as db:
        assert db.execute('SELECT query FROM old_query_history').fetchone()[0] == 'Private original history'


def test_partial_context_retry_and_new_receiving_memories_survive(tmp_path, packet, monkeypatch):
    receiver = receiving(tmp_path, packet)
    original = onboarding_guest.new_bytes
    failed = False
    def disconnect(path, raw, **kwargs):
        nonlocal failed
        if path.name == 'INHERITANCE.md' and not failed:
            failed = True
            raise RuntimeError('fixture transport disconnect')
        return original(path, raw, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(onboarding_guest, 'new_bytes', disconnect)
        with pytest.raises(RuntimeError):
            receiver.install_context()
    assert receiver.observe_context().state == 'absent'
    receiver.install_context()
    receiver.verify_memory()
    with closing(sqlite3.connect(receiver.received / 'memory/store-001/library.db')) as db:
        db.execute("INSERT INTO chapters VALUES(3,'New work','New memory','New work',0,1)")
        db.commit()
    receiver.install_context()
    receiver.verify_memory()
    assert receiver.observe_memory().facts['memory_chapters'] == 3
    (receiver.home / '.codex/AGENTS.md').write_text('Human changed instructions')
    assert receiver.observe_context().state == 'conflict'
    with pytest.raises(OnboardingError, match='existing_receiving_file_preserved'):
        # Never rewrite new receiving instructions to recover automatically.
        receiver.install_context()
    assert (receiver.home / '.codex/AGENTS.md').read_text() == 'Human changed instructions'


def test_native_upgrade_cannot_erase_other_history_or_claim_memory_ready(tmp_path, packet):
    destructive = NATIVE.replace('    db.commit()\n    value', "    db.execute('DELETE FROM old_query_history')\n    db.commit()\n    value", 1)
    receiver = receiving(tmp_path, packet, destructive)
    receiver.install_context()
    with pytest.raises(OnboardingError, match='original_rows_changed'):
        receiver.verify_memory()
    assert not (receiver.state / 'memory.json').exists()
    with closing(sqlite3.connect(receiver.state / 'backups/store-001.db')) as db:
        assert db.execute('SELECT COUNT(*) FROM old_query_history').fetchone()[0] == 1


def test_failed_snapshot_is_unpublished_and_retry_takes_a_complete_snapshot(tmp_path, packet, monkeypatch):
    receiver = receiving(tmp_path, packet)
    receiver.install_context()
    original_link = os.link
    def interrupted(source, destination, **kwargs):
        if str(source).endswith('.partial'):
            raise OSError('Interrupted before snapshot publication')
        return original_link(source, destination, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(os, 'link', interrupted)
        with pytest.raises(OSError):
            receiver.verify_memory()
    assert not (receiver.state / 'backups/store-001.db').exists()
    assert list((receiver.state / 'backups').glob('*.partial'))
    receiver.verify_memory()
    assert receiver.observe_memory().state == 'complete'


def test_release_integrity_owner_modes_links_and_private_cli_refusal(tmp_path, packet, capsys):
    receiver = receiving(tmp_path, packet)
    receiver.code.chmod(0o777)
    with pytest.raises(OnboardingError, match='trusted_receiving_code'):
        onboarding_release.verify(receiver.code, receiver.plan['release_digest'], uid=os.geteuid())
    receiver.code.chmod(0o755)
    target = receiver.code / 'hmk/scripts/native_records.py'
    target.unlink()
    target.symlink_to(receiver.code / 'hmk/scripts/memoryctl.py')
    with pytest.raises(being_seed.SeedError, match='symlink'):
        onboarding_release.verify(receiver.code, receiver.plan['release_digest'], uid=os.geteuid())
    job = tmp_path / 'plan.json'
    being_seed._write(job, receiver.plan)
    assert onboarding_guest.main(['execute', 'context', '--home', str(receiver.home), '--input', str(receiver.incoming),
                                  '--code', str(receiver.code), '--plan', str(job)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report == dict(state='conflict', facts={}, reason='verification_failed', safe_to_execute=False)
    assert not (receiver.state / 'context.json').exists()


def test_snapshot_publication_before_disconnect_reconciles_the_known_link(tmp_path, packet, monkeypatch):
    receiver = receiving(tmp_path, packet)
    receiver.install_context()
    original_link = os.link
    def disconnect(source, destination, **kwargs):
        original_link(source, destination, **kwargs)
        raise OSError('Lost response after snapshot publication')
    with monkeypatch.context() as patch:
        patch.setattr(os, 'link', disconnect)
        with pytest.raises(OSError):
            receiver.verify_memory()
    backup = receiver.state / 'backups/store-001.db'
    assert backup.stat().st_nlink == 2
    receiver.verify_memory()
    assert backup.stat().st_nlink == 1
    assert receiver.observe_memory().state == 'complete'
