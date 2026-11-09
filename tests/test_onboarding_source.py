"""Actual signed native Source survives an additive peer ceremony and restart."""
import hashlib
import os
import threading
from pathlib import Path

import pytest
from daimon_matrix import native_egress

from clusterctl import onboarding_peer
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_source import Source
from tests import test_onboarding_group_authorities as group_fixtures
pytest_plugins = ['tests.test_onboarding_peer']
group_source = group_fixtures.group_source


@pytest.mark.parametrize('observe', [False, True])
def test_loaded_source_cli_requires_qualified_startup_before_owner_state(tmp_path, monkeypatch, capsys, observe):
    from clusterctl import onboarding_source
    monkeypatch.setattr(onboarding_source, 'Source', lambda *a, **k:
        pytest.fail('unqualified observation opened owner state'))
    arguments = ['--config', str(tmp_path / 'unread.json'), '--require-loaded']
    if observe:
        arguments.append('--observe')
    assert onboarding_source.main(arguments) == 1
    assert capsys.readouterr().out == '{"error": "native_onboarding_source_refused"}\n'


def test_source_group_construction_does_not_invoke_unrelated_pair_ceremony(tmp_path, monkeypatch):
    root = tmp_path / 'runtime'
    root.mkdir(mode=0o700)
    calls = []
    def unavailable(*args, **kwargs):
        calls.append(True)
        raise OnboardingError('qualified_native_peer_sdk_required')
    monkeypatch.setattr(onboarding_peer, 'native', unavailable)
    source = Source(dict(schema='cluster-onboarding-source/v1', runtime_root=str(root),
        password_file=str(tmp_path / 'unused.unlock'), native_visibility=str(tmp_path / 'unused.json'),
        outputs=str(tmp_path / 'outputs'), applications=[]))
    assert calls == []
    with pytest.raises(OnboardingError, match='qualified_native_peer_sdk_required'):
        source.tool
    assert calls == [True]  # Explicit ceremony still has the exact existing guard.


def test_source_migration_cli_refuses_unqualified_code_before_owner_state(tmp_path, monkeypatch, capsys):
    from clusterctl import onboarding_source
    monkeypatch.setattr(onboarding_source, 'Source', lambda *a, **k:
        pytest.fail('unqualified migration opened owner state'))
    assert onboarding_source.main(['--config', str(tmp_path/'unread.json'),
        '--visibility-migration', '-']) == 1
    assert capsys.readouterr().out == '{"error": "native_onboarding_source_refused"}\n'


@pytest.mark.skipif(native_egress.VISIBILITY_SCHEMA_VERSION < 2,
    reason='Schema1 producer stays pinned; explicit successor qualification runs schema2')
def test_source_migrates_legacy_signed_catalogs_before_ordinary_views(group_source, tmp_path, monkeypatch):
    """Reproduce the original-three failure with real keys and native catalogs."""
    import copy
    import json
    import socket
    import sqlite3
    import time
    from contextlib import closing
    from daimon_matrix.chat_host import application_view
    from daimon_matrix.messaging_config import config_digest
    from daimon_matrix.runtime import RuntimeError as MatrixRuntimeError
    from clusterctl.onboarding_receiving_update import source_bootstrap_group
    from tests.test_onboarding_group_publication import initial_publication
    monkeypatch.setattr(socket, 'create_connection', lambda *_a, **_k:
        pytest.fail('offline catalog migration attempted a transport'))
    owner, group, _journal, initial, _base = initial_publication(group_source, 'source')
    owner.group_publication(initial, authority_closure={})
    identifier = initial['operation_id']
    def submit(step, action, params):
        return owner.group_publication(dict(operation_id=identifier, step=step,
            action=action, params=params), authority_closure={})
    destination = dict(bot_id=1, chat_id=-123, topic_id=None, representation='plain-json/v2')
    disclosure = submit('disclosure', 'visibility-disclosure', dict(
        approved_destination=destination, issued_at_ms=time.time_ns()//1_000_000))['disclosure']
    accepted = submit('accept', 'visibility-accept', dict(approved_destination=destination,
        disclosures=[disclosure]))['bindings'][0]['binding']
    visibility = group/'visibility'
    visibility.mkdir(mode=0o700)
    token, proof = b'1:SYNTHETIC_NOT_A_TOKEN', os.urandom(32)
    for name, raw in (('telegram.token', token), ('proof.key', proof)):
        path = visibility/name
        path.write_bytes(raw)
        path.chmod(0o600)
    submit('visibility', 'visibility-publish', dict(disclosure=disclosure, bindings=[accepted],
        expected_installation_sha256=None, initial_configuration=dict(destination=destination,
            secrets=dict(telegram_token_file='telegram.token',
                telegram_token_sha256=hashlib.sha256(token).hexdigest(), proof_key_file='proof.key'),
            telegram_qualification=dict(schema='dm.messaging.telegram-qualification/v1',
                qualified_at_ms=disclosure['issued_at_ms'], token_sha256=hashlib.sha256(token).hexdigest(),
                get_me_bot_id=1, probe_chat_id=-123, probe_topic_id=None,
                probe_message_id=1, probe_text_sha256='b'*64))))
    submit('select', 'selection', dict(expected_selection_sha256=None))
    target = group_source[1]
    owner.settings['native_visibility'] = str(signed_visibility(target, tmp_path/'base-visibility'))
    owner.visibility = Path(owner.settings['native_visibility'])
    bundle = target.document_bundle()
    frozen = source_bootstrap_group(owner, bundle)
    installation = json.loads((visibility/'installation.json').read_bytes())
    selected = {key: frozen[key] for key in ('selected', 'application_sha256',
        'publication_sha256', 'installation_sha256')}
    selected.update(outbound_release=True, policy_sha256=config_digest(installation['document']['policy']))
    request = dict(operation_id='eea1992e-b6a0-457d-9ef7-4ed7e71446c7',
        runtime_sha256=digest(bundle), origin=bundle['local_origin'], group=selected)
    original = {p:p.read_bytes() for p in (owner.root/'runtime.json', owner.root/'custody.json',
        owner.visibility, owner.visibility.parent/'proof.key', visibility/'installation.json', visibility/'proof.key')}
    hosted = owner._load(signed=True, catalog_mode='migrate')
    view = application_view(hosted, group/'application', visibility/'installation.json', catalog_mode='migrate')
    catalogs = {c.path for controller in (hosted.egress, view.egress) for c in controller._catalogs.values()}
    retained = {}
    for path in catalogs:
        with closing(sqlite3.connect(path)) as db, db:
            retained[path] = list(db.execute('SELECT operation_id,record FROM echo_v2_obligations'))
            db.execute('DROP INDEX mandatory_egress_pending')
            db.execute('ALTER TABLE mandatory_egress_operations RENAME TO migration_fixture')
            db.execute(native_egress.LEGACY_OPERATION_TABLE_SQL)
            columns = ','.join(r[1] for r in db.execute('PRAGMA table_info(mandatory_egress_operations)'))
            db.execute(f'INSERT INTO mandatory_egress_operations({columns}) SELECT {columns} FROM migration_fixture')
            db.execute('DROP TABLE migration_fixture')
    with pytest.raises((MatrixRuntimeError, native_egress.NativeEgressError)):
        owner.views()
    another = Source(dict(owner.settings), code=owner.code, code_uid=owner.code_uid)
    with owner.writer(), pytest.raises(BlockingIOError):
        another.migrate_visibility(request, deadline_ns=time.monotonic_ns()+10_000_000_000)
    changed = copy.deepcopy(request)
    changed['group']['publication_sha256'] = 'f'*64
    with monkeypatch.context() as guard:
        guard.setattr(owner, '_reader', lambda: pytest.fail('wrong group opened custody'))
        with pytest.raises(OnboardingError, match='migration_binding_changed'):
            owner.migrate_visibility(changed, deadline_ns=time.monotonic_ns()+10_000_000_000)
    result = owner.migrate_visibility(request, deadline_ns=time.monotonic_ns()+30_000_000_000)
    assert result['catalog_schema_version'] == 2 and result['group'] == selected
    assert owner.migrate_visibility(request, deadline_ns=time.monotonic_ns()+30_000_000_000) == result
    assert len(owner.views()) == 2
    assert {p:p.read_bytes() for p in original} == original
    for path in catalogs:
        with closing(sqlite3.connect(path)) as db:
            assert list(db.execute('SELECT operation_id,record FROM echo_v2_obligations')) == retained[path]
            assert 'retirement_json' in {r[1] for r in db.execute('PRAGMA table_info(mandatory_egress_operations)')}


def signed_visibility(target, directory):
    from daimon_matrix import canonical, daemon, native_egress, runtime
    from daimon_matrix.messaging_config import config_digest, create_binding
    import time
    def clock():
        return time.time_ns() // 1_000_000
    body = onboarding_peer.loaded(target)
    being = target.document_bundle()['manifest']['being_ref']
    scope = dict(mode='all-inter-daimon-communications', channels=[dict(
        channel_id='runtime-control-only', direction='outgoing', local_being_ref=being,
        peer_being_ref=being, bootstrap_policy={}, relationship_disclosure={})],
        projected_content='complete-plaintext-content-and-metadata')
    destination = dict(bot_id=123, chat_id=-100123, topic_id=None, representation='plain-json/v2')
    disclosure = dict(schema='dm.messaging.visibility-disclosure/v1', issued_at_ms=clock(),
        destination=destination, scope=scope, scope_sha256=config_digest(scope), participants=[being],
        risk='all-inter-daimon-communication-will-be-posted-as-plaintext-to-the-fixed-telegram-destination')
    acceptance = dict(schema='dm.messaging.visibility-acceptance-set/v1', disclosure_sha256=config_digest(disclosure),
        bindings=[create_binding(body, disclosure)])
    token = b'123:disposable-source-test-only'
    proof = os.urandom(32)
    directory.mkdir(mode=0o700)
    for name, raw in (('telegram.token', token), ('proof.key', proof)):
        (directory / name).write_bytes(raw)
        (directory / name).chmod(0o600)
    document = dict(schema='dm.messaging.visibility-installation/v1', generation=1,
        runtime_id=target.document_bundle()['runtime_id'], application_sha256=config_digest(target.document_bundle()),
        disclosure=disclosure, acceptance_set=acceptance,
        policy=dict(schema='daimon-visibility-policy/v2', generation=1, origin='owner-signed-installation',
            **destination, acceptance_digest=config_digest(acceptance), proof_key_id='sha256:' + hashlib.sha256(proof).hexdigest()),
        secrets=dict(telegram_token_file='telegram.token', telegram_token_sha256=hashlib.sha256(token).hexdigest(),
            proof_key_file='proof.key'),
        telegram_qualification=dict(schema='dm.messaging.telegram-qualification/v1', qualified_at_ms=clock(),
            token_sha256=hashlib.sha256(token).hexdigest(), get_me_bot_id=123, probe_chat_id=-100123,
            probe_topic_id=None, probe_message_id=1, probe_text_sha256='b' * 64))
    path = directory / 'installation.json'
    path.write_bytes(canonical.canonical_bytes(dict(document=document, binding=create_binding(body, document))))
    path.chmod(0o600)
    adopted = runtime.load_runtime(target.package / 'runtime', 'runtime.json', target._reader, clock=clock,
        egress_factory=daemon._visibility_factory(path, clock=clock, catalog_mode='migrate'))
    adopted.egress.adopt_closed_visibility_catalogs(version=native_egress.VISIBILITY_SCHEMA_VERSION)
    return path


def prepare(journey, tmp_path, *, semantic_receipts=False):
    tool, sources, public, _, payload = journey
    target = sources[0][1]
    visibility = signed_visibility(target, tmp_path / 'native-visibility')
    source = Source(dict(schema='cluster-onboarding-source/v1', runtime_root=str(target.package / 'runtime'),
        password_file=str(target.root / 'body.unlock'), native_visibility=str(visibility),
        outputs=str(target.home / 'source-output'), applications=[]), code=target.code, code_uid=target.code_uid)
    if semantic_receipts:
        source._load(signed=True).service.communication.upgrade_receipts_v2()
    original = tool.read_public(visibility)
    fingerprint = digest(target.plan)
    packet = source.offer(fingerprint, public[1], payload['plan']['endpoints'])
    response = onboarding_peer.accept(sources[1][1], packet,
        expected_being=public[0]['document']['authority']['manifest']['being_ref'])
    return source, sources[1][1], fingerprint, response, original


def test_source_load_connects_the_parent_body_reader_to_actual_scope(journey, tmp_path):
    import json
    import time
    from daimon_matrix.canonical import canonical_bytes
    source, *_ = prepare(journey, tmp_path)
    bundle_path = source.root / 'runtime.json'
    bundle = json.loads(bundle_path.read_text())
    bundle['scopes'] = {'body_capabilities': [], 'relationships_filename': None}
    bundle_path.write_bytes(canonical_bytes(bundle))
    calls = []
    def reader(body_ref, embodiment_id, incarnation_id, evaluated_at_ms):
        calls.append((body_ref, embodiment_id, incarnation_id))
        return dict(schema='dm.cluster-body-snapshot/v1', body_ref=body_ref,
            embodiment_id=embodiment_id, incarnation_id=incarnation_id,
            observed_at_ms=evaluated_at_ms, state='running', resource_fences=[])
    source.body_reader = reader
    hosted = source._load(signed=False)
    identity = hosted.service.scopes.identity()
    assert identity['body']['state'] == 'running'
    assert identity['body_capabilities'] == []
    origin = bundle['local_origin']
    assert calls == [(origin['body_ref'], origin['embodiment_id'], origin['incarnation_id'])]
    assert identity['evaluated_at_ms'] <= time.time_ns() // 1_000_000


def assert_original(source, original):
    current = source.tool.read_public(source.visibility)
    for field in ('disclosure', 'secrets', 'telegram_qualification'):
        assert current['document'][field] == original['document'][field]
    source._load(signed=True).egress.validate_registered_catalogs()


@pytest.mark.parametrize('semantic_receipts', [False, True])
def test_signed_source_retains_native_client_and_peer_under_one_lock(journey, tmp_path, semantic_receipts):
    from daimon_matrix.client import ClientConfig, LocalClient
    source, target, fingerprint, response, original = prepare(journey, tmp_path, semantic_receipts=semantic_receipts)
    custody = (source.root / 'custody.json').read_bytes()
    ready = source.finish(fingerprint, response)
    assert source.finish(fingerprint, response) == ready
    packet = source.tool.read_public(source.directory(fingerprint) / 'offer.json')
    assert source.offer(fingerprint, journey[2][1], journey[4]['plan']['endpoints']) == packet
    assert (source.root / 'custody.json').read_bytes() == custody
    assert_original(source, original)
    assert source._load(signed=True).service.communication.receipts_v2 is semantic_receipts
    from clusterctl import being_seed
    config = source.outputs / 'config.json'
    being_seed._write(config, source.settings)
    unit = source.outputs / 'daimon-matrix-native.service'
    original_unit = b'[Service]\nWorkingDirectory=existing\nLoadCredential=matrix-password:existing\nExecStart=existing\nRestart=on-failure\n'
    unit.write_bytes(original_unit)
    unit.chmod(0o600)
    unit_digest = hashlib.sha256(original_unit).hexdigest()
    import sys
    from pathlib import Path
    import shutil
    # The actual host entry point includes Source, unlike receiving-only code.
    checkout = Path(__file__).resolve().parents[1]
    source.code = tmp_path / 'qualified-host-previous'
    (source.code / 'clusterctl').mkdir(parents=True)
    for filename in ('onboarding_peer.py', 'onboarding_peer_native.py', 'onboarding_source.py'):
        captured = source.code / 'clusterctl' / filename
        shutil.copyfile(checkout / 'clusterctl' / filename, captured)
        captured.chmod(0o644)
    old_tool = source.code / 'clusterctl/onboarding_peer_native.py'
    old_tool.write_bytes(old_tool.read_bytes() + b'\n# Retained previous host generation.\n')
    old_adapter = source.code / 'clusterctl/onboarding_peer.py'
    old_adapter.write_text(old_adapter.read_text().replace(onboarding_peer.TOOL_SHA256,
        hashlib.sha256(old_tool.read_bytes()).hexdigest()))
    source.register(config, unit, unit_digest, target.code / sys.executable, fingerprint)
    source.register(config, unit, unit_digest, target.code / sys.executable, fingerprint)
    successor = tmp_path / 'qualified-host-successor'
    (successor / 'clusterctl').mkdir(parents=True)
    for filename in ('onboarding_peer.py', 'onboarding_peer_native.py', 'onboarding_source.py'):
        shutil.copyfile(checkout / 'clusterctl' / filename, successor / 'clusterctl' / filename)
        (successor / 'clusterctl' / filename).chmod(0o644)
    source.code = successor
    source.register(config, unit, unit_digest, target.code / sys.executable, fingerprint)
    source.register(config, unit, unit_digest, target.code / sys.executable, fingerprint)
    selected_unit = unit.read_bytes()
    assert str(successor).encode() in selected_unit
    foreign = selected_unit.replace(b'WorkingDirectory=existing', b'WorkingDirectory=foreign')
    unit.write_bytes(foreign)
    from clusterctl.onboarding import OnboardingError
    with pytest.raises(OnboardingError, match='existing_onboarding_source_service_preserved'):
        source.register(config, unit, unit_digest, target.code / sys.executable, fingerprint)
    assert unit.read_bytes() == foreign
    unit.write_bytes(selected_unit)
    assert source.settings['applications'] == [fingerprint]
    assert (source.outputs / ('native-unit-' + unit_digest)).read_bytes() == original_unit
    assert b'LoadCredential=matrix-password:existing\n' in unit.read_bytes()
    native = ClientConfig.load(source.root / 'client.json', bytearray((source.root / 'client.key').read_bytes()))
    application = source.directory(fingerprint) / 'application'
    peer = ClientConfig.load(application / 'client.json', bytearray((application / 'client.key').read_bytes()))
    # Restart proves both authenticated surfaces retain their original identity;
    # no inbox, Telegram API or external transport is exercised by this check.
    for _ in range(2):
        stop = threading.Event()
        reader, writer = os.pipe()
        errors = []
        def run():
            try:
                source.serve(stop, ready_descriptor=writer)
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=run)
        thread.start()
        try:
            import select
            assert select.select([reader], [], [], 8)[0]
            assert os.read(reader, 16) == b'READY\n'
            assert LocalClient(source.root / 'matrix.sock', native).runtime_status()[1]['ok']
            # Capability authentication is checked by the local hello itself.
            client = LocalClient(source.outputs / ('peer-' + fingerprint[:12] + '.sock'), peer)
            # An invalid send reaches the authenticated peer dispatcher but
            # cannot create or deliver a message.
            assert client.invoke('messaging.send', {})[1]['error']['code'] == 'invalid_params'
            observed = source.observe()
            assert observed['running'] is True
            assert observed['applications'] == [fingerprint]
            assert observed['receiving_readiness'] == 'unobserved'
            assert observed['base_runtime_status']['local_origin'] == native.expected_server
            connected = 'connection_observer' in getattr(LocalClient, '__dataclass_fields__', {})
            assert observed['responder_association'] == ('same-connection' if connected else 'legacy-probe')
            if connected:
                assert observed['process']['pid'] == os.getpid()
            with pytest.raises(OnboardingError, match='qualified_onboarding_(?:client|group)_required'):
                source.observe(require_loaded=True)
        finally:
            stop.set()
            thread.join(timeout=10)
            os.close(reader)
        assert not thread.is_alive() and errors == []
    assert_original(source, original)


def test_lost_source_ack_after_publication_keeps_native_daemon_restartable(journey, tmp_path):
    source, _, fingerprint, response, original = prepare(journey, tmp_path)
    replace = source.tool.replace_document
    failures = []
    def interrupted(path, value):
        replace(path, value)
        if not failures:
            failures.append(True)
            raise OSError('lost source publication ACK')
    source.tool.replace_document = interrupted
    with pytest.raises(OSError, match='lost source publication ACK'):
        source.finish(fingerprint, response)
    assert_original(source, original)
    source.tool.replace_document = replace
    source.finish(fingerprint, response)
    assert_original(source, original)
