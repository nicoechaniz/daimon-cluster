"""Composed owning APIs: exact source modules explicitly supplied by qualification."""
from __future__ import annotations

import base64
import copy
from dataclasses import replace
from contextlib import closing
from types import SimpleNamespace
import importlib.util
import hashlib
import json
import os
import signal
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import pytest

from clusterctl.behavior_delta import BehaviorConflict, BehaviorDelta
from clusterctl.operation_journal import OperationJournal
from clusterctl.same_being_integration import (
    IntegrationConflict, NativeMemory, SameBeingIntegration, SelectedSkills,
)

MATRIX_SOURCE = os.environ.get('SAME_BEING_MATRIX_SOURCE')
DMK_SCRIPTS = os.environ.get('SAME_BEING_DMK_SCRIPTS')
SKILLS_SCRIPT = os.environ.get('SAME_BEING_SKILLS_SCRIPT')
pytestmark = pytest.mark.skipif(not all((MATRIX_SOURCE, DMK_SCRIPTS, SKILLS_SCRIPT)),
                               reason='explicit qualified owning sources required')


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


@pytest.fixture
def composed(tmp_path, monkeypatch, request):
    tmp_path.chmod(0o700)
    sys.path.insert(0, str(Path(MATRIX_SOURCE) / 'src'))
    sys.path.insert(0, str(Path(MATRIX_SOURCE)))
    sys.path.insert(0, str(Path(DMK_SCRIPTS)))
    from daimon_matrix import cluster
    from daimon_matrix.local_api import create_capability, create_request, verify_response, request_hash
    from daimon_matrix.service import HostedWeave, METHODS
    module('tools.generate_dm022_vectors', Path(MATRIX_SOURCE) / 'tools/generate_dm022_vectors.py')
    from tests import test_dm022_ledger as ledger_fixture
    NOW = time.time_ns() // 1_000_000
    monkeypatch.setattr(ledger_fixture, 'NOW', NOW)
    fixture = ledger_fixture.RootLedgerFixture()
    fixture.setUp()
    request.addfinalizer(fixture.tearDown)
    sync = module('qualified_sync', Path(DMK_SCRIPTS) / 'same_being_sync.py')
    backup = module('qualified_backup', Path(DMK_SCRIPTS) / 'backupctl.py')
    installer = module('qualified_skills', SKILLS_SCRIPT)
    memories = []
    for label in ('source', 'receiver'):
        base = tmp_path / label
        base.mkdir(mode=0o700)
        monkeypatch.setenv('HMK_AGENT_MEMORY_BASE', str(base))
        monkeypatch.setenv('HMK_DB_PATH', str(base / 'library.db'))
        memory = module('qualified_memory_' + label, Path(DMK_SCRIPTS) / 'memoryctl.py')
        memory.init_db()
        memories.append(memory)
    source, memory = memories
    source.add_text('library', 'Useful attributed original', 'Preserved original memory and its source.')
    owner = dict(fixture.origins['daimonmatrix'], being_ref=fixture.state.being_ref)
    source_owner = dict(fixture.origins['legion'], being_ref=fixture.state.being_ref)
    memory_owner = {k: owner[k] for k in ('being_ref', 'body_ref', 'embodiment_id', 'incarnation_id')}
    memory_owner['pool_lineage'] = 'qualified-receiver'
    incoming_owner = {k: source_owner[k] for k in memory_owner if k != 'pool_lineage'}
    incoming_owner['pool_lineage'] = 'qualified-source'
    packet = sync.export(source.DB_PATH, incoming_owner)
    repo = tmp_path / 'skills-source'
    repo.mkdir(mode=0o700)
    def git(*args):
        return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL).decode().strip()
    git('init')
    git('config', 'user.name', 'Synthetic qualifier')
    git('config', 'user.email', 'qualifier@example.invalid')
    git('remote', 'add', 'origin', 'https://github.com/AlterMundi/Skills.git')
    package = repo / 'skills' / 'useful-example'
    package.mkdir(parents=True)
    (package / 'SKILL.md').write_text('---\nname: useful-example\ndescription: Qualified selective behavior\n---\nUse the retained native workflow.\n')
    (package / 'package.json').write_text(json.dumps(dict(schema='altermundi.skill-package/v1',
        name='useful-example', version='1.0.0', auxiliary_skills=[])))
    git('add', '.')
    git('commit', '-m', 'Synthetic exact skill')
    descriptor = installer.describe(repo, git('rev-parse', 'HEAD'), ['useful-example'])
    skills_root, skills_state = tmp_path / 'skills-live', tmp_path / 'skills-state'
    skills_root.mkdir(mode=0o700)
    plan = installer.prepare(repo, descriptor, skills_root, skills_state)
    instructions = tmp_path / 'AGENTS.md'
    instructions.write_text('Original local instructions.\n')
    behavior_hash = sync.digest({'instruction': 'Use the retained native workflow.'})
    event = fixture.ledger_a.append_local(kind='configuration.proposed', subject='same-being:qualified',
        payload={'content_refs': [sync.digest(packet), installer.digest(descriptor), behavior_hash]},
        signer=fixture.signers['legion'], sensitivity='private')
    fixture.ledger_b.ingest([event], source='qualified-native-sync')
    capability = create_capability(hashlib.sha256(b'qualified-local-fixture-key').digest(), client_id='client:qualified',
                                  methods=sorted(METHODS), not_before_ms=NOW-1000, not_after_ms=NOW+1000)
    hosted = HostedWeave(fixture.ledger_b, fixture.signers['daimonmatrix'],
        {capability.capability_id: capability}, lambda: NOW,
        'dm:runtime:v1:' + 'q' * 43, 'qualification')
    class Matrix:
        clock = staticmethod(lambda: NOW)
        def __init__(self):
            self.requests = []
            self.service = hosted
            self.config = SimpleNamespace(capability=capability)
        def prepare(self, method, params, *, request_id=None):
            # Real authenticated protocol. Unknown receipt method remains a
            # demonstrated missing source bridge, never synthetic completion.
            return create_request(capability, request_id=request_id or str(uuid.uuid4()),
                issued_at_ms=NOW, method=method, params=params, nonce=os.urandom(16))
        def send(self, request):
            self.requests.append(copy.deepcopy(request))
            value = self.service.handle(request)
            return verify_response(value, capability, expected_request_id=request['request_id'],
                expected_request_hash=request_hash(request), expected_server=self.service.origin,
                expected_runtime=self.service.runtime_identity)
        def invoke(self, method, params):
            request = self.prepare(method, params)
            return request, self.send(request)
    client = Matrix()
    backup_config = {'database': str(memory.DB_PATH), 'snapshots': dict(
        directory=str(tmp_path / 'snapshots'), retention_scope='database',
        max_count=3, max_bytes=16*1024*1024, min_free_bytes=1, keep_latest=2, pins=[])}
    journal = OperationJournal(tmp_path / 'journal')
    behavior = BehaviorDelta(journal, owner)
    integration = SameBeingIntegration(journal, owner, client, cluster,
        memory=NativeMemory(memory, sync, backup, memory_owner, backup_config),
        skills=SelectedSkills(installer, repo, skills_root, skills_state), behavior=behavior)
    client.service = replace(hosted, projection_observer=integration.observe_effect)
    selection = dict(source_event_id=event['event_id'], reason='Integrate this selected attributed delta',
        packets=[packet], skill_plan=plan,
        behavior_selection=dict(source=source_owner, source_refs=[behavior_hash],
            files={str(instructions): base64.b64encode(b'Use the retained native workflow.\n').decode()}),
        behavior_sources={behavior_hash: base64.b64encode(sync.wire({'instruction': 'Use the retained native workflow.'})).decode()},
        residual=['Actual harness consumption remains unverified'])
    yield integration, selection, memory, instructions, client, sync, source


OPERATION = '37600000-0000-4000-8000-000000000001'


def test_composed_real_children_preserve_pending_receipt_and_exact_requests(composed):
    integration, selection, memory, instructions, client, sync, source = composed
    before = instructions.read_bytes()
    assert integration.prepare(OPERATION, **selection)['state'] == 'planned'
    assert instructions.read_bytes() == before
    integration.apply(OPERATION)
    # All three owning implementations and the trusted observer are real;
    # Matrix independently reconciles the retained canonical projection.
    status = integration.status(OPERATION)
    assert status['materialized'] and status['projection_receipted']
    assert status['state'] == 'completed'
    assert status['consumption'] == 'unverified'
    with closing(memory.connect()) as con:
        assert con.execute('select count(*) from chapters').fetchone()[0] == 1
    assert instructions.read_text() == 'Use the retained native workflow.\n'
    journal = json.loads((Path(integration.memory.backup_config['snapshots']['directory']) /
                          'control/operations.json').read_text())
    assert list(journal['entries']) == [OPERATION]
    assert journal['entries'][OPERATION]['state'] == 'complete'
    retained = integration.journal.get(OPERATION)['runtime_observation']['matrix_requests']['adoption']
    integration.recover(OPERATION)
    assert all(request == retained for request in client.requests if request['method'] == 'we.decide')
    with closing(memory.connect()) as con:
        assert con.execute('select count(*) from chapters').fetchone()[0] == 1


def test_proposal_refs_and_receiving_bindings_cannot_be_silently_changed(composed):
    integration, selection, memory, instructions, client, sync, source = composed
    altered = copy.deepcopy(selection)
    altered['behavior_selection']['source_refs'] = ['f' * 64]
    with pytest.raises(IntegrationConflict, match='source_closure_missing'):
        integration.prepare(OPERATION, **altered)
    integration.prepare(OPERATION, **selection)
    integration.memory.owner['pool_lineage'] = 'different receiving pool'
    with pytest.raises(IntegrationConflict, match='binding_changed'):
        integration.apply(OPERATION)
    assert instructions.read_text() == 'Original local instructions.\n'


def test_lost_adoption_return_resends_the_exact_authenticated_document(composed):
    integration, selection, memory, instructions, client, sync, source = composed
    integration.prepare(OPERATION, **selection)
    class LostReturn(BaseException):
        pass
    def interrupt(stage):
        if stage == 'after-adoption-return':
            raise LostReturn()
    with pytest.raises(LostReturn):
        integration.apply(OPERATION, fault=interrupt)
    assert instructions.read_text() == 'Original local instructions.\n'
    integration.recover(OPERATION)
    requests = [r for r in client.requests if r['method'] == 'we.decide']
    assert len(requests) == 2 and requests[0] == requests[1]
    assert integration.status(OPERATION)['materialized']
    with closing(memory.connect()) as con:
        assert con.execute('select count(*) from chapters').fetchone()[0] == 1


def test_conflict_after_partial_completion_never_recreates_earlier_effects(composed):
    integration, selection, memory, instructions, client, sync, source = composed
    integration.prepare(OPERATION, **selection)
    class PartialReturn(BaseException):
        pass
    def stop_after_behavior(stage):
        if stage == 'after-behavior-return':
            raise PartialReturn()
    with pytest.raises(PartialReturn):
        integration.apply(OPERATION, fault=stop_after_behavior)
    instructions.write_text('Later receiving correction.\n')
    with pytest.raises(BehaviorConflict, match='completed_effect_changed'):
        integration.recover(OPERATION)
    assert instructions.read_text() == 'Later receiving correction.\n'
    assert not integration.status(OPERATION)['materialized']
    with closing(memory.connect()) as con:
        assert con.execute('select count(*) from chapters').fetchone()[0] == 1


def test_multi_page_memory_resumes_pending_cross_page_links_with_one_checkpoint(composed):
    integration, selection, memory, instructions, client, sync, source = composed
    second = source.add_text('library', 'A linked original', 'Second attributed memory.')
    with closing(source.connect()) as con:
        first = con.execute('select id from chapters order by id limit 1').fetchone()[0]
    source.add_link(first, second, 'related', note='Preserve the original relation')
    owner = selection['packets'][0]['exporter']
    page_one = sync.export(source.DB_PATH, owner, limit=1)
    page_two = sync.export(source.DB_PATH, owner, after=page_one['cursor'], limit=1)
    packets = [page_one, page_two]
    adapter = integration.memory
    adapter.prepare(packets)
    adapter.backup.operate(adapter.backup_config, 'begin', operation=OPERATION,
                           reason='Before selected same-being integration ' + OPERATION)
    # Actual interruption after the first committed native page: its link is
    # waiting for the second page, not a new backup or a permanently failed job.
    partial = sync.apply(memory, page_one, adapter.owner, operation_id=OPERATION + '.memory.0')
    assert partial['current_links']['pending'] == 1
    observed = adapter.apply(OPERATION, packets)
    assert observed['entries'] == 2 and observed['preserved_conflicts'] == 0
    assert adapter.apply(OPERATION, packets) == observed
    with closing(memory.connect()) as con:
        assert con.execute('select count(*) from chapters').fetchone()[0] == 2
        assert con.execute('select count(*) from chapter_links').fetchone()[0] == 1
    journal = json.loads((Path(adapter.backup_config['snapshots']['directory']) /
                          'control/operations.json').read_text())
    assert list(journal['entries']) == [OPERATION]


def test_missing_receiver_observer_refuses_before_any_effect(composed):
    integration, selection, memory, instructions, client, sync, source = composed
    integration.prepare(OPERATION, **selection)
    client.service = replace(client.service, projection_observer=None)
    with pytest.raises(IntegrationConflict, match='observer_unavailable'):
        integration.apply(OPERATION)
    assert instructions.read_text() == 'Original local instructions.\n'
    with closing(memory.connect()) as con:
        assert con.execute('select count(*) from chapters').fetchone()[0] == 0
    assert integration.journal.get(OPERATION)['state'] == 'planned'


def test_actual_killed_skill_writer_recovers_only_its_exact_native_plan(composed):
    integration, selection, memory, instructions, client, sync, source = composed
    integration.prepare(OPERATION, **selection)
    adapter = integration.skills
    child = os.fork()
    if child == 0:
        # Kill after the actual atomic move to the live skill tree, before the
        # native installed record or completed transaction can be persisted.
        original = adapter.installer.os.replace
        def kill_after_move(src, dst):
            original(src, dst)
            if Path(dst) == adapter.root / 'useful-example':
                os.kill(os.getpid(), signal.SIGKILL)
        adapter.installer.os.replace = kill_after_move
        adapter.apply(selection['skill_plan'])
        os._exit(99)
    _, outcome = os.waitpid(child, 0)
    assert os.WIFSIGNALED(outcome) and os.WTERMSIG(outcome) == signal.SIGKILL
    assert (adapter.root / 'useful-example/SKILL.md').is_file()
    assert adapter.installer.record(adapter.state, 'useful-example') is None
    old = [adapter.installer.read_json(p) for p in adapter.state.glob('transaction-*.json')]
    assert len(old) == 1 and old[0]['status'] == 'applying'
    integration.recover(OPERATION)
    assert integration.status(OPERATION)['state'] == 'completed'
    journals = [adapter.installer.read_json(p) for p in adapter.state.glob('transaction-*.json')]
    assert sorted(j['status'] for j in journals) == ['applied', 'rolled_back']
    assert adapter.installer.read_json(adapter.installer.journal_path(adapter.state, old[0]['transaction']))['status'] == 'rolled_back'
    integration.recover(OPERATION)
    assert len(list(adapter.state.glob('transaction-*.json'))) == 2


def test_unrelated_skill_transaction_is_never_recovered_by_this_parent(composed):
    integration, selection, memory, instructions, client, sync, source = composed
    adapter = integration.skills
    row = dict(transaction='a' * 32, root=str(adapter.root), status='applying',
               descriptor=selection['skill_plan']['descriptor'],
               expected={'useful-example': None}, previous_records={'useful-example': None},
               reconciliation={'another': 'operation'})
    adapter.installer.save_journal(adapter.state, row)
    with pytest.raises(IntegrationConflict, match='unrelated_skill_recovery'):
        adapter.apply(selection['skill_plan'])
    assert adapter.installer.read_json(adapter.installer.journal_path(adapter.state, row['transaction'])) == row
    assert not (adapter.root / 'useful-example').exists()


def test_controls_rollback_restores_owners_and_retains_native_memory(composed):
    integration, selection, memory, instructions, client, sync, source = composed
    before = instructions.read_bytes()
    integration.prepare(OPERATION, **selection)
    integration.apply(OPERATION)
    result = integration.rollback(OPERATION)
    assert result['controls_restored'] and result['memory'] == 'retained-attributed-history'
    assert instructions.read_bytes() == before
    assert not (integration.skills.root / 'useful-example').exists()
    assert integration.rollback(OPERATION) == result
    with closing(memory.connect()) as con:
        assert con.execute('select count(*) from chapters').fetchone()[0] == 1
    assert integration.journal.get(OPERATION)['state'] == 'completed'
    assert integration.status(OPERATION)['controls_rollback'] == 'completed'
    with pytest.raises(IntegrationConflict, match='rollback_started'):
        integration.apply(OPERATION)


def test_controls_rollback_preserves_later_skill_edit_before_any_inverse(composed):
    integration, selection, memory, instructions, client, sync, source = composed
    integration.prepare(OPERATION, **selection)
    integration.apply(OPERATION)
    (integration.skills.root / 'useful-example/SKILL.md').write_text('Later deliberate edit.\n')
    with pytest.raises(IntegrationConflict, match='rollback_owner_changed'):
        integration.rollback(OPERATION)
    assert instructions.read_text() == 'Use the retained native workflow.\n'
    assert integration.journal.get(integration._rollback_id(OPERATION)) is None


def test_actual_kill_inside_skill_inverse_resumes_exact_native_rollback(composed):
    integration, selection, memory, instructions, client, sync, source = composed
    integration.prepare(OPERATION, **selection)
    integration.apply(OPERATION)
    adapter = integration.skills
    transaction = adapter.installer.record(adapter.state, 'useful-example')['transaction']
    retained = adapter.installer.transaction_dir(adapter.root, transaction) / 'retained/useful-example'
    child = os.fork()
    if child == 0:
        original = adapter.installer.os.replace
        def kill_inside_inverse(src, dst):
            original(src, dst)
            if Path(dst) == retained:
                os.kill(os.getpid(), signal.SIGKILL)
        adapter.installer.os.replace = kill_inside_inverse
        integration.rollback(OPERATION)
        os._exit(99)
    _, outcome = os.waitpid(child, 0)
    assert os.WIFSIGNALED(outcome) and os.WTERMSIG(outcome) == signal.SIGKILL
    journal = adapter.installer.journal_path(adapter.state, transaction)
    assert adapter.installer.read_json(journal)['status'] == 'rolling_back'
    assert retained.is_dir()
    assert integration.rollback(OPERATION)['controls_restored']
    assert adapter.installer.read_json(journal)['status'] == 'rolled_back'
    assert integration.rollback(OPERATION)['controls_restored']
    assert retained.is_dir() and not (adapter.root / 'useful-example').exists()
    with closing(memory.connect()) as con:
        assert con.execute('select count(*) from chapters').fetchone()[0] == 1


def test_residual_originals_stay_private_while_status_returns_only_summary(composed):
    integration, selection, memory, instructions, client, sync, source = composed
    private = ['/private/retained/original', {'note': 'private original retained locally'}]
    selection['residual'] = private
    status = integration.prepare(OPERATION, **selection)
    assert status['residual']['count'] == 2
    assert len(status['residual']['sha256']) == 64
    assert 'private' not in json.dumps(status)
    assert integration.journal.get(OPERATION)['intent']['selection']['residual'] == private


@pytest.mark.parametrize('interrupted_stage', ['after-revert-return', 'after-behavior-rollback-return'])
def test_lost_control_inverse_return_resumes_same_inverse(composed, interrupted_stage):
    integration, selection, memory, instructions, client, sync, source = composed
    integration.prepare(OPERATION, **selection)
    integration.apply(OPERATION)
    class LostInverse(BaseException):
        pass
    def interrupt(stage):
        if stage == interrupted_stage:
            raise LostInverse()
    with pytest.raises(LostInverse):
        integration.rollback(OPERATION, fault=interrupt)
    if interrupted_stage == 'after-behavior-rollback-return':
        assert instructions.read_text() == 'Original local instructions.\n'
    result = integration.rollback(OPERATION)
    assert result['controls_restored']
    requests = [r for r in client.requests if r['method'] == 'we.decide' and r['params']['decision'] == 'revert']
    assert len(requests) == (2 if interrupted_stage == 'after-revert-return' else 1)
    assert all(request == requests[0] for request in requests)


def test_actual_operator_cli_uses_private_binding_and_authenticated_native_socket(composed, tmp_path):
    integration, selection, memory, instructions, client, sync, source = composed
    from daimon_matrix.daemon import serve_connection
    from daimon_matrix.client import CLIENT_CONFIG_SCHEMA_V3
    from daimon_matrix.local_api import create_capability
    from clusterctl.same_being_operator import load_operator
    def now():
        return time.time_ns() // 1_000_000
    old = client.config.capability
    capability = create_capability(old.key, client_id=old.client_id,
        methods=list(old.methods), not_before_ms=now()-1000, not_after_ms=now()+120000)
    client.service = replace(client.service, capabilities={capability.capability_id: capability}, clock=now)
    client.service.ledger.clock = now
    def private(name, content):
        path = tmp_path / name
        path.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
        path.chmod(0o600)
        return path
    config = private('client.json', dict(schema=CLIENT_CONFIG_SCHEMA_V3, capability=capability.descriptor,
        expected_server=client.service.origin, runtime_id=client.service.runtime_identity['runtime_id'],
        runtime_label=client.service.runtime_identity['runtime_label']))
    key = private('capability.key', capability.key)
    scripts = Path(DMK_SCRIPTS)
    manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in scripts.glob('*.py')}
    with tempfile.TemporaryDirectory(prefix='same-being-socket-') as short:
        endpoint = str(Path(short) / 'owner.sock')
        binding = private('receiving.json', dict(schema='cluster-same-being-binding/v1',
            binding=integration.binding, journal=str(integration.journal.path.parent),
            matrix=dict(socket=endpoint, client_config=str(config), key_file=str(key)),
            memory=dict(scripts=str(scripts), files=manifest,
                environment=dict(HMK_AGENT_MEMORY_BASE=str(memory.BASE_DIR), HMK_DB_PATH=str(memory.DB_PATH)),
                owner=integration.memory.owner, backup_config=integration.memory.backup_config),
            skills=dict(installer=SKILLS_SCRIPT, installer_sha256=hashlib.sha256(Path(SKILLS_SCRIPT).read_bytes()).hexdigest(),
                repository=str(integration.skills.repository), root=str(integration.skills.root), state=str(integration.skills.state)),
            behavior={}))
        # The trusted host bootstrap resolves exactly the same owning journal.
        observer = load_operator(binding, matrix=client)
        client.service = replace(client.service, projection_observer=observer.observe_effect)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(endpoint)
        os.chmod(endpoint, 0o600)
        listener.listen()
        listener.settimeout(.2)
        stop, errors = threading.Event(), []
        def serve():
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                try:
                    with connection:
                        serve_connection(SimpleNamespace(service=client.service), connection)
                except BaseException as error:
                    errors.append(error)
                    return
        worker = threading.Thread(target=serve)
        worker.start()
        selected = private('selection.json', selection)
        environment = dict(os.environ, PYTHONPATH=str(Path(MATRIX_SOURCE) / 'src') + os.pathsep + str(Path(__file__).resolve().parents[1]))
        def run(action, *extra):
            result = subprocess.run([sys.executable, '-m', 'clusterctl.same_being_operator',
                '--binding', str(binding), action, '--operation-id', OPERATION, *extra],
                env=environment, capture_output=True, timeout=30)
            assert result.returncode == 0, result.stderr.decode()
            return json.loads(result.stdout)
        try:
            assert run('inspect', '--source-event-id', selection['source_event_id'])['local_state'] == 'pending'
            assert run('prepare', '--selection', str(selected))['state'] == 'planned'
            assert run('apply')['state'] == 'completed'
            assert run('recover')['materialized']
            assert run('status')['projection_receipted']
            assert run('rollback')['controls_restored']
            assert run('rollback')['controls_restored']
        finally:
            stop.set()
            worker.join(timeout=3)
            listener.close()
        assert not worker.is_alive() and not errors
    assert instructions.read_text() == 'Original local instructions.\n'
    with closing(memory.connect()) as con:
        assert con.execute('select count(*) from chapters').fetchone()[0] == 1
