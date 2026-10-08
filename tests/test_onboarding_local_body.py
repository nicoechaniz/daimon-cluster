"""Local requests reuse owner access, preserve evidence and never enroll a body."""
import dataclasses
import hashlib
import json
import os
import time
import uuid
from pathlib import Path

import pytest

from clusterctl import being_seed, onboarding_local_body as local, onboarding_peer
from daimon_matrix.daemon import acquire_lock
from tests.test_being_seed import KEY, http_server
from tests.test_onboarding_target import receiving
from tools.export_local_matrix_identity import export


def request(name='eko', owner='sai', expected=None):
    return dict(schema=local.SCHEMA, name=name, owner=owner, request_id=str(uuid.uuid4()),
        expected_being_ref=expected, updated_ms=int(time.time() * 1000))


def report(task, identity=None):
    return dict(schema=local.REPORT, request_id=task['request_id'], checked_at_ms=int(time.time() * 1000),
        checks={key: 'passed' for key in local.CHECKS},
        matrix_state='signed-identity' if identity is not None else 'not-found', matrix_identity=identity)


def test_private_requests_before_intake_reuse_supplied_inputs_and_preserve_reports(tmp_path):
    state, progress = tmp_path / 'state', tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    publisher = local.Requests(progress, worker_uid=os.geteuid())
    task, other = request(), request('oliva', 'ani')
    publisher.publish(task)
    publisher.publish(other)
    with http_server(state) as (server, http):
        server.deps = dataclasses.replace(server.deps, seed_only=True,
            onboarding_progress=str(progress), onboarding_worker_uid=os.geteuid())
        endpoint = '/v1/onboarding/local-body'
        code, headers, value = http(endpoint, owner='sai')
        assert code == 200 and headers['Cache-Control'] == 'no-store'
        assert [row['name'] for row in value['items']] == ['eko']
        assert http(endpoint + '/eko', owner='ani')[0] == 404
        assert http(endpoint, owner='reader')[0] == 403
        assert http(endpoint, extra={'Authorization': ''})[0] == 401
        assert len(http(endpoint, owner='operator')[2]['items']) == 2
        being_seed.create(state, dict(name='eko', label='Eko', mode='import'), owner='sai', key=KEY)
        being_seed.connections(state, 'eko', dict(telegram_bot_token='123456789:' + 'a' * 40,
            telegram_chat_id=123, ssh_public_key='ssh-ed25519 ' + 'a' * 44), owner='sai')
        received = http(endpoint + '/eko', owner='sai')[2]['received']
        assert received['ssh_key_received'] and received['telegram_data_received']
        record = state / 'being-seeds/eko/record.json'
        being_seed._write(record, {**being_seed._read(record), 'preparation_queued': True})
        waiting = http(endpoint + '/eko', owner='sai')[2]
        assert 'receiving_selection_and_preparation' not in waiting['pending_inputs']
        assert waiting['host_tasks'] == ['context_preparation']
        data = report(task)
        code, _, value = http(endpoint + '/eko', 'POST', data, owner='sai')
        assert code == 200 and value['report']['identity_verified'] is False
        assert value['report']['hosted_acceptance'] is False
        assert http(endpoint + '/eko', 'POST', data, owner='sai')[2] == value
        changed = {**data, 'checked_at_ms': data['checked_at_ms'] + 1,
                   'checks': {**data['checks'], 'memory': 'failed'}}
        assert http(endpoint + '/eko', 'POST', changed, owner='sai')[0] == 200
        assert http(endpoint + '/eko', 'POST', data, owner='sai')[2]['report']['checks']['memory'] == 'failed'
        preserved = state / 'local-body-reports/eko'
        assert len([path for path in preserved.glob('*.json') if path.name != 'latest.json']) == 2
        assert http(endpoint + '/eko', 'POST', {**data, 'password': 'must not be accepted'}, owner='sai')[0] == 400
        assert http(endpoint + '/eko', 'POST', {**data, 'checked_at_ms': True}, owner='sai')[0] == 400
        assert not (state / 'being-seeds/oliva').exists()
        assert not list(state.rglob('custody.json'))
        publisher.publish({**task, 'request_id': str(uuid.uuid4())})
        assert http(endpoint + '/eko', 'POST', data, owner='sai')[0] == 400
        assert http(endpoint + '/eko', owner='sai')[2]['report'] is None
        for tool in ('export_local_matrix_identity.py', 'onboarding_peer_native.py'):
            code, headers, source = http(endpoint + '/tools/' + tool, owner='sai')
            assert code == 200
            assert headers['X-Content-SHA256'] == hashlib.sha256(source.encode()).hexdigest()
        assert http(endpoint + '/tools/custody.json', owner='sai')[0] == 404
        assert 'local-body-section' in http('/v1/onboarding')[2]
        assert 'local_body_report' in http('/v1/onboarding?format=json')[2]['requests']


def test_real_existing_identity_export_and_signature_verification_no_new_custody(tmp_path, monkeypatch):
    ceremony, plan, target = receiving(tmp_path)
    proposal = target.prepare()
    target.activate(ceremony.authorize_target(plan, proposal))
    target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
    root = target.package / 'runtime'
    before = {name: (root / name).read_bytes() for name in ('runtime.json', 'custody.json')}
    password = target.root / 'body.unlock'
    output = target.root / 'public-local.json'
    asset = Path(__file__).resolve().parents[1] / 'clusterctl/onboarding_peer_native.py'
    lock = acquire_lock(root)
    try:
        with pytest.raises(BlockingIOError):
            export(root, password, output, peer_file=asset)
        assert not output.exists()
    finally:
        os.close(lock)
    export(root, password, output, peer_file=asset)
    assert output.stat().st_mode & 0o077 == 0
    identity = json.loads(output.read_bytes())
    assert before == {name: (root / name).read_bytes() for name in before}
    task = request(expected=identity['document']['authority']['manifest']['being_ref'])
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    accepted = local.submit(state, task, report(task, identity), code_uid=os.geteuid())
    assert accepted['report']['identity_verified']
    assert accepted['report']['hosted_acceptance'] is False
    assert 'matrix_identity' not in accepted['report']
    forged = json.loads(json.dumps(identity))
    forged['document']['runtime_label'] = 'Another identity'
    with pytest.raises(being_seed.SeedError, match='signed_identity_required'):
        local.submit(state, task, report(task, forged), code_uid=os.geteuid())
    wrong = {**task, 'expected_being_ref': 'dm:being:v1:' + 'a' * 43}
    with pytest.raises(being_seed.SeedError, match='signed_identity_required'):
        local.submit(state, wrong, report(wrong, identity), code_uid=os.geteuid())
    with pytest.raises(being_seed.SeedError, match='existing_local_body_identity_preserved'):
        local.submit(state, task, report(task), code_uid=os.geteuid())
    with pytest.raises(FileExistsError):
        export(root, password, output, peer_file=asset)
    actual = onboarding_peer.native
    monkeypatch.setattr(onboarding_peer, 'native', lambda code, uid=0: actual(code, uid=os.geteuid()))
    assert local.worker_identity(state, task, intake_uid=os.geteuid()) == identity
    with pytest.raises(Exception, match='private_local_body_report_required'):
        local.worker_identity(state, task, intake_uid=os.geteuid() + 1)
    progress = tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    local.Requests(progress, worker_uid=os.geteuid()).publish(task)
    with http_server(state) as (server, http):
        server.deps = dataclasses.replace(server.deps, seed_only=True,
            onboarding_progress=str(progress), onboarding_worker_uid=os.geteuid())
        assert http('/v1/onboarding/local-body/eko', 'POST', report(task, identity), owner='sai')[0] == 200
    assert before == {name: (root / name).read_bytes() for name in before}


def test_blocker_diagnostics_before_archive_are_private_preserved_and_do_not_replace_identity_checks(tmp_path):
    state, progress = tmp_path / 'state', tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    task = request()
    publisher = local.Requests(progress, worker_uid=os.geteuid())
    publisher.publish(task)
    publisher.publish(request('oliva', 'ani'))
    with http_server(state) as (server, http):
        server.deps = dataclasses.replace(server.deps, seed_only=True,
            onboarding_progress=str(progress), onboarding_worker_uid=os.geteuid())
        endpoint = '/v1/onboarding/local-body/eko'
        data = dict(schema=local.DIAGNOSTIC, request_id=task['request_id'],
            reported_at_ms=task['updated_ms'], component='context-exporter', no_credentials=True,
            report={'error': 'embedded_credential_requires_separate_handoff',
                    'harmless_cases': ['code without credentials', 'empty JPEG'], 'originals_intact': True})
        assert http(endpoint + '/diagnostic', 'POST', data, owner='ani')[0] == 404
        assert http(endpoint + '/diagnostic', 'POST', data, owner='reader')[0] == 403
        assert http(endpoint + '/diagnostic', 'POST', data, extra={'Authorization': ''})[0] == 401
        code, headers, first = http(endpoint + '/diagnostic', 'POST', data, owner='sai')
        assert code == 200 and headers['Cache-Control'] == 'no-store'
        assert first['report'] is None and not first['received']['archive_received']
        assert first['diagnostic']['received'] and first['diagnostic']['resolution'] == 'host-review-pending'
        assert 'report' not in first['diagnostic']
        assert http(endpoint + '/diagnostic', 'POST', data, owner='sai')[2] == first
        checks = report(task)
        assert http(endpoint, 'POST', checks, owner='sai')[0] == 200
        later = {**data, 'reported_at_ms': data['reported_at_ms'] + 1,
                 'report': {'reproduction': 'additional harmless evidence'}}
        assert http(endpoint + '/diagnostic', 'POST', later, owner='sai')[0] == 200
        value = http(endpoint + '/diagnostic', 'POST', data, owner='sai')[2]
        assert value['diagnostic']['reported_at_ms'] == later['reported_at_ms']
        assert value['report']['checks'] == checks['checks']
        saved = state / 'local-body-reports/eko/diagnostics'
        assert saved.stat().st_mode & 0o077 == 0
        evidence = [path for path in saved.glob('*.json') if path.name != 'latest.json']
        assert len(evidence) == 2 and all(path.stat().st_mode & 0o077 == 0 for path in evidence)
        assert any(json.loads(path.read_bytes()) == data for path in evidence)
        for bad in ({**data, 'no_credentials': False}, {**data, 'request_id': str(uuid.uuid4())},
                    {**data, 'reported_at_ms': True}, {**data, 'report': {'large': 'x' * 60000}},
                    {**data, 'report': {'token': 'ghp_' + 'a' * 40}}):
            assert http(endpoint + '/diagnostic', 'POST', bad, owner='sai')[0] == 400
        assert len([path for path in saved.glob('*.json') if path.name != 'latest.json']) == 2
        assert not (state / 'being-seeds').exists()
        assert 'local-body-send-diagnostic' in http('/v1/onboarding')[2]
        assert 'local_body_diagnostic' in http('/v1/onboarding?format=json')[2]['requests']
        publisher.publish({**task, 'request_id': str(uuid.uuid4())})
        assert http(endpoint, owner='sai')[2]['diagnostic'] is None
