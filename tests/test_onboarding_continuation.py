"""Finite local continuation, exact cached replies and confidential inputs."""
import copy
import hashlib
import json

import pytest

from tools import continue_seed_onboarding as client

ROOT = 'dm:being:v1:' + 'A' * 43


def frame(phase):
    payload = dict(base={'expected_being_ref': ROOT}, plan={'name': 'oliva', 'owner': 'ani'}, phase=phase)
    fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return dict(name='oliva', owner='ani', payload=payload, phase=phase, request_digest=fingerprint)


class Host:
    def __init__(self):
        self.phase = 0
        self.posts = []
        self.accepted = []
        self.lost_ack = False
        self.queued = False
        self.clock = 0
        self.source_received = False
        self.connected = False
        self.task = dict(expected_being_ref=ROOT, owner='ani', request_id='fixed-request',
            pending_inputs=['signed_existing_matrix_source', 'receiving_selection_and_preparation',
                'telegram_bot_and_destination', 'ssh_public_key'])

    def __call__(self, path, body=None):
        if body is not None:
            self.posts.append((path, copy.deepcopy(body)))
            if body.get('schema') == 'cluster-onboarding-existing-source/v1':
                self.source_received = True
            elif body.get('schema') == 'cluster-onboarding-enrollment-reply/v1':
                self.accepted.append(body['request_digest'])
                self.phase += 1
                if self.lost_ack:
                    self.lost_ack = False
                    raise OSError('private token and credential-bearing URL must not be printed')
            elif path.endswith('/connections'):
                self.connected = True
            elif path.endswith('/prepare'):
                self.queued = True
            return {'stored': True}
        if path.endswith('/enrollment'):
            return dict(expected_being_ref=ROOT, request_id='fixed-request', source_received=self.source_received,
                hosted_identity_ready=self.phase >= 2, handoff=frame(('enrollment', 'credential')[self.phase])
                    if self.phase < 2 and self.queued else None)
        if path.endswith('/onboarding'):
            return dict(state='waiting', active=False, completed_steps=['matrix', 'access', 'telegram', 'welcome']
                if self.phase >= 2 else [])
        needed = []
        if not self.source_received:
            needed.append('signed_existing_matrix_source')
        if not self.connected:
            needed += ['telegram_bot_and_destination', 'ssh_public_key']
        if not self.queued:
            needed.append('receiving_selection_and_preparation')
        return {**self.task, 'pending_inputs': needed}

    def wait(self, elapsed):
        self.clock += elapsed


def inputs():
    return dict(source=dict(schema='cluster-onboarding-existing-source/v1', request_id='fixed-request',
        identity={'document': {'authority': {'manifest': {'being_ref': ROOT}}}}, routes=[]),
        connections=dict(telegram_bot_token='dedicated-private-token', telegram_chat_id=42,
            ssh_public_key='dedicated-public-key'), selection=dict(soul='own-preserved-soul', skills=[]))


def test_finite_client_sends_missing_inputs_and_completes_two_exact_handoffs(tmp_path):
    host = Host()
    signed = []
    def sign(value):
        signed.append(value['phase'])
        return dict(schema='cluster-onboarding-enrollment-reply/v1',
            request_digest=value['request_digest'], response={'public_signature': value['phase']})
    with client.state_directory(tmp_path / 'state') as state:
        result = client.continue_job(host, 'oliva', state, sign=sign, wait=host.wait,
            clock=lambda:host.clock, **inputs())
    assert signed == ['enrollment', 'credential']
    assert result == dict(state='hosted-conversation-ready', hosted_identity_ready=True, human_acceptance=False)
    assert len([path for path, body in host.posts if path.endswith('/prepare')]) == 1
    assert len(host.accepted) == 2
    assert 'dedicated-private-token' not in ''.join(p.read_text() for p in state.glob('*.json'))
    assert not list(state.glob('*.partial'))


def test_rerun_after_lost_ack_reuses_public_reply_and_received_inputs(tmp_path):
    host = Host()
    host.lost_ack = True
    signed = []
    def sign(value):
        signed.append(value['phase'])
        return dict(schema='cluster-onboarding-enrollment-reply/v1',
            request_digest=value['request_digest'], response={})
    with client.state_directory(tmp_path / 'state') as state:
        with pytest.raises(OSError):
            client.continue_job(host, 'oliva', state, sign=sign, wait=host.wait,
                clock=lambda:host.clock, **inputs())
    # The host advances asynchronously; a second invocation must not send
    # another source/selection/bot bundle or discard its existing signatures.
    with client.state_directory(tmp_path / 'state') as state:
        result = client.continue_job(host, 'oliva', state, sign=sign, wait=host.wait,
            clock=lambda:host.clock)
    assert signed == ['enrollment', 'credential'] and result['state'] == 'hosted-conversation-ready'
    assert len([x for x, body in host.posts if 'selection' in body]) == 1
    assert len(list(state.glob('*.reply.json'))) == 2


def test_changed_root_or_handoff_payload_cannot_reuse_cached_signature(tmp_path):
    host = Host()
    host.source_received = host.connected = host.queued = True
    original = host.__call__
    def changed(path, body=None):
        value = original(path, body)
        if path.endswith('/enrollment') and value.get('handoff'):
            value['handoff']['payload']['base']['expected_being_ref'] = 'another-root'
        return value
    with client.state_directory(tmp_path / 'state') as state:
        with pytest.raises(client.ContinuationError, match='same_root_handoff_required'):
            client.continue_job(changed, 'oliva', state, sign=lambda frame:pytest.fail('foreign Root was signed'),
                wait=host.wait, clock=lambda:host.clock)
    assert not host.accepted


def test_missing_inputs_return_actionable_state_without_asking_for_received_archive(tmp_path):
    host = Host()
    with client.state_directory(tmp_path / 'state') as state:
        result = client.continue_job(host, 'oliva', state)
    assert result == dict(state='inputs-required', pending_inputs=['signed_existing_matrix_source'])
    assert not host.posts


def test_private_files_and_binding_cannot_be_reused_by_another_owner(tmp_path):
    path = tmp_path / 'token'
    path.write_text('sensitive')
    path.chmod(0o644)
    with pytest.raises(client.ContinuationError, match='private_participant_file_required'):
        client.private_read(path)
    host = Host()
    with client.state_directory(tmp_path / 'state') as state:
        client.continue_job(host, 'oliva', state)
    host.task['owner'] = 'sai'
    with client.state_directory(tmp_path / 'state') as state:
        with pytest.raises(client.ContinuationError, match='existing_public_reply_preserved'):
            client.continue_job(host, 'oliva', state)
