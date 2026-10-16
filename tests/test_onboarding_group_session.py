"""Bounded owner process lifetime and fresh per-command coordination."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_group_session import Frames, OwnerConversation, client_scope


PROGRAM = '''
import sys
from pathlib import Path
from clusterctl import onboarding_group_session as session
class Owner:
    def __init__(self, owner, packet, **kw): self.packet=packet
    def __enter__(self): return self
    def __exit__(self,*args): Path(sys.argv[2]).write_text('released')
    def call(self,packet): return dict(echo=packet)
session.RelationshipSession=Owner
session.serve(None,deadline_ns=int(sys.argv[1]),reader=0,writer=1,
    quiescence=lambda child,social:dict(child=child,social=social))
'''


def conversation(tmp_path, seconds=4):
    deadline = time.monotonic_ns()+int(seconds*1_000_000_000)
    marker = tmp_path/'writer-released'
    return OwnerConversation([sys.executable, '-B', '-c', PROGRAM, str(deadline), str(marker)],
        dict(command={'operation_id': 'original-operation'}), deadline_ns=deadline), marker


def test_actual_process_reuses_one_owner_and_closes_after_writer_release(tmp_path):
    owner, marker = conversation(tmp_path)
    with owner as session:
        process = session.process
        assert session.call({'first': True}) == {'echo': {'first': True}}
        assert not marker.exists()
        assert session.call({'quiescence': 'original-child'}) == {
            'child': 'original-child', 'social': 'original-operation'}
        assert session.call({'second': True}) == {'echo': {'second': True}}
        assert session.process is process
    assert marker.read_text() == 'released' and process.poll() == 0


def test_owner_enforces_deadline_without_host_close(tmp_path):
    owner, marker = conversation(tmp_path, 2)
    session = owner.__enter__()
    process = session.process
    # No host input or renewal: the child releases its writer and exits itself.
    process.wait(timeout=5)
    assert marker.read_text() == 'released' and process.returncode != 0
    with pytest.raises(OnboardingError, match='exit_unobserved'):
        owner.__exit__(None, None, None)


def test_wrong_sequence_closes_without_dispatch_and_releases_writer(tmp_path):
    owner, marker = conversation(tmp_path)
    session = owner.__enter__()
    process = session.process
    session.frames.write(dict(sequence=2, packet={'unapproved': True}))
    process.wait(timeout=3)
    assert process.returncode != 0 and marker.read_text() == 'released'
    with pytest.raises(OnboardingError, match='exit_unobserved'):
        owner.__exit__(None, None, None)


def test_expired_invocation_never_spawns_a_process(monkeypatch):
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **k: pytest.fail('expired process spawn'))
    with pytest.raises(OnboardingError, match='deadline_expired'):
        with OwnerConversation([], {}, deadline_ns=time.monotonic_ns()-1):
            pass


def test_frame_limit_rejects_before_decoding_or_writing():
    read, write = os.pipe()
    try:
        frames = Frames(read, write, time.monotonic_ns()+1_000_000_000)
        with pytest.raises(OnboardingError, match='frame_required'):
            frames.write({'oversize': 'x' * (2*1024**2)})
        os.write(write, json.dumps(['not an object']).encode()+b'\n')
        with pytest.raises(OnboardingError, match='frame_required'):
            frames.read()
    finally:
        os.close(read)
        os.close(write)


def test_lazy_scope_preserves_original_exception_and_clears_process():
    owner = SimpleNamespace()
    class Child:
        def __enter__(self): return self
        def __exit__(self, kind, error, tb):
            assert kind is ValueError
    with pytest.raises(ValueError, match='original'):
        with client_scope(owner):
            assert owner._relationship_process is None
            owner._relationship_process = owner._relationship_stack.enter_context(Child())
            raise ValueError('original')
    assert owner._relationship_process is owner._relationship_stack is None


def test_old_qualified_owner_keeps_one_shot_route(tmp_path):
    from clusterctl.onboarding_group_session import supported_scope
    code = tmp_path/'code'
    code.mkdir()
    manifest = code/'release.json'
    owner = SimpleNamespace()
    manifest.write_text(json.dumps(dict(files=[{'path': 'clusterctl/onboarding_source.py'}])))
    manifest.chmod(0o644)
    with supported_scope(owner, code, uid=os.geteuid(), code_digest=digest(json.loads(manifest.read_text()))):
        assert not hasattr(owner, '_relationship_stack')
    manifest.write_text(json.dumps(dict(files=[{'path': 'clusterctl/onboarding_group_session.py'}])))
    with pytest.raises(OnboardingError, match='digest_mismatch'):
        supported_scope(owner, code, uid=os.geteuid(), code_digest='f'*64)
    with supported_scope(owner, code, uid=os.geteuid(), code_digest=digest(json.loads(manifest.read_text()))):
        assert owner._relationship_stack is not None
    assert owner._relationship_stack is None


def test_source_fresh_quiescence_uses_same_writer_process(monkeypatch):
    from clusterctl.onboarding_receiving_update import SourceGroupClient
    owner = object.__new__(SourceGroupClient)
    owner.lifecycle_journal = Path('/approved/journal')
    calls = []
    class Process:
        def __enter__(self):
            calls.append('open')
            return self
        def __exit__(self, *_): calls.append('close')
        def call(self, packet):
            calls.append(packet)
            return {'observed': True}
    monkeypatch.setattr(owner, '_relationship_conversation', lambda packet: Process())
    monkeypatch.setattr(owner, '_call', lambda *a, **k: pytest.fail('cold owner invocation under held writer'))
    with client_scope(owner):
        owner.group_relationship({'operation_id': 'same'}, offline=True)
        assert owner.lifecycle_action('bound-child', 'quiescence') == {'observed': True}
        owner.group_relationship({'operation_id': 'same'}, offline=True)
    assert calls[0] == 'open' and calls[-1] == 'close'
    assert calls[2] == {'quiescence': 'bound-child'} and len(calls) == 5


def test_source_command_drops_privileges_without_inspecting_private_sdk(tmp_path, monkeypatch):
    from clusterctl.onboarding_receiving_update import SourceGroupClient
    owner = object.__new__(SourceGroupClient)
    owner.config = tmp_path/'source.json'
    owner.config.write_text('{}')
    owner.config.chmod(0o600)
    owner.owner_uid, owner.owner_gid = os.geteuid(), os.getegid()
    owner.lifecycle_journal = tmp_path/'journal'
    owner.venv = Path('/private-owner-sdk/venv')
    owner.imports = owner.venv.parent/'runtime-imports'
    owner.code, owner.code_uid, owner.code_digest = tmp_path/'code', 0, 'c'*64
    owner.config_sha256, owner.timeout_seconds, owner.deadline_ns = 'a'*64, 5, None
    original = Path.lstat
    def no_sdk(path, *args, **kwargs):
        if str(path).startswith('/private-owner-sdk'):
            pytest.fail('coordinator inspected the owner private SDK')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'lstat', no_sdk)
    child = owner._relationship_conversation({'approved': True})
    assert child.argv[0] == str(owner.venv/'bin/python')
    assert child.options['user'] == owner.owner_uid and child.options['extra_groups'] == ()
    assert child.argv[child.argv.index('--observation-deadline-ns')+1] == str(child.deadline_ns)
    assert '--group-session' in child.argv and '--operation-journal' in child.argv


@pytest.mark.parametrize('stage', ['loading', 'handling'])
def test_kernel_deadline_releases_writer_even_when_native_execution_blocks(tmp_path, stage):
    import fcntl
    import signal
    marker = tmp_path/'writer-lock'
    program = '''
import fcntl,os,sys,time
from clusterctl.onboarding_group_session import hard_deadline
with hard_deadline(int(sys.argv[1])):
    descriptor=os.open(sys.argv[2],os.O_CREAT|os.O_RDWR,0o600)
    fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if sys.argv[3]=='loading': time.sleep(60)
    # Simulate a native handle blocked after durable dispatch, beyond all
    # cooperative frame/RPC deadline checks. Kernel exit must release writer.
    os.write(1,b'ready\\n')
    time.sleep(60)
'''
    deadline = time.monotonic_ns()+1_000_000_000
    with subprocess.Popen([sys.executable, '-B', '-c', program, str(deadline), str(marker), stage],
            stdout=subprocess.PIPE) as child:
        if stage == 'handling':
            assert child.stdout.readline() == b'ready\n'
        assert child.wait(timeout=5) == -signal.SIGALRM
    descriptor = os.open(marker, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX|fcntl.LOCK_NB)
    finally:
        os.close(descriptor)
