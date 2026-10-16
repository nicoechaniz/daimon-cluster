"""Finite owner conversation over its qualified CLI, never a listener or model.

Each request keeps the existing native journal/authentication. The caller still
checks fresh stopped-service evidence before every write; this scope only avoids
repeated interpreter, custody and runtime initialization within one invocation.
"""
from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import time
from contextlib import ExitStack, contextmanager, nullcontext

from . import being_seed
from .onboarding import OnboardingError, digest


@contextmanager
def hard_deadline(deadline_ns):
    """CLI-only kernel lifetime bound, including blocked load/native execution.

    SIG_DFL terminates the exact technical owner even while native code holds
    the GIL. Kernel exit releases its writer; an interrupted native effect stays
    uncertain in its original journal. This is never installed in a daemon.
    """
    remaining = (deadline_ns-time.monotonic_ns())/1_000_000_000
    if not 0 < remaining <= 60 or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise OnboardingError('receiving_owner_deadline_expired')
    previous = signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.setitimer(signal.ITIMER_REAL, remaining)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class Frames:
    def __init__(self, reader, writer, deadline_ns):
        if type(deadline_ns) is not int or not 0 < deadline_ns - time.monotonic_ns() <= 60_000_000_000:
            raise OnboardingError('receiving_owner_deadline_expired')
        self.reader, self.writer, self.deadline_ns = reader, writer, deadline_ns
        self.pending = bytearray()

    def remaining(self):
        seconds = (self.deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if seconds <= 0:
            raise OnboardingError('receiving_owner_deadline_expired')
        return seconds

    def read(self):
        while b'\n' not in self.pending:
            if not select.select([self.reader], [], [], self.remaining())[0]:
                raise OnboardingError('receiving_owner_deadline_expired')
            chunk = os.read(self.reader, min(65536, being_seed.MAX_SELECTION + 1 - len(self.pending)))
            if not chunk:
                raise OnboardingError('receiving_owner_session_closed')
            self.pending.extend(chunk)
            if len(self.pending) > being_seed.MAX_SELECTION:
                raise OnboardingError('receiving_owner_session_frame_required')
        line, _, remainder = self.pending.partition(b'\n')
        self.pending = bytearray(remainder)
        value = json.loads(line)
        if not isinstance(value, dict):
            raise OnboardingError('receiving_owner_session_frame_required')
        self.remaining()
        return value

    def write(self, value):
        raw = json.dumps(value, separators=(',', ':')).encode() + b'\n'
        if len(raw) > being_seed.MAX_SELECTION:
            raise OnboardingError('receiving_owner_session_frame_required')
        while raw:
            if not select.select([], [self.writer], [], self.remaining())[1]:
                raise OnboardingError('receiving_owner_deadline_expired')
            raw = raw[os.write(self.writer, raw[:4096]):]


class OwnerConversation:
    """Join the local invocation; retain uncertainty if remote exit is unseen."""
    def __init__(self, argv, packet, *, deadline_ns, validate=lambda: None, **options):
        self.argv, self.packet, self.deadline_ns = argv, packet, deadline_ns
        self.validate, self.options = validate, options
        self.process = self.frames = None
        self.sequence = 0

    def __enter__(self):
        self.validate()
        if not 0 < self.deadline_ns-time.monotonic_ns() <= 60_000_000_000:
            raise OnboardingError('receiving_owner_deadline_expired')
        self.process = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True, **self.options)
        try:
            self.frames = Frames(self.process.stdout.fileno(), self.process.stdin.fileno(), self.deadline_ns)
            self.frames.write(self.packet)
            if self.frames.read() != {'ready': True}:
                raise OnboardingError('receiving_owner_session_unavailable')
            return self
        except BaseException as error:
            self.__exit__(type(error), error, error.__traceback__)
            raise

    def call(self, packet):
        self.validate()
        self.sequence += 1
        self.frames.write(dict(sequence=self.sequence, packet=packet))
        result = self.frames.read()
        if set(result) != {'sequence', 'result'} or result['sequence'] != self.sequence or not isinstance(result['result'], dict):
            raise OnboardingError('receiving_owner_session_unavailable')
        return result['result']

    def __exit__(self, exc_type, _error, _traceback):
        if self.process is None:
            return
        process, self.process = self.process, None
        failed = False
        try:
            if process.poll() is None and self.frames is not None:
                self.frames.write({'close': True})
                if self.frames.read() != {'closed': True}:
                    raise OnboardingError('receiving_owner_session_unavailable')
            process.wait(timeout=max(.1, (self.deadline_ns-time.monotonic_ns())/1_000_000_000))
            failed = process.returncode != 0
        except (OSError, ValueError, OnboardingError, subprocess.TimeoutExpired):
            failed = True
            # A transport loss does not establish remote writer exit. The owner
            # also enforces this same absolute deadline independently.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        finally:
            process.stdin.close()
            process.stdout.close()
        if failed and exc_type is None:
            raise OnboardingError('receiving_owner_session_exit_unobserved')


@contextmanager
def client_scope(owner):
    """Lazy: the first fresh barrier still precedes acquiring any native writer."""
    if getattr(owner, '_relationship_stack', None) is not None:
        raise OnboardingError('receiving_owner_session_already_open')
    stack = ExitStack()
    owner._relationship_stack, owner._relationship_process = stack, None
    try:
        with stack:
            yield
    finally:
        owner._relationship_stack = owner._relationship_process = None


def supported_scope(owner, code, *, uid, code_digest):
    """Older qualified owner artifacts retain their supported one-shot route.

    The public captured inventory is the feature declaration. Never probe a
    private SDK as root or try an unknown CLI option to discover support.
    """
    from . import onboarding_release
    manifest = json.loads(onboarding_release.regular(code/'release.json', uid=uid))
    if digest(manifest) != code_digest:
        raise OnboardingError('receiving_release_digest_mismatch')
    paths = {item['path'] for item in manifest['files']}
    return client_scope(owner) if 'clusterctl/onboarding_group_session.py' in paths else nullcontext()


class RelationshipSession:
    """One loaded native owner under its continuously held original writer."""
    def __init__(self, owner, packet, *, deadline_ns, target=False):
        from .onboarding_group_admission import request_packet
        self.packet = request_packet(packet)
        if not self.packet['offline'] or 'action' in self.packet['command']:
            raise OnboardingError('onboarding_group_relationship_writer_required')
        self.owner, self.deadline_ns, self.target = owner, deadline_ns, target
        self.stack = ExitStack()

    def __enter__(self):
        from .onboarding_group_admission import check_retained_ledger, load_owner_runtime, owner_authorities
        owner, packet = self.owner, self.packet
        try:
            if self.target:
                self.stack.enter_context(being_seed._locked(owner.root))
                self.stack.enter_context(owner._runtime_writer())
                self.root, self.journal, group = owner.package/'runtime', owner.root/'group-admission', owner.root/'tribe'
            else:
                self.stack.enter_context(owner.writer())
                self.root, self.journal, group = owner.root, owner.outputs/'group-admission', owner.outputs/'tribe'
            check_retained_ledger(self.root, self.journal, packet['command'])
            authorities = owner_authorities(self.root, group, self.journal, packet['command']['operation_id'],
                packet['authority_closure'], expected_context_sha256=packet.get('expected_context_sha256'))
            if self.target and owner._observe_receiving()['phase'] != 'v8':
                raise OnboardingError('current_onboarding_target_required')
            self.hosted = load_owner_runtime(self.root, owner._reader, authorities=authorities,
                qualified_startup=owner.qualified_startup)
            return self
        except BaseException:
            self.stack.close()
            raise

    def call(self, packet, *, inspect_only=False):
        from .onboarding_group_admission import check_retained_ledger, relationship_request, request_packet
        packet = request_packet(packet)
        if (not packet['offline'] or 'action' in packet['command']
                or packet['command']['operation_id'] != self.packet['command']['operation_id']
                or any(packet.get(key) != self.packet.get(key) for key in ('authority_closure', 'expected_context_sha256'))):
            raise OnboardingError('onboarding_group_relationship_request_conflict')
        check_retained_ledger(self.root, self.journal, packet['command'])
        return relationship_request(self.root, self.journal, packet['command'], offline=self.hosted,
            deadline_ns=self.deadline_ns, membership_precondition=packet.get('membership_precondition'),
            inspect_only=inspect_only)

    def __exit__(self, *_):
        self.stack.close()


def serve(owner, *, deadline_ns, reader, writer, target=False, quiescence=None):
    """Closed, sequential protocol; EOF/timeout releases the writer, zero models."""
    frames = Frames(reader, writer, deadline_ns)
    packet = frames.read()
    closed = False
    with RelationshipSession(owner, packet, deadline_ns=deadline_ns, target=target) as session:
        frames.write({'ready': True})
        for sequence in range(1, 129):
            frame = frames.read()
            if frame == {'close': True}:
                closed = True
                break
            if set(frame) != {'sequence', 'packet'} or type(frame['sequence']) is not int or frame['sequence'] != sequence:
                raise OnboardingError('receiving_owner_session_frame_required')
            value = frame['packet']
            if isinstance(value, dict) and set(value) == {'quiescence'} and callable(quiescence):
                result = quiescence(value['quiescence'], session.packet['command']['operation_id'])
            elif isinstance(value, dict) and set(value) == {'inspect'}:
                result = session.call(value['inspect'], inspect_only=True)
            else:
                result = session.call(value)
            frames.write(dict(sequence=sequence, result=result))
        else:
            raise OnboardingError('receiving_owner_session_limit')
    # This acknowledgement follows release of the actual native writer.
    if closed:
        frames.write({'closed': True})
