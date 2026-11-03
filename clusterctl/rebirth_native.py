"""Qualified native Matrix profile under the ordinary H8 admission supervisor.

This selects existing Source hosting, including its approved group applications;
it does not create authority, provision applications or start a model harness.
"""
from __future__ import annotations

import hmac
import os
import select
import socket
import threading
from pathlib import Path

from . import onboarding_code_successor, onboarding_release, onboarding_sdk
from .onboarding import digest


def start_record(journal, target: str, intent: dict, *, actor: str, embodiment_id: str) -> dict:
    """Retain a qualified SDK-only successor under the caller's start lock.

    Preparation already verifies the protected owner selection. Starting still
    requires the ordinary singleton admission; this plans no physical effect.
    Original startup/audit records remain immutable and exact retries reuse the
    current planned or completed record instead of manufacturing another birth.
    """
    from .rebirth_host import RebirthHostError

    previous = journal.latest_for_target(target)
    key = f"rebirth-start:{intent['activation_id']}"
    retained = dict(intent)
    if previous is not None:
        prior = dict(previous['intent'])
        anchor = prior.pop('native_start_predecessor', None)
        if anchor is not None:
            if not isinstance(anchor, dict) or set(anchor) != {'operation_id', 'intent_hash'}:
                raise RebirthHostError('rebirth_host_journal_conflict')
            parent = journal.get(anchor['operation_id'])
            if (parent is None or parent['state'] != 'completed'
                    or parent['operation'] != 'rebirth-start' or parent['target'] != target
                    or parent['intent_hash'] != anchor['intent_hash']):
                raise RebirthHostError('rebirth_host_journal_conflict')
        if previous['operation'] != 'rebirth-start' or previous['state'] not in {
                'planned', 'runtime-dispatching', 'runtime-applied',
                'logical-committed', 'audited', 'completed'}:
            raise RebirthHostError('rebirth_host_journal_conflict')
        if prior == intent:
            return previous
        before, after = prior.get('runtime_call'), intent.get('runtime_call')
        if (previous['state'] != 'completed'
                or {k: v for k, v in prior.items() if k != 'runtime_call'}
                != {k: v for k, v in intent.items() if k != 'runtime_call'}
                or not isinstance(before, dict) or not isinstance(after, dict)
                or set(before) != {'operation', 'selection'} or set(after) != set(before)
                or before['operation'] != 'native-source' or after['operation'] != 'native-source'):
            raise RebirthHostError('rebirth_host_journal_conflict')
        old, new = before['selection'], after['selection']
        fields = {'config', 'config_sha256', 'code', 'code_digest', 'venv', 'sdk_digest'}
        if (not isinstance(old, dict) or not isinstance(new, dict)
                or set(old) != fields or set(new) != fields
                or any(not isinstance(v, str) or not v for v in (*old.values(), *new.values()))
                or old['config'] != new['config'] or old['config_sha256'] != new['config_sha256']):
            raise RebirthHostError('rebirth_host_journal_conflict')
        for selection in (old, new):
            venv = Path(selection['venv'])
            if (not venv.is_absolute() or venv.name != 'venv'
                    or venv.parent.name != selection['sdk_digest']):
                raise RebirthHostError('rebirth_host_journal_conflict')
        if Path(old['venv']).parent.parent != Path(new['venv']).parent.parent:
            raise RebirthHostError('rebirth_host_journal_conflict')
        retained['native_start_predecessor'] = {
            'operation_id': previous['operation_id'], 'intent_hash': previous['intent_hash']}
        key += ':native:' + digest(retained)
    return journal.plan(
        operation='rebirth-start', target=target, idempotency_key=key, intent=retained,
        expected_precondition={'install_state': 'completed'},
        intended_transition={'registry_status': 'running',
                             'incarnation_id': intent['origin']['incarnation_id']},
        audit_identity={'actor': actor, 'target': embodiment_id})


def prepare(state: Path, identity: dict, profile: Path, password_fd: int) -> dict:
    from .matrix_host import matrix_root
    from .rebirth_host import RebirthHostError, _owner_file, _read_json

    try:
        value = _read_json(_owner_file(profile))
        if (not isinstance(value, dict) or set(value) != {
                'schema', 'config', 'code', 'code_digest', 'home'}
                or value['schema'] != 'dm.cluster.rebirth-native-profile/v1'
                or any(not isinstance(value[k], str) or not Path(value[k]).is_absolute()
                       for k in ('config', 'code', 'home'))):
            raise ValueError('profile')
        config = Path(value['config'])
        settings = _read_json(_owner_file(config))
        root = matrix_root(state, identity['origin']['embodiment_id'])
        if (settings.get('schema') != 'cluster-onboarding-source/v1'
                or settings.get('runtime_root') != str(root)):
            raise ValueError('root')
        password = _owner_file(Path(settings['password_file'])).read_bytes()
        supplied = bytearray()
        while len(supplied) <= 4096:
            part = os.read(password_fd, 4097 - len(supplied))
            if not part:
                break
            supplied.extend(part)
        matches = bool(password) and len(supplied) <= 4096 and hmac.compare_digest(password, supplied)
        supplied[:] = b'\0' * len(supplied)
        if not matches:
            raise ValueError('password')
        code = Path(value['code'])
        onboarding_release.verify(code, value['code_digest'], uid=0)
        parameters = onboarding_code_successor.sdk_parameters(code, uid=0)
        if not parameters:
            raise ValueError('qualified SDK required')
        sdk = onboarding_sdk.verify(code, uid=0, **parameters)
        sdk_root = Path(value['home']) / '.local/share/daimon-matrix/sdk' / digest(sdk)
        venv = sdk_root / 'venv'
        if not (venv / 'bin/python').is_file():
            raise ValueError('SDK not installed')
        return {'config':str(config), 'config_sha256':digest(settings),
                    'code':str(code), 'code_digest':value['code_digest'], 'venv':str(venv),
                    'sdk_digest':digest(sdk)}
    except Exception as error:
        raise RebirthHostError('rebirth_host_native_profile_rejected') from error


def command(selection: dict, ready_fd: int, *, body_observer_fd: int | None = None) -> list[str]:
    """Use the qualified SDK bootstrap and a kernel-enforced parent lifetime."""
    venv, code = Path(selection['venv']), Path(selection['code'])
    result = onboarding_sdk.runtime_command(venv, venv.parent / 'runtime-imports', code,
        'clusterctl.onboarding_source', ['--config', selection['config'], '--code-digest',
        selection['code_digest'], '--code-owner', '0', '--ready-fd', str(ready_fd),
        '--expected-config-sha256', selection['config_sha256']])
    if body_observer_fd is not None:
        result.extend(['--body-observer-fd', str(body_observer_fd)])
    # No preexec_fn: admission supervision has live threads. Set PDEATHSIG in
    # the fresh interpreter before any runtime import, checking both race edges.
    guard = ('import os,signal,ctypes,hashlib,json\n'
             f'expected_parent={os.getpid()}\n'
             'if os.getppid()!=expected_parent: raise SystemExit(1)\n'
             'if ctypes.CDLL(None,use_errno=True).prctl(1,signal.SIGKILL,0,0,0)!=0: raise SystemExit(1)\n'
             'if os.getppid()!=expected_parent: raise SystemExit(1)\n'
             f'with open({selection["config"]!r},"rb") as stream: config=json.load(stream)\n'
             f'if hashlib.sha256(json.dumps(config,sort_keys=True,separators=(",", ":")).encode()).hexdigest()!={selection["config_sha256"]!r}: raise SystemExit(1)\n')
    result[5] = guard + result[5]
    return result


class NativeBodyObserver:
    """Serve the H8 child's body reads from its EXISTING registry and admission.

    The inherited socket carries bounded public observations, not credentials.
    Its lifetime is the supervised process; no listener or persistent attention
    is installed. Resource-fence adoption and body capabilities stay separate.
    """
    def __init__(self, state: Path, origin: dict, connection: socket.socket,
                 process, supervisor):
        from .embodiments import Registry
        self.registry = Registry(state)
        self.origin = origin
        self.connection = connection
        self.connection.settimeout(5)
        self.process = process
        self.supervisor = supervisor
        self.thread = threading.Thread(target=self._serve,
            name=f'native-body-observer-{process.pid}', daemon=True)

    def verify(self):
        from .onboarding import OnboardingError
        row = self.registry.status(self.origin['embodiment_id'])
        if (row.get('status') != 'running' or row.get('body_ref') != self.origin['body_ref']
                or row.get('current_incarnation_id') != self.origin['incarnation_id']):
            raise OnboardingError('onboarding_runtime_origin_rejected')

    def snapshot(self, request):
        from .onboarding_runtime import admitted_body_snapshot
        return admitted_body_snapshot(self.origin, self, self.supervisor, request)

    def _serve(self):
        from .onboarding_runtime import receive, send
        try:
            while self.process.poll() is None:
                ready, _, _ = select.select([self.connection], [], [], .25)
                if not ready:
                    continue
                request = receive(self.connection)
                try:
                    response = dict(ok=True, result=self.snapshot(request))
                except Exception:
                    response = dict(ok=False)
                send(self.connection, response)
        except (OSError, ValueError, RuntimeError):
            if not self.supervisor.shutdown_requested and self.process.poll() is None:
                self.supervisor.force_stop('body-observer-unavailable')
        finally:
            self.connection.close()


def verify_ready(state: Path, identity: dict, process_pid: int, selection: dict) -> dict:
    from .distributed_rebirth import _native_peer_observation
    from .matrix_host import matrix_root
    from .rebirth_host import RebirthHostError, _read_json

    root = matrix_root(state, identity['origin']['embodiment_id'])
    try:
        status, me, we, proof = _native_peer_observation(root, _read_json(root / 'runtime.json'))
    except Exception as error:
        raise RebirthHostError('rebirth_host_native_readiness_rejected') from error
    active = sorted(row['embodiment_id'] for row in we.get('embodiments', [])
                    if row.get('manifest_status') == 'active')
    if (status.get('integrity') != 'ok' or status.get('being_ref') != identity['being_ref']
            or status.get('manifest_hash') != identity['manifest_hash']
            or status.get('local_origin') != identity['origin'] or me.get('origin') != identity['origin']
            or identity['origin']['embodiment_id'] not in active
            or proof['process']['pid'] != process_pid
            or status.get('loaded_runtime', {}).get('qualified_startup', {}).get('sdk_digest')
                != selection['sdk_digest']):
        raise RebirthHostError('rebirth_host_native_readiness_mismatch')
    return {'integrity':'ok', 'active_embodiment_ids':active, 'native_process':proof['process'],
                'harness_lifecycle_claimed':False}
