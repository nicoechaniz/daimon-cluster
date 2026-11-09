"""Qualified native Matrix profile under the ordinary H8 admission supervisor.

This selects existing Source hosting, including its approved group applications;
it does not create authority, provision applications or start a model harness.
"""
from __future__ import annotations

import hmac
import os
import re
import select
import socket
import threading
from pathlib import Path

from . import onboarding_code_successor, onboarding_release, onboarding_sdk
from .onboarding import digest

PROFILE_ERRORS = frozenset({
    'rebirth_host_native_profile_selection_conflict', 'rebirth_host_native_profile_operation_required',
    'rebirth_host_native_profile_binding_changed', 'rebirth_host_native_profile_exit_unobserved',
    'rebirth_host_native_profile_start_unconfirmed', 'rebirth_host_native_profile_start_unobserved',
    'rebirth_host_native_profile_deadline_expired', 'rebirth_host_native_profile_owner_unconfirmed',
    'rebirth_host_native_profile_published_group_required', 'rebirth_host_native_profile_migration_unconfirmed',
    'rebirth_host_native_profile_selection_unconfirmed', 'rebirth_host_native_profile_maintenance_spec_required',
    'rebirth_host_native_profile_journal_full',
})


def _profile(value: dict) -> dict:
    if (not isinstance(value, dict) or set(value) != {
            'schema', 'config', 'code', 'code_digest', 'home'}
            or value['schema'] != 'dm.cluster.rebirth-native-profile/v1'
            or not isinstance(value['code_digest'], str)
            or re.fullmatch('[0-9a-f]{64}', value['code_digest']) is None
            or any(not isinstance(value[key], str) or not Path(value[key]).is_absolute()
                or '..' in Path(value[key]).parts for key in ('config', 'code', 'home'))):
        raise ValueError('profile')
    return dict(value)


def select_profile(path: Path, candidate: dict, *, previous: dict) -> dict:
    """CAS only a prepared native profile, retaining its config and SDK home.

    The owning maintenance journal retains `previous` and qualifies the candidate
    before quiescence. This writer does not stop/start a service or acquire body
    admission. An exact retry observes selection and restores directory durability;
    it never replaces a concurrent successor. No per-update backup files accrue.
    """
    from .onboarding_service import selection_lock
    from .rebirth import _atomic_json, _read_json
    from .rebirth_host import RebirthHostError
    try:
        previous, candidate = _profile(previous), _profile(candidate)
        if any(previous[key] != candidate[key] for key in ('schema', 'config', 'home')):
            raise ValueError('binding')
        with selection_lock(path):
            current = _read_json(path)
            if current not in (previous, candidate):
                raise ValueError('concurrent profile')
            if current != candidate:
                _atomic_json(path, candidate)
            else:
                descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            if _read_json(path) != candidate:
                raise ValueError('profile readback')
            return dict(schema='cluster-native-profile-selected/v1',
                previous_sha256=digest(previous), selected_sha256=digest(candidate),
                selected=True, loaded_readiness='unobserved')
    except (OSError, ValueError) as error:
        raise RebirthHostError('rebirth_host_native_profile_selection_conflict') from error


def start_record(journal, target: str, intent: dict, *, actor: str, embodiment_id: str,
                 recover_operation_id: str | None = None) -> dict:
    """Retain a qualified SDK-only successor under the caller's start lock.

    Preparation already verifies the protected owner selection. Starting still
    requires the ordinary singleton admission; this plans no physical effect.
    Original startup/audit records remain immutable and exact retries reuse the
    current planned or completed record instead of manufacturing another birth.
    """
    from .rebirth_host import RebirthHostError

    previous = journal.latest_for_target(target)
    if previous is None and recover_operation_id is not None:
        raise RebirthHostError('rebirth_host_journal_conflict')
    key = f"rebirth-start:{intent['activation_id']}"
    retained = dict(intent)
    if previous is not None:
        prior = dict(previous['intent'])
        anchor = prior.pop('native_start_predecessor', None)
        recovery = prior.pop('native_start_recovery', None)
        if recovery is not None:
            failed = journal.get(recovery.get('operation_id')) if isinstance(recovery, dict) else None
            if (not isinstance(recovery, dict) or set(recovery) != {'operation_id', 'intent_hash'}
                    or failed is None or failed['target'] != target or failed['operation'] != 'rebirth-start'
                    or failed['state'] != 'compensated' or failed.get('runtime_observation')
                    or failed.get('logical_observation')
                    or (failed.get('result') or {}).get('schema') != 'dm.cluster.native-unready-recovery/v1'
                    or failed['intent_hash'] != recovery['intent_hash']):
                raise RebirthHostError('rebirth_host_journal_conflict')
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
                'logical-committed', 'audited', 'completed', 'compensated'}:
            raise RebirthHostError('rebirth_host_journal_conflict')
        if recover_operation_id is not None and recover_operation_id not in {
                previous['operation_id'], None if recovery is None else recovery['operation_id']}:
            raise RebirthHostError('rebirth_host_journal_conflict')
        if prior == intent:
            return previous
        before, after = prior.get('runtime_call'), intent.get('runtime_call')
        recovering = (recover_operation_id == previous['operation_id']
            and (previous['state'] == 'runtime-dispatching' or (
                previous['state'] == 'compensated'
                and (previous.get('result') or {}).get('schema') == 'dm.cluster.native-unready-recovery/v1'
                and previous['result'].get('replacement_intent_hash') == digest(intent)))
            and not previous.get('runtime_observation') and not previous.get('logical_observation'))
        if (previous['state'] != 'completed' and not recovering
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
        if recovering:
            if previous['state'] == 'runtime-dispatching':
                journal.advance(previous['operation_id'], 'compensated',
                    expected_runtime_observation=None, result={
                        'schema': 'dm.cluster.native-unready-recovery/v1',
                        'outcome': 'startup-attempt-superseded-before-ready',
                        'replacement_intent_hash': digest(intent),
                        'native_effects_reconciled': False})
            if anchor is not None:
                retained['native_start_predecessor'] = anchor
            retained['native_start_recovery'] = {
                'operation_id': previous['operation_id'], 'intent_hash': previous['intent_hash']}
        else:
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
        value = _profile(_read_json(_owner_file(profile)))
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
        from .onboarding_runtime import admitted_observation
        return admitted_observation(self.origin, self, self.supervisor, request)

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


class ProfileMaintenance:
    """Resume one profile update through the existing operation journal.

    The owner adapter supplies qualified, same-body Source observations and
    bounded owner CLI calls. The manager controls only its bound Matrix unit.
    Neither adapter starts a model or changes native goals/accounting.
    """

    def __init__(self, journal, operation_id: str, owner, manager, candidate: dict):
        self.journal, self.operation_id = journal, operation_id
        self.owner, self.manager, self.candidate = owner, manager, _profile(candidate)

    def _record(self, key: str, value: dict) -> dict:
        row = self.journal.get(self.operation_id)
        observations = dict(row['runtime_observation'] or {})
        if key in observations and observations[key] != value:
            raise ValueError('native profile effect changed')
        observations[key] = value
        self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
            expected_runtime_observation=row['runtime_observation'])
        return value

    def run(self, *, deadline_ns: int) -> dict:
        import time
        from .onboarding_service import GuestServiceBootstrap
        from .owner_process import ParentProcessPresence, observe_process_exit
        from .rebirth_host import RebirthHostError
        def budget():
            GuestServiceBootstrap._budget(deadline_ns)
        budget()
        with self.journal.mutation_lock(self.operation_id):
            row = self.journal.get(self.operation_id)
            if row is None or row['operation'] != 'receiving-update':
                raise RebirthHostError('rebirth_host_native_profile_operation_required')
            if row['state'] == 'completed':
                return {**row['result'],'retained_completion':True}
            before = row['expected_precondition']
            if (row['intended_transition'] != {'native_profile':self.candidate}
                    or set(before) != {'native_profile', 'receiving', 'service', 'scope'}):
                raise RebirthHostError('rebirth_host_native_profile_binding_changed')
            previous, receiving, service, scope = (before[key] for key in (
                'native_profile', 'receiving', 'service', 'scope'))
            if any(previous[key] != self.candidate[key] for key in ('schema','config','home')):
                raise RebirthHostError('rebirth_host_native_profile_binding_changed')
            def unchanged():
                budget()
                current = self.manager.inspect(deadline_ns=deadline_ns)
                if (current['unit_sha256'] != service['unit_sha256']
                        or current.get('dropins',{}) != service.get('dropins',{})):
                    raise RebirthHostError('rebirth_host_native_profile_binding_changed')
                return current
            effects = dict(row['runtime_observation'] or {})
            if row['state'] == 'planned':
                self.journal.advance(self.operation_id,'runtime-dispatching')
            if 'quiesced' not in effects:
                if self.owner.profile() != previous:
                    raise RebirthHostError('rebirth_host_native_profile_binding_changed')
                current = unchanged()
                processes = (receiving['process'], scope['admission_parent'])
                if not all(observe_process_exit(process) for process in processes):
                    with ParentProcessPresence(receiving['process']) as family:
                        if family.process != scope['admission_parent']:
                            raise RebirthHostError('rebirth_host_native_profile_binding_changed')
                        associated = {**receiving, 'admission_parent':family.process}
                        if self.manager.bind_admitted_process(associated,current) != scope:
                            raise RebirthHostError('rebirth_host_native_profile_binding_changed')
                        self._record('stop_intent',dict(scope=scope,service_sha256=service['unit_sha256']))
                        self.manager.stop(deadline_ns=deadline_ns)
                        for pinned in (family.child, family.parent):
                            if not pinned.wait_for_exit(min(60.0,max(0,(deadline_ns-time.monotonic_ns())/1e9))):
                                raise RebirthHostError('rebirth_host_native_profile_exit_unobserved')
                current = unchanged()
                if current['manager']['ActiveState'] != 'inactive':
                    raise RebirthHostError('rebirth_host_native_profile_exit_unobserved')
                effects['quiesced'] = self._record('quiesced',dict(process=receiving['process'],
                    admission_parent=scope['admission_parent'],exit_observed=True))
            if 'started' not in effects:
                current = unchanged()
                new_start = 'start_intent' not in effects
                if new_start:
                    current_profile = self.owner.profile()
                    if (current_profile != previous and not (
                            'catalogs_migrated' in effects and current_profile == self.candidate)):
                        raise RebirthHostError('rebirth_host_native_profile_binding_changed')
                    if (current['manager']['ActiveState'] != 'inactive'
                            or not all(observe_process_exit(process) for process in (
                                receiving['process'],scope['admission_parent']))):
                        raise RebirthHostError('rebirth_host_native_profile_exit_unobserved')
                    if 'catalogs_migrated' not in effects:
                        effects['catalogs_migrated'] = self._record('catalogs_migrated',
                            self.owner.migrate(self.candidate,receiving,operation_id=self.operation_id,
                                deadline_ns=deadline_ns))
                    if 'profile_selected' not in effects:
                        effects['profile_selected'] = self._record('profile_selected',
                            self.owner.select(self.candidate,previous=previous,deadline_ns=deadline_ns))
                    self._record('start_intent',dict(selected_sha256=digest(self.candidate)))
                current = unchanged()
                if self.owner.profile() != self.candidate:
                    raise RebirthHostError('rebirth_host_native_profile_binding_changed')
                if current['manager']['ActiveState'] == 'inactive':
                    if not new_start:
                        raise RebirthHostError('rebirth_host_native_profile_start_unconfirmed')
                    self.manager.start(deadline_ns=deadline_ns,pre_start=unchanged)
                elif current['manager']['ActiveState'] not in {'active','activating'}:
                    raise RebirthHostError('rebirth_host_native_profile_start_unobserved')
                # The owner status call is bounded by this same deadline; an
                # accepted start with unavailable readiness stays unconfirmed.
                while True:
                    try:
                        observed = self.owner.status(self.candidate,deadline_ns=deadline_ns)
                        break
                    except RebirthHostError as error:
                        if str(error) != 'rebirth_host_native_profile_owner_unconfirmed':
                            raise
                        budget()
                        if unchanged()['manager']['ActiveState'] not in {'active','activating'}:
                            raise
                        # An accepted start is observed, never issued again.
                        time.sleep(min(0.2,max(0,(deadline_ns-time.monotonic_ns())/1e9)))
                loaded = observed['runtime_status']['loaded_runtime']
                prior_runtime = receiving['runtime_status']['loaded_runtime']
                application = observed['runtime_status']['loaded_application']
                prior_application = receiving['runtime_status']['loaded_application']
                if (observed['server'] != receiving['server']
                        or loaded['qualified_startup']['code_digest'] != self.candidate['code_digest']
                        or loaded['runtime_bundle_sha256'] != prior_runtime['runtime_bundle_sha256']
                        or any(application[key] != prior_application[key]
                            for key in ('application_sha256','publication_sha256'))
                        or application['visibility']['installation_sha256']
                            != prior_application['visibility']['installation_sha256']):
                    raise RebirthHostError('rebirth_host_native_profile_binding_changed')
                with ParentProcessPresence(observed['process']) as family:
                    observed['admission_parent'] = family.process
                    self.manager.bind_admitted_process(observed,unchanged())
                effects['started'] = self._record('started',observed)
            budget()
            result = dict(schema='cluster-native-profile-maintenance-result/v1',operation_id=self.operation_id,
                candidate_digest=self.candidate['code_digest'],process=effects['started']['process'],
                origin=effects['started']['server'],loaded=effects['started'],
                complete=True,receiving_readiness='unobserved')
            self.journal.advance(self.operation_id,'completed',result=result)
            return result


class ProfileOwner:
    """Existing private owner and qualified Source CLI, entered after UID drop."""

    def __init__(self, path: Path):
        import pwd
        self.path = path
        info = path.lstat()
        self.uid = info.st_uid
        self.gid = pwd.getpwuid(self.uid).pw_gid
        self.profile()

    def profile(self) -> dict:
        import json
        from .rebirth import canonical_bytes
        raw = onboarding_release.regular(self.path,uid=self.uid,limit=65536)
        if self.path.stat().st_mode & 0o077:
            raise ValueError('native profile must be owner private')
        value = _profile(json.loads(raw))
        if canonical_bytes(value) != raw.rstrip(b'\n'):
            raise ValueError('native profile must be canonical')
        return value

    def _call(self, argv: list[str], *, deadline_ns: int, payload: dict | None = None) -> dict:
        import json
        import subprocess
        import time
        from .onboarding_receiving_update import _run_owner
        from .rebirth_host import RebirthHostError
        remaining = min(30.0,(deadline_ns-time.monotonic_ns())/1e9)
        if remaining <= 0:
            raise RebirthHostError('rebirth_host_native_profile_deadline_expired')
        options = {} if os.geteuid() == self.uid and os.getegid() == self.gid else dict(
            user=self.uid,group=self.gid,extra_groups=())
        try:
            result = _run_owner(argv,input=None if payload is None else json.dumps(payload),text=True,
                capture_output=True,timeout=remaining,env={'PATH':os.defpath,'LANG':'C.UTF-8'},**options)
        except (OSError, subprocess.TimeoutExpired):
            raise RebirthHostError('rebirth_host_native_profile_owner_unconfirmed') from None
        if (result.returncode or len(result.stdout.encode()) > 1024*1024
                or time.monotonic_ns() >= deadline_ns):
            raise RebirthHostError('rebirth_host_native_profile_owner_unconfirmed')
        value = json.loads(result.stdout)
        if not isinstance(value,dict):
            raise RebirthHostError('rebirth_host_native_profile_owner_unconfirmed')
        return value

    def _source(self, profile: dict, args: list[str], *, deadline_ns: int,
                payload: dict | None = None) -> dict:
        import time
        deadline_ns = min(deadline_ns,time.monotonic_ns()+30_000_000_000)
        code = Path(profile['code'])
        onboarding_release.verify(code,profile['code_digest'],uid=0)
        parameters = onboarding_code_successor.sdk_parameters(code,uid=0)
        if not parameters:
            raise ValueError('qualified native SDK required')
        sdk = onboarding_sdk.verify(code,uid=0,**parameters)
        venv = Path(profile['home'])/'.local/share/daimon-matrix/sdk'/digest(sdk)/'venv'
        argv = onboarding_sdk.runtime_command(venv,venv.parent/'runtime-imports',code,
            'clusterctl.onboarding_source',['--config',profile['config'],
            '--code-digest',profile['code_digest'],'--code-owner','0',
            '--observation-deadline-ns',str(deadline_ns),*args])
        return self._call(argv,deadline_ns=deadline_ns,payload=payload)

    def status(self, profile: dict, *, deadline_ns: int) -> dict:
        return self._source(profile,['--owner-status'],deadline_ns=deadline_ns)

    def migrate(self, profile: dict, receiving: dict, *, operation_id: str, deadline_ns: int) -> dict:
        from .rebirth_host import RebirthHostError
        status = receiving['runtime_status']
        app = status['loaded_application']
        visibility = app['visibility']
        expected = dict(selected=receiving['group'],application_sha256=app['application_sha256'],
            publication_sha256=app['publication_sha256'],
            installation_sha256=visibility['installation_sha256'],outbound_release=True,
            policy_sha256=visibility['policy_sha256'])
        if visibility['release_enabled'] is not True:
            raise RebirthHostError('rebirth_host_native_profile_published_group_required')
        request = dict(operation_id=operation_id,runtime_sha256=status['loaded_runtime']['runtime_bundle_sha256'],
            origin=receiving['server'],group=expected)
        result = self._source(profile,['--visibility-migration','-'],deadline_ns=deadline_ns,payload=request)
        if (result.get('schema') != 'cluster-native-visibility-migrated/v1'
                or any(result.get(key) != value for key,value in request.items() if key != 'origin')
                or type(result.get('catalog_schema_version')) is not int):
            raise RebirthHostError('rebirth_host_native_profile_migration_unconfirmed')
        return result

    def select(self, candidate: dict, *, previous: dict, deadline_ns: int) -> dict:
        import sys
        from .onboarding_service import code_command
        from .rebirth_host import RebirthHostError
        argv = code_command(Path(sys.executable),Path(__file__).resolve().parents[1],
            'clusterctl.rebirth_native',['--profile-selection',str(self.path)])
        result = self._call(argv,deadline_ns=deadline_ns,payload=dict(candidate=candidate,previous=previous))
        if (result.get('schema') != 'cluster-native-profile-selected/v1'
                or result.get('selected_sha256') != digest(candidate)
                or result.get('previous_sha256') != digest(previous)):
            raise RebirthHostError('rebirth_host_native_profile_selection_unconfirmed')
        return result


def run_profile_maintenance(spec: dict, *, check_only: bool = False,
                            deadline_ns: int | None = None) -> dict:
    """One bounded H8 update, using existing owner/service/journal controls."""
    import grp
    import pwd
    import time
    from .onboarding_service import MatrixProfileService
    from .operation_journal import OperationJournal
    from .owner_process import ParentProcessPresence
    from .rebirth_host import RebirthHostError
    fields = {'schema','operation_id','profile','candidate','unit','journal','max_seconds'}
    if (not isinstance(spec,dict) or set(spec) != fields
            or spec['schema'] != 'cluster-native-profile-maintenance/v1'
            or type(spec['max_seconds']) is not int or not 1 <= spec['max_seconds'] <= 180
            or not isinstance(spec['operation_id'],str)
            or re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',spec['operation_id']) is None
            or any(not isinstance(spec[key],str) or not Path(spec[key]).is_absolute()
                or '..' in Path(spec[key]).parts for key in ('profile','unit','journal'))
            or os.geteuid() != 0):
        raise RebirthHostError('rebirth_host_native_profile_maintenance_spec_required')
    candidate = _profile(spec['candidate'])
    deadline = time.monotonic_ns()+spec['max_seconds']*1_000_000_000
    if deadline_ns is not None:
        deadline = min(deadline,deadline_ns)
    owner = ProfileOwner(Path(spec['profile']))
    manager = MatrixProfileService(Path(spec['unit']),user=pwd.getpwuid(owner.uid).pw_name,
        group=grp.getgrgid(owner.gid).gr_name)
    journal = OperationJournal.existing(Path(spec['journal']))
    row = None if journal is None else journal.get(spec['operation_id'])
    intent = dict(native_profile_maintenance=spec)
    if row is not None:
        if row['intent'].get('native_profile_maintenance') != spec:
            raise RebirthHostError('rebirth_host_native_profile_binding_changed')
    else:
        previous = owner.profile()
        if any(previous[key] != candidate[key] for key in ('schema','config','home')):
            raise RebirthHostError('rebirth_host_native_profile_binding_changed')
        # The successor CLI validates its immutable SDK/import context before
        # observing the still-serving predecessor. No offline runtime is loaded.
        observed = owner.status(candidate,deadline_ns=deadline)
        loaded = observed['runtime_status']['loaded_runtime']
        if (observed['process']['uid'] != owner.uid
                or loaded['qualified_startup']['code_digest'] != previous['code_digest']):
            raise RebirthHostError('rebirth_host_native_profile_binding_changed')
        inspected = manager.inspect(deadline_ns=deadline)
        with ParentProcessPresence(observed['process']) as family:
            associated = {**observed,'admission_parent':family.process}
            scope = manager.bind_admitted_process(associated,inspected)
        if check_only:
            return dict(schema='cluster-native-profile-maintenance-check/v1',qualified=True,
                process=observed['process'],candidate_digest=candidate['code_digest'],effects='none')
        if previous == candidate:
            return dict(schema='cluster-native-profile-maintenance-result/v1',complete=True,
                operation_id=spec['operation_id'],candidate_digest=candidate['code_digest'],
                process=observed['process'],origin=observed['server'],loaded=observed,
                receiving_readiness='unobserved',unchanged=True)
        journal = journal or OperationJournal(Path(spec['journal']))
        from . import being_seed
        with being_seed._locked(journal.path.parent):
            # Dedicated append-only maintenance history: reserve8MiB for the
            # bounded in-flight records before admitting another operation.
            size = sum(path.stat().st_size for path in journal.path.parent.glob('operation-journal.sqlite3*'))
            records = journal.list_all()
            pending = sum(record['state'] != 'completed' for record in records)
            if size+(pending+1)*8*1024**2 > 64*1024**2 or len(records) >= 64:
                raise RebirthHostError('rebirth_host_native_profile_journal_full')
            target = 'native-profile:' + str(owner.path)
            prior = journal.latest_for_target(target)
            if prior is not None and prior['state'] != 'completed':
                raise RebirthHostError('rebirth_host_native_profile_operation_required')
            row = journal.plan(operation='receiving-update',target=target,
                idempotency_key='native-profile:'+spec['operation_id'],operation_id=spec['operation_id'],
                intent=intent,expected_precondition=dict(native_profile=previous,receiving=observed,
                    service=inspected,scope=scope),intended_transition=dict(native_profile=candidate),
                audit_identity=dict(actor='native-profile-maintenance'),allow_terminal_successor=True)
    assert journal is not None and row is not None
    if check_only:
        observed = owner.status(owner.profile(),deadline_ns=deadline)
        with ParentProcessPresence(observed['process']) as family:
            manager.bind_admitted_process({**observed,'admission_parent':family.process},
                manager.inspect(deadline_ns=deadline))
        return dict(schema='cluster-native-profile-maintenance-check/v1',qualified=True,
            operation_id=spec['operation_id'],retained_state=row['state'],
            process=observed['process'],effects='none')
    return ProfileMaintenance(journal,spec['operation_id'],owner,manager,candidate).run(deadline_ns=deadline)


def main(argv=None) -> int:
    """Owner-side file selection only; lifecycle stays with the root operator."""
    import argparse
    import json
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile-selection',required=True,type=Path)
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read(65537)
        value = json.loads(raw) if len(raw) <= 65536 else None
        if not isinstance(value,dict) or set(value) != {'candidate','previous'}:
            raise ValueError('selection request')
        print(json.dumps(select_profile(args.profile_selection,value['candidate'],previous=value['previous'])))
        return 0
    except Exception:
        print(json.dumps({'error':'native_profile_selection_unconfirmed'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
