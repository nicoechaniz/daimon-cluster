"""Control recovery and deadlines through the existing native request contract."""
import copy
import os
import socket
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from clusterctl import onboarding_owner_control as control
from clusterctl.onboarding import OnboardingError
from daimon_matrix.local_api import CAPABILITY_SCHEMA, LocalCapability, create_request, request_hash
from clusterctl.owner_process import ConnectedProcessObserver


def fixture(tmp_path):
    tmp_path.chmod(0o700)
    channel = tmp_path / 'tribe.sock'
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(channel))
    command = dict(channel_id='tribe', process_instance_id=str(uuid.uuid4()),
        expected_head='a'*64, operation_id=str(uuid.uuid4()), release_digest='b'*64,
        phase='select', readers=[{'selected': 'frozen-reader'}], expected_roster_sha256='c'*64)
    process = dict(uid=os.geteuid(), pid=os.getpid(), start_ticks=1, boot_id='test-boot')
    application = dict(application_sha256='c'*64, publication_sha256='d'*64,
        visibility=dict(installation_sha256='e'*64))
    runtime = dict(qualified_startup=dict(code_digest='f'*64, matrix_wheel_sha256='1'*64),
        runtime_bundle_sha256='2'*64)
    gate = dict(schema='dm.receiving.reader-selection/v1', channel_id='tribe', controlled=True,
        process_instance_id=command['process_instance_id'], process_id=process['pid'],
        context_sha256='3'*64, head='a'*64, phase='revoke', readers=[],
        operation_id=command['operation_id'], release_digest=command['release_digest'], request_sha256='4'*64)
    state = dict(process=process, server={'embodiment_id': 'test-body'}, gate=gate,
        runtime_status=dict(loaded_runtime=runtime, loaded_application=application))
    capability = LocalCapability(dict(schema=CAPABILITY_SCHEMA, capability_id='test-cap',
        client_id='client:test', key_id='test-key', methods=['runtime.reader-selection'],
        status='active', not_before_ms=0, not_after_ms=2**53-1), b'x'*32)
    calls = []
    class Client:
        lost = False
        corrupt = None
        def prepare(self, method, params):
            calls.append('prepare')
            return create_request(capability, request_id=str(uuid.uuid4()),
                issued_at_ms=time.time_ns()//1_000_000, method=method, params=params, nonce=os.urandom(16))
        def send(self, request):
            calls.append(('send', copy.deepcopy(request)))
            result = {**state['gate'], **{k:command[k] for k in (
                'channel_id','process_instance_id','phase','operation_id','release_digest','readers')},
                'head':'5'*64, 'request_sha256':request_hash(request)}
            state['gate'] = copy.deepcopy(result)
            if self.lost:
                self.lost = False
                raise TimeoutError('lost reply after native CAS')
            if self.corrupt:
                result[self.corrupt] = 'invalid'
            return dict(ok=True, result=result)
    client = Client()
    class Owner:
        root = tmp_path
        socket = channel
        deadline_ns = time.monotonic_ns()+60_000_000_000
        _observer = SimpleNamespace(verify=lambda: calls.append('verify'))
        def status(self):
            calls.append('status')
            return copy.deepcopy(state)
        def _control_directory(self, path):
            path.parent.mkdir(mode=0o700, exist_ok=True)
            return path.parent
        def _client(self, role):
            assert role == 'receiving-controller'
            return client
        def _durable_control(self, path):
            calls.append('durable')
            assert path.exists()
    owner = Owner()
    expected = dict(process=copy.deepcopy(process), server=copy.deepcopy(state['server']),
        selection=control._selection(state))
    path = tmp_path/'receiving-control'/'select.json'
    return owner, client, expected, command, path, state, calls, listener


def test_one_status_and_authenticated_ack_with_exact_retry(tmp_path):
    owner, _client, expected, command, path, _state, calls, listener = fixture(tmp_path)
    try:
        first = control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        raw = path.read_bytes()
        second = control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert second == first and path.read_bytes() == raw
        assert calls.count('status') == 2 and calls.count('prepare') == 1
        sends = [v[1] for v in calls if isinstance(v,tuple)]
        assert sends[0] == sends[1]
        assert first['gate']['readers'] == command['readers']
    finally:
        listener.close()


def test_lost_ack_reuses_original_native_request_without_reauthoring(tmp_path):
    owner, client, expected, command, path, _state, calls, listener = fixture(tmp_path)
    try:
        client.lost = True
        with pytest.raises(TimeoutError):
            control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        raw = path.read_bytes()
        result = control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert result['gate']['phase'] == 'select' and path.read_bytes() == raw
        assert calls.count('prepare') == 1
        sends = [v[1] for v in calls if isinstance(v,tuple)]
        assert sends[0] == sends[1]
    finally:
        listener.close()


def observed_fixture(tmp_path):
    values = fixture(tmp_path)
    owner, original, expected, command, path, state, calls, listener = values
    listener.listen(10)
    process = dict(uid=os.geteuid(), pid=os.getpid(), start_ticks=int(
        Path('/proc/self/stat').read_text().rpartition(')')[2].split()[19]),
        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    expected['process'] = state['process'] = process
    state['gate']['process_id'] = process['pid']
    state['runtime_status']['loaded_runtime']['runtime_id'] = 'fixture-runtime'
    observer = ConnectedProcessObserver().__enter__()
    owner._observer = observer

    @dataclass(frozen=True)
    class Client:
        config: object
        connection_observer: object
        def prepare(self, *args): return original.prepare(*args)
        def send(self, request):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.connect(str(owner.socket))
                with self.connection_observer(connection):
                    return original.send(request)

    client = Client(SimpleNamespace(expected_server=state['server'], runtime_id='fixture-runtime'), observer)
    owner._client = lambda role: client
    return values, observer


@pytest.mark.parametrize('gate_schema', ['dm.receiving.reader-selection/v1', 'dm.receiving.reader-selection/v2'])
@pytest.mark.parametrize('lost_ack', [False, True])
def test_fresh_observation_skips_status_and_exact_retry_pins_real_peer(tmp_path, lost_ack, gate_schema):
    values, observer = observed_fixture(tmp_path)
    owner, client, expected, command, path, state, calls, listener = values
    try:
        client.lost = lost_ack
        state['gate']['schema'] = gate_schema
        observed = copy.deepcopy(state)
        if lost_ack:
            with pytest.raises(TimeoutError):
                control.execute(owner, command, path, expected=expected,
                    deadline_ns=owner.deadline_ns, observation=observed)
        else:
            control.execute(owner, command, path, expected=expected,
                deadline_ns=owner.deadline_ns, observation=observed)
        raw = path.read_bytes()
        result = control.execute(owner, command, path, expected=expected,
            deadline_ns=owner.deadline_ns, observation=copy.deepcopy(state))
        assert path.read_bytes() == raw and result['gate']['phase'] == 'select'
        assert 'status' not in calls and calls.count('prepare') == 1
        sends = [v[1] for v in calls if isinstance(v, tuple)]
        assert len(sends) == 2 and sends[0] == sends[1]
        assert observer.process == expected['process']
    finally:
        observer.__exit__()
        listener.close()


def test_observed_control_refuses_other_socket_peer_before_dispatch(tmp_path):
    values, observer = observed_fixture(tmp_path)
    owner, _client, expected, command, path, state, calls, listener = values
    # The declared process really exists, but it does not own this socket.
    parent = Path('/proc') / str(os.getppid())
    process = {**state['process'], 'pid':os.getppid(), 'start_ticks':int(
        (parent/'stat').read_text().rpartition(')')[2].split()[19])}
    state['process'] = expected['process'] = process
    state['gate']['process_id'] = process['pid']
    try:
        with pytest.raises(OnboardingError, match='process_changed'):
            control.execute(owner, command, path, expected=expected,
                deadline_ns=owner.deadline_ns, observation=state)
        assert path.exists(), 'retain the exact prepared request'
        assert 'status' not in calls and not any(isinstance(v,tuple) for v in calls)
    finally:
        observer.__exit__()
        listener.close()


@pytest.mark.parametrize('fault', ['parent', 'deadline', 'head', 'context'])
def test_observed_control_keeps_existing_refusals(tmp_path, monkeypatch, fault):
    values, observer = observed_fixture(tmp_path)
    owner, client, expected, command, path, state, calls, listener = values
    try:
        if fault == 'parent':
            expected['admission_parent'] = {'pid': -1}
        elif fault == 'deadline':
            owner.deadline_ns = time.monotonic_ns()-1
        elif fault == 'head':
            state['gate']['head'] = '0'*64
        else:
            client.corrupt = 'context_sha256'
        with pytest.raises(OnboardingError, match='parent_changed|deadline_expired|binding_conflict|completion_uncertain'):
            control.execute(owner, command, path, expected=expected,
                deadline_ns=owner.deadline_ns, observation=state)
        assert 'status' not in calls
        assert path.exists() == (fault == 'context')
    finally:
        observer.__exit__()
        listener.close()


@pytest.mark.parametrize('lost_reply', [False, True])
def test_retained_status_keeps_exact_request_but_reads_current_result(tmp_path, lost_reply):
    values, observer = observed_fixture(tmp_path)
    owner, _client, expected, _command, _path, state, calls, listener = values
    owner.expected_process = expected['process']
    capability = LocalCapability(dict(schema=CAPABILITY_SCHEMA, capability_id='status-cap',
        client_id='client:status', key_id='status-key', methods=['runtime.status'],
        status='active', not_before_ms=0, not_after_ms=2**53-1), b's'*32)
    sent = []
    lost = [lost_reply]
    current = [{'ok':True,'result':{'fresh':1}}]
    @dataclass(frozen=True)
    class StatusClient:
        config: object
        connection_observer: object
        def prepare(self, method, params):
            calls.append('status-prepare')
            return create_request(capability, request_id=str(uuid.uuid4()),
                issued_at_ms=time.time_ns()//1_000_000, method=method, params=params, nonce=os.urandom(16))
        def send(self, request):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.connect(str(owner.socket))
                with self.connection_observer(connection):
                    sent.append(copy.deepcopy(request))
                    if lost[0]:
                        lost[0] = False
                        raise TimeoutError('lost status reply')
                    return copy.deepcopy(current[0])
    client = StatusClient(SimpleNamespace(capability=capability,expected_server=state['server'],
        runtime_id='fixture-runtime',runtime_label='fixture'),observer)
    try:
        if lost_reply:
            with pytest.raises(TimeoutError):
                control.RetainedStatusOwner._status_response(owner,client)
        else:
            assert control.RetainedStatusOwner._status_response(owner,client)['result']['fresh']==1
        files = list((tmp_path/'receiving-control').glob('status-*.json'))
        assert len(files)==1
        saved = files[0].read_bytes()
        current[0] = {'ok':True,'result':{'fresh':2}}
        assert control.RetainedStatusOwner._status_response(owner,client)['result']['fresh']==2
        current[0] = {'ok':False,'error':{'code':'runtime_unavailable'}}
        assert control.RetainedStatusOwner._status_response(owner,client)['ok'] is False
        assert files[0].read_bytes()==saved and calls.count('status-prepare')==1
        assert len(sent)==3 and all(request==sent[0] for request in sent)
    finally:
        observer.__exit__()
        listener.close()


def test_expired_retained_status_never_prepares_or_dispatches(tmp_path):
    values, observer = observed_fixture(tmp_path)
    owner, _client, expected, _command, _path, state, calls, listener = values
    owner.expected_process=expected['process']
    owner.deadline_ns=time.monotonic_ns()-1
    capability=SimpleNamespace(descriptor={'exact':'status'})
    client=SimpleNamespace(config=SimpleNamespace(capability=capability,expected_server=state['server'],
        runtime_id='fixture-runtime',runtime_label='fixture'))
    try:
        with pytest.raises(OnboardingError,match='deadline_expired'):
            control.RetainedStatusOwner._status_response(owner,client)
        assert not calls and not list(tmp_path.rglob('status-*.json'))
    finally:
        observer.__exit__()
        listener.close()


@pytest.mark.parametrize('field',['readers','process_instance_id','request_sha256','context_sha256','head'])
def test_invalid_control_ack_never_becomes_a_success(tmp_path,field):
    owner, client, expected, command, path, _state, _calls, listener = fixture(tmp_path)
    try:
        client.corrupt = field
        with pytest.raises(OnboardingError,match='completion_uncertain'):
            control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert path.exists()
    finally:
        listener.close()


@pytest.mark.parametrize('field',['process','server','selection'])
def test_changed_receiving_identity_or_selection_refuses_before_request(tmp_path,field):
    owner, _client, expected, command, path, _state, calls, listener = fixture(tmp_path)
    try:
        expected[field] = {}
        with pytest.raises(OnboardingError,match='process_changed'):
            control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert not path.exists() and 'prepare' not in calls
    finally:
        listener.close()


def test_expired_budget_refuses_before_owner_read(tmp_path):
    owner, _client, expected, command, path, _state, calls, listener = fixture(tmp_path)
    try:
        owner.deadline_ns = time.monotonic_ns()-1
        with pytest.raises(OnboardingError,match='deadline_expired'):
            control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert not calls and not path.exists()
    finally:
        listener.close()


def test_guest_parent_mismatch_refuses_before_request(tmp_path,monkeypatch):
    owner, _client, expected, command, path, _state, calls, listener = fixture(tmp_path)
    class Parent:
        process = {'pid': -1}
        def __enter__(self):return self
        def __exit__(self,*args):pass
    monkeypatch.setattr(control,'ParentProcessPresence',lambda process:Parent())
    expected['admission_parent'] = {'pid':1}
    try:
        with pytest.raises(OnboardingError,match='parent_changed'):
            control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert not path.exists() and 'prepare' not in calls
    finally:
        listener.close()


def test_deadline_after_retention_keeps_request_without_dispatch(tmp_path):
    owner, _client, expected, command, path, _state, calls, listener = fixture(tmp_path)
    durable = owner._durable_control
    def slow_durable(selected):
        durable(selected)
        time.sleep(.12)
    owner._durable_control = slow_durable
    owner.deadline_ns = time.monotonic_ns()+50_000_000
    try:
        with pytest.raises(OnboardingError,match='deadline_expired'):
            control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert path.exists() and not any(isinstance(v,tuple) for v in calls)
    finally:
        listener.close()


def test_mismatched_time_namespace_refuses_before_opening_owner(monkeypatch,capsys):
    monkeypatch.setattr(control.sys,'argv',['owner-control','--root','/unopened',
        '--socket','/unopened/socket','--path','/unopened/request',
        '--deadline-ns',str(time.monotonic_ns()+5_000_000_000),'--time-namespace','time:[other]'])
    monkeypatch.setattr(control,'OwnerGroupClient',lambda *a,**k:pytest.fail('opened owner'))
    assert control.main()==1
    assert 'receiving_owner_deadline_binding_required' in capsys.readouterr().err


def test_observe_only_reads_known_receiver_once_without_authoring(tmp_path):
    owner, _client, expected, _command, path, _state, calls, listener = fixture(tmp_path)
    try:
        result = control.observe(owner,expected=expected,deadline_ns=owner.deadline_ns)
        assert result['process'] == expected['process']
        assert calls.count('status') == 1 and 'prepare' not in calls
        assert not path.exists()
    finally:
        listener.close()


def identity_fixture(tmp_path, monkeypatch):
    import hashlib
    from daimon_matrix.canonical import canonical_bytes
    from clusterctl import onboarding_owner_client
    values = fixture(tmp_path)
    owner, _client, expected, _command, _path, state, calls, _listener = values
    state['runtime_status']['loaded_application']['loaded_base_sha256'] = hashlib.sha256(
        canonical_bytes(state['runtime_status']['loaded_runtime'])).hexdigest()
    def existing_identity(**kwargs):
        calls.append(('existing-qualified-identity', kwargs))
        return {**copy.deepcopy(state), 'verified_identity': {'real-helper-proof': True}}
    owner.qualified_identity = existing_identity
    def existing_catalog(payload, **kwargs):
        calls.append(('existing-catalog', payload, kwargs))
        return {'current': True}
    monkeypatch.setattr(onboarding_owner_client, 'observe_selected_tooling', existing_catalog)
    return values


@pytest.mark.parametrize('admitted', [False, True])
def test_short_identity_keeps_current_owner_verification_catalog_and_parent(tmp_path, monkeypatch, admitted):
    owner, _client, expected, _command, path, state, calls, listener = identity_fixture(tmp_path, monkeypatch)
    parent_events = []
    class Parent:
        process = {'pid': 17}
        def __enter__(self):
            parent_events.append('open')
            return self
        def __exit__(self,*args): parent_events.append('close')
        def verify(self): parent_events.append('verify')
    if admitted:
        monkeypatch.setattr(control, 'ParentProcessPresence', lambda process: Parent())
        expected['admission_parent'] = {'pid': 17}
    try:
        horizon = time.time_ns()//1_000_000+10000
        result = control.qualified_identity(owner,expected=expected,expires_at_ms=horizon,
            deadline_ns=owner.deadline_ns,code=tmp_path,require_admitted=admitted,native_tooling={'accepted':'unchanged'})
        assert ('existing-qualified-identity',dict(expires_at_ms=horizon,require_admitted=admitted)) in calls
        catalog = next(c for c in calls if c[0]=='existing-catalog')
        assert catalog[1]=={'accepted':'unchanged'} and catalog[2]['deadline_ns']==owner.deadline_ns
        assert catalog[2]['startup']==state['runtime_status']['loaded_runtime']['qualified_startup']
        assert catalog[2]['receiving']['verified_identity']=={'real-helper-proof': True}
        assert result['group']==dict(channel_id='tribe',socket=str(owner.socket))
        assert result['admission_parent']==({'pid':17} if admitted else None)
        assert parent_events==(['open','verify','close'] if admitted else [])
        assert not path.exists() and 'prepare' not in calls and 'status' not in calls
    finally:
        listener.close()


@pytest.mark.parametrize('changed', ['process','selection','loaded_base','parent'])
def test_short_identity_rejects_changed_loaded_binding_before_catalog(tmp_path,monkeypatch,changed):
    owner, _client, expected, _command, _path, state, calls, listener = identity_fixture(tmp_path,monkeypatch)
    if changed in ('process','selection'):
        expected[changed]={}
    if changed=='loaded_base':
        state['runtime_status']['loaded_application']['loaded_base_sha256']='0'*64
    if changed=='parent':
        expected['admission_parent']={'pid':1}
        class Parent:
            process={'pid':2}
            def __enter__(self):return self
            def __exit__(self,*args):pass
        monkeypatch.setattr(control,'ParentProcessPresence',lambda process:Parent())
    try:
        with pytest.raises(OnboardingError):
            control.qualified_identity(owner,expected=expected,expires_at_ms=time.time_ns()//1_000_000+10000,
                deadline_ns=owner.deadline_ns,code=tmp_path,require_admitted=expected.get('admission_parent') is not None,native_tooling={'accepted':True})
        assert not any(c[0]=='existing-catalog' for c in calls if isinstance(c,tuple))
    finally:
        listener.close()


def test_short_identity_catalog_consumes_same_absolute_budget(tmp_path,monkeypatch):
    from clusterctl import onboarding_owner_client
    owner, _client, expected, _command, _path, _state, _calls, listener = identity_fixture(tmp_path,monkeypatch)
    owner.deadline_ns=time.monotonic_ns()+50_000_000
    def slow_catalog(*args,**kwargs):
        time.sleep(.12)
        return {'current':True}
    monkeypatch.setattr(onboarding_owner_client,'observe_selected_tooling',slow_catalog)
    try:
        with pytest.raises(OnboardingError,match='deadline_expired'):
            control.qualified_identity(owner,expected=expected,expires_at_ms=time.time_ns()//1_000_000+10000,
                deadline_ns=owner.deadline_ns,code=tmp_path,require_admitted=expected.get('admission_parent') is not None,native_tooling={'accepted':True})
    finally:
        listener.close()


def test_short_identity_guest_requires_expected_parent_before_owner_query(tmp_path,monkeypatch):
    owner, _client, expected, _command, _path, _state, calls, listener = identity_fixture(tmp_path,monkeypatch)
    try:
        with pytest.raises(OnboardingError,match='parent_changed'):
            control.qualified_identity(owner,expected=expected,expires_at_ms=time.time_ns()//1_000_000+10000,
                deadline_ns=owner.deadline_ns,code=tmp_path,require_admitted=True)
        assert not calls
    finally:
        listener.close()


def test_short_identity_socket_change_during_catalog_refuses(tmp_path,monkeypatch):
    from clusterctl import onboarding_owner_client
    owner, _client, expected, _command, _path, _state, _calls, listener = identity_fixture(tmp_path,monkeypatch)
    def replaced(*args,**kwargs):
        owner.socket.unlink()
        owner.socket.write_bytes(b'replacement')
        return {'current':True}
    monkeypatch.setattr(onboarding_owner_client,'observe_selected_tooling',replaced)
    try:
        with pytest.raises(OnboardingError,match='socket_changed'):
            control.qualified_identity(owner,expected=expected,expires_at_ms=time.time_ns()//1_000_000+10000,
                deadline_ns=owner.deadline_ns,code=tmp_path,require_admitted=False,native_tooling={'accepted':True})
    finally:
        listener.close()


@pytest.mark.parametrize('wrong', [False, True])
def test_observer_catalog_uses_actual_body_sdk_not_observer_sdk(tmp_path, monkeypatch, wrong):
    import hashlib
    from daimon_matrix.canonical import canonical_bytes
    owner, _, expected, _, _, state, calls, listener = identity_fixture(tmp_path, monkeypatch)
    observer = tmp_path / ('a' * 64) / 'venv'
    body = tmp_path / ('b' * 64) / 'venv'
    state['runtime_status']['loaded_runtime']['qualified_startup']['sdk_digest'] = 'b' * 64
    state['runtime_status']['loaded_application']['loaded_base_sha256'] = hashlib.sha256(
        canonical_bytes(state['runtime_status']['loaded_runtime'])).hexdigest()
    monkeypatch.setattr(control.sys, 'prefix', str(observer))
    selected = tmp_path / ('c' * 64) / 'venv' if wrong else body
    try:
        if wrong:
            with pytest.raises(OnboardingError, match='receiving_control_binding_conflict'):
                control.qualified_identity(owner, expected=expected, expires_at_ms=time.time_ns() // 1_000_000 + 10000,
                    deadline_ns=owner.deadline_ns, code=tmp_path, require_admitted=False,
                    native_tooling={'accepted': 'actual body'}, body_venv=selected)
            assert not any(isinstance(call, tuple) and call[0] == 'existing-catalog' for call in calls)
        else:
            control.qualified_identity(owner, expected=expected, expires_at_ms=time.time_ns() // 1_000_000 + 10000,
                deadline_ns=owner.deadline_ns, code=tmp_path, require_admitted=False,
                native_tooling={'accepted': 'actual body'}, body_venv=selected)
            catalog = next(call for call in calls if isinstance(call, tuple) and call[0] == 'existing-catalog')
            assert catalog[2]['venv'] == body and catalog[2]['venv'] != observer
    finally:
        listener.close()
