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
                'schema': ('dm.receiving.reader-selection/v2' if command.get('schema') == 'dm.runtime.reader-selection/v2' else 'dm.receiving.reader-selection/v1'),
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


@pytest.mark.parametrize('command_schema', [None, 'dm.runtime.reader-selection/v2'])
@pytest.mark.parametrize('gate_schema', ['dm.receiving.reader-selection/v1', 'dm.receiving.reader-selection/v2'])
@pytest.mark.parametrize('lost_ack', [False, True])
def test_fresh_observation_skips_status_and_exact_retry_pins_real_peer(tmp_path, lost_ack, gate_schema, command_schema):
    values, observer = observed_fixture(tmp_path)
    owner, client, expected, command, path, state, calls, listener = values
    try:
        client.lost = lost_ack
        state['gate']['schema'] = gate_schema
        if command_schema is not None:
            command['schema'] = command_schema
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
    capability=SimpleNamespace(descriptor={'exact':'status'},methods=['runtime.status'])
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


@pytest.mark.parametrize('error', ['invalid_params', 'authority_revoked', 'runtime_unavailable'])
def test_status_view_fallback_requires_authenticated_unsupported_params(error):
    from clusterctl.onboarding_receiving_update import OwnerGroupClient
    calls = []
    class Client:
        config = SimpleNamespace(capability=SimpleNamespace(methods=['runtime.status','scope.me']))
        def invoke(self, method, params):
            calls.append((method, params))
            return None, {'ok': False, 'error': {'code': error}}
        def runtime_status(self):
            calls.append(('legacy', {}))
            return None, {'ok': True, 'result': {'legacy': True}}
    response = OwnerGroupClient._status_response(None, Client())
    assert len(calls) == (2 if error == 'invalid_params' else 1)
    assert response['ok'] is (error == 'invalid_params')


def test_new_receiving_identity_uses_fresh_same_response_without_scope_projection():
    from clusterctl.onboarding_receiving_update import OwnerGroupClient
    from tests.test_receiving_cohort_control import identity_fixture
    response, status, server = identity_fixture()
    status.update(schema='dm.runtime.receiving-status/v1', identity=response['result'])
    owner = SimpleNamespace(status=lambda: dict(runtime_status=status, server=server),
        _client=lambda *args: pytest.fail('redundant full scope/projection read'))
    assert OwnerGroupClient.identity(owner, require_admitted=True)['identity']['origin'] == server
    response['result']['body']['state'] = 'stopped'
    with pytest.raises(OnboardingError, match='admission_conflict'):
        OwnerGroupClient.identity(owner, require_admitted=True)


@pytest.fixture(params=['optimized','classic'])
def auth_native_control(tmp_path, monkeypatch, request):
    """Real native HMAC/freshness and gate CAS; no child/model/daemon input."""
    from daimon_matrix.local_api import authenticate_request
    from daimon_matrix.native_egress import MandatoryEgressController, NativeEgressError
    owner, first, expected, command, path, state, calls, listener = fixture(tmp_path)
    clock=[time.time_ns()]
    monkeypatch.setattr(time,'time_ns',lambda:clock[0])
    native=MandatoryEgressController(policy={},proof_key=b'k'*32,transport=None)
    native.register_reader_channel('tribe','3'*64,controlled=True)
    state['gate']=native.reader_snapshot('tribe',deadline_ns=time.monotonic_ns()+5_000_000_000)
    state['process']['pid']=state['gate']['process_id']
    expected['process']=copy.deepcopy(state['process'])
    command.update(schema='dm.runtime.reader-selection/v2', phase='revoke',readers=[],
        expected_head=state['gate']['head'],process_instance_id=state['gate']['process_instance_id'])
    capability=LocalCapability(dict(schema=CAPABILITY_SCHEMA,capability_id='test-cap',client_id='client:test',
        key_id='test-key',methods=['runtime.reader-selection'],status='active',not_before_ms=0,
        not_after_ms=2**53-1),b'x'*32)
    admitted, sent, effects = set(), [], []
    fault=[None]
    class Client:
        def prepare(self,*args): return first.prepare(*args)
        def apply(self,request):
            authenticated,fingerprint=authenticate_request(request,capability,now_ms=clock[0]//1_000_000,
                allow_stale=request_hash(request) in admitted)
            admitted.add(fingerprint)
            before=state['gate']['head']
            try:
                accepted=native.select_readers({k:v for k,v in authenticated['params'].items()
                    if k!='expected_roster_sha256'},request_sha256=fingerprint,
                    deadline_ns=time.monotonic_ns()+5_000_000_000)
            except NativeEgressError as error:
                return dict(ok=False,error=dict(code=str(error)))
            state['gate']=accepted
            if accepted['head']!=before:
                effects.append(fingerprint)
            return dict(ok=True,result=copy.deepcopy(accepted))
        def send(self,request):
            sent.append(copy.deepcopy(request))
            if fault[0]=='before':
                fault[0]=None
                raise OSError('lost before native admission')
            if fault[0]=='pending':
                fault[0]=None
                _,fingerprint=authenticate_request(request,capability,now_ms=clock[0]//1_000_000)
                admitted.add(fingerprint)
                raise OSError('lost with native RPC pending before CAS')
            if fault[0]=='stale-unavailable':
                fault[0]='original-wins'
                raise OSError('stale exchange unavailable before pending native CAS')
            if fault[0]=='original-wins':
                fault[0]=None
                assert self.apply(sent[0])['ok'] is True
            result=self.apply(request)
            if fault[0]=='after':
                fault[0]=None
                raise OSError('lost after native CAS')
            return result
    client=Client()
    owner._client=lambda role:client
    def execute():
        if request.param == 'classic':
            from clusterctl.onboarding_receiving_update import OwnerGroupClient
            owner._accept_deadline=lambda:control._accept(owner.deadline_ns)
            owner._prepare_control=lambda c,p:OwnerGroupClient._prepare_control(owner,c,p)
            owner._apply_control=lambda p:OwnerGroupClient._apply_control(owner,p)
            return OwnerGroupClient.prepare_apply_control(owner,command,path)
        return control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
    try:
        yield SimpleNamespace(owner=owner,client=client,command=command,path=path,state=state,calls=calls,
            clock=clock,fault=fault,sent=sent,effects=effects,execute=execute,capability=capability)
    finally:
        listener.close()


def test_expired_unadmitted_envelope_renews_same_native_cas_without_losing_original(auth_native_control):
    from daimon_matrix.local_api import authenticate_request,LocalApiError
    from clusterctl import being_seed
    f=auth_native_control
    f.fault[0]='before'
    with pytest.raises(OSError):
        f.execute()
    original=being_seed._read(f.path)
    f.clock[0]+=31_000_000_000
    with pytest.raises(LocalApiError,match='authentication_failed'):
        authenticate_request(original['request'],f.capability,now_ms=f.clock[0]//1_000_000)
    result=f.execute()
    current=being_seed._read(f.path)
    assert current['command']==original['command']==f.command
    assert current['request']!=original['request']
    histories=list(f.path.parent.glob('auth-*.json'))
    assert len(histories)==1
    assert being_seed._read(histories[0])['requests']==[original['request'],current['request']]
    assert result['request_sha256']==request_hash(current['request'])
    assert len(f.effects)==1 and f.calls.count('prepare')==2
    assert f.execute()['request_sha256']==result['request_sha256'] and len(f.effects)==1


def test_expired_native_accepted_envelope_keeps_original_authenticated_recovery(auth_native_control):
    from clusterctl import being_seed
    f=auth_native_control
    f.fault[0]='after'
    with pytest.raises(OSError):
        f.execute()
    raw=f.path.read_bytes()
    original=being_seed._read(f.path)
    f.clock[0]+=31_000_000_000
    assert f.execute()['request_sha256']==request_hash(original['request'])
    assert f.path.read_bytes()==raw and not list(f.path.parent.glob('auth-*.json'))
    assert f.calls.count('prepare')==1 and len(f.effects)==1


def test_late_original_and_renewal_can_change_native_gate_only_once(auth_native_control):
    from clusterctl import being_seed
    f=auth_native_control
    f.fault[0]='pending'
    with pytest.raises(OSError):
        f.execute()
    original=being_seed._read(f.path)['request']
    f.clock[0]+=31_000_000_000
    f.fault[0]='stale-unavailable'
    result=f.execute()
    assert result['request_sha256']==request_hash(original)
    assert being_seed._read(f.path)['request']!=original
    assert len(f.effects)==1 and f.calls.count('prepare')==2
    assert len(being_seed._read(next(f.path.parent.glob('auth-*.json')))['requests'])==2


@pytest.mark.parametrize('boundary',['history','active'])
def test_lost_auth_publication_resumes_the_retained_envelope(auth_native_control,monkeypatch,boundary):
    from clusterctl import being_seed
    f=auth_native_control
    f.fault[0]='before'
    with pytest.raises(OSError):
        f.execute()
    original=being_seed._read(f.path)['request']
    f.clock[0]+=31_000_000_000
    write=being_seed._write
    def lost(path,value,**kwargs):
        write(path,value,**kwargs)
        if (boundary=='history' and path.name.startswith('auth-')
                or boundary=='active' and path==f.path):
            raise OSError('lost auth publication acknowledgment')
    with monkeypatch.context() as fault:
        fault.setattr(being_seed,'_write',lost)
        with pytest.raises(OSError,match='publication acknowledgment'):
            f.execute()
    history=being_seed._read(next(f.path.parent.glob('auth-*.json')))
    assert history['requests'][0]==original and len(history['requests'])==2
    assert f.execute()['request_sha256']==request_hash(history['requests'][-1])
    assert f.calls.count('prepare')==2 and len(f.effects)==1


def test_auth_history_capacity_preserves_every_original_request(auth_native_control,monkeypatch):
    from clusterctl import being_seed
    f=auth_native_control
    def unavailable(request):
        raise OSError('native exchange unavailable')
    monkeypatch.setattr(f.client,'send',unavailable)
    for _ in range(16):
        with pytest.raises(OSError):
            f.execute()
        f.clock[0]+=31_000_000_000
    history_path=next(f.path.parent.glob('auth-*.json'))
    raw=history_path.read_bytes()
    active=f.path.read_bytes()
    assert len(being_seed._read(history_path)['requests'])==16
    with pytest.raises(OnboardingError,match='auth_capacity'):
        f.execute()
    assert history_path.read_bytes()==raw and f.path.read_bytes()==active
    assert f.calls.count('prepare')==16 and not f.effects


@pytest.mark.parametrize('profile',['source','guest'])
@pytest.mark.parametrize('maintenance',[False,True])
def test_current_companion_controls_use_only_the_selected_qualified_helper(profile,maintenance):
    from clusterctl.onboarding_receiving_update import SourceGroupClient,GuestGroupClient
    owner=object.__new__(SourceGroupClient if profile=='source' else GuestGroupClient)
    owner.maintenance=(Path('/qualified-helper'),'a'*64) if maintenance else None
    calls=[]
    owner._call=lambda *args,**kwargs:calls.append((args,kwargs)) or {'same':'receipt'}
    command={'original':'control'}
    path=Path('/own-runtime/receiving-control/original-select.json')
    assert owner.prepare_apply_control(command,path)=={'same':'receipt'}
    assert calls[0][1].get('maintenance',False) is maintenance
    assert (calls[0][1]['command'] if profile=='source' else calls[0][1]['control_value'])==command


def test_expired_pending_but_native_admitted_request_is_tried_without_renewal(auth_native_control):
    from clusterctl import being_seed
    f=auth_native_control
    f.fault[0]='pending'
    with pytest.raises(OSError):
        f.execute()
    original=being_seed._read(f.path)['request']
    raw=f.path.read_bytes()
    f.clock[0]+=31_000_000_000
    result=f.execute()
    assert result['request_sha256']==request_hash(original)
    assert f.path.read_bytes()==raw and not list(f.path.parent.glob('auth-*.json'))
    assert f.calls.count('prepare')==1 and len(f.effects)==1


def fill_control_staging(path, remaining):
    from clusterctl import being_seed
    index=0
    while remaining:
        stage=path.with_name(path.name+'.'+format(index,'032x'))
        with stage.open('wb') as stream:
            stream.truncate(min(remaining,being_seed.MAX_SELECTION))
        stage.chmod(0o600)
        remaining-=stage.stat().st_size
        index+=1


def test_interrupted_initial_staging_is_bounded_before_another_publication(auth_native_control):
    f=auth_native_control
    from clusterctl import being_seed
    f.owner._control_directory(f.path)
    with being_seed._locked(f.path.parent):
        pass
    fill_control_staging(f.path,8*1024*1024)
    before={p.name:p.stat().st_size for p in f.path.parent.iterdir()}
    with pytest.raises(OnboardingError,match='auth_capacity'):
        f.execute()
    assert {p.name:p.stat().st_size for p in f.path.parent.iterdir()}==before
    assert not f.path.exists() and not f.effects


def test_known_accepted_envelope_recovers_at_full_staging_capacity(auth_native_control):
    from clusterctl import being_seed
    f=auth_native_control
    f.fault[0]='pending'
    with pytest.raises(OSError):
        f.execute()
    original=being_seed._read(f.path)['request']
    f.clock[0]+=31_000_000_000
    f.fault[0]='stale-unavailable'
    assert f.execute()['request_sha256']==request_hash(original)
    occupied=sum(p.stat().st_size for p in f.path.parent.iterdir())
    fill_control_staging(f.path,8*1024*1024-occupied)
    before={p.name:p.stat().st_size for p in f.path.parent.iterdir()}
    assert f.execute()['request_sha256']==request_hash(original)
    assert {p.name:p.stat().st_size for p in f.path.parent.iterdir()}==before
    assert f.calls.count('prepare')==2 and len(f.effects)==1
