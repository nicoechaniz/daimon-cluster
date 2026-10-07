"""Actual V8 bodies use the maintained signed ceremony and retain original custody."""
import hashlib
import os
import secrets
import socket
import tempfile
from pathlib import Path

import pytest

from clusterctl import onboarding_peer
from clusterctl.onboarding import OnboardingError, digest
from tests.test_onboarding_target import receiving, files


@pytest.fixture
def journey(tmp_path, monkeypatch):
    # Qualification must never reach Telegram or an external participant.
    connection = socket.create_connection
    def local_only(address, *args, **kwargs):
        if address[0] != '127.0.0.1':
            raise AssertionError('no external network')
        return connection(address, *args, **kwargs)
    monkeypatch.setattr(socket, 'create_connection', local_only)
    source = []
    with tempfile.TemporaryDirectory(prefix='dm-') as short:
        base = Path(short)
        for actor in (0, 1):
            location = tmp_path / str(actor)
            location.mkdir(mode=0o700)
            ceremony, plan, target = receiving(location)
            # Short owner sockets are necessary for an actual served body.
            from clusterctl.onboarding_target import Target
            home = base / str(actor)
            home.mkdir(mode=0o700)
            target = Target(home, plan, target.genesis, code_uid=os.geteuid())
            request = target.prepare()
            target.activate(ceremony.authorize_target(plan, request))
            target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
            source.append((ceremony, target))
        tool = onboarding_peer.native(Path(__file__).resolve().parents[1], uid=os.geteuid())
        runtimes = [onboarding_peer.loaded(target) for _, target in source]
        public = [onboarding_peer.identity(target) for _, target in source]
        reservations = [socket.socket(), socket.socket()]
        try:
            for reservation in reservations:
                reservation.bind(('127.0.0.1', 0))
            endpoints = [f'http://127.0.0.1:{r.getsockname()[1]}' for r in reservations]
        finally:
            for reservation in reservations:
                reservation.close()
        plan = tool.make_plan(runtimes[0], *public,
            endpoints,
            dict(bot_id=123, chat_id=-100123, topic_id=None, representation='plain-json/v2'))
        from daimon_matrix.canonical import b64url
        from daimon_matrix.messaging_config import create_binding
        token = b'123:disposable-peer-qualification-only'
        payload = dict(plan=plan,
            route_keys={f'{actor}-{phase}.key': b64url(secrets.token_bytes(32))
                for actor in (0, 1) for phase in ('evidence', 'message')},
            telegram_token=b64url(token), telegram_qualification=dict(
                schema='dm.messaging.telegram-qualification/v1', qualified_at_ms=tool.now(),
                token_sha256=hashlib.sha256(token).hexdigest(), get_me_bot_id=123,
                probe_chat_id=-100123, probe_topic_id=None, probe_message_id=1, probe_text_sha256='b' * 64),
            visibility_bindings=[[create_binding(runtimes[0], d) for d in tool.disclosures(plan)], []])
        packet = dict(sender_identity=public[0], packet=tool.encrypt_packet(runtimes[0], public[1], payload))
        yield tool, source, public, packet, payload


def test_actual_native_peer_accept_keeps_credential_receipt_and_receiving_writes(journey):
    _, sources, public, packet, _ = journey
    target = sources[1][1]
    credential = files(target.credential)
    custody = (target.package / 'runtime/custody.json').read_bytes()
    own = target.home / 'own-recent-memory'
    own.write_text('Own receiving work')
    before = target.observe()['receipt']['runtime_sha256']
    sender = public[0]['document']['authority']['manifest']['being_ref']
    response = onboarding_peer.accept(target, packet, expected_being=sender)
    observed = target.observe()
    assert observed['phase'] == 'v8'
    assert observed['receipt']['schema'] == 'cluster-onboarding-peer-runtime-observation/v1'
    assert observed['receipt']['runtime_sha256'] == digest(target.document_bundle()) != before
    assert observed['receipt']['credential_runtime_sha256'] == before
    assert observed['receipt']['peer_being_ref'] == sender
    assert (target.package / 'runtime/custody.json').read_bytes() == custody
    assert files(target.credential) == credential and own.read_text() == 'Own receiving work'
    assert 'telegram_token' not in str(response) and 'route_keys' not in str(response)
    after = files(onboarding_peer.root(target))
    assert onboarding_peer.accept(target, packet, expected_being=sender) == response
    assert files(onboarding_peer.root(target)) == after


def test_peer_cannot_substitute_identity_or_unsigned_plan(journey):
    _, sources, public, packet, _ = journey
    target = sources[1][1]
    original = target.document_bundle()
    with pytest.raises(OnboardingError, match='approved_onboarding_peer_required'):
        onboarding_peer.accept(target, packet, expected_being='dm:being:v1:unapproved')
    assert target.document_bundle() == original and not onboarding_peer.root(target).exists()
    sender = public[0]['document']['authority']['manifest']['being_ref']
    onboarding_peer.accept(target, packet, expected_being=sender)
    from daimon_matrix.keystore import _atomic_write
    from daimon_matrix.canonical import canonical_bytes
    changed = target.document_bundle()
    changed['runtime_label'] = 'another autobiography'
    _atomic_write(target.package / 'runtime/runtime.json', canonical_bytes(changed))
    with pytest.raises(OnboardingError, match='existing_onboarding_target_preserved'):
        target.observe()


def test_lost_ack_after_bundle_publication_resumes_native_signed_proposal(journey, monkeypatch):
    tool, sources, public, packet, _ = journey
    target = sources[1][1]
    actual = tool.replace_document
    failed = []
    def interrupt(path, value):
        actual(path, value)
        if not failed:
            failed.append(True)
            raise OSError('lost ACK after native bundle publication')
    tool.replace_document = interrupt
    real_native = onboarding_peer.native
    monkeypatch.setattr(onboarding_peer, 'native', lambda *a, **k: tool)
    sender = public[0]['document']['authority']['manifest']['being_ref']
    with pytest.raises(OSError, match='lost ACK'):
        onboarding_peer.accept(target, packet, expected_being=sender)
    observed = target.observe()
    assert observed['phase'] == 'peer-published'
    stored = (onboarding_peer.root(target) / 'accepted-private.json').read_bytes()
    tool.replace_document = actual
    monkeypatch.setattr(onboarding_peer, 'native', real_native)
    onboarding_peer.accept(target, packet, expected_being=sender)
    assert target.observe()['phase'] == 'v8'
    assert (onboarding_peer.root(target) / 'accepted-private.json').read_bytes() == stored


def test_tool_capture_requires_the_exact_upstream_bytes(tmp_path):
    from tools.build_onboarding_code import capture_peer_tool
    import json
    from clusterctl.matrix_host import MATRIX_CONTRACT_COMMIT
    provenance = json.loads((Path(__file__).resolve().parents[1] / 'support/matrix-onboarding/PROVENANCE.json').read_bytes())
    assert provenance['sha256'] == onboarding_peer.TOOL_SHA256
    assert provenance['commit'] == onboarding_peer.TOOL_COMMIT
    assert provenance['installed_sdk_commit'] == MATRIX_CONTRACT_COMMIT
    capture_peer_tool(tmp_path)
    module = tmp_path / 'clusterctl' / onboarding_peer.TOOL_MODULE
    assert hashlib.sha256(module.read_bytes()).hexdigest() == onboarding_peer.TOOL_SHA256
    assert onboarding_peer.native(tmp_path, uid=os.geteuid()).__file__ == str(module)
    module.write_text('raise RuntimeError("unqualified code executed")')
    with pytest.raises(OnboardingError, match='qualified_native_peer_tool_required'):
        onboarding_peer.native(tmp_path, uid=os.geteuid())


def test_service_carries_application_selection_and_refuses_receive_only(tmp_path):
    from clusterctl.onboarding_service import command
    code = Path('/opt/daimon-onboarding') / ('a' * 64)
    app = tmp_path / 'application'
    argv = command(code, receive_only=False, visibility=tmp_path / 'visibility.json', messaging_application=app)
    assert argv[argv.index('--messaging-application') + 1] == str(app)
    with pytest.raises(OnboardingError, match='visibility_selection_required'):
        command(code, receive_only=True, messaging_application=app)


def test_actual_admitted_body_keeps_native_and_peer_capabilities_through_restart(journey, tmp_path):
    from daimon_matrix.client import ClientConfig, ClientError, LocalClient
    from clusterctl.admission import AdmissionAuthority, AdmissionEndpoint, AdmissionTCPServer, serve_in_thread
    from clusterctl.onboarding_admission import ReceivingHolder, enrollment
    from clusterctl.onboarding_runtime import AdmittedDaemon
    from tests.test_admission import _key

    _, sources, public, packet, _ = journey
    ceremony, target = sources[1]
    sender = public[0]['document']['authority']['manifest']['being_ref']
    onboarding_peer.accept(target, packet, expected_being=sender)
    holder = ReceivingHolder(target)
    registrar = _key(tmp_path / 'host/registrar.pem', 'registrar')
    signer = _key(tmp_path / 'host/authority.pem', 'authority')
    authority = AdmissionAuthority(tmp_path / 'authority', signer=signer,
        holder_registrars={registrar.key_id: registrar.public_key})
    server = AdmissionTCPServer(('127.0.0.1', 0), authority)
    thread = serve_in_thread(server)
    endpoint = AdmissionEndpoint.network('127.0.0.1', server.server_address[1])
    def client():
        return holder.client(endpoint, authority_key_id=signer.key_id, authority_public_key=signer.public_key)
    client().enroll(enrollment(target.plan, holder.request(), ceremony.admission_coordinates(target.plan), registrar))
    root = target.package / 'runtime'
    application = onboarding_peer.root(target) / 'application'
    visibility = onboarding_peer.root(target) / 'visibility/installation.json'
    owner = ClientConfig.load(root / 'client.json', bytearray((root / 'client.key').read_bytes()))
    peer = ClientConfig.load(application / 'client.json', bytearray((application / 'client.key').read_bytes()))
    original = (root / 'runtime.json').read_bytes()
    custody = (root / 'custody.json').read_bytes()
    credential = files(target.credential)
    try:
        for _ in range(2):
            admitted = AdmittedDaemon(target, client())
            try:
                presence = admitted.start(visibility_installation=visibility, messaging_application=application)
                assert presence['origin'] == target.observe()['receipt']['origin']
                native = LocalClient(root / 'matrix.sock', owner)
                assert native.scope_me()[1]['result']['body']['state'] == 'running'
                assert native.runtime_status()[1]['ok'] is True
                linked = LocalClient(root / 'peer.sock', peer)
                params = dict(channel_id='peer-in', after=0, limit=1)
                assert linked.invoke('messaging.inbox', params)[1]['ok'] is True
                with pytest.raises(ClientError):
                    LocalClient(root / 'peer.sock', owner).scope_me()
                with pytest.raises(ClientError):
                    LocalClient(root / 'matrix.sock', peer).invoke('messaging.inbox', params)
            finally:
                admitted.close()
            assert admitted.client.current() is None
            assert not (root / 'matrix.sock').exists() and not (root / 'peer.sock').exists()
            assert (root / 'runtime.json').read_bytes() == original
            assert (root / 'custody.json').read_bytes() == custody and files(target.credential) == credential
        # A peer listener bind failure must never publish partial readiness or
        # leave the native owner surface alive outside the admission lease.
        from urllib.parse import urlsplit
        import json
        ready = json.loads((onboarding_peer.root(target) / 'ready.json').read_bytes())
        port = urlsplit(ready['endpoint']).port
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', port))
            occupied.listen()
            admitted = AdmittedDaemon(target, client())
            with pytest.raises(OnboardingError, match='onboarding_runtime_not_ready'):
                admitted.start(visibility_installation=visibility, messaging_application=application)
            assert admitted.process.poll() is not None and admitted.client.current() is None
            assert not (root / 'matrix.sock').exists() and not (root / 'peer.sock').exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_observation_refuses_signed_application_drift_and_broken_visibility(journey):
    import json
    from daimon_matrix.keystore import _atomic_write
    from daimon_matrix.canonical import canonical_bytes
    tool, sources, public, packet, _ = journey
    target = sources[1][1]
    sender = public[0]['document']['authority']['manifest']['being_ref']
    onboarding_peer.accept(target, packet, expected_being=sender)
    directory = onboarding_peer.root(target)
    token = directory / 'visibility/telegram.token'
    original = token.read_bytes()
    _atomic_write(token, b'123:changed-after-signing')
    with pytest.raises(OnboardingError, match='native_onboarding_peer_plan_conflict'):
        target.observe()
    _atomic_write(token, original)
    assert target.observe()['phase'] == 'v8'
    app_path = directory / 'application/application.json'
    app = json.loads(app_path.read_bytes())
    app['listen']['port'] = app['listen']['port'] + 1 if app['listen']['port'] < 65535 else 65534
    binding = tool.create_binding(onboarding_peer.loaded(target), app)
    ready_path = directory / 'ready.json'
    ready = json.loads(ready_path.read_bytes())
    ready['application_sha256'] = digest(app)
    _atomic_write(app_path, canonical_bytes(app))
    _atomic_write(directory / 'application/binding.json', canonical_bytes(binding))
    _atomic_write(ready_path, canonical_bytes(ready))
    # A valid Body signature is necessary but does not change the approved plan.
    with pytest.raises(OnboardingError, match='native_onboarding_peer_plan_conflict'):
        target.observe()


def test_captured_runtime_can_load_peer_tool_without_checkout_modules(tmp_path):
    import json
    import subprocess
    import sys
    from clusterctl.onboarding_code_successor import build
    from tests.test_onboarding_code_successor import fixture
    from tools.build_onboarding_code import MODULES
    base, original, _, _ = fixture(tmp_path)
    output = tmp_path / 'captured'
    source = Path(__file__).resolve().parents[1] / 'clusterctl'
    build(base, original, source, MODULES, output)
    launch = ('import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);'
              'from clusterctl.onboarding_peer import native;'
              'print(native(Path(sys.argv[1]),uid=int(sys.argv[2])).__file__)')
    result = subprocess.run([sys.executable, '-B', '-I', '-c', launch, str(output), str(os.geteuid())],
        capture_output=True, check=True, text=True)
    assert result.stdout.strip() == str(output / 'clusterctl/onboarding_peer_native.py')
    assert not (output / 'clusterctl/matrix_host.py').exists()
    # The receiving branch needs its approved offline installation receipt,
    # never a host-only import or the host VCS metadata as a fallback.
    (output / 'sdk/sdk.json').write_text(json.dumps(dict(matrix_commit='0' * 40, wheels=[])))
    denied = subprocess.run([sys.executable, '-B', '-I', '-c', launch, str(output), str(os.geteuid())],
        capture_output=True, check=False, text=True)
    assert denied.returncode != 0
