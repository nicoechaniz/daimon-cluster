"""Native H8 profile boundaries, retaining the existing shared admission path."""
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from clusterctl import onboarding_sdk, rebirth_host, rebirth_native
from clusterctl.matrix_host import matrix_root
from clusterctl.onboarding import digest
from tests import test_rebirth as base


@pytest.fixture
def native_state():
    yield from base.short_tmp_path.__wrapped__()


def private(path, value):
    path.write_text(json.dumps(value,sort_keys=True,separators=(',',':')))
    path.chmod(0o600)
    return path


def test_native_profile_binds_h7_root_password_and_qualified_selection(tmp_path, monkeypatch):
    state = tmp_path / 'state'
    identity = {'origin': {'embodiment_id': 'embodiment:fixture'}}
    root = matrix_root(state, identity['origin']['embodiment_id'])
    password = tmp_path / 'body.password'
    password.write_bytes(b'fixture password')
    password.chmod(0o600)
    config = private(tmp_path / 'source.json', {'schema': 'cluster-onboarding-source/v1',
        'runtime_root': str(root), 'password_file': str(password)})
    code = tmp_path / 'code'
    sdk = {'fixture': 'qualified SDK'}
    home = tmp_path / 'home'
    python = home / '.local/share/daimon-matrix/sdk' / digest(sdk) / 'venv/bin/python'
    python.parent.mkdir(parents=True)
    python.touch()
    profile = private(tmp_path / 'profile.json', {'schema': 'dm.cluster.rebirth-native-profile/v1',
        'config': str(config), 'home': str(home), 'code': str(code), 'code_digest': 'a' * 64})
    verified = []
    monkeypatch.setattr(rebirth_native.onboarding_release, 'verify', lambda *a, **k: verified.append((a, k)))
    monkeypatch.setattr(rebirth_native.onboarding_code_successor, 'sdk_parameters',
                        lambda *a, **k: {'matrix_commit': 'b' * 40})
    monkeypatch.setattr(onboarding_sdk, 'verify', lambda *a, **k: sdk)

    def prepare(secret):
        r, w = os.pipe()
        os.write(w, secret)
        os.close(w)
        try:
            return rebirth_native.prepare(state, identity, profile, r)
        finally:
            os.close(r)

    selected = prepare(password.read_bytes())
    assert selected['sdk_digest'] == digest(sdk)
    assert selected['config_sha256'] == digest(json.loads(config.read_bytes()))
    assert verified == [((code, 'a' * 64), {'uid': 0})]
    with pytest.raises(rebirth_host.RebirthHostError, match='native_profile_rejected'):
        prepare(b'wrong body password')
    settings = json.loads(config.read_text())
    settings['runtime_root'] = str(tmp_path / 'another body')
    private(config, settings)
    with pytest.raises(rebirth_host.RebirthHostError, match='native_profile_rejected'):
        prepare(password.read_bytes())


def test_native_child_refuses_changed_config_and_dies_with_parent(tmp_path):
    """Exercise the actual isolated bootstrap and kernel parent-death fencing."""
    code = tmp_path / 'code'
    (code / 'clusterctl').mkdir(parents=True)
    (code / 'clusterctl/__init__.py').touch()
    (code / 'clusterctl/onboarding_source.py').write_text(
        "import argparse,os,time\np=argparse.ArgumentParser()\n"
        "p.add_argument('--ready-fd',type=int);a,_=p.parse_known_args()\n"
        "os.write(a.ready_fd,b'READY\\n');os.close(a.ready_fd)\nwhile True:time.sleep(.1)\n")
    config = private(tmp_path / 'source.json', {'retained': True})
    venv = tmp_path / 'sdk/venv'
    (venv / 'bin').mkdir(parents=True)
    (venv / 'bin/python').symlink_to(sys.executable)
    selected = {'venv': str(venv), 'code': str(code), 'config': str(config),
        'config_sha256': hashlib.sha256(config.read_bytes()).hexdigest(), 'code_digest': 'a' * 64}
    runner = tmp_path / 'parent.py'
    checkout = Path(__file__).resolve().parents[1]
    runner.write_text(f"import sys,json,os,subprocess,time\nsys.path.insert(0,{str(checkout)!r})\n"
        "from clusterctl.rebirth_native import command\nselection=json.loads(sys.argv[1])\n"
        "r,w=os.pipe();child=subprocess.Popen(command(selection,w),pass_fds=(w,))\nos.close(w)\n"
        "ready=os.read(r,6);print(json.dumps({'pid':child.pid,'ready':ready.decode()}),flush=True)\n"
        "if ready!=b'READY\\n':child.wait();raise SystemExit(1)\nwhile True:time.sleep(.1)\n")
    parent = subprocess.Popen([sys.executable, str(runner), json.dumps(selected)], stdout=subprocess.PIPE)
    child_pid = None
    try:
        observed = json.loads(parent.stdout.readline())
        child_pid = observed['pid']
        assert observed['ready'] == 'READY\n'
        parent.kill()
        parent.wait(timeout=5)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            stat = Path(f'/proc/{child_pid}/stat')
            if not stat.exists() or stat.read_text().split(') ', 1)[1].startswith('Z '):
                break
            time.sleep(.02)
        else:
            pytest.fail('native Matrix survived its admission supervisor')
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)
        if child_pid:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    private(config, {'changed': True})
    refused = subprocess.run([sys.executable, str(runner), json.dumps(selected)],
                             capture_output=True, timeout=5, check=False)
    assert refused.returncode == 1
    assert json.loads(refused.stdout)['ready'] == ''


def test_native_readiness_rejects_another_process_or_sdk(tmp_path, monkeypatch):
    from clusterctl import distributed_rebirth
    identity = {'origin': {'embodiment_id': 'embodiment:e', 'body_ref': 'b'}, 'being_ref': 'being',
                'manifest_hash': 'hash'}
    state = tmp_path / 'state'
    root = matrix_root(state, 'embodiment:e')
    root.mkdir(parents=True)
    private(root / 'runtime.json', {})
    status = {'integrity': 'ok', 'being_ref': 'being', 'manifest_hash': 'hash',
              'local_origin': identity['origin'], 'loaded_runtime': {'qualified_startup': {'sdk_digest': 'sdk'}}}
    monkeypatch.setattr(distributed_rebirth, '_native_peer_observation', lambda *a:
        (status, {'origin': identity['origin']}, {'embodiments': [{'embodiment_id': 'embodiment:e',
            'manifest_status': 'active'}]}, {'process': {'pid': 123}}))
    assert rebirth_native.verify_ready(state, identity, 123, {'sdk_digest': 'sdk'})['integrity'] == 'ok'
    for pid, sdk in [(124, 'sdk'), (123, 'another SDK')]:
        with pytest.raises(rebirth_host.RebirthHostError, match='native_readiness_mismatch'):
            rebirth_native.verify_ready(state, identity, pid, {'sdk_digest': sdk})


def test_source_serves_only_the_exact_validated_config(tmp_path, monkeypatch):
    from clusterctl import onboarding_source
    settings = {'fixture': 'one retained snapshot'}
    config = private(tmp_path / 'source.json', settings)
    served = []
    class SelectedSource:
        def __init__(self, selected, **kwargs):
            assert selected == settings
        def serve(self, stop, ready_descriptor):
            served.append(True)
    monkeypatch.setattr(onboarding_source, 'Source', SelectedSource)
    monkeypatch.setattr(onboarding_source.onboarding_code_successor
                        if hasattr(onboarding_source, 'onboarding_code_successor')
                        else rebirth_native.onboarding_code_successor,
                        'sdk_parameters', lambda *a, **k: {})
    monkeypatch.setattr(onboarding_source.signal, 'signal', lambda *a: None)
    args = ['--config', str(config), '--expected-config-sha256', digest(settings)]
    assert onboarding_source.main(args) == 0
    private(config, {'fixture': 'replaced'})
    assert onboarding_source.main(args) == 1
    assert served == [True]


def test_native_branch_uses_shared_admission_and_dies_on_lease_loss(native_state, monkeypatch):
    """Real H7/H8 journal, authority server, lease refusal and supervisor cleanup.

    Only the child and native ready observation are fixture seams here; actual
    Source bootstrap/PID/SDK checks are covered above and by receiving adoption.
    """
    from clusterctl import rebirth
    fixture, state, values = base._install(native_state, ceremony_now_ms=time.time_ns() // 1_000_000)
    installed = rebirth.install_rebirth_package(**values)
    base._ensure_production_fences(state, installed['embodiment_id'], lease_ttl_s=6)
    monkeypatch.setattr(rebirth_native, 'prepare', lambda *a: {'fixture': 'native'})
    spawned = []
    def child(selection, ready_fd):
        spawned.append(True)
        return [sys.executable, '-c', ('import os,signal,time;'
                'signal.signal(signal.SIGTERM,lambda *a:exit(0));'
                f'os.write({ready_fd},b"READY\\n");os.close({ready_fd});time.sleep(60)')]
    monkeypatch.setattr(rebirth_native, 'command', child)
    monkeypatch.setattr(rebirth_native, 'verify_ready', lambda *a:
        {'integrity': 'ok', 'active_embodiment_ids': [installed['embodiment_id']]})
    process, ready = rebirth_host.launch_rebirth_host(state, installed['embodiment_id'],
        base._descriptor(fixture['password']), native_source_profile=state / 'profile.json')
    try:
        assert ready['state'] == 'running-ready'
        assert ready['admission']['lease_expires_at_ms'] > 0
        with pytest.raises(rebirth_host.RebirthHostError, match='admission_refused'):
            rebirth_host.launch_rebirth_host(state, installed['embodiment_id'],
                base._descriptor(fixture['password']), native_source_profile=state / 'profile.json')
        assert spawned == [True]
        server, thread = base._DISPOSABLE_ADMISSION_SERVERS.pop()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        process.communicate(timeout=8)
        rebirth_host.wait_rebirth_host_shutdown(process, timeout_s=5)
        assert process.returncode == -signal.SIGKILL
    finally:
        if process.poll() is None:
            base._stop_rebirth_host(process)
