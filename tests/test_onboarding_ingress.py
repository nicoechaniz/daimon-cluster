"""Port effects recover without duplicate allocation; private coordinates prove readiness only."""
import base64
import dataclasses
import os
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_ingress import Access, Ingress, POLICY, SCHEMA, fingerprint, policy
from tests.test_being_seed import KEY, http_server
from tests.test_onboarding import plan

PUBLIC = 'ssh-ed25519 ' + base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20' + b'a' * 32).decode()


class Host:
    def __init__(self, tmp_path):
        jobs, progress = tmp_path / 'jobs', tmp_path / 'progress'
        jobs.mkdir(mode=0o700)
        progress.mkdir(mode=0o750)
        path = tmp_path / 'policy.json'
        being_seed._write(path, dict(schema=POLICY, hostname='cluster.example', listen_address='127.0.0.1',
            first_port=32000, last_port=32009, revoked=False))
        self.config = SimpleNamespace(jobs=jobs, progress=progress, ssh_ingress=path)
        self.rows = [{'name': 'dm-eko', 'expanded_devices': {}}, {'name': 'dm-oliva', 'expanded_devices': {}}]
        self.calls = []
        self.lose_ack = False

    def instance(self, value):
        return 'dm-' + value['name']

    def _inventory(self):
        return self.rows, []

    def _dispatch(self, value, argv):
        self.calls.append(argv)
        assert argv[:3] == ['config', 'device', 'add']
        row = next(row for row in self.rows if row['name'] == argv[3])
        assert argv[4:6] == ['onboarding-ssh', 'proxy']
        row['expanded_devices']['onboarding-ssh'] = {'type': 'proxy', **dict(item.split('=', 1) for item in argv[6:])}
        if self.lose_ack:
            self.lose_ack = False
            raise OSError('fixture lost acknowledgement after real effect')


def guest(value):
    return dict(installed=True, service_verified=True, plan_digest=digest(value), port=2222, host_public_key=PUBLIC)


def test_missing_ack_restart_and_concurrent_distinct_jobs_preserve_ports(tmp_path):
    host = Host(tmp_path)
    ingress = Ingress(host, sockets=lambda: {32000}, probe=lambda *_: True)
    eko, oliva = plan(), plan(name='oliva', owner='ani')
    host.lose_ack = True
    with pytest.raises(OSError):
        ingress.execute(eko, guest(eko))
    assert not (host.config.progress / 'eko.access.json').exists()
    restarted = Ingress(host, sockets=lambda: {32000, 32001}, probe=lambda *_: True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda value: restarted.execute(value, guest(value)), [eko, oliva]))
    e = Access(host.config.progress, worker_uid=os.geteuid()).read('eko', owner='sai')
    o = Access(host.config.progress, worker_uid=os.geteuid()).read('oliva', owner='ani')
    assert e['ssh']['port'] == 32001 and o['ssh']['port'] == 32002
    assert e['ssh']['host_key_fingerprint'] == fingerprint(PUBLIC)
    assert len(host.calls) == 2
    assert 'ssh_verified' not in e and 'active' not in e


def test_proxy_configuration_is_not_connection_acceptance(tmp_path):
    host = Host(tmp_path)
    ingress = Ingress(host, sockets=lambda: set(), probe=lambda *_: False)
    value = plan()
    ingress.execute(value, guest(value))
    assert Access(host.config.progress, worker_uid=os.geteuid()).read('eko', owner='sai')['ssh'] is None
    assert not ingress.observe(value, guest(value))
    assert len(host.calls) == 1


def test_foreign_proxy_and_changed_host_key_are_preserved(tmp_path):
    host = Host(tmp_path)
    ingress = Ingress(host, sockets=lambda: set(), probe=lambda *_: True)
    value = plan()
    host.rows[0]['expanded_devices']['onboarding-ssh'] = dict(type='proxy', listen='tcp:127.0.0.1:22')
    with pytest.raises(OnboardingError, match='foreign_receiving_mount_preserved'):
        ingress.execute(value, guest(value))
    assert not host.calls
    del host.rows[0]['expanded_devices']['onboarding-ssh']
    ingress.execute(value, guest(value))
    changed = {**guest(value), 'host_public_key': PUBLIC + ' changed'}
    with pytest.raises(OnboardingError, match='existing_onboarding_ssh_preserved'):
        ingress.observe(value, changed)
    assert len(host.calls) == 1


@pytest.mark.parametrize('changed', [dict(first_port=22), dict(last_port=51000), dict(hostname='-oProxyCommand=fixture'),
    dict(listen_address='not-an-address'), dict(first_port=True), dict(private_key='fixture')])
def test_operator_policy_never_selects_admin_ports_or_commands(tmp_path, changed):
    host = Host(tmp_path)
    before = being_seed._read(host.config.ssh_ingress)
    being_seed._write(host.config.ssh_ingress, {**before, **changed})
    with pytest.raises(OnboardingError, match='invalid_onboarding_ingress_policy'):
        policy(host.config.ssh_ingress)
    assert not host.calls


def test_revocation_clears_readiness_without_reassigning_or_deleting_body(tmp_path):
    host = Host(tmp_path)
    value = plan()
    Ingress(host, sockets=lambda: set(), probe=lambda *_: True).execute(value, guest(value))
    before = being_seed._read(host.config.ssh_ingress)
    being_seed._write(host.config.ssh_ingress, {**before, 'revoked': True})
    ingress = Ingress(host, sockets=lambda: set(), probe=lambda *_: True)
    assert not ingress.observe(value, guest(value))
    assert Access(host.config.progress, worker_uid=os.geteuid()).read('eko', owner='sai')['ssh'] is None
    with pytest.raises(OnboardingError, match='host_authorization_required'):
        ingress.execute(value, guest(value))
    assert len(host.calls) == 1


def test_real_http_coordinates_are_owner_only_and_never_fleet_progress(tmp_path):
    state, progress = tmp_path / 'state', tmp_path / 'progress'
    progress.mkdir(mode=0o750)
    with http_server(state) as (server, request):
        being_seed.create(state, dict(name='eko', label='Eko', mode='import'), owner='sai', key=KEY)
        server.deps = dataclasses.replace(server.deps, seed_only=True,
            onboarding_progress=str(progress), onboarding_worker_uid=os.geteuid())
        value = dict(schema=SCHEMA, name='eko', owner='sai', plan_digest=digest(plan()),
            ssh=dict(hostname='cluster.example', port=32000, username='agent', host_public_key=PUBLIC,
                     host_key_fingerprint=fingerprint(PUBLIC)))
        Access(progress, worker_uid=os.geteuid()).publish(value)
        endpoint = '/v1/seeds/eko/onboarding/access'
        assert request(endpoint, owner='ani')[0] == 404
        assert request(endpoint, owner='reader')[0] == 403
        status, headers, fetched = request(endpoint, owner='sai')
        assert status == 200 and headers['Cache-Control'] == 'no-store' and fetched == value
        assert request(endpoint, 'POST', {}, owner='sai')[0] == 405
        assert 'cluster.example' not in str(request('/v1/seeds', owner='sai')[2])


def test_cli_reads_same_owner_projection_without_host_effects(tmp_path, capsys):
    from clusterctl.cli import run
    import json
    host = Host(tmp_path)
    state = tmp_path / 'state'
    being_seed.create(state, dict(name='eko', label='Eko', mode='import'), owner='sai', key=KEY)
    Ingress(host, sockets=lambda: set(), probe=lambda *_: True).execute(plan(), guest(plan()))
    args = ['--config', 'configs/clusterctl.yaml', '--state-dir', str(state), 'seed', '--owner', 'sai',
            'ssh', 'eko', '--progress', str(host.config.progress), '--worker-uid', str(os.geteuid())]
    assert run(args) == 0
    assert json.loads(capsys.readouterr().out)['ssh']['port'] == 32000
    assert len(host.calls) == 1
