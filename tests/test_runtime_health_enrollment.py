"""The real job worker registers authorized resources without reopening work."""
import json
from types import SimpleNamespace

import pytest

from clusterctl import onboarding as ob, onboarding_runtime_health as health
from clusterctl.onboarding_worker import Worker
from tests.test_onboarding import setup, advance


def test_worker_enrollment_is_durable_and_does_not_replay_completed_onboarding(tmp_path):
    store, backend = setup(tmp_path)
    directory = tmp_path / 'health'; directory.mkdir(mode=0o700)
    config = directory
    backend.instance = lambda plan: 'dm-' + plan['name']
    callback = lambda result: health.reconcile(config, store, backend, result)
    worker = Worker(store, lambda: backend, runtime_health=callback)
    assert worker.once()[0]['completed_steps'] == ['environment']
    assert not list(directory.glob('*.json'))
    advance(store, backend)
    before = (store.directory('eko') / 'job.json').read_bytes()
    calls = list(backend.calls)
    assert worker.once()[0]['active']
    path = directory / 'eko.json'; record = json.loads(path.read_text()); stamp = path.stat().st_mtime_ns
    assert record == dict(schema=health.SCHEMA, name='eko', instance='dm-eko',
                         resource_ref='container-dm-eko', plan_digest=ob.digest(store._load('eko')['plan']))
    assert worker.once()[0]['active']
    assert path.stat().st_mtime_ns == stamp
    assert backend.calls == calls
    assert (store.directory('eko') / 'job.json').read_bytes() == before
    assert path.stat().st_mode & 0o777 == 0o600


def test_registry_never_accepts_revoked_authority_or_rebinds_existing_resource(tmp_path):
    store, backend = setup(tmp_path); result = advance(store, backend)
    directory = tmp_path / 'health'; directory.mkdir(mode=0o700)
    config = directory
    backend.instance = lambda plan: 'dm-' + plan['name']
    backend.granted = False
    with pytest.raises(ob.OnboardingError, match='refused'):
        health.reconcile(config, store, backend, result)
    assert not list(directory.glob('*.json'))
    backend.granted = True; health.reconcile(config, store, backend, result)
    path=directory/'eko.json';v=json.loads(path.read_text());v['plan_digest']='a'*64;path.write_text(json.dumps(v))
    with pytest.raises(ob.OnboardingError, match='preserved'):
        health.reconcile(config, store, backend, result)


def test_retired_placement_is_not_resurrected_by_completed_onboarding(tmp_path):
    store, backend = setup(tmp_path); result = advance(store, backend)
    directory = tmp_path / 'health'; directory.mkdir(mode=0o700)
    backend.instance = lambda plan: 'dm-' + plan['name']
    health.reconcile(directory, store, backend, result)
    path = directory / 'eko.json'; original = path.read_bytes()
    retired = directory / 'eko.json.retired'; path.rename(retired)
    before = (store.directory('eko') / 'job.json').read_bytes(); calls = list(backend.calls)
    assert health.reconcile(directory, store, backend, result) == dict(enrolled=False, retired=True)
    assert not path.exists() and retired.read_bytes() == original
    # Recover an exact duplicate left by a legacy reconciler without replay.
    path.write_bytes(original); path.chmod(0o600)
    assert health.reconcile(directory, store, backend, result)['retired']
    assert not path.exists()
    assert (store.directory('eko') / 'job.json').read_bytes() == before
    assert backend.calls == calls
    changed = json.loads(original); changed['plan_digest'] = 'f' * 64
    retired.write_text(json.dumps(changed))
    with pytest.raises(ob.OnboardingError, match='retirement_preserved'):
        health.reconcile(directory, store, backend, result)
    assert not path.exists()


def test_fresh_bundle_includes_native_supervisor_and_can_import_it(tmp_path, monkeypatch):
    from tests.test_onboarding_release import test_builder_captures_mutable_code_but_publishes_qualified_read_only_artifact
    test_builder_captures_mutable_code_but_publishes_qualified_read_only_artifact(tmp_path, monkeypatch)
    p=tmp_path/'output/clusterctl/native_codex_supervisor.py'
    import runpy
    assert callable(runpy.run_path(str(p))['serve'])


def test_sixteenth_existing_entries_remain_intact_and_overflow_failure_is_visible(tmp_path):
    store, backend=setup(tmp_path);result=advance(store,backend)
    directory=tmp_path/'health';directory.mkdir(mode=0o700)
    for n in range(16):
        p=directory/f'n{n}.json';p.write_text(json.dumps(dict(schema=health.SCHEMA,name=f'n{n}',instance=f'dm-n{n}',resource_ref=f'container-dm-n{n}',plan_digest='a'*64)));p.chmod(0o600)
    before={p.name:p.read_bytes() for p in directory.iterdir()}
    config=directory;backend.instance=lambda plan:'dm-'+plan['name']
    worker=Worker(store,lambda:backend,runtime_health=lambda r:health.reconcile(config,store,backend,r))
    assert worker.once()[0]['state']=='attention-required'
    assert {p.name:p.read_bytes() for p in directory.glob('*.json')}==before
    assert json.loads((directory/'.failure-eko').read_text())==dict(reason='enrollment_unavailable')
    assert store._load('eko')['state']=='complete'
    (directory/'n15.json').unlink()
    assert worker.once()[0]['active']
    assert (directory/'eko.json').exists() and not (directory/'.failure-eko').exists()


def test_operator_installer_preserves_previous_configuration_and_exact_owner(tmp_path):
    from tools.install_host_runtime_health import replace
    import os
    p=tmp_path/'config.json';p.write_bytes(b'previous');p.chmod(0o600)
    replace(p,b'candidate');assert p.read_bytes()==b'candidate'
    backups=list(tmp_path.glob('*.previous'));assert len(backups)==1 and backups[0].read_bytes()==b'previous'
    assert p.stat().st_uid==os.getuid() and p.stat().st_mode & 0o777==0o600
    stamp=p.stat().st_mtime_ns;replace(p,b'candidate');assert p.stat().st_mtime_ns==stamp


def test_native_only_successor_preserves_existing_context_sdk_and_binary_under_private_umask(tmp_path, monkeypatch):
    from tests.test_onboarding_code_successor import telegram_fixture
    from clusterctl import onboarding_code_successor, onboarding_release
    from tools.build_onboarding_code import native_successor
    import os
    base,original,source,profile,telegram=telegram_fixture(tmp_path,monkeypatch)
    current=tmp_path/'current'
    current_digest=onboarding_code_successor.build(base,original,source,('onboarding_target.py',),current,telegram=telegram)['runtime_digest']
    before={p.relative_to(current).as_posix():p.read_bytes() for p in current.rglob('*') if p.is_file()}
    selected=tmp_path/'selected';prior=os.umask(0o077)
    try:result=native_successor(base,original,current,current_digest,selected)
    finally:os.umask(prior)
    onboarding_code_successor.verify(selected,result['release_digest'],base,original,uid=os.geteuid())
    changed={'clusterctl/'+n for n in ('onboarding_telegram.py','onboarding_code_successor.py','native_codex_supervisor.py')}
    assert all((selected/n).read_bytes()==raw for n,raw in before.items() if n not in changed|{'release.json'})
    assert selected.stat().st_mode & 0o777==0o755
    assert (selected/'telegram/telecodex').stat().st_mode & 0o777==0o755
    assert (selected/'release.json').stat().st_mode & 0o777==0o644
    assert not any(p.stat().st_mode & 0o022 for p in selected.rglob('*'))


def test_worker_health_binding_keeps_existing_control_argv_compatible():
    from pathlib import Path
    from tools.install_onboarding_worker import service
    body=service(Path('/opt/daimon-cluster-releases')/('a'*40),Path('/var/lib/example/host.json'),home_placements=Path('/var/lib/example/homes.json'),runtime_health_registry=Path('/var/lib/example/health')).decode()
    assert 'Environment="DAIMON_RUNTIME_HEALTH_REGISTRY=/var/lib/example/health"' in body
    command=next(line for line in body.splitlines() if line.startswith('ExecStart='))
    assert '--home-placements' in command and 'health' not in command
