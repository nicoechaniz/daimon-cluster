"""Cold guests receive pinned public App bytes without another private home."""
import hashlib
import json
import os
from types import SimpleNamespace
from dataclasses import replace
from unittest.mock import patch

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl import onboarding_conversation_bundle as bundle
from clusterctl.onboarding_host import HostBackend
from tests.test_onboarding_host import configured


def artifact(root):
    root.mkdir()
    root.chmod(0o755)
    (root / 'telecodex').write_bytes(b'public executable')
    (root / 'telecodex').chmod(0o644)
    raw = json.dumps({'schema': bundle.SCHEMA, 'files': {
        'telecodex': hashlib.sha256(b'public executable').hexdigest()}}).encode()
    (root / bundle.MARKER).write_bytes(raw)
    (root / bundle.MARKER).chmod(0o444)
    return hashlib.sha256(raw).hexdigest()


def test_cold_context_mount_is_pinned_read_only_and_original_job_stays_compatible(tmp_path):
    root = tmp_path / 'app'
    pin = artifact(root)
    config, plan, _, original = configured(tmp_path)
    assert original._conversation_bundle_mount(plan) == {}
    config = replace(config, conversation_bundle_by_name={plan['name']: (root, pin)})
    backend = HostBackend(config)
    assert backend._conversation_bundle_mount(plan) == {'onboarding-app': {
        'type': 'disk', 'source': str(root), 'path': '/opt/daimon-app',
        'readonly': 'true', 'shift': 'true'}}
    (root / 'telecodex').write_bytes(b'different bytes')
    with pytest.raises(OnboardingError, match='conversation_bundle_changed'):
        backend._environment(plan)  # Refuse before any Incus allocation/query.


@pytest.mark.parametrize('fault', ['link', 'extra', 'missing', 'writable', 'digest', 'private-directory'])
def test_bundle_refuses_unsafe_or_different_public_tree(tmp_path, fault):
    root = tmp_path / 'app'
    pin = artifact(root)
    assert bundle.verify(root, pin, uid=os.geteuid())['files'] == 1
    if fault == 'link':
        (root / 'link').symlink_to(root / 'telecodex')
    elif fault == 'extra':
        (root / 'private.json').write_bytes(b'never mount unlisted state')
    elif fault == 'missing':
        (root / 'telecodex').unlink()
    elif fault == 'writable':
        (root / 'telecodex').chmod(0o666)
    elif fault == 'private-directory':
        root.chmod(0o700)
    else:
        pin = '0' * 64
    with pytest.raises(OnboardingError):
        bundle.verify(root, pin, uid=os.geteuid())


def test_own_codex_is_exposed_idempotently_and_foreign_guest_executable_survives(tmp_path):
    root = tmp_path / 'app'
    root.mkdir()
    root.chmod(0o755)
    (root / 'bin').mkdir()
    (root / 'bin').chmod(0o755)
    binary = root / 'bin/codex'
    binary.write_bytes(b'qualified binary')
    binary.chmod(0o555)
    (root / 'codex-resources').mkdir(mode=0o755)
    (root / 'codex-path').mkdir(mode=0o755)
    for directory in root.iterdir():
        if directory.is_dir():
            directory.chmod(0o755)
    host = root / 'bin/codex-code-mode-host'
    host.write_bytes(b'qualified host')
    host.chmod(0o555)
    package = root / 'codex-package.json'
    package.write_text(json.dumps(dict(layoutVersion=1, entrypoint='bin/codex',
        resourcesDir='codex-resources', pathDir='codex-path')))
    package.chmod(0o444)
    raw = json.dumps({'schema': bundle.SCHEMA, 'files': {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (binary, host, package)}}).encode()
    (root / bundle.MARKER).write_bytes(raw)
    (root / bundle.MARKER).chmod(0o444)
    pin = hashlib.sha256(raw).hexdigest()
    destination = tmp_path / 'codex'
    destination.write_bytes(b'existing guest executable')
    with pytest.raises(OnboardingError, match='existing_guest_codex_preserved'):
        bundle.bootstrap_codex(pin, root=root, destination=destination)
    assert destination.read_bytes() == b'existing guest executable'
    destination.unlink()
    bundle.bootstrap_codex(pin, root=root, destination=destination)
    bundle.bootstrap_codex(pin, root=root, destination=destination)
    assert destination.readlink() == binary


def test_missing_guest_dependencies_have_one_finite_standard_package_install(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle.os, 'geteuid', lambda: 0)
    release = tmp_path / 'os-release'
    release.write_text('ID=debian\nVERSION_ID="13"\n')
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        assert kwargs['timeout'] == 90 and kwargs['env']['DEBIAN_FRONTEND'] == 'noninteractive'
        return SimpleNamespace(returncode=0)
    bundle.dependencies(ready=lambda: len(calls) == 2, run=run, release=release)
    assert len(calls) == 2
    assert calls[-1][-4:] == ['python3-venv', 'rsync', 'nodejs', 'git']
    bundle.dependencies(ready=lambda: True, run=run, release=release)
    assert len(calls) == 2
    release.write_text('ID=other\nVERSION_ID="13"\n')
    with pytest.raises(OnboardingError):
        bundle.dependencies(ready=lambda: False, run=run, release=release)
    assert len(calls) == 2


def test_lone_codex_binary_cannot_claim_native_daemon_delivery(tmp_path):
    root = tmp_path / 'app'
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    (root / 'bin').mkdir(mode=0o755)
    (root / 'bin').chmod(0o755)
    binary = root / 'bin/codex'
    binary.write_bytes(b'CLI version works, daemon needs its package')
    binary.chmod(0o555)
    raw = json.dumps({'schema': bundle.SCHEMA, 'files': {
        'bin/codex': hashlib.sha256(binary.read_bytes()).hexdigest()}}).encode()
    (root / bundle.MARKER).write_bytes(raw)
    (root / bundle.MARKER).chmod(0o444)
    with pytest.raises(OnboardingError, match='conversation_bundle_codex_package_required'):
        bundle.bootstrap_codex(hashlib.sha256(raw).hexdigest(), root=root,
            destination=tmp_path / 'codex')
    assert not (tmp_path / 'codex').exists()


def native_package(root):
    root.mkdir(mode=0o755)
    for name, value in {'bin/codex': b'qualified native engine',
            'bin/codex-code-mode-host': b'qualified code mode host',
            'bin/codex-exec-server': b'qualified exec server',
            'codex-resources/bwrap': b'qualified sandbox helper',
            'codex-path/rg': b'qualified search helper'}.items():
        path=root/name
        path.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        path.write_bytes(value)
        path.chmod(0o555)
    (root/'codex-package.json').write_text(json.dumps(dict(layoutVersion=1,version='0.167.0',
        target='x86_64-unknown-linux-gnu',entrypoint='bin/codex',execServer='bin/codex-exec-server',
        resourcesDir='codex-resources',pathDir='codex-path')))
    (root/'codex-package.json').chmod(0o444)


def test_native_composition_preserves_app_and_complete_selected_package_without_start(tmp_path):
    app=tmp_path/'app'
    pin=artifact(app)
    native=tmp_path/'native'
    native_package(native)
    (native/'auth.json').write_text('private unrelated decoy, never a package component')
    original=(native/'codex-package.json').read_bytes()
    with patch.object(bundle.subprocess,'run',side_effect=AssertionError('no native/model/service invocation')):
        result=bundle.compose_native(app,pin,native,tmp_path/'composed')
        again=bundle.compose_native(app,pin,native,tmp_path/'second')
        assert result==again
        out=tmp_path/'composed'
        metadata=json.loads((out/'native/codex-package.json').read_bytes())
        assert metadata['version'].startswith('0.167.0+local.')
        assert metadata['execServer']=='bin/codex-exec-server'
        for name in ('bin/codex','bin/codex-code-mode-host','bin/codex-exec-server',
                     'codex-resources/bwrap','codex-path/rg'):
            assert (out/'native'/name).read_bytes()==(native/name).read_bytes()
        assert (out/'telecodex').read_bytes()==(app/'telecodex').read_bytes()
        assert not (out/'auth.json').exists()
        bundle.bootstrap_codex(result['conversation_bundle_sha256'],root=out,destination=tmp_path/'codex')
        assert (tmp_path/'codex').readlink()==out/'native/bin/codex'
    assert (native/'codex-package.json').read_bytes()==original
    with pytest.raises(OnboardingError,match='destination_required'):
        bundle.compose_native(app,pin,native,out)


@pytest.mark.parametrize('fault',['missing-exec','linked-helper','capacity'])
def test_native_composition_refuses_incomplete_or_unbounded_source_before_output(tmp_path,monkeypatch,fault):
    app=tmp_path/'app'
    pin=artifact(app)
    native=tmp_path/'native'
    native_package(native)
    if fault=='missing-exec':
        (native/'bin/codex-exec-server').unlink()
    elif fault=='linked-helper':
        (native/'codex-path/rg').unlink()
        (native/'codex-path/rg').symlink_to(native/'bin/codex')
    else:
        monkeypatch.setattr(bundle,'MAX_BYTES',300)
    with pytest.raises(OnboardingError):
        bundle.compose_native(app,pin,native,tmp_path/'refused')
    assert not (tmp_path/'refused').exists()


def test_installed_private_package_umask_is_not_published(tmp_path):
    app=tmp_path/'app'
    pin=artifact(app)
    native=tmp_path/'native'
    native_package(native)
    native.chmod(0o700)
    for path in native.rglob('*'):
        path.chmod(0o775 if path.is_dir() else 0o664 if path.name=='codex-package.json' else 0o775)
    out=tmp_path/'composed'
    result=bundle.compose_native(app,pin,native,out)
    assert bundle.verify(out,result['conversation_bundle_sha256'],uid=os.geteuid())['files']==7
    assert not any(path.stat().st_mode & 0o022 for path in out.rglob('*'))
    native.chmod(0o755)
    with pytest.raises(OnboardingError,match='native_package_required'):
        bundle.compose_native(app,pin,native,tmp_path/'public-source-refused')


def test_common_app_is_frozen_before_allocation_and_survives_later_default(tmp_path):
    from clusterctl.onboarding import CONVERSATION_PLAN_SCHEMA, JobStore
    config, plan, run, _ = configured(tmp_path)
    plan['schema'] = CONVERSATION_PLAN_SCHEMA
    first, later = tmp_path/'first-app', tmp_path/'later-app'
    pin, next_pin = artifact(first), artifact(later)
    config = replace(config, conversation_bundle_default=(first, pin))
    store = JobStore(config.jobs)
    bundle.prepare_selection(config, plan, store, authorize=lambda: True)
    record = store.directory(plan['name'])/'conversation-bundle.json'
    original = record.read_bytes()
    assert not (record.parent/'job.json').exists() and run.calls == []
    changed = replace(config, conversation_bundle_default=(later, next_pin))
    bundle.prepare_selection(changed, plan, store, authorize=lambda: True)
    assert record.read_bytes() == original
    assert HostBackend(changed)._conversation_bundle_mount(plan)['onboarding-app']['source'] == str(first)
    with pytest.raises(OnboardingError, match='companion_app_selection_changed'):
        HostBackend(changed)._conversation_bundle_mount(dict(plan, owner='another-owner'))
    assert run.calls == []


def test_common_app_does_not_rebind_an_existing_job(tmp_path):
    from clusterctl import being_seed
    from clusterctl.onboarding import CONVERSATION_PLAN_SCHEMA, JobStore, private_directory
    config, plan, run, _ = configured(tmp_path)
    plan['schema'] = CONVERSATION_PLAN_SCHEMA
    root = tmp_path/'app'
    pin = artifact(root)
    config = replace(config, conversation_bundle_default=(root, pin))
    store = JobStore(config.jobs)
    directory = private_directory(store.directory(plan['name']), create=True)
    being_seed._write(directory/'job.json', {'original-job':'preserved'})
    before = (directory/'job.json').read_bytes()
    bundle.prepare_selection(config, plan, store, authorize=lambda: True)
    assert bundle.selected_bundle(config, plan) is None
    assert not (directory/'conversation-bundle.json').exists()
    assert (directory/'job.json').read_bytes() == before and run.calls == []


def test_explicit_app_wins_and_changed_explicit_selection_refuses(tmp_path):
    from clusterctl.onboarding import CONVERSATION_PLAN_SCHEMA, JobStore
    config, plan, _, _ = configured(tmp_path)
    plan['schema'] = CONVERSATION_PLAN_SCHEMA
    first, later = tmp_path/'first-app', tmp_path/'later-app'
    pin, next_pin = artifact(first), artifact(later)
    config = replace(config, conversation_bundle_by_name={plan['name']:(first,pin)},
        conversation_bundle_default=(later,next_pin))
    bundle.prepare_selection(config, plan, JobStore(config.jobs), authorize=lambda: True)
    assert bundle.selected_bundle(config, plan) == (first,pin)
    changed = replace(config, conversation_bundle_by_name={plan['name']:(later,next_pin)})
    with pytest.raises(OnboardingError,match='companion_app_selection_changed'):
        bundle.selected_bundle(changed,plan)
    (first/'telecodex').write_bytes(b'changed')
    with pytest.raises(OnboardingError,match='conversation_bundle_changed'):
        bundle.prepare_selection(config,plan,JobStore(config.jobs),authorize=lambda: True)


def test_common_app_cannot_prepare_without_actual_plan_authorization(tmp_path):
    from clusterctl.onboarding import CONVERSATION_PLAN_SCHEMA, JobStore
    config, plan, run, _ = configured(tmp_path)
    plan['schema'] = CONVERSATION_PLAN_SCHEMA
    root = tmp_path/'app'
    pin = artifact(root)
    config = replace(config, conversation_bundle_default=(root,pin))
    with pytest.raises(OnboardingError,match='host_authorization_required'):
        bundle.prepare_selection(config,plan,JobStore(config.jobs),authorize=lambda: False)
    assert not (config.jobs/plan['name']).exists() and run.calls == []


def listener_app(root):
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    native_package(root/'native')
    (root/'bin').mkdir(mode=0o755)
    (root/'bin/telecodex').write_bytes(b'old listener')
    (root/'bin/telecodex').chmod(0o555)
    for directory in root.rglob('*'):
        if directory.is_dir():
            directory.chmod(0o755)
    manifest = dict(schema=bundle.SCHEMA, codex_package='native', files={
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob('*') if p.is_file()})
    raw = (json.dumps(manifest, sort_keys=True)+'\n').encode()
    (root/bundle.MARKER).write_bytes(raw)
    (root/bundle.MARKER).chmod(0o444)
    return hashlib.sha256(raw).hexdigest()


def test_listener_successor_cli_keeps_native_package_and_existing_app_exact(tmp_path, monkeypatch, capsys):
    from tools.build_onboarding_code import main
    app, out, listener = tmp_path/'app', tmp_path/'next', tmp_path/'listener'
    pin = listener_app(app)
    before = {p.relative_to(app):p.read_bytes() for p in app.rglob('*') if p.is_file()}
    listener.write_bytes(b'qualified corrected listener')
    listener.chmod(0o555)
    checksum = hashlib.sha256(listener.read_bytes()).hexdigest()
    monkeypatch.setattr('sys.argv', ['builder', '--conversation-app-bundle', str(app),
        '--conversation-app-digest', pin, '--conversation-listener', str(listener),
        '--conversation-listener-digest', checksum, '--output', str(out)])
    with patch.object(bundle.subprocess, 'run', side_effect=AssertionError('no native/model/service calls')):
        assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result['listener_sha256'] == checksum
    assert bundle.verify(out, result['conversation_bundle_sha256'], uid=os.geteuid())['files'] == 7
    assert (out/'bin/telecodex').read_bytes() == listener.read_bytes()
    for name, raw in before.items():
        assert (app/name).read_bytes() == raw
        if name.as_posix() not in ('bin/telecodex', bundle.MARKER):
            assert (out/name).read_bytes() == raw
    assert json.loads((out/bundle.MARKER).read_bytes())['codex_package'] == 'native'


@pytest.mark.parametrize('fault', ['pin', 'not-executable', 'link', 'capacity', 'inside-source'])
def test_listener_successor_refuses_bad_selection_before_output(tmp_path, monkeypatch, fault):
    app, out, listener = tmp_path/'app', tmp_path/'next', tmp_path/'listener'
    pin = listener_app(app)
    listener.write_bytes(b'qualified corrected listener')
    listener.chmod(0o555)
    checksum = hashlib.sha256(listener.read_bytes()).hexdigest()
    if fault == 'pin':
        checksum = '0'*64
    elif fault == 'not-executable':
        listener.chmod(0o444)
    elif fault == 'link':
        target = tmp_path/'actual-listener'
        listener.rename(target)
        listener.symlink_to(target)
    elif fault == 'capacity':
        old = bundle.verify(app, pin, uid=os.geteuid())['bytes']
        monkeypatch.setattr(bundle, 'MAX_BYTES', old)
    else:
        out = app/'must-not-mutate-source'
    with pytest.raises((OnboardingError, bundle.being_seed.SeedError)):
        bundle.compose_listener(app, pin, listener, checksum, out)
    assert not out.exists()
