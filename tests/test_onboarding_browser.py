"""Receiving browser code survives retry and preserves private owner state."""
import dataclasses
import hashlib
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from clusterctl import browser, being_seed
from clusterctl.onboarding import Observation, OnboardingError
from clusterctl.onboarding_browser import Browser, artifact


def assets(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    daemon = source / 'daemon'
    daemon.write_bytes(b'qualified code fixture')
    extension = source / 'extension'
    extension.mkdir()
    (extension / 'manifest.json').write_text('{"version":"fixture"}')
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    pin = dict(image='a' * 64, daemon_sha256=hashlib.sha256(daemon.read_bytes()).hexdigest(),
        extension_sha256=browser.extension_digest(extension)[0])
    return source, home, pin


def test_atomic_code_publication_recovers_lost_ack_without_changing_later_profile(tmp_path, monkeypatch):
    source, home, pin = assets(tmp_path)
    monkeypatch.setattr(browser.shutil, 'which', lambda name: '/fixture/' + name)
    args = (source / 'daemon', pin['daemon_sha256'], source / 'extension', pin['extension_sha256'], home)
    actual = browser.publish_directory
    def lose_ack(before, after):
        actual(before, after)
        raise OSError('lost publication acknowledgement')
    monkeypatch.setattr(browser, 'publish_directory', lose_ack)
    with pytest.raises(OSError, match='lost publication'):
        browser.prepare(*args, apply=True, launcher=b'qualified launcher')
    profile = home / '.kimi-webbridge/chromium-profile'
    profile.mkdir()
    (profile / 'own-history').write_text('Later receiving work')
    browser.prepare(*args, apply=True, launcher=b'qualified launcher')
    assert (profile / 'own-history').read_text() == 'Later receiving work'
    assert not list(home.glob('.kimi-webbridge-preparing-*'))


def test_atomic_publication_never_replaces_concurrent_owner_directory(tmp_path, monkeypatch):
    source, home, pin = assets(tmp_path)
    monkeypatch.setattr(browser.shutil, 'which', lambda name: '/fixture/' + name)
    actual = browser.publish_directory
    def owner_wins(before, after):
        after.mkdir()
        (after / 'own-state').write_text('Owner state')
        actual(before, after)
    monkeypatch.setattr(browser, 'publish_directory', owner_wins)
    with pytest.raises(FileExistsError):
        browser.prepare(source / 'daemon', pin['daemon_sha256'], source / 'extension',
            pin['extension_sha256'], home, apply=True)
    assert (home / '.kimi-webbridge/own-state').read_text() == 'Owner state'
    assert not (home / '.kimi-webbridge/cluster-code.json').exists()


def test_interrupted_copy_leaves_no_partial_live_directory_and_can_retry(tmp_path, monkeypatch):
    source, home, pin = assets(tmp_path)
    monkeypatch.setattr(browser.shutil, 'which', lambda name: '/fixture/' + name)
    actual = os.fsync
    def interrupted(_descriptor):
        raise OSError('interrupted code copy')
    monkeypatch.setattr(os, 'fsync', interrupted)
    with pytest.raises(OSError, match='interrupted code copy'):
        browser.prepare(source / 'daemon', pin['daemon_sha256'], source / 'extension',
            pin['extension_sha256'], home, apply=True)
    assert not (home / '.kimi-webbridge').exists()
    assert not list(home.glob('.kimi-webbridge-preparing-*'))
    monkeypatch.setattr(os, 'fsync', actual)
    browser.prepare(source / 'daemon', pin['daemon_sha256'], source / 'extension',
        pin['extension_sha256'], home, apply=True)
    assert (home / '.kimi-webbridge/cluster-code.json').is_file()


def test_native_receiving_adapter_installs_without_launch_and_verifies_preserved_profile(tmp_path):
    source, home, pin = assets(tmp_path)
    calls = []
    def dispatch(plan, argv):
        assert argv[2:6] == ['--user', '1000', '--group', '1000']
        calls.append(argv)
        position = argv.index('-c')
        program = argv[position + 1].replace("Path('/home/agent')", 'Path(' + repr(str(home)) + ')')
        program = program.replace('/opt/browser-code', str(source))
        # Only transport paths/system package discovery are fixtures. The actual
        # maintained module, Linux publication and private filesystem execute.
        module = argv[position + 2]
        program = program.replace("home=Path(", "module.shutil.which=lambda name: '/fixture/'+name\nhome=Path(", 1)
        result = subprocess.run([sys.executable, '-B', '-I', '-c', program, module,
            *argv[position + 3:]], capture_output=True, text=True)
        if result.returncode:
            raise ValueError(result.stderr)
        return result.stdout
    backend = SimpleNamespace(config=SimpleNamespace(browser_artifact=pin, browser_image=pin['image']),
        instance=lambda plan: 'dm-fixture', _dispatch=dispatch,
        _environment=lambda plan: Observation('complete', dict(root_gib=8, home_gib=22)))
    selected = Browser(backend)
    assert selected.observe({'browser': True}).state == 'absent'
    selected.execute({'browser': True})
    profile = home / '.kimi-webbridge/chromium-profile'
    profile.mkdir()
    (profile / 'own-history').write_text('Receiving only')
    assert selected.observe({'browser': True}).state == 'complete'
    selected.execute({'browser': True})
    assert (profile / 'own-history').read_text() == 'Receiving only'
    assert not (home / '.kimi-webbridge/cluster-launch.log').exists()
    assert selected.code.startswith('"""Optional owner-local') and calls
    (home / '.kimi-webbridge/bin/cluster-browser.py').write_text('unqualified code')
    with pytest.raises(ValueError, match='installed_browser_code_changed'):
        selected.observe({'browser': True})
    with pytest.raises(OnboardingError, match='browser_not_selected'):
        selected.execute({'browser': False})


def test_selected_artifact_and_host_context_guard(tmp_path, monkeypatch):
    from tests.test_onboarding_host import configured
    from clusterctl.onboarding_host import HostBackend
    config, plan, transport, backend = configured(tmp_path)
    pin = dict(image=config.browser_image, daemon_sha256='b' * 64, extension_sha256='c' * 64)
    config = dataclasses.replace(config, browser_artifact=pin, code=tmp_path / 'code',
        inputs=tmp_path / 'inputs', views=tmp_path / 'views')
    backend = HostBackend(config, run=transport)
    plan['browser'] = True
    being_seed._write(config.grants / 'eko.json', dict(schema='cluster-onboarding-host-grant/v1',
        plan=plan, revoked=False))
    backend.execute(plan, 'environment', 'environment')
    monkeypatch.setattr(backend, '_consented', lambda plan, stage: True)
    monkeypatch.setattr(backend, '_guest_observe', lambda plan, stage: Observation('complete', dict(context_verified=True)))
    state = {'installed': False}
    monkeypatch.setattr(Browser, 'observe', lambda self, plan: Observation('complete', dict(verified=True, browser_code_verified=True))
        if state['installed'] else Observation('absent', safe_to_execute=True))
    monkeypatch.setattr(Browser, 'execute', lambda self, plan: state.update(installed=True))
    monkeypatch.setattr(backend, '_guest_execute', lambda plan, stage: None)
    assert backend.observe(plan, 'context', 'context').state == 'absent'
    backend.execute(plan, 'context', 'context')
    facts = backend.observe(plan, 'context', 'context').facts
    assert facts['context_verified'] and facts['browser_code_verified']
    backend.observe(plan, 'context', 'context').validate()
    # An already advanced job repairs this missing home dependency without
    # repeating its Matrix stage or touching custody during the repair tick.
    state['installed'] = False
    monkeypatch.setattr(backend, '_matrix_execute', lambda *args: pytest.fail('unexpected enrollment'))
    assert backend.observe(plan, 'matrix', 'matrix').state == 'absent'
    backend.execute(plan, 'matrix', 'matrix')
    assert state['installed']
    assert artifact(pin, config.browser_image) == pin
    with pytest.raises(OnboardingError, match='qualified_browser_artifact_required'):
        artifact(pin, 'd' * 64)
