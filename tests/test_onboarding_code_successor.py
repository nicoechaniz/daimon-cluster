"""Runtime updates preserve frozen receiving context and dependency artifacts."""
import os
import json
import subprocess
import sys
from dataclasses import replace

import pytest

from clusterctl import being_seed, onboarding_release
from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_code_successor import build, selected, verify


def fixture(tmp_path):
    base = tmp_path / 'original'
    base.mkdir(mode=0o755)
    files = {'inheritance.md': b'Previously approved Source text.',
        'hmk/scripts/memoryctl.py': b'Original memory tooling.',
        'hmk/scripts/native_records.py': b'Original record tooling.',
        'sdk/pinned.whl': b'Existing qualified dependency artifact.',
        'telegram/telecodex': b'Existing qualified consumer artifact.',
        'clusterctl/__init__.py': b'', 'clusterctl/onboarding_target.py': b'Original runtime.'}
    files.update({'support/being-seed-tools/tools/' + name: b'Original tool.' for name in being_seed.TOOL_HASHES})
    for name, raw in files.items():
        p = base / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
        p.chmod(0o644)
    for directory in base.rglob('*'):
        if directory.is_dir():
            directory.chmod(0o755)
    profile = dict(schema=onboarding_release.PROFILE, model='gpt-6.1', reasoning='medium',
        approval='never', sandbox='danger-full-access', skills=[], primary_store=None)
    fingerprint = onboarding_release.seal(base, profile)
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'onboarding_target.py').write_bytes(b'Updated runtime.')
    return base, fingerprint, source, profile


def test_runtime_successor_preserves_original_code_and_context_bytes(tmp_path):
    base, original, source, _ = fixture(tmp_path)
    output = tmp_path / 'successor'
    result = build(base, original, source, ('onboarding_target.py',), output)
    assert result['base_release_digest'] == original
    assert selected(output, result['runtime_digest'], base, original, uid=os.geteuid()) == output
    assert selected(base, None, base, original, uid=os.geteuid()) == base
    assert (base / 'clusterctl/onboarding_target.py').read_bytes() == b'Original runtime.'
    assert (output / 'clusterctl/onboarding_target.py').read_bytes() == b'Updated runtime.'


@pytest.mark.parametrize('asset', ['inheritance.md', 'hmk/scripts/memoryctl.py',
    'sdk/pinned.whl', 'telegram/telecodex'])
def test_even_resealed_successor_cannot_change_approved_context_or_dependencies(tmp_path, asset):
    base, original, source, profile = fixture(tmp_path)
    output = tmp_path / 'successor'
    build(base, original, source, ('onboarding_target.py',), output)
    (output / 'release.json').unlink()
    (output / asset).write_bytes(b'Unapproved replacement.')
    replacement = onboarding_release.seal(output, profile)
    with pytest.raises(OnboardingError, match='original_onboarding_context_preserved'):
        verify(output, replacement, base, original, uid=os.geteuid())


def test_successor_requires_matching_profile_and_explicit_selection(tmp_path):
    base, original, source, profile = fixture(tmp_path)
    output = tmp_path / 'successor'
    build(base, original, source, ('onboarding_target.py',), output)
    with pytest.raises(OnboardingError, match='qualified_onboarding_runtime_required'):
        selected(output, None, base, original, uid=os.geteuid())
    (output / 'release.json').unlink()
    replacement = onboarding_release.seal(output, {**profile, 'model': 'another-model'})
    with pytest.raises(OnboardingError, match='compatible_onboarding_runtime_successor_required'):
        verify(output, replacement, base, original, uid=os.geteuid())


def test_builder_refuses_base_descendant_and_non_module_input_before_writes(tmp_path):
    base, original, source, _ = fixture(tmp_path)
    for output, names in [(base / 'successor', ('onboarding_target.py',)),
                          (tmp_path / 'successor', ('../private.txt',))]:
        with pytest.raises(OnboardingError):
            build(base, original, source, names, output)
        assert not output.exists()
    onboarding_release.verify(base, original, uid=os.geteuid())


@pytest.mark.parametrize('missing', ['runtime_code', 'runtime_digest'])
def test_host_configuration_requires_both_qualified_runtime_coordinates(tmp_path, missing):
    from clusterctl.onboarding_host import HostConfig
    base, original, source, _ = fixture(tmp_path)
    output = tmp_path / 'successor'
    result = build(base, original, source, ('onboarding_target.py',), output)
    value = dict(schema='cluster-onboarding-host/v1', native_image='3' * 64, browser_image='4' * 64,
        release_digest=original, pool='daimon-cluster', profile='daimon-agent', concurrency=1,
        code=str(base), runtime_code=str(output), runtime_digest=result['runtime_digest'])
    for key in ('jobs', 'grants', 'inputs', 'views', 'progress'):
        directory = tmp_path / key
        directory.mkdir(mode=0o700)
        value[key] = str(directory)
    config = tmp_path / 'host.json'
    being_seed._write(config, value)
    loaded = HostConfig.load(config)
    assert loaded.runtime_code == output and loaded.release_digest == original
    being_seed._write(config, {key: item for key, item in value.items() if key != missing})
    with pytest.raises(OnboardingError, match='invalid_onboarding_host_configuration'):
        HostConfig.load(config)


def test_host_attaches_runtime_once_before_v8_observation_and_preserves_foreign_mount(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from clusterctl.onboarding_host import HostBackend
    from tests.test_onboarding_host import configured
    base, original, source, _ = fixture(tmp_path)
    output = tmp_path / 'successor'
    result = build(base, original, source, ('onboarding_target.py',), output)
    config, plan, run, _ = configured(tmp_path)
    plan = {**plan, 'release_digest': original}
    config = replace(config, code=base, release_digest=original, runtime_code=output,
                     runtime_digest=result['runtime_digest'], views=tmp_path / 'views')
    being_seed._write(config.grants / 'eko.json', dict(schema='cluster-onboarding-host-grant/v1', plan=plan, revoked=False))
    config.views.mkdir(mode=0o700)
    backend = HostBackend(config, run=run)
    backend.execute(plan, 'environment', 'unused')
    run.instances[0]['expanded_devices']['onboarding-matrix-public'] = backend._matrix_mount(plan)
    root = tmp_path / 'custody'
    from clusterctl.onboarding import digest
    (root / digest(plan)).mkdir(mode=0o700, parents=True)
    being_seed._write(root / digest(plan) / 'genesis.json', {})
    monkeypatch.setattr('clusterctl.onboarding_mounts.prepare_matrix_public', lambda *args: None)
    actions = []
    def observe(_plan, action):
        actions.append(action)
        assert 'onboarding-runtime-' + result['runtime_digest'] in run.instances[0]['expanded_devices']
        return dict(phase='v8')
    monkeypatch.setattr(backend, '_matrix_command', observe)
    run.calls.clear()
    backend._matrix_execute(plan, SimpleNamespace(root=root))
    backend._matrix_execute(plan, SimpleNamespace(root=root))
    assert actions == ['observe', 'observe'] and len(run.calls) == 1
    device = run.instances[0]['expanded_devices']['onboarding-runtime-' + result['runtime_digest']]
    assert device['readonly'] == 'true' and device['source'] == str(output)
    device['source'] = '/foreign/runtime'
    with pytest.raises(OnboardingError, match='foreign_receiving_mount_preserved'):
        backend._matrix_execute(plan, SimpleNamespace(root=root))
    assert len(run.calls) == 1 and len(actions) == 2


def test_service_launches_selected_runtime_while_retaining_original_code_argument(tmp_path):
    from clusterctl.onboarding_service import command
    base, original, source, _ = fixture(tmp_path)
    (source / 'onboarding_target.py').write_text(
        'import json,sys\ndef main():\n print(json.dumps(sys.argv[1:]));return 0\n')
    output = tmp_path / 'successor'
    result = build(base, original, source, ('onboarding_target.py',), output)
    argv = command(base, receive_only=True, runtime_code=output, runtime_digest=result['runtime_digest'])
    launched = subprocess.run([sys.executable, *argv[1:]], capture_output=True, check=True, text=True)
    options = json.loads(launched.stdout)
    assert options[0] == 'admitted-serve'
    assert options[options.index('--code') + 1] == str(base)
    assert options[options.index('--runtime-code') + 1] == str(output)
    assert options[options.index('--runtime-digest') + 1] == result['runtime_digest']
    assert not list(output.rglob('__pycache__'))
    with pytest.raises(OnboardingError, match='qualified_onboarding_runtime_required'):
        command(base, receive_only=True, runtime_code=output)


def test_target_reexec_preserves_selected_runtime_and_uses_original_sdk(tmp_path, monkeypatch):
    from clusterctl import onboarding_code_successor, onboarding_target
    base, original, source, _ = fixture(tmp_path)
    output = tmp_path / 'successor'
    result = build(base, original, source, ('onboarding_target.py',), output)
    plan_path = tmp_path / 'plan.json'
    from tests.test_onboarding import plan
    being_seed._write(plan_path, {**plan(), 'release_digest': original})
    venv = tmp_path / 'private-venv'
    sdk_codes, execs = [], []
    actual = onboarding_code_successor.selection
    def owned_selection(*args, **kwargs):
        return actual(*args, uid=os.geteuid())
    def sdk(_home, code):
        sdk_codes.append(code)
        return venv
    def execute(executable, argv):
        execs.append((executable, argv))
        raise RuntimeError('captured SDK reexec')
    monkeypatch.setattr(onboarding_code_successor, 'selection', owned_selection)
    monkeypatch.setattr(onboarding_target.onboarding_sdk, 'observe', sdk)
    monkeypatch.setattr(onboarding_target.os, 'execv', execute)
    args = ['observe', '--home', str(tmp_path / 'home'), '--code', str(base), '--plan', str(plan_path),
        '--genesis', str(tmp_path / 'genesis.json'), '--runtime-code', str(output),
        '--runtime-digest', result['runtime_digest']]
    assert onboarding_target.main(args) == 1
    assert sdk_codes == [base] and len(execs) == 1
    executable, argv = execs[0]
    assert executable == venv / 'bin/python'
    assert argv[5] == str(output) and argv[6:] == args
    assert '--runtime-digest' in argv
