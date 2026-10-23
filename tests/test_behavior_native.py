"""Opt-in exact installed native qualification, with no thread or model requests."""
from __future__ import annotations

import hashlib
import json
import os
import selectors
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from clusterctl.behavior_delta import BehaviorDelta
from clusterctl.operation_journal import OperationJournal
from clusterctl.same_being_operator import CodexConfigControl

BINARY = os.environ.get('BEHAVIOR_NATIVE_BINARY')


@pytest.mark.skipif(not BINARY, reason='exact native binary must be explicitly selected')
def test_actual_native_websocket_config_control_uses_no_model(tmp_path):
    binary = Path(BINARY).resolve(strict=True)
    home = tmp_path / 'home'
    native_home = home / '.codex'
    native_home.mkdir(parents=True, mode=0o700)
    config = native_home / 'config.toml'
    config.write_text('model_reasoning_summary = "auto"\n')
    env = dict(os.environ, HOME=str(home), CODEX_HOME=str(native_home))
    with tempfile.TemporaryDirectory(prefix='config-control-') as short:
        endpoint = Path(short) / 'native.sock'
        with (tmp_path / 'native-stderr.log').open('wb') as stderr:
            process = subprocess.Popen([str(binary), 'app-server', '--listen', 'unix://' + str(endpoint)],
                                       env=env, cwd=home, stdout=subprocess.DEVNULL, stderr=stderr)
            try:
                deadline = time.monotonic() + 15
                while not endpoint.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.05)
                assert endpoint.exists(), (tmp_path / 'native-stderr.log').read_text()
                control = CodexConfigControl(endpoint)
                before = control('config/read', dict(includeLayers=True, cwd=str(home)))
                assert before['config']['model_reasoning_summary'] == 'auto'
                control('config/batchWrite', dict(edits=[dict(keyPath='model_reasoning_summary',
                    value='concise', mergeStrategy='replace')], reloadUserConfig=True))
                assert control('config/read', dict(includeLayers=True, cwd=str(home)))['config']['model_reasoning_summary'] == 'concise'
                with pytest.raises(ValueError, match='native_method_not_supported'):
                    control('turn/start', {})
            finally:
                process.terminate()
                process.wait(timeout=5)


@pytest.mark.skipif(not BINARY, reason='exact native binary must be explicitly selected')
def test_actual_native_selected_write_lost_return_and_inverse(tmp_path):
    binary = Path(BINARY).resolve(strict=True)
    home = tmp_path / 'home'
    native_home = home / '.codex'
    native_home.mkdir(parents=True, mode=0o700)
    config = native_home / 'config.toml'
    config.write_text('model_reasoning_summary = "auto"\n')
    instructions = native_home / 'AGENTS.md'
    instructions.write_text('Original receiving instructions.\n')
    env = dict(os.environ, HOME=str(home), CODEX_HOME=str(native_home))
    methods = []
    with (tmp_path / 'native-stderr.log').open('wb') as stderr:
        process = subprocess.Popen([str(binary), 'app-server', '--stdio'], env=env,
                                   cwd=home, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=stderr)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        pending = b''
        identifier = 0
        def native(method, params):
            nonlocal pending, identifier
            identifier += 1
            methods.append(method)
            process.stdin.write(json.dumps(dict(id=identifier, method=method, params=params)).encode() + b'\n')
            process.stdin.flush()
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                while b'\n' in pending:
                    line, pending = pending.split(b'\n', 1)
                    response = json.loads(line)
                    if response.get('id') == identifier:
                        assert 'error' not in response, response.get('error')
                        return response['result']
                assert selector.select(max(0, deadline - time.monotonic())), 'native response deadline'
                raw = os.read(process.stdout.fileno(), 65536)
                assert raw, 'native closed'
                pending += raw
                assert len(pending) <= 4 * 1024 * 1024
            raise TimeoutError('native response deadline')
        try:
            native('initialize', dict(clientInfo=dict(name='cluster_behavior_qualification', version='1.0.0'),
                                      capabilities=dict(experimentalApi=True)))
            process.stdin.write(b'{"method":"initialized"}\n')
            process.stdin.flush()
            owner = dict(being_ref='qualification-being', body_ref='qualification-local',
                         embodiment_id='qualification-body', incarnation_id='qualification-life',
                         principal_id='qualification-principal')
            adapter = BehaviorDelta(OperationJournal(tmp_path / 'journal'), owner,
                                    native=native, native_file=config, cwd=home)
            adapter.prepare('actual-native', source=dict(owner, body_ref='qualification-source'),
                            source_refs=[hashlib.sha256(b'selected synthetic intent').hexdigest()],
                            files={str(instructions): b'Qualified selected instructions.\n'},
                            edits=[(['model_reasoning_summary'], 'concise')])
            class LostReturn(BaseException):
                pass
            def lose_return(stage):
                if stage == 'after-native-effect':
                    raise LostReturn()
            with pytest.raises(LostReturn):
                adapter.apply('actual-native', fault=lose_return)
            assert methods.count('config/batchWrite') == 1
            recovered = adapter.recover('actual-native')
            assert recovered['materialized'] and recovered['native_effective']
            assert not recovered['native_reload_acknowledged']
            assert recovered['consumption'] == 'unverified'
            adapter.apply('actual-native')
            assert methods.count('config/batchWrite') == 1
            # Native-supported unrelated edit must survive the targeted inverse.
            native('config/batchWrite', dict(edits=[dict(keyPath='model_verbosity', value='low',
                                                       mergeStrategy='replace')], reloadUserConfig=True))
            restored = adapter.rollback('actual-native')
            assert restored['materialized']
            result = native('config/read', dict(includeLayers=True, cwd=str(home)))
            assert result['config']['model_reasoning_summary'] == 'auto'
            assert result['config']['model_verbosity'] == 'low'
            assert instructions.read_text() == 'Original receiving instructions.\n'
            assert set(methods) == {'initialize', 'config/read', 'config/batchWrite'}
            assert len(adapter.journal.list_all()) == 2
        finally:
            process.stdin.close()
            selector.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
            process.stdout.close()
