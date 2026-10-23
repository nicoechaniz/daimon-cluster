"""Owner-local entrypoint and trusted observer binding for finite integration.

Only the receiving operator selects implementations, credentials and resources.
Peer proposals/packets cannot supply this binding or native-control destination.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from .behavior_delta import BehaviorDelta
from .operation_journal import OperationJournal
from .same_being_integration import NativeMemory, SameBeingIntegration, SelectedSkills


def private_json(path, *, maximum=128 * 1024 * 1024):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_size > maximum):
            raise ValueError('integration_private_binding_or_input_required')
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('integration_input_too_large')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('integration_duplicate_json_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def source_module(name, path, expected_sha256):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_size > 8 * 1024 * 1024:
            raise ValueError('integration_selected_module_not_regular')
        raw = stream.read(8 * 1024 * 1024 + 1)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('integration_selected_module_changed')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    # Execute exactly the selected bytes, without reopening a writable checkout
    # after verification or requiring permission changes to the source repo.
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


class CodexConfigControl:
    """Existing native daemon WebSocket; no process, thread or model creation."""

    def __init__(self, socket_path):
        self.socket_path, self.sequence = Path(socket_path), 0

    def __call__(self, method, params):
        if method not in {'config/read', 'config/batchWrite'}:
            raise ValueError('integration_native_method_not_supported')
        # Codex advertises a rendezvous symlink to its protected physical socket.
        # Inspect and connect that actual endpoint, as the native transport does.
        target = self.socket_path.resolve(strict=True)
        info = target.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise ValueError('integration_native_socket_not_owned')
        from websockets.sync.client import unix_connect
        with unix_connect(path=str(target), uri='ws://localhost',
                          open_timeout=10, close_timeout=2, max_size=16 * 1024 * 1024) as connection:
            def rpc(name, arguments):
                self.sequence += 1
                ident = self.sequence
                connection.send(json.dumps({'id': ident, 'method': name, 'params': arguments}))
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    reply = json.loads(connection.recv(timeout=max(.01, deadline - time.monotonic())))
                    if reply.get('id') == ident:
                        if 'error' in reply:
                            raise ValueError('integration_native_request_rejected')
                        return reply['result']
                raise TimeoutError('integration_native_deadline')
            rpc('initialize', {'clientInfo': {'name': 'cluster_same_being', 'version': '1.0.0'},
                               'capabilities': {'experimentalApi': True}})
            connection.send(json.dumps({'method': 'initialized'}))
            return rpc(method, params)


def load_operator(path, *, matrix=None):
    """Called by the CLI or trusted host bootstrap, never from a peer/RPC field.

    The host may pass its existing authenticated client. The returned observer
    reads this same journal through actual owners and needs no Matrix re-entry.
    """
    from daimon_matrix import cluster
    from daimon_matrix.client import ClientConfig, LocalClient, read_capability_key

    config = private_json(path, maximum=1024 * 1024)
    if (set(config) != {'schema', 'binding', 'journal', 'matrix', 'memory', 'skills', 'behavior'}
            or config['schema'] != 'cluster-same-being-binding/v1'):
        raise ValueError('integration_invalid_receiving_binding')
    if matrix is None:
        selected = config['matrix']
        descriptor = os.open(selected['key_file'], os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            os.close(descriptor)
            raise ValueError('integration_existing_capability_not_private')
        client_config = ClientConfig.load(Path(selected['client_config']), read_capability_key(descriptor))
        matrix = LocalClient(Path(selected['socket']), client_config,
                             timeout_seconds=selected.get('timeout_seconds', 40))
    journal = OperationJournal(config['journal'])
    memory = skills = behavior = None
    if config['memory'] is not None:
        selected = config['memory']
        scripts = Path(selected['scripts'])
        hashes = selected['files']
        # Verify the selected package closure, including imported helpers.
        for relative, expected in hashes.items():
            if Path(relative).is_absolute() or '..' in Path(relative).parts:
                raise ValueError('integration_invalid_selected_module_path')
            target = scripts / relative
            if (target.is_symlink() or not target.is_file()
                    or target.stat().st_uid != os.geteuid() or target.stat().st_mode & 0o022
                    or hashlib.sha256(target.read_bytes()).hexdigest() != expected):
                raise ValueError('integration_selected_package_changed')
            existing = sys.modules.get(Path(relative).stem)
            if existing is not None and relative.endswith('.py'):
                loaded = getattr(existing, '__file__', None)
                if loaded is None or hashlib.sha256(Path(loaded).read_bytes()).hexdigest() != expected:
                    raise ValueError('integration_existing_module_selection_changed')
        if any(name not in hashes for name in ('memoryctl.py', 'same_being_sync.py', 'backupctl.py')):
            raise ValueError('integration_memory_module_selection_missing')
        sys.path.insert(0, str(scripts))
        # memoryctl resolves its receiving globals at import. Preserve the
        # daemon's environment; reject an already bound different memory pool.
        environment = selected['environment']
        if set(environment) - {'HMK_AGENT_MEMORY_BASE', 'HMK_DB_PATH', 'HMK_WORKSPACE_ROOT', 'HMK_ENV_FILE', 'HMK_HERMES_HOME'}:
            raise ValueError('integration_memory_environment_not_supported')
        old = {name: os.environ.get(name) for name in environment}
        try:
            os.environ.update(environment)
            namespace = '_integration_' + hashlib.sha256(str(scripts).encode()).hexdigest()[:16]
            modules = {name: source_module(namespace + '_' + name, scripts / (name + '.py'), hashes[name + '.py'])
                       for name in ('memoryctl', 'same_being_sync', 'backupctl')}
        finally:
            for name, value in old.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        legacy = None
        if selected.get('legacy_provenance'):
            legacy_module = source_module(namespace + '_legacy_native_sync', scripts / 'legacy_native_sync.py',
                                          hashes['legacy_native_sync.py'])
            legacy = legacy_module.load(Path(selected['legacy_provenance']), selected['legacy_provenance_sha256'])
        memory = NativeMemory(modules['memoryctl'], modules['same_being_sync'], modules['backupctl'],
                              selected['owner'], selected['backup_config'], legacy=legacy)
    if config['skills'] is not None:
        selected = config['skills']
        installer = source_module('_integration_selected_skills', selected['installer'], selected['installer_sha256'])
        skills = SelectedSkills(installer, selected['repository'], selected['root'], selected['state'])
    if config['behavior'] is not None:
        selected = config['behavior']
        native = CodexConfigControl(selected['native_control_socket']) if selected.get('native_control_socket') else None
        behavior = BehaviorDelta(journal, config['binding'], native=native,
                                 native_file=selected.get('native_file'), cwd=selected.get('cwd'))
    return SameBeingIntegration(journal, config['binding'], matrix, cluster,
                                memory=memory, skills=skills, behavior=behavior)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binding', required=True, type=Path)
    parser.add_argument('action', choices=('prepare', 'apply', 'recover', 'status', 'rollback'))
    parser.add_argument('--operation-id', required=True)
    parser.add_argument('--selection', type=Path)
    args = parser.parse_args(argv)
    try:
        operator = load_operator(args.binding)
        if args.action == 'prepare':
            if args.selection is None:
                parser.error('prepare requires --selection')
            result = operator.prepare(args.operation_id, **private_json(args.selection))
        else:
            if args.selection is not None:
                parser.error('--selection is only used by prepare; retries use retained input')
            result = getattr(operator, args.action)(args.operation_id)
    except (ValueError, RuntimeError, OSError, KeyError) as error:
        code = str(error)
        safe = code if re.fullmatch('[a-z][a-z0-9_-]{0,100}', code) else 'integration_operation_failed'
        print(json.dumps({'ok': False, 'code': safe, 'error_type': type(error).__name__}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
