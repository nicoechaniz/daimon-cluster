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
import stat
import sys
import time

from .behavior_delta import BehaviorDelta
from .operation_journal import OperationJournal
from .same_being_integration import NativeMemory, SameBeingIntegration, SelectedSkills

# Exception prose (even an identifier-looking word) is private input, not a
# public diagnostic. Only these maintained domain codes may reach stdout/stderr.
PUBLIC_CODES = frozenset('integration_' + suffix for suffix in '''
    behavior_adapter_unavailable behavior_binding_mismatch behavior_rollback_state_changed
    behavior_source_bytes_changed behavior_source_closure_missing behavior_source_origin_changed
    canonical_operation_uuid_required checkpoint_memory_binding_changed completed_effect_changed
    content_not_in_proposal controls_rollback_started decision_preview_changed decision_view_changed
    deliberate_local_decision effect_receipt_binding_changed effect_truth_unavailable effects_unobserved
    empty_selection invalid_residual known_proposal_required local_decision_changed local_decision_fork
    local_reason_required matrix_binding_changed matrix_capability_unavailable memory_adapter_unavailable
    memory_being_mismatch memory_effect_unobserved memory_links_pending memory_packet_bounds
    observed_effect_changed operation_binding_changed operation_not_resumable operation_selection_changed
    projection_observer_unavailable proposal_content_refs_required proposal_projection_unavailable
    retained_matrix_request_changed rollback_identity_collision rollback_not_resumable
    rollback_requires_completed_parent skill_adapter_unavailable skill_effect_unobserved
    skill_rollback_owner_changed skill_rollback_state_changed skill_selection_conflict source_event_changed
    unrelated_skill_recovery duplicate_json_key existing_capability_not_private existing_module_selection_changed
    input_too_large invalid_receiving_binding invalid_selected_module_path memory_environment_not_supported
    memory_module_selection_missing native_deadline native_method_not_supported native_request_rejected
    native_socket_not_owned operation_failed private_binding_or_input_required selected_module_changed
    selected_module_not_regular selected_package_changed
'''.split())
PUBLIC_MATRIX_CODES = frozenset('''
    protocol_rejected projection_invalid runtime_unavailable durable_conflict causal_gap
    invalid_params unknown_target target_not_projectable decision_chain_failed decision_predecessor_mismatch
    projection_effect_truth_unverifiable projection_known_proposal_required projection_local_adoption_required
    projection_effect_actor_mismatch projection_effect_fence_holder_mismatch projection_effect_timing_invalid
    projection_adoption_not_current projection_decision_view_changed projection_effect_identity_conflict
    effect-truth-unverifiable effect-truth-discrepancy
'''.split())


def public_error(error):
    code = str(error)
    if code in PUBLIC_CODES:
        return code
    for prefix in ('integration_matrix_read_', 'integration_matrix_mutation_'):
        if code.startswith(prefix) and code[len(prefix):] in PUBLIC_MATRIX_CODES:
            return code
    return 'integration_operation_failed'


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
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_size > 8 * 1024 * 1024:
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


class OwnerMatrixClient:
    """Route existing disjoint owner profiles without widening their grants."""

    def __init__(self, mutation, observation=None):
        self.clients = [mutation] if observation is None else [mutation, observation]
        self.config, self.socket_path, self.clock = mutation.config, mutation.socket_path, mutation.clock
        for client in self.clients:
            if (client.socket_path != self.socket_path
                    or client.config.expected_server != self.config.expected_server
                    or client.config.runtime_id != self.config.runtime_id
                    or client.config.runtime_label != self.config.runtime_label):
                raise ValueError('integration_matrix_binding_changed')

    def prepare(self, method, params, *, request_id=None):
        for client in self.clients:
            if method in client.config.capability.methods:
                return client.prepare(method, params, request_id=request_id)
        raise ValueError('integration_matrix_capability_unavailable')

    def send(self, request):
        for client in self.clients:
            if client.config.capability.capability_id == request['capability_id']:
                return client.send(request)
        raise ValueError('integration_retained_matrix_request_changed')

    def invoke(self, method, params):
        request = self.prepare(method, params)
        return request, self.send(request)


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
        def existing_client(config_key, key_key):
            descriptor = os.open(selected[key_key], os.O_RDONLY | os.O_NOFOLLOW)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                os.close(descriptor)
                raise ValueError('integration_existing_capability_not_private')
            client_config = ClientConfig.load(Path(selected[config_key]), read_capability_key(descriptor))
            return LocalClient(Path(selected['socket']), client_config,
                               timeout_seconds=selected.get('timeout_seconds', 40))
        mutation = existing_client('client_config', 'key_file')
        if ('observe_client_config' in selected) != ('observe_key_file' in selected):
            raise ValueError('integration_matrix_binding_changed')
        observation = existing_client('observe_client_config', 'observe_key_file') if 'observe_client_config' in selected else None
        matrix = OwnerMatrixClient(mutation, observation)
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
                    or target.stat().st_uid not in {0, os.geteuid()} or target.stat().st_mode & 0o022
                    or hashlib.sha256(target.read_bytes()).hexdigest() != expected):
                raise ValueError('integration_selected_package_changed')
            existing = sys.modules.get(Path(relative).stem)
            if existing is not None and relative.endswith('.py'):
                loaded = getattr(existing, '__file__', None)
                if loaded is None or hashlib.sha256(Path(loaded).read_bytes()).hexdigest() != expected:
                    raise ValueError('integration_existing_module_selection_changed')
        if any(name not in hashes for name in ('memoryctl.py', 'same_being_sync.py', 'backupctl.py')):
            raise ValueError('integration_memory_module_selection_missing')
        # memoryctl resolves its receiving globals at import. Preserve the
        # daemon's environment and qualified import context. The selected
        # package may itself insert its script directory while bootstrapping.
        environment = selected['environment']
        if set(environment) - {'HMK_AGENT_MEMORY_BASE', 'HMK_DB_PATH', 'HMK_WORKSPACE_ROOT', 'HMK_ENV_FILE', 'HMK_HERMES_HOME'}:
            raise ValueError('integration_memory_environment_not_supported')
        old = {name: os.environ.get(name) for name in environment}
        original_path = sys.path[:]
        try:
            sys.path.insert(0, str(scripts))
            os.environ.update(environment)
            namespace = '_integration_' + hashlib.sha256(str(scripts).encode()).hexdigest()[:16]
            modules = {name: source_module(namespace + '_' + name, scripts / (name + '.py'), hashes[name + '.py'])
                       for name in ('memoryctl', 'same_being_sync', 'backupctl')}
            # Native exchange validates legacy packets with a late canonical
            # import. Register only the already hash-checked selected helper;
            # retaining the script path would invalidate qualified startup.
            legacy_module = (source_module('legacy_native_sync', scripts / 'legacy_native_sync.py',
                                          hashes['legacy_native_sync.py'])
                             if 'legacy_native_sync.py' in hashes else None)
            legacy = None
            if selected.get('legacy_provenance'):
                if legacy_module is None:
                    raise ValueError('integration_memory_module_selection_missing')
                legacy = legacy_module.load(Path(selected['legacy_provenance']), selected['legacy_provenance_sha256'])
        finally:
            sys.path[:] = original_path
            for name, value in old.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
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
    parser.add_argument('action', choices=('inspect', 'prepare', 'apply', 'recover', 'status', 'rollback'))
    parser.add_argument('--operation-id')
    parser.add_argument('--source-event-id')
    parser.add_argument('--selection', type=Path)
    args = parser.parse_args(argv)
    if args.action == 'inspect':
        if args.source_event_id is None or args.selection is not None:
            parser.error('inspect requires --source-event-id and no selection')
    elif args.operation_id is None or args.source_event_id is not None:
        parser.error('this action requires --operation-id and no --source-event-id')
    try:
        operator = load_operator(args.binding)
        if args.action == 'inspect':
            result = operator.inspect(args.source_event_id)
        elif args.action == 'prepare':
            if args.selection is None:
                parser.error('prepare requires --selection')
            result = operator.prepare(args.operation_id, **private_json(args.selection))
        else:
            if args.selection is not None:
                parser.error('--selection is only used by prepare; retries use retained input')
            result = getattr(operator, args.action)(args.operation_id)
    except (ValueError, RuntimeError, OSError, KeyError) as error:
        print(json.dumps({'ok': False, 'code': public_error(error),
                          'error_type': type(error).__name__}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
