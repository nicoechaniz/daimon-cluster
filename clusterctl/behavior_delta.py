"""Receiving-local, selected behavioral materialization; never a peer executor.

The caller supplies its verified local binding, selected local destinations and
native client. Discovery/proposals do not call this adapter or select authority.
OperationJournal retains preimages and uncertainty; no separate effect journal.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .operation_journal import JournalConflict, OperationJournal, canonical_bytes

BINDING_FIELDS = frozenset({'being_ref', 'body_ref', 'embodiment_id', 'incarnation_id', 'principal_id'})
MAX_BYTES = 8 * 1024 * 1024
MAX_FILES = 128
Native = Callable[[str, dict[str, Any]], dict[str, Any]]


class BehaviorConflict(JournalConflict):
    """Selected receiving state differs; preserve it instead of repairing by overwrite."""


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _binding(value: Mapping[str, Any]) -> dict[str, str]:
    if set(value) != BINDING_FIELDS or any(not isinstance(v, str) or not v for v in value.values()):
        raise ValueError('invalid_behavior_binding')
    return dict(value)


def _key(value: Sequence[str]) -> tuple[str, ...]:
    if (isinstance(value, (str, bytes)) or not 1 <= len(value) <= 16
            or any(not isinstance(s, str) or not s or len(s) > 256 for s in value)):
        raise ValueError('invalid_behavior_key')
    return tuple(value)


def _selected(config: Mapping[str, Any], key: Sequence[str]) -> dict[str, Any]:
    value: Any = config
    for part in key:
        if not isinstance(value, Mapping) or part not in value:
            return {'present': False, 'value': None}
        value = value[part]
    return {'present': True, 'value': copy.deepcopy(value)}


def _path(path: str | Path) -> Path:
    result = Path(path)
    if not result.is_absolute() or '..' in result.parts:
        raise ValueError('behavior_destination_must_be_local_absolute')
    for parent in (result, *result.parents):
        if parent.is_symlink():
            raise ValueError('behavior_symlink_destination')
    if not result.parent.is_dir():
        raise ValueError('behavior_destination_parent_missing')
    info = result.parent.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('behavior_destination_parent_not_owned')
    return result


def _file(path: str | Path) -> dict[str, Any]:
    target = _path(path)
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {'present': False, 'bytes': None, 'mode': None}
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > MAX_BYTES):
            raise ValueError('behavior_file_not_owned_or_bounded')
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('behavior_file_too_large')
    return {'present': True, 'bytes': base64.b64encode(raw).decode(),
            'mode': stat.S_IMODE(info.st_mode)}


def _replace(path: str, expected: dict[str, Any], desired: dict[str, Any]) -> None:
    target = _path(path)
    if _file(target) != expected:
        raise BehaviorConflict('behavior_file_changed')
    if not desired['present']:
        target.unlink()
    else:
        fd, temporary = tempfile.mkstemp(prefix='.behavior-', dir=target.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), desired['mode'])
                stream.write(base64.b64decode(desired['bytes'], validate=True))
                stream.flush()
                os.fsync(stream.fileno())
            if _file(target) != expected:
                raise BehaviorConflict('behavior_file_changed')
            os.replace(temporary, target)
        finally:
            Path(temporary).unlink(missing_ok=True)
    fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class BehaviorDelta:
    """One finite owner-requested child operation, reusable by the integration parent."""

    def __init__(self, journal: OperationJournal, binding: Mapping[str, Any], *,
                 native: Native | None = None, native_file: str | Path | None = None,
                 cwd: str | Path | None = None):
        self.journal = journal
        self.binding = _binding(binding)
        self.native = native
        self.native_file = str(_path(native_file)) if native_file is not None else None
        self.cwd = str(cwd) if cwd is not None else None

    def _native(self, keys: list[list[str]]) -> dict[str, Any]:
        if self.native is None or self.native_file is None:
            raise ValueError('behavior_native_adapter_unavailable')
        response = self.native('config/read', {'includeLayers': True, 'cwd': self.cwd})
        layers = [layer for layer in response.get('layers', [])
                  if layer.get('name', {}).get('type') == 'user'
                  and layer['name'].get('file') == self.native_file]
        if len(layers) != 1 or not isinstance(layers[0].get('version'), str):
            raise ValueError('behavior_native_user_layer_unknown')
        layer = layers[0]
        return {'version': layer['version'],
                'values': [_selected(layer['config'], key) for key in keys],
                'effective': [_selected(response['config'], key) for key in keys]}

    def prepare(self, operation_id: str, *, source: Mapping[str, Any],
                source_refs: Sequence[str], files: Mapping[str, bytes | None],
                edits: Sequence[tuple[Sequence[str], Any]] = ()) -> dict[str, Any]:
        """Retain only explicitly selected local changes; no materialization."""
        source_binding = _binding(source)
        if source_binding['being_ref'] != self.binding['being_ref']:
            raise ValueError('behavior_cross_being_source')
        if (not source_refs or len(source_refs) > 128
                or any(not isinstance(ref, str) or not re.fullmatch('[0-9a-f]{64}', ref)
                       for ref in source_refs)):
            raise ValueError('behavior_exact_source_refs_required')
        if self.native_file is not None and any(str(_path(p)) == self.native_file for p in files):
            raise ValueError('behavior_config_requires_native_adapter')
        if len({str(_path(p)) for p in files}) != len(files):
            raise ValueError('behavior_duplicate_local_destination')
        if len(files) > MAX_FILES or len(edits) > 128 or not (files or edits):
            raise ValueError('behavior_selection_bounds')
        # A known operation is immutable, including after a lost prepare reply.
        old = self.journal.get(operation_id)
        selection = {'source': source_binding, 'source_refs': list(source_refs),
                     'files': {str(p): None if raw is None else base64.b64encode(raw).decode()
                               for p, raw in files.items()},
                     'edits': [[list(_key(key)), value] for key, value in edits],
                     'binding': self.binding, 'native_file': self.native_file, 'cwd': self.cwd}
        if len(canonical_bytes(selection)) > MAX_BYTES * 2:
            raise ValueError('behavior_selection_too_large')
        if old is not None:
            if old['operation'] != 'behavior-delta' or old['intent']['selection'] != selection:
                raise BehaviorConflict('behavior_operation_identity_changed')
            return self.status(operation_id)
        entries = []
        total = 0
        for path, raw in sorted(files.items()):
            if raw is not None and not isinstance(raw, bytes):
                raise ValueError('behavior_file_bytes_required')
            before = _file(path)
            after = {'present': raw is not None,
                     'bytes': None if raw is None else base64.b64encode(raw).decode(),
                     'mode': (before['mode'] if before['present'] else 0o600) if raw is not None else None}
            total += len(raw or b'') + len(base64.b64decode(before['bytes'] or ''))
            entries.append({'local_destination': str(_path(path)), 'before': before, 'after': after})
        if total > MAX_BYTES:
            raise ValueError('behavior_selection_too_large')
        keys = [list(_key(key)) for key, _ in edits]
        if any(a == b[:len(a)] for i, a in enumerate(keys) for j, b in enumerate(keys) if i != j):
            raise ValueError('behavior_overlapping_native_keys')
        snapshot = self._native(keys) if keys else None
        config = None if snapshot is None else {
            'keys': keys, 'before': snapshot['values'],
            'after': [{'present': value is not None, 'value': value} for _, value in edits],
            'preview_version': snapshot['version']}
        intent = {'selection': selection, 'files': entries, 'config': config,
                  'runtime_call': {'selection_sha256': _hash(selection)}}
        self.journal.plan(operation='behavior-delta', target='behavior:' + self.binding['body_ref'],
                          operation_id=operation_id, idempotency_key=operation_id, intent=intent,
                          expected_precondition={}, intended_transition={}, audit_identity=self.binding)
        return self.status(operation_id)

    def _row(self, operation_id: str) -> dict[str, Any]:
        row = self.journal.get(operation_id)
        if (row is None or row['operation'] not in {'behavior-delta', 'behavior-rollback'}
                or row['intent']['selection']['binding'] != self.binding
                or row['intent']['selection']['native_file'] != self.native_file
                or row['intent']['selection']['cwd'] != self.cwd):
            raise BehaviorConflict('behavior_operation_binding_changed')
        return row

    def status(self, operation_id: str) -> dict[str, Any]:
        """Reobserve selected effects; historical completion is not current consumption."""
        row = self._row(operation_id)
        intent = row['intent']
        files = [{'matches_before': _file(entry['local_destination']) == entry['before'],
                  'matches_after': _file(entry['local_destination']) == entry['after']}
                 for entry in intent['files']]
        config = intent['config']
        native = self._native(config['keys']) if config is not None else None
        matches = all(item['matches_after'] for item in files) and (
            native is None or native['values'] == config['after'])
        return {'schema': 'cluster-behavior-status/v1', 'operation_id': operation_id,
                'state': row['state'], 'files': files, 'materialized': matches,
                'native_effective': native is None or native['effective'] == config['after'],
                'native_reload_acknowledged': bool((row['runtime_observation'] or {}).get('native_ack')),
                'consumption': 'unverified', 'intent_sha256': row['intent_hash']}

    def apply(self, operation_id: str, *, fault: Callable[[str], None] = lambda _: None) -> dict[str, Any]:
        """Resume exactly this operation. Status discrepancies never trigger a replay."""
        with self.journal.mutation_lock(operation_id):
            row = self._row(operation_id)
            if row['state'] == 'completed':
                status = self.status(operation_id)
                if not status['materialized']:
                    raise BehaviorConflict('behavior_completed_effect_changed')
                return status
            if row['state'] != 'planned' and row['state'] != 'runtime-dispatching':
                raise BehaviorConflict('behavior_operation_not_resumable')
            intent = row['intent']
            progress = row['runtime_observation'] or {'files': [], 'dispatch': None, 'native_done': False,
                                                     'native_ack': False}
            # Check every remaining target before beginning or resuming effects.
            for index, entry in enumerate(intent['files']):
                current = _file(entry['local_destination'])
                if index in progress['files']:
                    if current != entry['after']:
                        raise BehaviorConflict('behavior_completed_file_changed')
                elif current != entry['before'] and not (
                        progress['dispatch'] == ['file', index] and current == entry['after']):
                    raise BehaviorConflict('behavior_file_changed')
            config = intent['config']
            if config is not None:
                native = self._native(config['keys'])
                expected = config['after'] if progress['native_done'] else config['before']
                if native['values'] != expected and not (
                        progress['dispatch'] == ['native'] and native['values'] == config['after']):
                    raise BehaviorConflict('behavior_native_selection_changed')
            if row['state'] == 'planned':
                self.journal.advance(operation_id, 'runtime-dispatching', runtime_observation=progress)
            for index, entry in enumerate(intent['files']):
                if index in progress['files']:
                    continue
                uncertain = progress['dispatch'] == ['file', index]
                progress['dispatch'] = ['file', index]
                self.journal.advance(operation_id, 'runtime-dispatching', runtime_observation=progress)
                current = _file(entry['local_destination'])
                if current != entry['after'] or not uncertain:
                    if current != entry['before']:
                        raise BehaviorConflict('behavior_file_changed')
                    if current != entry['after']:
                        _replace(entry['local_destination'], current, entry['after'])
                fault('after-file-effect')
                progress['files'].append(index)
                progress['dispatch'] = None
                self.journal.advance(operation_id, 'runtime-dispatching', runtime_observation=progress)
            if config is not None and not progress['native_done']:
                native = self._native(config['keys'])
                recovering = progress['dispatch'] == ['native'] and native['values'] == config['after']
                if native['values'] != config['before'] and not recovering:
                    raise BehaviorConflict('behavior_native_selection_changed')
                if not recovering and config['before'] != config['after']:
                    progress['dispatch'] = ['native']
                    self.journal.advance(operation_id, 'runtime-dispatching', runtime_observation=progress)
                    assert self.native is not None
                    result = self.native('config/batchWrite', {
                        'filePath': self.native_file, 'expectedVersion': native['version'],
                        'reloadUserConfig': True,
                        'edits': [{'keyPath': '.'.join(json.dumps(part) for part in key),
                                   'value': value['value'] if value['present'] else None,
                                   'mergeStrategy': 'replace'}
                                  for key, value in zip(config['keys'], config['after'], strict=True)]})
                    fault('after-native-effect')
                    # A return is acknowledgment of the native write/reload request,
                    # not evidence an existing model context now contains new text.
                    progress['native_ack'] = result.get('status') in {'ok', 'okOverridden'}
                if self._native(config['keys'])['values'] != config['after']:
                    raise BehaviorConflict('behavior_native_postcondition_mismatch')
                progress['native_done'] = True
                progress['dispatch'] = None
                self.journal.advance(operation_id, 'runtime-dispatching', runtime_observation=progress)
            status = self.status(operation_id)
            if not status['materialized']:
                raise BehaviorConflict('behavior_postcondition_changed')
            self.journal.advance(operation_id, 'completed', result={
                'intent_sha256': row['intent_hash'], 'materialized': True, 'consumption': 'unverified'})
            return self.status(operation_id)

    recover = apply

    def rollback(self, operation_id: str, *,
                 fault: Callable[[str], None] = lambda _: None) -> dict[str, Any]:
        """A retained inverse child restores only unchanged selected effects."""
        with self.journal.mutation_lock(operation_id):
            original = self._row(operation_id)
            if original['operation'] != 'behavior-delta' or original['state'] != 'completed':
                raise BehaviorConflict('behavior_rollback_requires_completed_child')
            rollback_id = operation_id + ':rollback'
            if self.journal.get(rollback_id) is None:
                if not self.status(operation_id)['materialized']:
                    raise BehaviorConflict('behavior_rollback_postcondition_changed')
                intent = copy.deepcopy(original['intent'])
                intent.pop('schema')
                for entry in intent['files']:
                    entry['before'], entry['after'] = entry['after'], entry['before']
                if intent['config'] is not None:
                    config = intent['config']
                    config['before'], config['after'] = config['after'], config['before']
                intent['rollback_of'] = operation_id
                intent['runtime_call'] = {'inverse_of': original['intent_hash']}
                self.journal.plan(operation='behavior-rollback', target='behavior:' + self.binding['body_ref'],
                                  operation_id=rollback_id, idempotency_key=rollback_id, intent=intent,
                                  expected_precondition={}, intended_transition={}, audit_identity=self.binding)
            return self.apply(rollback_id, fault=fault)
