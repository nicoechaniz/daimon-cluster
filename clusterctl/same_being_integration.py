"""Finite same-being integration over existing owning APIs and retained requests.

Receiving modules/clients are injected by the trusted local launcher. Peer data
supplies content, never those implementations, bindings or destinations.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import re
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any

from .behavior_delta import BehaviorDelta, _binding
from .operation_journal import JournalConflict, OperationJournal, canonical_bytes

ADAPTER = 'cluster-same-being-integration/v1'


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


class IntegrationConflict(JournalConflict):
    pass


class NativeMemory:
    """Current DMK native API; its own transaction remains canonical."""

    def __init__(self, memory, sync, backup, owner, backup_config, *, legacy=None):
        self.memory, self.sync, self.backup = memory, sync, backup
        self.owner = sync.binding(owner)
        self.backup_config, self.legacy = copy.deepcopy(backup_config), legacy
        if Path(backup_config['database']).resolve() != Path(memory.DB_PATH).resolve():
            raise ValueError('integration_checkpoint_memory_binding_changed')

    def prepare(self, packets):
        if not isinstance(packets, list) or not 1 <= len(packets) <= 128:
            raise ValueError('integration_memory_packet_bounds')
        # Preflight closure before any backup or canonical effect.
        with closing(sqlite3.connect(self.sync.database(self.memory.DB_PATH).as_uri() + '?mode=ro', uri=True)) as con:
            for packet in packets:
                self.sync._validate_packet(packet, self.owner, con=con)
        return copy.deepcopy(packets)

    def status(self, parent, packets, *, allow_pending=False):
        receipts = []
        for index, packet in enumerate(packets):
            receipt = self.sync.status(self.memory, operation_id=f'{parent}.memory.{index}',
                                       packet=packet, owner=self.owner)
            if receipt is None:
                return None
            if receipt['current_links']['pending']:
                if allow_pending:
                    return None
                raise IntegrationConflict('integration_memory_links_pending')
            receipts.append(receipt)
        # Counts and source hashes only: no private text, local paths or titles.
        return {'packets': [r['packet_hash'] for r in receipts],
                'entries': sum(len(r['entries']) for r in receipts),
                'preserved_conflicts': sum(r['current_links']['preserved_conflicts'] for r in receipts)}

    def apply(self, parent, packets):
        self.prepare(packets)
        # Reuse the parent checkpoint, including when a return was lost.
        if self.status(parent, packets, allow_pending=True) is None:
            self.backup.operate(self.backup_config, 'begin', operation=parent,
                                reason='Before selected same-being integration ' + parent)
        for index, packet in enumerate(packets):
            self.sync.apply(self.memory, packet, self.owner,
                            operation_id=f'{parent}.memory.{index}', legacy=self.legacy)
        result = self.status(parent, packets)
        if result is None:
            raise IntegrationConflict('integration_memory_effect_unobserved')
        return result

    def complete(self, parent):
        self.backup.operate(self.backup_config, 'complete', operation=parent,
                            reason='Selected same-being effects and retained history verified')


class SelectedSkills:
    """The existing immutable selective installer owns transactions and recovery."""

    def __init__(self, installer, repository, root, state):
        self.installer, self.repository = installer, Path(repository)
        self.root, self.state = Path(root).absolute(), Path(state).absolute()

    def prepare(self, plan):
        self.installer.validate_descriptor(self.repository, plan['descriptor'])
        if (plan.get('conflicts') or plan['root'] != str(self.root)
                or plan['state'] != str(self.state)):
            raise IntegrationConflict('integration_skill_selection_conflict')
        return copy.deepcopy(plan)

    def status(self, plan):
        self.prepare(plan)
        packages = plan['descriptor']['packages']
        actual = self.installer.status(self.root, self.state, [p['name'] for p in packages])
        expected = {p['name']: p for p in packages}
        for row in actual['packages']:
            item = expected[row['package']]
            if (row['outcome'] != 'installed' or row['commit'] != plan['descriptor']['commit']
                    or row['content_sha256'] != self.installer.digest(item['files'])):
                return None
        return {'descriptor_sha256': self.installer.digest(plan['descriptor']),
                'packages': actual['packages']}

    def apply(self, plan):
        self.prepare(plan)
        # Recover only this exact plan using the owning inverse under its lock.
        # Inspect every pending participant before restoring any of them.
        with self.installer.locked(self.state) as state:
            pending = []
            for path in sorted(state.glob('transaction-*.json')):
                row = self.installer.read_json(path)
                if row['root'] != str(self.root) or row['status'] not in {'applying', 'rolling_back'}:
                    continue
                if any(row.get(key) != plan.get(key) for key in
                       ('descriptor', 'expected', 'previous_records', 'reconciliation')):
                    raise IntegrationConflict('integration_unrelated_skill_recovery')
                pending.append(row)
            for row in pending:
                self.installer.restore(state, row)
        self.installer.apply(self.repository, plan, self.installer.digest(plan))
        observed = self.status(plan)
        if observed is None:
            raise IntegrationConflict('integration_skill_effect_unobserved')
        return observed

    def rollback_transaction(self, plan):
        """Resolve an owning inverse, never infer ownership from installed bytes."""
        self.prepare(plan)
        with self.installer.locked(self.state) as state:
            records = [self.installer.record(state, p['name'])
                       for p in plan['descriptor']['packages']]
            if all(record == plan['previous_records'][p['name']]
                   and self.installer.snapshot(self.root / p['name']) == plan['expected'][p['name']]
                   for record, p in zip(records, plan['descriptor']['packages'])):
                return None
            transactions = {r['transaction'] for r in records if r is not None}
            if len(transactions) != 1 or any(r is None for r in records):
                raise IntegrationConflict('integration_skill_rollback_owner_changed')
            transaction = transactions.pop()
            row = self.installer.read_json(self.installer.journal_path(state, transaction))
            if (row['root'] != str(self.root) or row['status'] != 'applied'
                    or any(row.get(k) != plan.get(k) for k in
                           ('descriptor', 'expected', 'previous_records', 'reconciliation'))
                    or self.status_unlocked(plan, state) is False):
                raise IntegrationConflict('integration_skill_rollback_owner_changed')
            return transaction

    def status_unlocked(self, plan, state):
        return all(self.installer.snapshot(self.root / p['name']) == p['files']
                   and (record := self.installer.record(state, p['name'])) is not None
                   and record['descriptor'] == plan['descriptor']
                   and record['files'] == p['files']
                   for p in plan['descriptor']['packages'])

    def rollback(self, plan, transaction):
        self.prepare(plan)
        if transaction is not None:
            with self.installer.locked(self.state) as state:
                row = self.installer.read_json(self.installer.journal_path(state, transaction))
                if (row['transaction'] != transaction or row['root'] != str(self.root)
                        or any(row.get(k) != plan.get(k) for k in
                               ('descriptor', 'expected', 'previous_records', 'reconciliation'))):
                    raise IntegrationConflict('integration_skill_rollback_owner_changed')
                if row['status'] == 'rolling_back':
                    # A SIGKILL inside the owning inverse leaves this durable
                    # phase. Resume only that exact native restore under its lock.
                    self.installer.restore(state, row)
            self.installer.rollback(self.root, self.state, transaction)
        with self.installer.locked(self.state) as state:
            if not all(self.installer.snapshot(self.root / p['name']) == plan['expected'][p['name']]
                       and self.installer.record(state, p['name']) == plan['previous_records'][p['name']]
                       for p in plan['descriptor']['packages']):
                raise IntegrationConflict('integration_skill_rollback_state_changed')
        return {'restored': True, 'transaction': transaction}


class SameBeingIntegration:
    """One owner-requested parent. It does not install a scheduler or peer executor."""

    def __init__(self, journal: OperationJournal, binding, matrix, cluster, *,
                 memory: NativeMemory | None = None, skills: SelectedSkills | None = None,
                 behavior: BehaviorDelta | None = None):
        self.journal, self.binding = journal, _binding(binding)
        self.matrix, self.cluster = matrix, cluster
        self.memory, self.skills, self.behavior = memory, skills, behavior
        if memory is not None and memory.owner['being_ref'] != self.binding['being_ref']:
            raise ValueError('integration_memory_being_mismatch')
        if behavior is not None and behavior.binding != self.binding:
            raise ValueError('integration_behavior_binding_mismatch')

    def _read(self, method, params):
        _request, response = self.matrix.invoke(method, params)
        if not response.get('ok'):
            raise IntegrationConflict('integration_matrix_read_' + response['error']['code'])
        return response['result']

    def _source(self, event_id, *, require_observer=False):
        status = self._read('runtime.status', {})
        if (status['being_ref'] != self.binding['being_ref']
                or status['local_origin'] != {k: self.binding[k] for k in
                    ('body_ref', 'embodiment_id', 'incarnation_id', 'principal_id')}):
            raise IntegrationConflict('integration_matrix_binding_changed')
        if require_observer and status.get('projection_receipts', {}).get('observer_available') is not True:
            raise IntegrationConflict('integration_projection_observer_unavailable')
        event = self._read('we.event.get', {'event_id': event_id})['event']
        if (event is None or event['being_ref'] != self.binding['being_ref']
                or event['kind'] not in {'configuration.proposed', 'skill.proposed'}):
            raise IntegrationConflict('integration_known_proposal_required')
        refs = event['payload'].get('content_refs')
        if (not isinstance(refs, list) or not refs or len(refs) > 256
                or any(not isinstance(ref, str) or not re.fullmatch('[0-9a-f]{64}', ref) for ref in refs)):
            raise IntegrationConflict('integration_proposal_content_refs_required')
        return event

    def _decision(self, event):
        # Fresh native projection, not the optional historical projection cache.
        after, projection_hash = None, None
        for _ in range(16):
            page = self._read('we.diff', {'after': after, 'kind': None, 'limit': 256,
                                         'subject': event['subject']})
            if projection_hash is not None and page['projection_hash'] != projection_hash:
                raise IntegrationConflict('integration_decision_view_changed')
            projection_hash = page['projection_hash']
            for entry in page['entries']:
                if entry['event_id'] == event['event_id']:
                    if entry['state'] == 'failed':
                        raise IntegrationConflict('integration_local_decision_fork')
                    return entry
            if not page['more']:
                break
            after = page['next_after']
        raise IntegrationConflict('integration_proposal_projection_unavailable')

    def _resources(self):
        resources = {}
        if self.memory is not None:
            resources['memory'] = {'database': str(Path(self.memory.memory.DB_PATH).absolute()),
                'owner': self.memory.owner, 'backup_config_sha256': digest(self.memory.backup_config)}
        if self.skills is not None:
            resources['skills'] = {'repository': str(self.skills.repository.absolute()),
                                  'root': str(self.skills.root), 'state': str(self.skills.state)}
        if self.behavior is not None:
            resources['behavior'] = {'journal': str(self.behavior.journal.path),
                                    'native_file': self.behavior.native_file, 'cwd': self.behavior.cwd}
        return resources

    def inspect(self, source_event_id):
        """Read exact proposal references and local decision without adoption."""
        event = self._source(source_event_id)
        entry = self._decision(event)
        return {'schema': 'cluster-same-being-inspection/v1',
                'source_event_id': event['event_id'], 'kind': event['kind'],
                'content_refs': event['payload']['content_refs'],
                'local_state': entry['state'], 'decision_event_id': entry['decision_event_id']}

    @staticmethod
    def _behavior_args(selection):
        return {**selection, 'files': {path: None if raw is None else base64.b64decode(raw, validate=True)
                                     for path, raw in selection['files'].items()}}

    def prepare(self, operation_id, *, source_event_id, reason, packets=None,
                skill_plan=None, behavior_selection=None, behavior_sources=None, residual=None):
        if str(uuid.UUID(operation_id)) != operation_id:
            raise ValueError('integration_canonical_operation_uuid_required')
        if not isinstance(reason, str) or not 1 <= len(reason) <= 512:
            raise ValueError('integration_local_reason_required')
        if not (packets or skill_plan or behavior_selection):
            raise ValueError('integration_empty_selection')
        if residual is not None and (not isinstance(residual, list) or len(residual) > 256):
            raise ValueError('integration_invalid_residual')
        selection = dict(source_event_id=source_event_id, reason=reason, packets=packets,
                         skill_plan=skill_plan, behavior_selection=behavior_selection, behavior_sources=behavior_sources,
                         residual=residual or [], binding=self.binding, resources=self._resources())
        old = self.journal.get(operation_id)
        if old is not None:
            if old['operation'] != ADAPTER or old['intent']['selection'] != selection:
                raise IntegrationConflict('integration_operation_selection_changed')
            return self.status(operation_id)
        event = self._source(source_event_id)
        local_decision = self._decision(event)
        if local_decision['state'] not in {'pending', 'adopted'}:
            raise IntegrationConflict('integration_deliberate_local_decision')
        refs = set(event['payload']['content_refs'])
        needed = set()
        if packets:
            if self.memory is None:
                raise IntegrationConflict('integration_memory_adapter_unavailable')
            self.memory.prepare(packets)
            needed.update(self.memory.sync.digest(packet) for packet in packets)
        if skill_plan:
            if self.skills is None:
                raise IntegrationConflict('integration_skill_adapter_unavailable')
            self.skills.prepare(skill_plan)
            needed.add(self.skills.installer.digest(skill_plan['descriptor']))
        if behavior_selection:
            if self.behavior is None:
                raise IntegrationConflict('integration_behavior_adapter_unavailable')
            if behavior_selection['source'] != dict(event['origin'], being_ref=event['being_ref']):
                raise IntegrationConflict('integration_behavior_source_origin_changed')
            needed.update(behavior_selection['source_refs'])
            if not isinstance(behavior_sources, dict) or set(behavior_sources) != set(behavior_selection['source_refs']):
                raise IntegrationConflict('integration_behavior_source_closure_missing')
            for reference, encoded in behavior_sources.items():
                original = base64.b64decode(encoded, validate=True)
                if hashlib.sha256(original).hexdigest() != reference:
                    raise IntegrationConflict('integration_behavior_source_bytes_changed')
        if not needed <= refs:
            raise IntegrationConflict('integration_content_not_in_proposal')
        if behavior_selection:
            self.behavior.prepare(operation_id + '.behavior', **self._behavior_args(behavior_selection))
        intent = dict(selection=selection, source_event=event, source_refs=sorted(needed),
                      decision_predecessor=local_decision['decision_event_id'],
                      runtime_call={'selection_sha256': digest(selection)})
        self.journal.plan(operation=ADAPTER, target='integration:' + self.binding['body_ref'],
                          operation_id=operation_id, idempotency_key=operation_id,
                          intent=intent, expected_precondition={}, intended_transition={},
                          audit_identity=self.binding)
        return self.status(operation_id)

    def _row(self, operation_id):
        row = self.journal.get(operation_id)
        if (row is None or row['operation'] != ADAPTER
                or row['intent']['selection']['binding'] != self.binding
                or row['intent']['selection']['resources'] != self._resources()):
            raise IntegrationConflict('integration_operation_binding_changed')
        return row

    def _observe(self, row):
        parent = row['operation_id']
        selection = row['intent']['selection']
        observed = {}
        if selection['packets']:
            observed['memory'] = self.memory.status(parent, selection['packets'])
        if selection['skill_plan']:
            observed['skills'] = self.skills.status(selection['skill_plan'])
        if selection['behavior_selection']:
            value = self.behavior.status(parent + '.behavior')
            observed['behavior'] = {k: value[k] for k in ('materialized', 'native_effective',
                                  'native_reload_acknowledged', 'consumption', 'intent_sha256')}
            if not value['materialized']:
                observed['behavior'] = None
        return observed

    def status(self, operation_id):
        row = self._row(operation_id)
        observed = self._observe(row)
        inverse = self.journal.get(self._rollback_id(operation_id))
        return {'schema': 'cluster-same-being-status/v1', 'operation_id': operation_id,
                'state': row['state'], 'observed': observed,
                'materialized': all(value is not None for value in observed.values()),
                'projection_receipted': bool((row['runtime_observation'] or {}).get('projection_event')),
                'consumption': 'unverified',
                'residual': {'count': len(row['intent']['selection']['residual']),
                             'sha256': digest(row['intent']['selection']['residual'])},
                'controls_rollback': None if inverse is None else inverse['state']}

    def _mutation(self, row, progress, name, method, params):
        requests = progress.setdefault('matrix_requests', {})
        request = requests.get(name)
        if request is None:
            request = self.matrix.prepare(method, params,
                request_id=str(uuid.uuid5(uuid.UUID(row['operation_id']), name)))
            requests[name] = request
            self.journal.advance(row['operation_id'], 'runtime-dispatching', runtime_observation=progress)
        elif request['method'] != method or request['params'] != params:
            raise IntegrationConflict('integration_retained_matrix_request_changed')
        response = self.matrix.send(request)
        if not response.get('ok'):
            raise IntegrationConflict('integration_matrix_mutation_' + response['error']['code'])
        return response['result']

    def apply(self, operation_id, *, fault=lambda _: None):
        with self.journal.mutation_lock(operation_id):
            row = self._row(operation_id)
            if self.journal.get(self._rollback_id(operation_id)) is not None:
                raise IntegrationConflict('integration_controls_rollback_started')
            selection = row['intent']['selection']
            if self._source(selection['source_event_id'], require_observer=True) != row['intent']['source_event']:
                raise IntegrationConflict('integration_source_event_changed')
            progress = row['runtime_observation'] or {'matrix_requests': {}}
            entry = self._decision(row['intent']['source_event'])
            if row['state'] == 'completed':
                if entry['state'] != 'adopted' or entry['decision_event_id'] != progress['decision_event']['event_id']:
                    raise IntegrationConflict('integration_local_decision_changed')
                current = self.status(operation_id)
                if not current['materialized']:
                    raise IntegrationConflict('integration_completed_effect_changed')
                self._mutation(row, progress, 'projection', 'we.projection.receipt',
                               {'receipt': progress['effect_receipt']})
                return current
            if row['state'] not in {'planned', 'runtime-dispatching'}:
                raise IntegrationConflict('integration_operation_not_resumable')
            capability = getattr(getattr(self.matrix, 'config', None), 'capability', None)
            if capability is None or 'we.projection.receipt' not in capability.methods:
                raise IntegrationConflict('integration_matrix_capability_unavailable')
            self.journal.advance(operation_id, 'runtime-dispatching', runtime_observation=progress)
            if 'decision_event' not in progress:
                # Retain the predecessor and full signed request before dispatch.
                # Recovering a lost decision return resends that exact document.
                request = progress['matrix_requests'].get('adoption')
                predecessor = row['intent']['decision_predecessor']
                if request is None and entry['decision_event_id'] != predecessor:
                    raise IntegrationConflict('integration_decision_preview_changed')
                decided = self._mutation(row, progress, 'adoption', 'we.decide', {
                    'target_event_id': selection['source_event_id'], 'decision': 'adopt',
                    'reason': selection['reason'], 'sensitivity': row['intent']['source_event']['sensitivity'],
                    'supersedes': predecessor, 'occurred_at_ms': None,
                    'event_id': str(uuid.uuid5(uuid.UUID(operation_id), 'adoption-event'))})
                fault('after-adoption-return')
                progress['decision_event'] = decided['event']
                self.journal.advance(operation_id, 'runtime-dispatching', runtime_observation=progress)
            entry = self._decision(row['intent']['source_event'])
            if entry['state'] != 'adopted' or entry['decision_event_id'] != progress['decision_event']['event_id']:
                raise IntegrationConflict('integration_local_decision_changed')
            if selection['packets']:
                self.memory.apply(operation_id, selection['packets'])
                fault('after-memory-return')
            if selection['skill_plan']:
                self.skills.apply(selection['skill_plan'])
                fault('after-skills-return')
            if selection['behavior_selection']:
                self.behavior.apply(operation_id + '.behavior')
                fault('after-behavior-return')
            observed = self._observe(row)
            if any(value is None for value in observed.values()):
                raise IntegrationConflict('integration_effects_unobserved')
            intent = self.effect_intent(row, progress)
            receipt = progress.get('effect_receipt')
            if receipt is None:
                now = self.matrix.clock()
                receipt = self.cluster.create_effect_receipt(effect_id=operation_id,
                    target_event_id=selection['source_event_id'],
                    decision_event_id=progress['decision_event']['event_id'], adapter=ADAPTER,
                    preview_hash=digest(row['intent']['selection']), intent_hash=digest(intent),
                    actor=self.binding['principal_id'], authority='daimon', resource_fence=None,
                    result='applied', observed_postcondition=observed,
                    started_at_ms=progress['decision_event']['occurred_at_ms'], completed_at_ms=now)
                progress['effect_receipt'] = receipt
                self.journal.advance(operation_id, 'runtime-dispatching', runtime_observation=progress)
            elif receipt['observed_postcondition'] != observed:
                raise IntegrationConflict('integration_observed_effect_changed')
            projected = self._mutation(row, progress, 'projection', 'we.projection.receipt', {'receipt': receipt})
            fault('after-projection-return')
            progress['projection_event'] = projected['event']
            self.journal.advance(operation_id, 'runtime-dispatching', runtime_observation=progress)
            if selection['packets']:
                self.memory.complete(operation_id)
            self.journal.advance(operation_id, 'completed', result={
                'effect_receipt_sha256': receipt['content_hash'],
                'projection_event_id': projected['event']['event_id'], 'consumption': 'unverified'})
            return self.status(operation_id)

    recover = apply

    @staticmethod
    def _rollback_id(operation_id):
        return str(uuid.uuid5(uuid.UUID(operation_id), 'controls-rollback'))

    def rollback(self, operation_id, *, fault=lambda _: None):
        """Revert adopted controls through their owners; keep attributed memory."""
        with self.journal.mutation_lock(operation_id):
            original = self._row(operation_id)
            if original['state'] != 'completed':
                raise IntegrationConflict('integration_rollback_requires_completed_parent')
            selection = original['intent']['selection']
            original_progress = original['runtime_observation']
            inverse_id = self._rollback_id(operation_id)
            inverse = self.journal.get(inverse_id)
            intent = {'rollback_of': operation_id, 'original_intent_sha256': original['intent_hash'],
                      'binding': self.binding, 'resources': self._resources(),
                      'memory': 'retained-attributed-history'}
            if inverse is None:
                # Preflight both control owners before reverting either one.
                transaction = self.skills.rollback_transaction(selection['skill_plan']) if selection['skill_plan'] else None
                if selection['behavior_selection'] and not self.behavior.status(operation_id + '.behavior')['materialized']:
                    raise IntegrationConflict('integration_behavior_rollback_state_changed')
                entry = self._decision(original['intent']['source_event'])
                if entry['state'] != 'adopted' or entry['decision_event_id'] != original_progress['decision_event']['event_id']:
                    raise IntegrationConflict('integration_local_decision_changed')
                intent['skills_transaction'] = transaction
                inverse = self.journal.plan(operation=ADAPTER + '.rollback',
                    target='integration-controls:' + self.binding['body_ref'], operation_id=inverse_id,
                    idempotency_key=inverse_id, intent=intent, expected_precondition={},
                    intended_transition={}, audit_identity=self.binding)
            else:
                intent['skills_transaction'] = inverse['intent'].get('skills_transaction')
                # OperationJournal adds its generic schema to retained intent.
                expected = {'schema': inverse['intent']['schema'], **intent}
                if inverse['operation'] != ADAPTER + '.rollback' or inverse['intent'] != expected:
                    raise IntegrationConflict('integration_rollback_identity_collision')
            progress = inverse['runtime_observation'] or {'matrix_requests': {}}
            if inverse['state'] not in {'planned', 'runtime-dispatching', 'completed'}:
                raise IntegrationConflict('integration_rollback_not_resumable')
            entry = self._decision(original['intent']['source_event'])
            retained_revert = progress.get('revert_event')
            if retained_revert is not None:
                if entry['decision_event_id'] != retained_revert['event_id'] or entry['state'] != 'reverted':
                    raise IntegrationConflict('integration_local_decision_changed')
            else:
                # Reuse the complete signed revert request after a lost return.
                request = progress['matrix_requests'].get('revert')
                if request is None and entry['decision_event_id'] != original_progress['decision_event']['event_id']:
                    raise IntegrationConflict('integration_local_decision_changed')
                result = self._mutation(inverse, progress, 'revert', 'we.decide', {
                    'target_event_id': selection['source_event_id'], 'decision': 'revert',
                    'reason': 'Revert selected controls; retain attributed memory and history',
                    'sensitivity': original['intent']['source_event']['sensitivity'],
                    'supersedes': original_progress['decision_event']['event_id'], 'occurred_at_ms': None,
                    'event_id': str(uuid.uuid5(uuid.UUID(inverse_id), 'revert-event'))})
                fault('after-revert-return')
                progress['revert_event'] = result['event']
                self.journal.advance(inverse_id, 'runtime-dispatching', runtime_observation=progress)
            if selection['behavior_selection']:
                self.behavior.rollback(operation_id + '.behavior')
                fault('after-behavior-rollback-return')
            if selection['skill_plan']:
                self.skills.rollback(selection['skill_plan'], inverse['intent']['skills_transaction'])
                fault('after-skills-rollback-return')
            result = {'schema': 'cluster-same-being-controls-rollback/v1',
                      'operation_id': inverse_id, 'rollback_of': operation_id,
                      'controls_restored': True, 'memory': 'retained-attributed-history',
                      'revert_event_id': progress['revert_event']['event_id']}
            self.journal.advance(inverse_id, 'completed', result=result)
            return result

    @staticmethod
    def effect_intent(row, progress):
        return {'schema': 'cluster-same-being-effect-intent/v1',
                'selection_sha256': digest(row['intent']['selection']),
                'source_event_id': row['intent']['selection']['source_event_id'],
                'decision_event_id': progress['decision_event']['event_id'],
                'binding_sha256': digest(row['intent']['selection']['binding'])}

    def observe_effect(self, receipt, at_ms):
        """Trusted Cluster observer seam. Never registered from an RPC/peer payload."""
        receipt = self.cluster.validate_effect_receipt(receipt)
        row = self._row(receipt['effect_id'])
        progress = row['runtime_observation'] or {}
        if (receipt['adapter'] != ADAPTER or progress.get('effect_receipt') != receipt
                or receipt['actor'] != self.binding['principal_id']):
            raise IntegrationConflict('integration_effect_receipt_binding_changed')
        observed = self._observe(row)
        if any(value is None for value in observed.values()):
            raise IntegrationConflict('integration_effect_truth_unavailable')
        return {'intent': self.effect_intent(row, progress), 'observed_postcondition': observed,
                'current_fence_evidence': None}
