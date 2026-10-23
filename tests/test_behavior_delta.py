"""Selected I/O and lost-result recovery for the recurring behavior adapter."""
from __future__ import annotations

import copy
import json

import pytest

from clusterctl.behavior_delta import BehaviorConflict, BehaviorDelta
from clusterctl.operation_journal import OperationJournal

OWNER = dict(being_ref='being:one', body_ref='codex:receiver', embodiment_id='body:one',
             incarnation_id='life:one', principal_id='local:one')
SOURCE = dict(OWNER, body_ref='codex:source', embodiment_id='body:two')


class Crash(BaseException):
    pass


class Native:
    def __init__(self, path):
        self.path = str(path)
        self.config = {'style': 'old', 'unrelated': 'keep'}
        self.version = 1
        self.writes = 0
        self.race = False
        self.override = None

    def __call__(self, method, params):
        if method == 'config/read':
            return {'config': self.override or copy.deepcopy(self.config), 'layers': [{
                'name': {'type': 'user', 'file': self.path}, 'version': str(self.version),
                'config': copy.deepcopy(self.config)}]}
        assert method == 'config/batchWrite'
        assert params['reloadUserConfig'] is True
        assert params['filePath'] == self.path
        if self.race:
            self.config['style'] = 'concurrent'
            self.version += 1
            self.race = False
        if params['expectedVersion'] != str(self.version):
            raise BehaviorConflict('native_version_conflict')
        for edit in params['edits']:
            # The fixture's one-segment keys still exercise quoted native paths.
            key = json.loads(edit['keyPath'])
            if edit['value'] is None:
                self.config.pop(key, None)
            else:
                self.config[key] = edit['value']
        self.version += 1
        self.writes += 1
        return {'status': 'ok', 'version': str(self.version)}


@pytest.fixture
def setup(tmp_path):
    tmp_path.chmod(0o700)
    instructions = tmp_path / 'AGENTS.md'
    instructions.write_bytes(b'original instructions')
    instructions.chmod(0o640)
    config = tmp_path / 'config.toml'
    config.write_text('')
    native = Native(config)
    adapter = BehaviorDelta(OperationJournal(tmp_path / 'state'), OWNER,
                            native=native, native_file=config, cwd=tmp_path)
    return adapter, native, instructions


def prepare(setup, identifier='selected', **kwargs):
    adapter, native, path = setup
    return adapter.prepare(identifier, source=SOURCE, source_refs=['a' * 64],
                           files={str(path): b'selected instruction'},
                           edits=[(['style'], 'clear')], **kwargs)


def test_prepare_apply_retry_and_inverse_preserve_originals_and_unrelated_edits(setup):
    adapter, native, path = setup
    before = path.read_bytes()
    assert prepare(setup)['state'] == 'planned'
    assert path.read_bytes() == before and native.writes == 0
    applied = adapter.apply('selected')
    assert applied['materialized'] and applied['native_reload_acknowledged']
    assert applied['consumption'] == 'unverified'
    assert path.read_bytes() == b'selected instruction'
    assert path.stat().st_mode & 0o777 == 0o640
    assert prepare(setup) == adapter.status('selected')
    adapter.apply('selected')
    assert native.writes == 1
    native.config['unrelated'] = 'later edit'
    native.version += 1
    restored = adapter.rollback('selected')
    assert restored['materialized'] and path.read_bytes() == before
    assert native.config == {'style': 'old', 'unrelated': 'later edit'}
    adapter.rollback('selected')
    assert native.writes == 2
    assert len(adapter.journal.list_all()) == 2
    with pytest.raises(BehaviorConflict):
        adapter.apply('selected')


@pytest.mark.parametrize('boundary', ['after-file-effect', 'after-native-effect'])
def test_lost_return_observes_same_operation_without_repeating_effect(setup, boundary):
    adapter, native, path = setup
    prepare(setup)
    def fail(stage):
        if stage == boundary:
            raise Crash()
    with pytest.raises(Crash):
        adapter.apply('selected', fault=fail)
    assert adapter.journal.get('selected')['state'] == 'runtime-dispatching'
    result = adapter.recover('selected')
    assert result['materialized'] and native.writes == 1
    assert result['native_reload_acknowledged'] is (boundary != 'after-native-effect')
    assert len(adapter.journal.list_all()) == 1


@pytest.mark.parametrize('target', ['file', 'native'])
def test_concurrent_selection_edit_refuses_before_any_other_effect(setup, target):
    adapter, native, path = setup
    prepare(setup)
    if target == 'file':
        path.write_text('human edit')
    else:
        native.config['style'] = 'human edit'
    with pytest.raises(BehaviorConflict):
        adapter.apply('selected')
    assert native.writes == 0
    assert path.read_text() == ('human edit' if target == 'file' else 'original instructions')


def test_native_cas_conflict_retains_partial_file_and_does_not_replay_it(setup):
    adapter, native, path = setup
    prepare(setup)
    native.race = True
    with pytest.raises(BehaviorConflict, match='native_version_conflict'):
        adapter.apply('selected')
    assert path.read_text() == 'selected instruction'
    assert adapter.journal.get('selected')['runtime_observation']['files'] == [0]
    path.write_text('later file edit')
    with pytest.raises(BehaviorConflict):
        adapter.recover('selected')
    assert path.read_text() == 'later file edit' and native.writes == 0


@pytest.mark.parametrize('target', ['file', 'native'])
def test_completed_drift_blocks_retry_and_rollback(setup, target):
    adapter, native, path = setup
    prepare(setup)
    adapter.apply('selected')
    if target == 'file':
        path.write_text('later edit')
    else:
        native.config['style'] = 'later edit'
    assert not adapter.status('selected')['materialized']
    for action in (adapter.apply, adapter.rollback):
        with pytest.raises(BehaviorConflict):
            action('selected')
    assert native.writes == 1


def test_native_override_is_not_consumption_or_effective_success(setup):
    adapter, native, path = setup
    prepare(setup)
    native.override = {'style': 'policy override'}
    result = adapter.apply('selected')
    assert result['materialized'] and not result['native_effective']
    assert result['consumption'] == 'unverified'


def test_unknown_native_layer_or_cross_being_never_prepares(setup):
    adapter, native, path = setup
    native.path += '.other'
    with pytest.raises(ValueError, match='user_layer_unknown'):
        prepare(setup)
    with pytest.raises(ValueError, match='cross_being'):
        adapter.prepare('other', source=dict(SOURCE, being_ref='being:other'),
                        source_refs=['b' * 64], files={str(path): b'wrong'})
    assert not adapter.journal.list_all()


def test_missing_file_creation_and_native_key_removal_are_reversible(setup):
    adapter, native, path = setup
    path.unlink()
    adapter.prepare('new', source=SOURCE, source_refs=['a' * 64],
                    files={str(path): b'created'}, edits=[(['style'], None)])
    adapter.apply('new')
    assert path.read_bytes() == b'created' and 'style' not in native.config
    adapter.rollback('new')
    assert not path.exists() and native.config['style'] == 'old'


def test_file_mode_drift_and_symlink_are_preserved(setup, tmp_path):
    adapter, native, path = setup
    prepare(setup)
    path.chmod(0o600)
    with pytest.raises(BehaviorConflict):
        adapter.apply('selected')
    path.unlink()
    target = tmp_path / 'private'
    target.write_text('untouched')
    path.symlink_to(target)
    with pytest.raises(ValueError, match='symlink'):
        adapter.status('selected')
    assert target.read_text() == 'untouched'


def test_rollback_lost_result_resumes_same_inverse_child(setup):
    adapter, native, path = setup
    prepare(setup)
    adapter.apply('selected')
    def crash(stage):
        if stage == 'after-native-effect':
            raise Crash()
    with pytest.raises(Crash):
        adapter.rollback('selected', fault=crash)
    assert native.writes == 2
    result = adapter.rollback('selected')
    assert result['materialized'] and native.writes == 2
    assert path.read_text() == 'original instructions'
    assert len(adapter.journal.list_all()) == 2


def test_native_file_cannot_bypass_native_api_as_plain_content(setup):
    adapter, native, path = setup
    with pytest.raises(ValueError, match='requires_native_adapter'):
        adapter.prepare('overwrite-config', source=SOURCE, source_refs=['a' * 64],
                        files={adapter.native_file: b'style = "bypass"'})
    assert not adapter.journal.list_all() and native.writes == 0


def test_rollback_refuses_existing_unrelated_operation_with_inverse_name(setup, tmp_path):
    adapter, native, path = setup
    prepare(setup)
    adapter.apply('selected')
    unrelated = tmp_path / 'unrelated.md'
    unrelated.write_text('other original')
    adapter.prepare('selected:rollback', source=SOURCE, source_refs=['b' * 64],
                    files={str(unrelated): b'other selected'})
    adapter.apply('selected:rollback')
    with pytest.raises(BehaviorConflict, match='rollback_identity_collision'):
        adapter.rollback('selected')
    assert path.read_text() == 'selected instruction'
    assert unrelated.read_text() == 'other selected' and native.writes == 1
