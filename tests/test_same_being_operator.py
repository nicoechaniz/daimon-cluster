"""Receiving binding and executable-selection boundaries, without model calls."""
import hashlib
import json
import os
import sys
from types import SimpleNamespace

import pytest

from clusterctl.same_being_operator import private_json, public_error, source_module


@pytest.mark.parametrize('failure', [None, 'memoryctl', 'legacy_native_sync', 'legacy_unsupported'])
@pytest.mark.parametrize('lineage', [None, 'retained-local'])
def test_memory_bootstrap_preserves_qualified_import_context_and_environment(tmp_path, monkeypatch, failure, lineage):
    from clusterctl import same_being_operator as operator
    monkeypatch.delitem(sys.modules, 'legacy_native_sync', raising=False)

    scripts = tmp_path / 'selected-scripts'
    scripts.mkdir()
    for name in ('memoryctl', 'same_being_sync', 'backupctl', 'legacy_native_sync'):
        text = ('import os, sys\n'
                'assert os.environ["HMK_DB_PATH"] == "selected-database"\n'
                'sys.path.append("bootstrap-added-path")\n'
                'def load(*args, receiving_lineage=None):\n'
                ' return {"selected": True, "lineage": receiving_lineage}\n')
        if name == 'legacy_native_sync' and failure == 'legacy_unsupported':
            text += 'def load(*args): return {"selected": True, "lineage": None}\n'
        if name == failure:
            text += 'raise RuntimeError("selected bootstrap failed")\n'
        (scripts / (name + '.py')).write_text(text)
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in scripts.iterdir()}
    binding = tmp_path / 'binding.json'
    binding.write_text(json.dumps(dict(schema='cluster-same-being-binding/v1',
        binding={name: 'qualified-' + name for name in ('being_ref', 'body_ref', 'embodiment_id', 'incarnation_id', 'principal_id')},
        journal=str(tmp_path / 'journal'), matrix={}, skills=None, behavior=None,
        memory=dict(scripts=str(scripts), files=hashes, environment={'HMK_DB_PATH': 'selected-database'},
                    legacy_provenance=str(tmp_path / 'legacy.json'), legacy_provenance_sha256='unused',
                    owner={'being_ref': 'qualified-being_ref'}, backup_config={}))))
    binding.chmod(0o600)
    if lineage is not None:
        selected = json.loads(binding.read_text())
        selected['memory']['legacy_receiving_lineage'] = lineage
        binding.write_text(json.dumps(selected))
    monkeypatch.setenv('HMK_DB_PATH', 'original-database')
    monkeypatch.setattr(operator, 'NativeMemory',
                        lambda memory, sync, backup, owner, config, **kwargs:
                        SimpleNamespace(owner=owner, legacy=kwargs['legacy']))
    original = (sys.path[:], sys.dont_write_bytecode, sys.pycache_prefix)
    if failure == 'legacy_unsupported' and lineage is not None:
        with pytest.raises(ValueError, match='integration_legacy_receiving_lineage_unavailable'):
            operator.load_operator(binding, matrix=object())
    elif failure not in (None, 'legacy_unsupported'):
        with pytest.raises(RuntimeError, match='selected bootstrap failed'):
            operator.load_operator(binding, matrix=object())
    else:
        loaded = operator.load_operator(binding, matrix=object())
        assert loaded.memory.legacy == {'selected': True, 'lineage': lineage}
    assert (sys.path, sys.dont_write_bytecode, sys.pycache_prefix) == original
    assert os.environ['HMK_DB_PATH'] == 'original-database'


def test_private_binding_refuses_duplicates_and_public_inputs(tmp_path):
    path = tmp_path / 'receiving.json'
    path.write_text('{"owner":"first","owner":"second"}')
    path.chmod(0o600)
    with pytest.raises(ValueError, match='duplicate_json_key'):
        private_json(path)
    path.write_text(json.dumps({'owner': 'selected'}))
    path.chmod(0o644)
    with pytest.raises(ValueError, match='private_binding_or_input_required'):
        private_json(path)


def test_selected_executable_uses_exact_bytes_without_changing_source_permissions(tmp_path):
    source = tmp_path / 'selected.py'
    source.write_bytes(b'VALUE = 42\n')
    source.chmod(0o664)
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    assert source_module('_qualification_selected_code', source, expected).VALUE == 42
    assert source.stat().st_mode & 0o777 == 0o664
    source.write_bytes(b'raise AssertionError("unselected bytes must not execute")\n')
    with pytest.raises(ValueError, match='selected_module_changed'):
        source_module('_qualification_selected_code', source, expected)
    alias = tmp_path / 'alias.py'
    alias.symlink_to(source)
    with pytest.raises(OSError):
        source_module('_qualification_selected_code', alias, expected)


def test_error_output_uses_known_codes_and_never_arbitrary_identifier_prose():
    assert public_error(ValueError('private_human_word')) == 'integration_operation_failed'
    assert public_error(ValueError('integration_matrix_mutation_private_human_word')) == 'integration_operation_failed'
    assert public_error(ValueError('integration_selected_module_changed')) == 'integration_selected_module_changed'
    assert public_error(ValueError('integration_legacy_receiving_lineage_unavailable')) == 'integration_legacy_receiving_lineage_unavailable'
    assert public_error(ValueError('integration_matrix_mutation_protocol_rejected')) == 'integration_matrix_mutation_protocol_rejected'
