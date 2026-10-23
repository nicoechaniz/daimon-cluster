"""Receiving binding and executable-selection boundaries, without model calls."""
import hashlib
import json

import pytest

from clusterctl.same_being_operator import private_json, public_error, source_module


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
    assert public_error(ValueError('integration_matrix_mutation_protocol_rejected')) == 'integration_matrix_mutation_protocol_rejected'
