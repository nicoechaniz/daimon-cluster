"""The maintenance bridge exposes only current proof and native reader controls."""
import time
from types import SimpleNamespace
from pathlib import Path

import pytest

from clusterctl import onboarding_owner_control as control
from clusterctl import onboarding_receiving_update as receiving
from clusterctl.onboarding import OnboardingError


def test_reader_proof_reuses_qualified_owner_and_exact_expected_selection(monkeypatch):
    owner=SimpleNamespace(root=Path('/owner'))
    options=dict(expected_selection={'code':'a'*64},expires_at_ms=123,
        require_admitted=True,receive_only=False)
    seen=[]
    def observe(actual,**arguments):
        assert actual is owner
        seen.append(arguments)
        return {'proof':'current'}
    monkeypatch.setattr(receiving,'observe_current_reader',observe)
    assert control.reader_rpc(owner,dict(action='observe',options=options),
        deadline_ns=time.monotonic_ns()+1_000_000_000) == {'proof':'current'}
    assert seen == [options]


def test_control_derives_owner_path_and_reuses_existing_execute(monkeypatch):
    owner=SimpleNamespace(root=Path('/owner'))
    command=dict(phase='select',operation_id='ba53c470-8dce-408c-8ede-b9a1469baf61')
    expected={'process':'current'}
    def execute(actual,cmd,path,**options):
        assert actual is owner and cmd is command
        assert path == owner.root/'receiving-control'/(command['operation_id']+'-select.json')
        assert options['expected'] is expected
        return {'gate':'accepted'}
    monkeypatch.setattr(control,'execute',execute)
    assert control.reader_rpc(owner,dict(action='control',command=command,expected=expected),
        deadline_ns=time.monotonic_ns()+1_000_000_000) == {'gate':'accepted'}


@pytest.mark.parametrize('value',[dict(action='restart'),dict(action='observe',options={},path='/foreign'),
    dict(action='control',command={},expected={},path='/foreign')])
def test_unknown_or_expanded_rpc_refused(value):
    with pytest.raises(OnboardingError,match='invalid_receiving_control_request'):
        control.reader_rpc(SimpleNamespace(),value,deadline_ns=time.monotonic_ns()+1_000_000_000)
