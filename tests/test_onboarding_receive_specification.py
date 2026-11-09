"""Pure receive preparation preserves signed originals and explicit own stores."""
import copy
import time

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_receive_specification import compile_specification
from tests import test_onboarding_group_authorities as fixtures
from tests.test_onboarding_group_admission import closure

group_source=fixtures.group_source


@pytest.fixture
def inputs(group_source):
    from daimon_matrix.messaging_config import read_publication
    source,target,_peer,peer_bundle,_old=group_source
    base=source._load(signed=False)
    application,_=read_publication(base,source.outputs/'tribe/application')
    return dict(runtime=target.document_bundle(),runtime_root=str(source.root),
        authorities={**closure(target.document_bundle()),**closure(peer_bundle)},
        authority_order=[row['manifest']['being_ref'] for row in application['authorities']],
        governance=application['relationship_events'],tribe_ref=application['tribe']['policy']['tribe_ref'],
        policy={k:application['tribe']['policy'][k] for k in ('classification','max_ttl_ms')},
        listen=application['listen'],intake=application['intake'],roster=application['roster'],
        stores=application['stores'],at_ms=time.time_ns()//1_000_000)


def test_compile_matches_existing_real_signed_receive_specification_without_effects(inputs,group_source,monkeypatch):
    from daimon_matrix.messaging_config import read_publication
    from daimon_matrix import operator_messaging
    source,*_=group_source
    original=copy.deepcopy(inputs)
    app,_=read_publication(source._load(signed=False),source.outputs/'tribe/application')
    app.pop('client')
    monkeypatch.setattr(operator_messaging,'prepare',lambda *a,**kw:pytest.fail('publication'))
    result=compile_specification(**inputs)
    assert result==app
    assert inputs==original
    result['stores']['relationships']='changed.sqlite'
    assert inputs==original


@pytest.mark.parametrize('fault',['private','duplicate','signature','tribe','runtime','identity','roster','body','route','policy','root','time','stores'])
def test_mismatched_or_unsigned_receive_preparation_refuses_before_any_effect(inputs,fault):
    value=copy.deepcopy(inputs)
    if fault=='private': value['governance'][0]['sensitivity']='private'
    elif fault=='duplicate': value['governance']*=2
    elif fault=='signature': value['governance'][0]['payload']['declaration']['nonce']='changed'
    elif fault=='tribe': value['tribe_ref']='foreign'
    elif fault=='runtime': value['runtime']['local_origin']['body_ref']='foreign'
    elif fault=='identity': value['runtime']['manifest']['being_ref']='foreign'
    elif fault=='roster': value['roster'][0]['being_ref']='foreign'
    elif fault=='body': value['roster'][0]['body_ref']='foreign'
    elif fault=='route': value['intake']['secret_sha256']='f'*64
    elif fault=='policy': value['policy']['classification']='private'
    elif fault=='root': value['runtime_root']='/own/../foreign'
    elif fault=='time': value['at_ms']=False
    else: value['stores']['relationships']='/adult/private/history'
    with pytest.raises(OnboardingError,match='signed_membership_required'):
        compile_specification(**value)


def test_default_order_is_deterministic_and_explicit_order_preserves_original(inputs):
    first=compile_specification(**inputs)
    value=copy.deepcopy(inputs)
    value['authorities']=dict(reversed(list(value['authorities'].items())))
    assert compile_specification(**value)==first
    value.pop('authority_order')
    sorted_result=compile_specification(**value)
    assert [row['manifest']['being_ref'] for row in sorted_result['authorities']]==sorted(value['authorities'])
    value['authority_order']=[]
    with pytest.raises(OnboardingError,match='signed_membership_required'):
        compile_specification(**value)
