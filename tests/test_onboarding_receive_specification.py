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
    if fault=='private':
        value['governance'][0]['sensitivity']='private'
    elif fault=='duplicate':
        value['governance']*=2
    elif fault=='signature':
        value['governance'][0]['payload']['declaration']['nonce']='changed'
    elif fault=='tribe':
        value['tribe_ref']='foreign'
    elif fault=='runtime':
        value['runtime']['local_origin']['body_ref']='foreign'
    elif fault=='identity':
        value['runtime']['manifest']['being_ref']='foreign'
    elif fault=='roster':
        value['roster'][0]['being_ref']='foreign'
    elif fault=='body':
        value['roster'][0]['body_ref']='foreign'
    elif fault=='route':
        value['intake']['secret_sha256']='f'*64
    elif fault=='policy':
        value['policy']['classification']='private'
    elif fault=='root':
        value['runtime_root']='/own/../foreign'
    elif fault=='time':
        value['at_ms']=False
    else:
        value['stores']['relationships']='/adult/private/history'
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


@pytest.fixture
def controller_inputs(inputs):
    from daimon_matrix.release_compatibility import describe_reader
    runtime=inputs['runtime']
    authorities=copy.deepcopy(inputs['authorities'])
    authorities.update(closure(runtime))
    target=dict(being_ref=runtime['manifest']['being_ref'],
                embodiment_id=runtime['local_origin']['embodiment_id'])
    row=dict(being_ref=target['being_ref'],manifest_hash='1'*64,control_head='dm:control:v1:template')
    template=dict(schema='dm.receiving-release/v1',artifacts={'matrix_sdk':'2'*64},
        provenance=dict(matrix_revision='b'*40,qualification_sha256='3'*64),
        contract=describe_reader()['contract'],authorities=dict(current=[row],candidate=[copy.deepcopy(row)]),
        required_receivers=[dict(target,expected_selection_sha256='4'*64)])
    return dict(template=template,target=target,authority_closure=authorities,
        baseline=dict(receiving_code='5'*64,matrix_sdk='2'*64,runtime_bundle_sha256='6'*64),
        snapshot=dict(outbound_release=False,group=dict(application_sha256='7'*64,publication_sha256='8'*64)),
        code_digest='9'*64)


def test_controller_manifest_uses_real_signed_authorities_and_retained_six_pin_selection(controller_inputs):
    from clusterctl.onboarding_receive_specification import compile_controller_manifest
    from clusterctl.onboarding import digest
    value=controller_inputs
    original=copy.deepcopy(value)
    result=compile_controller_manifest(**value)
    expected=dict(value['baseline'],application_sha256='7'*64,publication_sha256='8'*64,
                  visibility_installation_sha256=None)
    assert result['required_receivers']==[dict(value['target'],expected_selection_sha256=digest(expected),
        artifacts=dict(receiving_code=value['code_digest']))]
    assert {r['being_ref'] for r in result['authorities']['current']}==set(value['authority_closure'])
    assert result['authorities']['candidate']==result['authorities']['current']
    assert result['artifacts']==value['template']['artifacts'] and value==original
    result['authorities']['current'].clear()
    assert value==original


@pytest.mark.parametrize('fault',['sdk','active-body','signature','visibility','selection','template'])
def test_controller_manifest_refuses_mismatched_identity_contract_or_receive_result(controller_inputs,fault):
    from clusterctl.onboarding_receive_specification import compile_controller_manifest
    value=copy.deepcopy(controller_inputs)
    if fault=='sdk':
        value['baseline']['matrix_sdk']='a'*64
    elif fault=='active-body':
        value['target']['embodiment_id']='embodiment:foreign'
    elif fault=='signature':
        entry=value['authority_closure'][value['target']['being_ref']]
        entry['authority']['control_head']='dm:control:v1:forged'
    elif fault=='visibility':
        value['snapshot']['outbound_release']=True
    elif fault=='selection':
        value['snapshot']['group']['application_sha256']='invalid'
    else:
        value['template']['contract']['profile']='invalid profile'
    with pytest.raises(OnboardingError,match='companion_controller_signed_preparation_required'):
        compile_controller_manifest(**value)
