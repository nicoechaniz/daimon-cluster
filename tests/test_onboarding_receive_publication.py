"""First receive publication reuses the native writer and exact retained inputs."""
import copy

import pytest

from clusterctl import onboarding_group_admission as native
from clusterctl.onboarding import OnboardingError, digest
from tests.test_onboarding_group_publication import initial_publication
from tests import test_onboarding_group_authorities as fixtures
from tests.test_onboarding_group_admission import closure

group_source=fixtures.group_source


@pytest.mark.parametrize('profile',['source','guest'])
@pytest.mark.parametrize('lost',[False,True])
def test_compiled_receive_publication_resumes_same_client_and_never_installs_visibility(group_source,profile,lost,monkeypatch):
    owner,group,journal,request,_base=initial_publication(group_source,profile)
    source,target,_peer,peer_bundle,_old=group_source
    from daimon_matrix.messaging_config import read_publication
    # Use the genuine public closure and the original app's explicit routes.
    app,_=read_publication(source._load(signed=False),source.outputs/'tribe/application')
    app.pop('client')
    params=dict(tribe_ref=app['tribe']['policy']['tribe_ref'],
        policy={k:app['tribe']['policy'][k] for k in ('classification','max_ttl_ms')},
        **{k:app[k] for k in ('listen','intake','roster','stores')},
        authority_order=[row['manifest']['being_ref'] for row in app['authorities']],
        secret_sources=request['params']['secret_sources'])
    command=dict(operation_id=request['operation_id'],step='receive-application',action='receive-application',params=params)
    publish=native._publish_application
    calls=[]
    def effect(*args,**kwargs):
        result=publish(*args,**kwargs)
        calls.append(result)
        if lost and len(calls)==1:
            raise OSError('lost after native application publication')
        return result
    monkeypatch.setattr(native,'_publish_application',effect)
    if lost:
        with pytest.raises(OSError,match='lost after native'):
            owner.group_publication(command,authority_closure=closure(peer_bundle))
    result=owner.group_publication(command,authority_closure=closure(peer_bundle))
    persisted,_=read_publication(source._load(signed=False),group/'application')
    assert {k:v for k,v in persisted.items() if k!='client'}==app
    client=copy.deepcopy(persisted['client'])
    assert not (group/'visibility/installation.json').exists()
    repeated=owner.group_publication(command,authority_closure=closure(peer_bundle))
    assert repeated==result
    after,_=read_publication(source._load(signed=False),group/'application')
    assert after['client']==client
    assert result['receive_specification_sha256']==digest(app)
    changed=copy.deepcopy(command)
    changed['params']['policy']['max_ttl_ms']+=1
    with pytest.raises(OnboardingError,match='intent_conflict'):
        owner.group_publication(changed,authority_closure=closure(peer_bundle))


def test_changed_derived_specification_refuses_after_lost_publication_reply(group_source,monkeypatch):
    from clusterctl import being_seed
    from daimon_matrix.messaging_config import read_publication
    owner,group,journal,request,_base=initial_publication(group_source,'source')
    source,_target,_peer,peer_bundle,_old=group_source
    app,_=read_publication(source._load(signed=False),source.outputs/'tribe/application')
    params=dict(tribe_ref=app['tribe']['policy']['tribe_ref'],
        policy={k:app['tribe']['policy'][k] for k in ('classification','max_ttl_ms')},
        **{k:app[k] for k in ('listen','intake','roster','stores')},
        authority_order=[row['manifest']['being_ref'] for row in app['authorities']],
        secret_sources=request['params']['secret_sources'])
    command=dict(operation_id=request['operation_id'],step='receive',action='receive-application',params=params)
    publish=native._publish_application
    def lost(*args,**kwargs):
        publish(*args,**kwargs)
        raise OSError('lost native reply')
    monkeypatch.setattr(native,'_publish_application',lost)
    with pytest.raises(OSError,match='lost native reply'):
        owner.group_publication(command,authority_closure=closure(peer_bundle))
    path=journal/request['operation_id']/'receive-specification.json'
    record=being_seed._read(path,limit=being_seed.MAX_SELECTION)
    record['specification']['stores']['relationships']='changed.sqlite'
    being_seed._write(path,record,limit=being_seed.MAX_SELECTION)
    monkeypatch.setattr(native,'_publish_application',lambda *a,**kw:pytest.fail('changed derived spec reached writer'))
    with pytest.raises(OnboardingError,match='intent_conflict'):
        owner.group_publication(command,authority_closure=closure(peer_bundle))
