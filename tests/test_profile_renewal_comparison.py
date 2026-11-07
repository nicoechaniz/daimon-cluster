"""Historical equality accepts only same-key, same-method expired-role renewal."""
import copy
import pytest
from daimon_matrix.local_api import create_capability
from clusterctl.onboarding_target import _same_profile_after_owner_renewal

@pytest.mark.parametrize("mutation", [None, "methods", "key", "early", "horizon", "revoked", "profile", "runtime"])
def test_renewal_comparison(mutation):
    key=b'k'*32
    old=dict(profile={'role':'observe'}, runtime_id='runtime:test', secret_slot='same',
        descriptor=create_capability(key,client_id='client:test',methods=['runtime.status','scope.me'],
            not_before_ms=1000,not_after_ms=2000).descriptor)
    new=copy.deepcopy(old)
    new['descriptor']=create_capability(key if mutation!='key' else b'z'*32,
        client_id='client:test',methods=['runtime.status'] if mutation=='methods' else ['runtime.status','scope.me'],
        not_before_ms=1500 if mutation=='early' else 3000,
        not_after_ms=3000+31*86400000 if mutation=='horizon' else 3000+86400000,
        status='revoked' if mutation=='revoked' else 'active').descriptor
    if mutation=='profile': new['profile']={'role':'weave'}
    if mutation=='runtime': new['runtime_id']='runtime:other'
    assert _same_profile_after_owner_renewal(old,old)
    assert _same_profile_after_owner_renewal(old,new) is (mutation is None)
