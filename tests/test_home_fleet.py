from types import SimpleNamespace
import pytest
from clusterctl.homes.fleet import Fleet, routes


def configuration():
    return dict(schema='cluster-home-dashboard/v1', home='one', readers=['human:telegram:1'],
                runtime_root='/unused', placements={'emb:1':dict(name='One', host='Host', hosting='Native')},
                planned=[dict(name='Next',host='New host',hosting='Incus')])


def inventory():
    return dict(schema='dm.scope.discovery/v1',scope='/all',partial=False,evaluated_at_ms=1000,
                members=[dict(embodiment_id='emb:1',body_ref='body:1',lease_expires_at_ms=2000,
                              credential='NEVER EXPOSE',fence_token='NEVER EXPOSE')])


def test_sanitized_current_inventory_and_failure():
    calls=[]
    def read(_):
        calls.append(1)
        if len(calls)>1: raise OSError('unavailable')
        return inventory()
    fleet=Fleet(configuration(),reader=read)
    value=fleet.snapshot()
    assert value['instances'][0]['name']=='One'
    assert 'NEVER EXPOSE' not in str(value)
    assert fleet.snapshot()==value and len(calls)==1
    fleet.cached_until=0
    with pytest.raises(OSError): fleet.snapshot()


def test_native_inventory_bounds():
    value=inventory();value['members']*=65
    with pytest.raises(ValueError): Fleet(configuration(),reader=lambda _:value).snapshot()
    value=inventory();value['members']*=2
    with pytest.raises(ValueError): Fleet(configuration(),reader=lambda _:value).snapshot()


class Handler:
    def __init__(self, current): self.current=current; self.result=None
    def respond(self, code, body, *args): self.result=(code,body)
    def context(self): return None,None,self.current,None,None,None


def test_no_native_read_for_anonymous_other_human_or_vpn():
    def forbidden(_): raise AssertionError('native inventory leaked')
    app=SimpleNamespace(cluster_dashboard=Fleet(configuration(),reader=forbidden))
    for actor,vpn,expected in [(None,False,401),(SimpleNamespace(kind='human',ref='human:telegram:2'),False,403),
                               (SimpleNamespace(kind='human',ref='human:telegram:1'),True,401)]:
        h=Handler(actor);routes(h,app,'/cluster/api/fleet','one',actor,vpn)
        assert h.result[0]==expected


def test_authenticated_read_and_identity_recheck():
    app=SimpleNamespace(cluster_dashboard=Fleet(configuration(),reader=lambda _:inventory()))
    actor=SimpleNamespace(kind='human',ref='human:telegram:1')
    h=Handler(actor);routes(h,app,'/cluster/api/fleet','one',actor,False)
    assert h.result[0]==200 and len(h.result[1]['instances'])==1
    h=Handler(None);routes(h,app,'/cluster/api/fleet','one',actor,False)
    assert h.result[0]==403
