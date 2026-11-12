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


def test_resources_do_not_wait_for_inventory_or_usage_and_keep_failed_sample_date(monkeypatch):
    from clusterctl.homes import fleet as module
    import time
    cfg=configuration();cfg['observer_socket']='/unused/reader.sock'
    reading={'observed_at':'2026-11-12T05:00:00Z','scope':'host','sample_seconds':1,
             'memory':None,'cpu':None,'disks':[],'services':[]}
    live={'health':{'schema':'computer-health/v1','targets':[
        dict(id='h',label='Host',scope='host',state='available',attempted_at='now',reading=reading)]}}
    seen=[]
    def observer(path,**kw):seen.append(kw);return live
    monkeypatch.setattr(module,'observation_socket',observer)
    f=Fleet(cfg,reader=lambda _:(_ for _ in ()).throw(AssertionError('slow inventory must not run')))
    with f.lock:
        first=f.resources()
    assert seen==[{'view':'resources'}]
    assert first['observability']['health']['targets'][0]['reading']['observed_at']==reading['observed_at']
    f.resources_until=0
    monkeypatch.setattr(module,'observation_socket',lambda *a,**kw:(_ for _ in ()).throw(OSError()))
    failed=f.resources()
    assert failed['observability']['health_state']=='unavailable'
    assert failed['observability']['health']['targets'][0]['reading']['observed_at']==reading['observed_at']


def test_resources_endpoint_requires_same_grant_and_rechecks_identity(monkeypatch):
    f=Fleet(configuration(),reader=lambda _:(_ for _ in ()).throw(AssertionError('no inventory')))
    app=SimpleNamespace(cluster_dashboard=f); actor=SimpleNamespace(kind='human',ref='human:telegram:1')
    for subject,expected in [(None,401),(SimpleNamespace(kind='human',ref='human:telegram:2'),403)]:
        h=Handler(subject);routes(h,app,'/cluster/api/resources','one',subject,False)
        assert h.result[0]==expected
    h=Handler(actor);routes(h,app,'/cluster/api/resources','one',actor,False)
    assert h.result[0]==200 and h.result[1]['schema']=='cluster-home-resources/v1'
    h=Handler(None);routes(h,app,'/cluster/api/resources','one',actor,False)
    assert h.result[0]==403


def test_admitted_virtual_does_not_reappear_as_a_legacy_preparation(monkeypatch):
    from clusterctl.homes import fleet as module
    cfg=configuration();cfg['observer_socket']='/unused/reader.sock'
    physical=dict(name='one',host='Host',hosting='Incus',physical_state='running',
                  stage='old-stage',job_state='waiting',services={'native.service':'active'},observed_at_ms=123)
    monkeypatch.setattr(module,'observation_socket',lambda _:dict(
        health={'schema':'computer-health/v1','targets':[]},preparations=[physical],partial=False))
    value=Fleet(cfg,reader=lambda _:inventory()).snapshot()
    assert value['planned']==[]
    assert value['instances'][0]['physical']=={
        'physical_state':'running','services':{'native.service':'active'},'observed_at_ms':123}
    assert 'old-stage' not in str(value) and 'waiting' not in str(value)


def test_foreground_source_replaces_fixed_plan_and_refuses_stale_substitution(monkeypatch):
    import time
    from clusterctl.homes import fleet as module
    config=configuration();config['observer_socket']='/unused/reader.sock'
    current={'schema':'cluster-fleet-observation/v1','observed_at_ms':int(time.time()*1000),
        'partial':False,'health':{'schema':'computer-health/v1','targets':[]},
        'preparations':[dict(name='Actual',host='Host',hosting='Incus',physical_state='running',
                            stage='matrix',job_state='waiting',observed_at_ms=1,services={})]}
    monkeypatch.setattr(module,'observation_socket',lambda _:current)
    fleet=Fleet(config,reader=lambda _:inventory())
    assert fleet.snapshot()['planned'][0]['name']=='Actual'
    assert 'Next' not in str(fleet.snapshot())
    fleet.cached_until=0
    def unavailable(_):raise OSError('private')
    monkeypatch.setattr(module,'observation_socket',unavailable)
    missing=fleet.snapshot()
    assert missing['planned']==[] and missing['preparation_state']=='unavailable'
    assert len(missing['instances'])==1
