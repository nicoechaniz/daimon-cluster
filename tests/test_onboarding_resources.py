"""Plan-bound two-pool resources preserve defaults, foreign volumes and retries."""
import copy
import json
from dataclasses import replace
import pytest
from clusterctl import being_seed, onboarding_intake
from clusterctl.onboarding import JobStore, OnboardingError, digest, validate_plan
from clusterctl.onboarding_host import HostBackend
from tests.test_onboarding import plan
from tests.test_onboarding_host import configured

RESOURCES=dict(root_gib=8,home_gib=8,cold_gib=48,cpu=3,memory_gib=4)

class ResourcesIncus:
    def __init__(self):
        self.instances=[];self.volumes=[];self.calls=[];self.ready=False;self.fail_after=None
    def __call__(self,argv,**kwargs):
        if kwargs: assert kwargs == {"timeout_seconds":20}
        if argv[0]=='list':return json.dumps(self.instances)
        if argv[:3]==['storage','volume','list']:
            return json.dumps([v for v in self.volumes if v['pool']==argv[3]])
        if argv[0]=='query':
            return json.dumps(next(v for v in self.volumes if '/'+v['pool']+'/volumes/custom/'+v['name']==argv[1].removeprefix('/1.0/storage-pools')))
        if argv[0]=='exec' and argv[-1]=='observe':return json.dumps({'ready':self.ready})
        self.calls.append(argv)
        if argv[0]=='init':
            config={'volatile.base_image':argv[1]}
            for i,key in enumerate(argv):
                if key=='--config':k,v=argv[i+1].split('=',1);config[k]=v
            size=argv[argv.index('--device')+1].split('=',1)[1]
            self.instances.append(dict(name=argv[2],status='Stopped',config=config,
                expanded_devices={'root':dict(type='disk',path='/',pool=argv[6],size=size)}))
        elif argv[:3]==['storage','volume','create']:
            self.volumes.append(dict(name=argv[4],type='custom',pool=argv[3],
                config=dict(v.split('=',1) for v in argv[5:])))
        elif argv[:3]==['config','device','add']:
            self.instances[0]['expanded_devices'][argv[4]]=dict(type='disk',**dict(v.split('=',1) for v in argv[6:]))
        elif argv[0]=='start':self.instances[0]['status']='Running'
        elif argv[0]=='exec' and argv[-1]=='prepare':self.ready=True
        else:raise AssertionError(argv)
        if len(self.calls)==self.fail_after:raise RuntimeError('lost response after known fixture effect')
        return json.dumps({'ready':True}) if argv[0]=='exec' else ''


def setup(tmp_path):
    cfg,value,_,_=configured(tmp_path);cfg=replace(cfg,cold_pool='cold')
    value=validate_plan({**value,'resources':dict(RESOURCES)})
    being_seed._write(cfg.grants/'eko.json',dict(schema='cluster-onboarding-host-grant/v1',plan=value,revoked=False))
    run=ResourcesIncus();backend=HostBackend(cfg,run=run)
    return cfg,value,run,backend


@pytest.mark.parametrize('field,value',[('cpu',True),('memory_gib',0),('root_gib',3),('cold_gib',-1),('home_gib','8')])
def test_resource_units_and_bounds(field,value):
    r={**RESOURCES,field:value}
    with pytest.raises(OnboardingError):validate_plan({**plan(),'resources':r})
    assert 'resources' not in validate_plan(plan())


def test_resource_plan_is_frozen_and_completion_requires_all_limits():
    original=plan();selected=validate_plan({**original,'resources':RESOURCES})
    assert digest(original)!=digest(selected)
    JobStore.validate_completion(selected,'environment',{'verified':True,**RESOURCES})
    for k in RESOURCES:
        wrong={**RESOURCES,k:RESOURCES[k]+1}
        with pytest.raises(OnboardingError):JobStore.validate_completion(selected,'environment',{'verified':True,**wrong})
    with pytest.raises(OnboardingError):JobStore.validate_completion(original,'environment',dict(root_gib=8,home_gib=8))


def test_missing_cold_pool_waits_before_mutation(tmp_path):
    cfg,value,run,_=setup(tmp_path);backend=HostBackend(replace(cfg,cold_pool=None),run=run)
    assert backend.observe(value,'environment','unused').reason=='capacity_required'
    assert not run.calls


@pytest.mark.parametrize('after',range(1,8))
def test_each_partial_effect_reconciles_without_recreating(tmp_path,after):
    cfg,value,run,backend=setup(tmp_path);store=JobStore(cfg.jobs)
    store.submit(value,backend);run.fail_after=after
    assert not store.tick('eko',backend)['active']
    run.fail_after=None
    result=store.tick('eko',backend)
    assert result['completed_steps']==['environment']
    assert len(run.calls)==7
    assert backend.observe(value,'environment','unused').facts=={'verified':True,**RESOURCES}
    assert {(v['pool'],v['config']['size']) for v in run.volumes}=={(cfg.pool,'8GiB'),('cold','48GiB')}


@pytest.mark.parametrize('field,value',[('user.dm.onboarding-plan','foreign'),('size','1GiB')])
def test_foreign_cold_volume_is_preserved_before_creating_instance(tmp_path,field,value):
    cfg,p,run,b=setup(tmp_path)
    config={'user.dm.onboarding-plan':digest(p),'size':'48GiB',field:value}
    run.volumes.append(dict(name='dm-eko-cold',type='custom',pool='cold',config=config))
    assert b.observe(p,'environment','unused').state=='conflict'
    with pytest.raises(OnboardingError):b.execute(p,'environment','unused')
    assert run.calls==[] and run.instances==[]


@pytest.mark.parametrize('key,value',[('limits.cpu','4'),('limits.memory','5GiB')])
def test_actual_config_drift_is_not_reported_ready(tmp_path,key,value):
    _,p,run,b=setup(tmp_path);b.execute(p,'environment','unused')
    run.instances[0]['config'][key]=value
    assert b.observe(p,'environment','unused').state=='conflict'


def test_intake_resources_cannot_exceed_its_exact_selection(tmp_path):
    cfg,p,_,_=setup(tmp_path);path=tmp_path/'intake.json'
    value=dict(schema=onboarding_intake.POLICY,release_digest=cfg.release_digest,revoked=False,
        beings={'eko':{k:p[k] for k in ['owner','account_profile','browser','resources']}})
    being_seed._write(path,value);cfg=replace(cfg,intake_policy=path)
    assert onboarding_intake.allows(cfg,p)
    changed=copy.deepcopy(p);changed['resources']['cold_gib']+=1
    assert not onboarding_intake.allows(cfg,changed)
    del value['beings']['eko']['resources'];being_seed._write(path,value)
    assert not onboarding_intake.allows(cfg,p)
