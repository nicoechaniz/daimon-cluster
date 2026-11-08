import contextlib
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from clusterctl.homes.fleet_reader import collect


def test_live_jobs_and_physical_state_change_without_dashboard_configuration(tmp_path):
    jobs=tmp_path/'jobs';(jobs/'companion').mkdir(parents=True)
    job=jobs/'companion'/'job.json';job.write_text(json.dumps({'schema':'cluster-onboarding-job/v1','plan':{'name':'companion'},'stage':'matrix','state':'waiting'}))
    source=tmp_path/'probe.py';source.write_text('import json,time\nfrom pathlib import Path\ndef probe(spec):return {"observed_at":"now","scope":spec["scope"],"sample_seconds":1,"memory":None,"cpu":None,"disks":[],"services":[]}\n')
    config={'probe_source':str(source),'probe_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'targets':[dict(id='host',label='Host',scope='host',command=['python3','-'],probe=dict(scope='host',jobs=str(jobs),instance_prefix='dm-',services=['conversation.service']))]}
    status={'value':'Running'}
    def execute(argv, program):
        def run(command, **kwargs):
            if command[:2]==['incus','list']:
                value=json.dumps([{'name':'dm-companion','status':status['value'],'expanded_config':{'limits.cpu':'3','limits.memory':'4GiB'}}])
            else:value='Id=conversation.service\nLoadState=loaded\nActiveState=active\n'
            return SimpleNamespace(stdout=value)
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):
            # The production reader runs this same public program in the selected OS.
            import subprocess
            from unittest.mock import patch
            with patch.object(subprocess,'run',side_effect=run):exec(program,{})
        return json.loads(stream.getvalue())
    first=collect(config,execute=execute)
    assert first['preparations'][0]['physical_state']=='running'
    assert first['preparations'][0]['services']=={'conversation.service':'active'}
    status['value']='Stopped';job.write_text(json.dumps({'schema':'cluster-onboarding-job/v1','plan':{'name':'companion'},'stage':'access','state':'waiting'}))
    next_read=collect(config,execute=execute)
    assert next_read['preparations'][0]['physical_state']=='stopped'
    assert next_read['preparations'][0]['stage']=='access'
    assert next_read['preparations'][0]['services']=={}


def test_unavailable_host_never_becomes_a_fixed_preparation_or_healthy_read(tmp_path):
    source=tmp_path/'probe.py';source.write_text('def probe(spec): pass\n')
    cfg=dict(probe_source=str(source),probe_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
             targets=[dict(id='host',label='Host',scope='host',command=['python3','-'],probe={})])
    result=collect(cfg,execute=Mock(side_effect=OSError('private error must not escape')))
    assert result['partial'] and result['preparations']==[]
    assert result['health']['targets'][0]['state']=='unavailable'
    assert 'private error' not in str(result)
