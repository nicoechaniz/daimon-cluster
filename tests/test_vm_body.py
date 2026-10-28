"""Full-OS VM placement preserves native controls and never creates SSH grants."""
import hashlib
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from clusterctl import being_seed, native_body, vm_body
from clusterctl.onboarding import OnboardingError, digest


def placement(tmp_path):
    plan = {'name': 'oliva'}
    value = dict(schema='cluster-incus-vm-body-placement/v1', plan_digest=digest(plan),
        project='default', instance='dm-oliva', instance_uuid='18f437a2-bc2d-408a-8aaf-7693ebc797e4',
        host_machine_id_sha256=hashlib.sha256(Path('/etc/machine-id').read_bytes().strip()).hexdigest(),
        machine_id_sha256='a'*64, bootstrap_python='/usr/bin/python3', home='/home/agent')
    path = tmp_path/'vm.json'
    being_seed._write(path, value)
    return plan, path, value


def test_vm_transport_preserves_input_and_pinned_identity(tmp_path, monkeypatch):
    plan, path, value = placement(tmp_path)
    body = native_body.NativeBody.load(path, plan, expected_digest=digest(value))
    assert isinstance(body, vm_body.VMBody)
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        assert argv[:2] == ['incus', '--force-local']
        if argv[2] == 'query':
            assert argv[3] == '/1.0/instances/dm-oliva?project=default'
            return SimpleNamespace(returncode=0, stdout=json.dumps({'type':'virtual-machine',
                'config':{'volatile.uuid':value['instance_uuid']}}))
        assert argv[2:4] == ['--project', 'default']
        assert argv[4:7] == ['exec', 'dm-oliva', '--']
        req = json.loads(argv[-1])
        assert req['machine_id_sha256'] == value['machine_id_sha256']
        assert req['argv'] == ['owner', 'literal $(no shell)']
        assert req['owner_clock'] and kwargs['input'] == '{"same":"operation"}'
        return SimpleNamespace(returncode=0, stdout='{"observed":true}', stderr='')
    monkeypatch.setattr(vm_body.subprocess,'run',run)
    assert body.execute(['owner','literal $(no shell)'], input_data='{"same":"operation"}',
        owner_clock=True, deadline_ns=time.monotonic_ns()+2_000_000_000) == '{"observed":true}'
    assert len(calls) == 2


@pytest.mark.parametrize('change', [{'type':'container','config':{}},
    {'type':'virtual-machine','config':{'volatile.uuid':'different'}}])
def test_vm_replacement_never_executes_or_replays(tmp_path, monkeypatch, change):
    plan,path,_ = placement(tmp_path)
    body=native_body.NativeBody.load(path,plan)
    calls=[]
    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0,stdout=json.dumps(change))
    monkeypatch.setattr(vm_body.subprocess,'run',run)
    with pytest.raises(OnboardingError,match='vm_receiving_instance_changed'):
        body.execute(['owner'])
    assert len(calls)==1 and calls[0][2]=='query'


@pytest.mark.parametrize('field,value', [('project','--remote'),('instance','dm-eko'),
    ('instance_uuid','bad'),('host_machine_id_sha256','b'*64),('bootstrap_python','/opt/../bad')])
def test_vm_placement_cannot_redirect_existing_plan(tmp_path,field,value):
    plan,path,row=placement(tmp_path);row[field]=value;being_seed._write(path,row)
    with pytest.raises(OnboardingError,match='vm_receiving_(placement_required|host_changed)'):
        native_body.NativeBody.load(path,plan)


def test_existing_host_binding_uses_vm_os_controls_and_refuses_container_reconciliation(tmp_path, monkeypatch):
    from dataclasses import replace
    from tests.test_onboarding_host import configured
    _,plan,_,backend=configured(tmp_path)
    _,path,row=placement(tmp_path)
    row.update(plan_digest=digest(plan),instance='dm-'+plan['name'])
    being_seed._write(path,row)
    backend.config=replace(backend.config,native_by_name={plan['name']:(path,digest(row))})
    def execute(self,argv,**kwargs):
        assert argv==['owner-control'] and kwargs['env']=={'HOME':'/home/agent'}
        return 'retained-native-result'
    monkeypatch.setattr(vm_body.VMBody,'execute',execute)
    backend.run=lambda *args,**kwargs: pytest.fail('retired container adapter entered')
    assert backend.execute_body(plan,['owner-control'],home=True)=='retained-native-result'
    with pytest.raises(OnboardingError,match='native_receiving_incus_unsupported'):
        backend._dispatch(plan,['restart','dm-'+plan['name']])


def remote_placement(tmp_path):
    plan,path,row=placement(tmp_path)
    row['host_machine_id_sha256']='b'*64
    key=tmp_path/'parent.key';key.write_text('fixture key reference');key.chmod(0o600)
    hosts=tmp_path/'hosts';hosts.write_text('fixture host reference');hosts.chmod(0o600)
    row['incus_host_ssh']=dict(host='fixture.invalid',port=22,ssh_user='operator',
        identity_file=str(key),identity_uid=os.geteuid(),known_hosts=str(hosts),bootstrap_python='/usr/bin/python3')
    being_seed._write(path,row)
    return plan,path,row


def test_remote_vm_checks_both_host_and_guest_without_key_installation(tmp_path,monkeypatch):
    import shlex
    plan,path,row=remote_placement(tmp_path);body=native_body.NativeBody.load(path,plan)
    calls=[]
    def run(argv,**kwargs):
        calls.append(argv)
        assert argv[0]=='ssh' and 'StrictHostKeyChecking=yes' in argv
        remote=shlex.split(argv[-1]);assert remote[4]==vm_body.HOST_LAUNCH
        assert remote[5]==row['host_machine_id_sha256']
        incus=json.loads(remote[6])
        if 'query' in incus:
            return SimpleNamespace(returncode=0,stdout=json.dumps({'type':'virtual-machine',
                'config':{'volatile.uuid':row['instance_uuid']}}))
        request=json.loads(incus[-1])
        assert request['machine_id_sha256']==row['machine_id_sha256']
        assert request['argv']==['owner','literal ; $(unchanged)']
        assert kwargs['input']=='original request'
        return SimpleNamespace(returncode=0,stdout='retained',stderr='')
    monkeypatch.setattr(vm_body.subprocess,'run',run)
    assert body.execute(['owner','literal ; $(unchanged)'],input_data='original request')=='retained'
    assert len(calls)==2


def test_remote_public_transfer_uses_existing_rsync_directly_into_agent(tmp_path,monkeypatch):
    import shlex
    plan,path,_=remote_placement(tmp_path);body=native_body.NativeBody.load(path,plan)
    monkeypatch.setattr(vm_body.VMBody,'_verify_instance',lambda *a:None)
    monkeypatch.setattr(vm_body.VMBody,'execute',lambda *a,**k:'')
    calls=[]
    def run(argv,**kwargs):
        calls.append(argv);assert argv[0]=='rsync' and '--delete' not in argv
        server=shlex.split(argv[argv.index('--rsync-path')+1])
        assert server[4]==vm_body.HOST_LAUNCH
        assert json.loads(server[6])[-4:]==['exec','dm-oliva','--','rsync']
        assert argv[-1].endswith(':/opt/retained-stage/')
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(vm_body.subprocess,'run',run)
    body._transfer_code(tmp_path,Path('/opt/retained-stage'),2)
    assert len(calls)==1


def test_parent_ssh_reference_is_closed_and_private(tmp_path):
    plan,path,row=remote_placement(tmp_path)
    row['incus_host_ssh']['host']='-oProxyCommand=invalid';being_seed._write(path,row)
    with pytest.raises(OnboardingError,match='vm_receiving_placement_required'):
        native_body.NativeBody.load(path,plan)


def test_remote_parent_mismatch_stops_before_guest_operation(tmp_path,monkeypatch):
    plan,path,_=remote_placement(tmp_path);body=native_body.NativeBody.load(path,plan);calls=[]
    def run(argv,**kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=1,stdout='',stderr='vm_receiving_host_changed\n')
    monkeypatch.setattr(vm_body.subprocess,'run',run)
    with pytest.raises(OnboardingError,match='^vm_receiving_host_changed$'):
        body.execute(['owner'])
    assert len(calls)==1


def test_parent_launcher_validates_actual_host_and_preserves_rsync_server_arguments():
    import subprocess,sys
    actual=hashlib.sha256(Path('/etc/machine-id').read_bytes().strip()).hexdigest()
    argv=[sys.executable,'-I','-c',vm_body.HOST_LAUNCH,actual,
          json.dumps(['/usr/bin/printf','%s\n','literal ; $(not executed)']),'--server','-s']
    result=subprocess.run(argv,capture_output=True,text=True,check=True)
    assert result.stdout=='literal ; $(not executed)\n--server\n-s\n'
    argv[4]='b'*64
    result=subprocess.run(argv,capture_output=True,text=True)
    assert result.returncode!=0 and result.stdout=='' and result.stderr.strip()=='vm_receiving_host_changed'
