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
