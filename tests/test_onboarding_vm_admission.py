"""KVM admission keeps loopback and the existing signed authority boundaries."""
import json
from types import SimpleNamespace

import pytest

from clusterctl import onboarding_vm_admission as relay
from clusterctl.onboarding import OnboardingError
from tests.test_onboarding import plan


@pytest.mark.parametrize('endpoint', ['example.org:8696','127.0.0.1:8696',
    '0.0.0.0:8696','169.254.1.1:8696','224.1.1.1:8696','8.8.8.8:8696',
    '10.2.3.4:22','10.2.3.4:8696\nExecStart=bad','10.2.3.4:8696:1'])
def test_relay_cannot_select_public_metadata_loopback_or_command_destination(endpoint):
    with pytest.raises(ValueError):
        relay.request(endpoint,8696,'a'*64,apply=False)


def test_vm_uses_own_loopback_and_exact_destination_without_incus_proxy():
    calls=[]
    def execute(value, argv, **kw):
        calls.append((argv,kw))
        request=json.loads(kw['input_data'])
        assert request['apply'] is False
        socket=request['files']['daimon-cluster-admission.socket']
        service=request['files']['daimon-cluster-admission.service']
        assert 'ListenStream=127.0.0.1:8696\n' in socket
        assert 'IPAddressDeny=any\n' in service
        assert 'IPAddressAllow=10.2.3.4/32\n' in service
        assert '--exit-idle-time=5min 10.2.3.4:8696\n' in service
        assert 'MemoryMax=32M\n' in service and 'LimitNOFILE=64\n' in service
        return '{"ready":true}'
    backend=SimpleNamespace(execute_body=execute)
    assert relay.reconcile(backend,plan(),'10.2.3.4:8696',8696,apply=False,deadline_ns=123)
    assert len(calls)==1 and calls[0][1]['uid']==calls[0][1]['gid']==0
    assert calls[0][1]['deadline_ns']==123
    assert 'incus' not in calls[0][0]
    backend.execute_body=lambda *a,**kw:'{"ready":1}'
    with pytest.raises(OnboardingError,match='relay_unconfirmed'):
        relay.reconcile(backend,plan(),'10.2.3.4:8696',8696,apply=False)
