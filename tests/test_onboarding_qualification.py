"""Disposable cleanup never names or destroys a live/foreign resource."""
import copy

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_qualification import cleanup_disposable
from tests.test_onboarding_host import configured


def setup(tmp_path):
    config, old, run, backend = configured(tmp_path)
    plan = {**old, 'name': 'qualify-fixture'}
    being_seed._write(config.grants / (plan['name'] + '.json'),
                     dict(schema='cluster-onboarding-host-grant/v1', plan=plan, revoked=False))
    backend.execute(plan, 'environment', 'unused')
    run.instances[0]['config']['user.dm.onboarding-disposable'] = digest(plan)
    run.volumes[0]['config']['user.dm.onboarding-disposable'] = digest(plan)
    original = backend.run
    def delete(argv):
        if argv[0] == 'delete':
            run.calls.append(argv)
            run.instances = [row for row in run.instances if row['name'] != argv[1]]
            return ''
        if argv[:3] == ['storage', 'volume', 'delete']:
            run.calls.append(argv)
            run.volumes = [row for row in run.volumes if row['name'] != argv[4]]
            return ''
        return original(argv)
    backend.run = delete
    return plan, run, backend


def test_cleanup_preserves_other_resources_and_reconciles_retries(tmp_path):
    plan, run, backend = setup(tmp_path)
    run.instances.append(dict(name='existing-body', config={}, expanded_devices={}))
    run.volumes.append(dict(name='existing-home', type='custom', config={}))
    foreign = copy.deepcopy((run.instances[-1], run.volumes[-1]))
    cleanup_disposable(backend, plan)
    before = list(run.calls)
    cleanup_disposable(backend, plan)
    assert run.calls == before
    assert (run.instances[0], run.volumes[0]) == foreign
    assert [call for call in run.calls if call[0] == 'delete'] == [['delete', 'dm-qualify-fixture', '--force']]


@pytest.mark.parametrize('conflict', ['live-name', 'body-marker', 'volume-marker', 'root', 'home'])
def test_cleanup_refuses_live_labels_or_conflicting_owned_resources(tmp_path, conflict):
    plan, run, backend = setup(tmp_path)
    if conflict == 'live-name':
        plan = {**plan, 'name': 'eko'}
    elif conflict == 'body-marker':
        run.instances[0]['config'].pop('user.dm.onboarding-disposable')
    elif conflict == 'volume-marker':
        run.volumes[0]['config']['user.dm.onboarding-plan'] = 'foreign'
    else:
        run.instances[0]['expanded_devices'][conflict]['source' if conflict == 'home' else 'pool'] = 'foreign'
    before = copy.deepcopy((run.instances, run.volumes, run.calls))
    with pytest.raises(OnboardingError):
        cleanup_disposable(backend, plan)
    assert (run.instances, run.volumes, run.calls) == before
