"""One finite native-update command reuses existing jobs, routes and effects."""
import copy
import json
from types import SimpleNamespace

import pytest

from clusterctl import being_seed, onboarding_host, onboarding_managed as managed
from clusterctl.onboarding import OnboardingError


def spec():
    return dict(schema='cluster-native-code-maintenance/v1', host_config='/held/host.json',
        vm_qualification=None, candidate=dict(code='/held/code', code_digest='a'*64),
        targets=['first', 'second', 'third'], group='published',
        operation_id='31bca744-1da3-4379-a6df-211f38d5c347', max_seconds=480)


@pytest.mark.parametrize('change', [dict(max_seconds=481), dict(targets=['first', 'first']),
    dict(candidate=dict(code='../foreign', code_digest='a'*64)), dict(host_config=None),
    dict(operation_id='new-each-retry'), dict(group='enable-everything')])
def test_refuse_invalid_or_unbounded_spec_before_any_backend(change):
    with pytest.raises(OnboardingError, match='native_code_maintenance_spec_required'):
        managed.validate_code_update({**spec(), **change})


def test_partial_batch_reuses_one_operation_and_existing_effects(tmp_path, monkeypatch):
    clock = [1_000_000_000]
    monkeypatch.setattr(managed.time, 'monotonic_ns', lambda: clock[0])
    config = SimpleNamespace(jobs=tmp_path)
    monkeypatch.setattr(onboarding_host.HostConfig, 'load', lambda _: config)
    class Jobs:
        def __init__(self, _):
            pass
        def _load(self, name):
            return dict(plan=dict(name=name))
    monkeypatch.setattr(managed, 'JobStore', Jobs)
    prepared, budgets, attempts, effects = [], [], [], {}
    class Backend:
        def __init__(self, selected, run=None):
            assert selected is config and run is None
        def runtime_available(self, plan, candidate, *, prepare, deadline_ns):
            assert prepare and candidate[1] == 'a'*64
            assert 0 < deadline_ns-clock[0] <= 120_000_000_000
            prepared.append(plan['name'])
            clock[0] += 20_000_000_000
            return True
    fail = [True]
    class Owner:
        def __init__(self, _):
            pass
        def update_native_code(self, plan, candidate, **options):
            assert options['published_group'] and not options['receive_only_group']
            budgets.append(options['timeout_seconds'])
            key = (options['operation_id'], plan['name'])
            attempts.append(key)
            if plan['name'] == 'second' and fail:
                fail.pop()
                raise being_seed.SeedError('seed_operation_in_progress', 409)
            effects.setdefault(key, dict(candidate_digest=candidate[1]))
            return copy.deepcopy(effects[key])
    monkeypatch.setattr(onboarding_host, 'HostBackend', Backend)
    monkeypatch.setattr(managed, 'ManagedRuntime', Owner)
    result = managed.run_code_update(spec())
    assert not result['complete'] and result['pending'] == ['third']
    assert [row['status'] for row in result['targets']] == ['updated', 'incomplete']
    assert result['targets'][1]['failure']['code'] == 'seed_operation_in_progress'
    assert prepared == ['first', 'second']
    assert all(0 < seconds <= 100 for seconds in budgets)
    result = managed.run_code_update(spec())
    assert result['complete'] and not result['pending']
    assert len(effects) == 3 and {key[0] for key in attempts} == {spec()['operation_id']}
    assert result['receiving_readiness'] == 'unobserved'


def test_command_requires_root_without_disclosing_spec_path(capsys, monkeypatch):
    monkeypatch.setattr('os.geteuid', lambda: 1000)
    assert managed.main(['--spec', '/private/never-read.json']) == 1
    result = json.loads(capsys.readouterr().out)
    assert result['failure']['code'] == 'native_code_maintenance_root_required'
    assert 'private' not in json.dumps(result)


def test_remote_cohort_uses_existing_placement_pins_without_initial_publication(tmp_path, monkeypatch):
    from clusterctl import vm_body
    selected = spec()
    selected.update(targets=['first'], vm_qualification=str(tmp_path))
    being_seed._write(tmp_path/'receiving.json', {'results': {'first': {'placement_sha256': 'b'*64}}})
    config = SimpleNamespace(jobs=tmp_path/'jobs')
    monkeypatch.setattr(onboarding_host.HostConfig, 'load', lambda _: config)
    monkeypatch.setattr(managed, 'JobStore', lambda _: SimpleNamespace(
        _load=lambda name: dict(plan=dict(name=name))))
    seen = {}
    class Runner:
        def __init__(self, placements, plans, *, publish):
            seen.update(placements=placements, plans=plans)
            with pytest.raises(OnboardingError, match='existing_body_required'):
                publish('forbidden-new-input')
    monkeypatch.setattr(vm_body, 'RemoteIncusRunner', Runner)
    class Backend:
        def __init__(self, _, *, run):
            assert isinstance(run, Runner)
        def runtime_available(self, *_, **__):
            return True
    monkeypatch.setattr(onboarding_host, 'HostBackend', Backend)
    monkeypatch.setattr(managed, 'ManagedRuntime', lambda _: SimpleNamespace(
        update_native_code=lambda *args, **kwargs: dict(candidate_digest='a'*64)))
    assert managed.run_code_update(selected)['complete']
    assert seen['placements'] == {'first': (tmp_path/'first-placement.json', 'b'*64)}
    assert seen['plans'] == {'first': {'name': 'first'}}
