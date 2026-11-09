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


def test_reader_route_failure_precedes_any_update_or_backend_creation(tmp_path, monkeypatch):
    selected = spec()
    selected['reader_completion'] = str(tmp_path/'readers.json')
    monkeypatch.setattr(managed, 'load_code_update_readers', lambda _: dict(owners={'current':{}}))
    class Client:
        def __init__(self, _):
            pass
        def _call(self, value):
            assert value == {'action':'status'}
            raise OnboardingError('receiving_reader_owner_unavailable')
    monkeypatch.setattr(managed, 'ReaderCommandClient', Client)
    monkeypatch.setattr(onboarding_host.HostConfig, 'load', lambda _:SimpleNamespace(jobs=tmp_path))
    monkeypatch.setattr(managed,'JobStore',lambda _:SimpleNamespace(_load=lambda name:dict(plan=dict(name=name))))
    monkeypatch.setattr(onboarding_host,'HostBackend',lambda *_,**__:SimpleNamespace())
    monkeypatch.setattr(managed,'ManagedRuntime',lambda _:pytest.fail('update began before route preflight'))
    with pytest.raises(OnboardingError, match='owner_unavailable'):
        managed.run_code_update(selected)


def test_reader_command_is_bounded_json_rpc_with_exact_control(tmp_path, monkeypatch):
    from clusterctl import onboarding_receiving_update as receiving
    import time
    client = managed.ReaderCommandClient(dict(root=str(tmp_path), command=['/held/owner']))
    client.deadline_ns = time.monotonic_ns()+30_000_000_000
    seen = []
    expected = dict(selection={'current':'selected'},process={'pid':42})
    def run(argv, **options):
        assert argv[0] == '/held/owner' and argv[1:3] == ['--reader-rpc','--max-seconds']
        assert 0 < float(argv[3]) <= options['timeout'] <= 30
        value=json.loads(options['input'])
        seen.append(value)
        return SimpleNamespace(returncode=0,stdout=json.dumps(dict(expected=expected)))
    monkeypatch.setattr(receiving,'_run_owner',run)
    assert client.current_reader(expected_selection=expected['selection'])['expected'] == expected
    command=dict(operation_id=spec()['operation_id'],phase='select',expected_head='a'*64,readers=[])
    client.prepare_apply_control(command,tmp_path/'receiving-control'/(spec()['operation_id']+'-select.json'))
    assert seen[-1] == dict(action='control',command=command,expected=expected)
    with pytest.raises(OnboardingError,match='binding_conflict'):
        client.prepare_apply_control(command,tmp_path/'foreign.json')


def test_reader_failure_keeps_update_complete_and_resumes_same_native_effects(tmp_path, monkeypatch):
    selected=spec()
    selected['reader_completion']=str(tmp_path/'readers.json')
    routes=dict(owners={'current':{}})
    monkeypatch.setattr(managed,'load_code_update_readers',lambda _:routes)
    monkeypatch.setattr(managed,'ReaderCommandClient',lambda _:SimpleNamespace(_call=lambda _:dict(ready=True)))
    config=SimpleNamespace(jobs=tmp_path/'jobs')
    monkeypatch.setattr(onboarding_host.HostConfig,'load',lambda _:config)
    monkeypatch.setattr(managed,'JobStore',lambda _:SimpleNamespace(_load=lambda name:dict(plan=dict(name=name))))
    monkeypatch.setattr(onboarding_host,'HostBackend',lambda *_,**__:SimpleNamespace(runtime_available=lambda *_,**__:True))
    effects={}
    def update(plan,*_,**options):
        return effects.setdefault((options['operation_id'],plan['name']),dict(loaded=True))
    monkeypatch.setattr(managed,'ManagedRuntime',lambda _:SimpleNamespace(update_native_code=update))
    first=[True]
    def finish(value,**options):
        assert value is routes and options['operation_id'] == selected['operation_id']
        if first:
            first.pop()
            raise OnboardingError('receiving_control_completion_uncertain')
        return dict(receiving_readiness='qualified-local-projection',communication_acceptance='unobserved')
    monkeypatch.setattr(managed,'complete_code_update_readers',finish)
    result=managed.run_code_update(selected)
    assert not result['complete'] and result['pending'] == [] and len(effects)==3
    assert all(row['status']=='updated' for row in result['targets'])
    result=managed.run_code_update(selected)
    assert result['complete'] and result['receiving_readiness']=='qualified-local-projection'
    assert len(effects)==3


def test_job_reader_reuses_owning_placement_executor(tmp_path, monkeypatch):
    from clusterctl import onboarding_receiving_update as receiving
    import time
    monkeypatch.setattr(receiving,'_run_owner',lambda *_,**__:pytest.fail('new transport bypassed placement'))
    plan=dict(name='current')
    def execute(actual,argv,**options):
        assert actual is plan and argv[0]=='/body/owner'
        assert options['uid']==options['gid']==1000
        assert json.loads(options['input_data'])=={'action':'status'}
        assert options['deadline_ns'] > time.monotonic_ns()
        return json.dumps({'current':'owner'})
    backend=SimpleNamespace(execute_body=execute)
    clients=managed.code_update_reader_clients(dict(owners={'current':dict(root=str(tmp_path),
        job='current',command=['/body/owner'])}),backend=backend,plans={'current':plan})
    clients['current'].deadline_ns=time.monotonic_ns()+1_000_000_000
    assert clients['current']._call(dict(action='status'))=={'current':'owner'}


@pytest.mark.parametrize('tamper',[None,'process','code','bundle'])
def test_updated_job_selection_is_derived_from_its_exact_receipt(tmp_path, monkeypatch, tamper):
    from clusterctl import onboarding_receiving_update as receiving
    import time
    observed=dict(process=dict(pid=42),server=dict(embodiment_id='body:current'),runtime_status=dict(
        loaded_runtime=dict(qualified_startup=dict(code_digest='a'*64,matrix_wheel_sha256='b'*64),
            runtime_bundle_sha256='c'*64),loaded_application=dict(application_sha256='d'*64,
                publication_sha256='e'*64,visibility=dict(installation_sha256='f'*64))))
    receipt=dict(operation_id=spec()['operation_id'],candidate_digest='a'*64,
        process=copy.deepcopy(observed['process']),origin=observed['server'],runtime_sha256='c'*64)
    if tamper=='process':
        observed['process']['pid']=43
    elif tamper=='code':
        observed['runtime_status']['loaded_runtime']['qualified_startup']['code_digest']='9'*64
    elif tamper=='bundle':
        observed['runtime_status']['loaded_runtime']['runtime_bundle_sha256']='9'*64
    client=SimpleNamespace(_call=lambda _:copy.deepcopy(observed))
    monkeypatch.setattr(managed,'code_update_reader_clients',lambda *_,**__:dict(current=client))
    def finish(owners,**options):
        assert owners['current'] is client
        assert options['selections']['current']['receiving_code']=='a'*64
        assert options['selections']['current']['runtime_bundle_sha256']=='c'*64
        return dict(ready=True)
    monkeypatch.setattr(receiving,'refresh_current_readers',finish)
    value=dict(checkpoint=str(tmp_path/'progress.json'),owners=dict(current=dict(
        job='current',selection=None,require_admitted=True)))
    options=dict(operation_id=receipt['operation_id'],release_digest='a'*64,
        deadline_ns=time.monotonic_ns()+1_000_000_000,updates={'current':receipt})
    if tamper:
        with pytest.raises(OnboardingError,match='selection_changed'):
            managed.complete_code_update_readers(value,**options)
    else:
        assert managed.complete_code_update_readers(value,**options)==dict(ready=True)
