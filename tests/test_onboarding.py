"""Durable orchestration: interrupted effects, independent jobs and closed progress."""
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from clusterctl import onboarding as ob


def plan(name="eko", owner="sai", browser=True):
    return dict(schema=ob.PLAN_SCHEMA, name=name, owner=owner, seed_digest="1" * 64,
                release_digest="2" * 64, account_profile="shared", browser=browser)


class Crash(BaseException):
    pass


class FixtureBackend:
    def __init__(self):
        self.granted = True
        self.effects = set()
        self.calls = []
        self.crash = None
        self.wait = None
        self.uncertain = None

    def authorize(self, plan, fingerprint):
        return self.granted

    def observe(self, plan, stage, operation_id):
        if stage == self.wait:
            return ob.Observation("waiting", reason="human_contact_required")
        if stage == self.uncertain:
            return ob.Observation("uncertain", reason="uncertain_external_effect")
        if operation_id not in self.effects:
            return ob.Observation("absent", safe_to_execute=True)
        facts = {"verified": True, **ob.STAGE_FACTS[stage]}
        if stage == "memory":
            facts.update(memory_stores=2, memory_chapters=25)
        if stage == "acceptance":
            facts.update(dict.fromkeys(ob.ACCEPTANCE, True), browser_verified=True)
        return ob.Observation("complete", facts)

    def execute(self, plan, stage, operation_id):
        self.calls.append((plan["name"], stage, operation_id))
        self.effects.add(operation_id)
        if stage == self.crash:
            raise Crash()


def setup(tmp_path, value=None):
    backend = FixtureBackend()
    store = ob.JobStore(tmp_path / "jobs")
    store.submit(value or plan(), backend)
    return store, backend


def advance(store, backend, name="eko", count=8):
    for _ in range(count):
        result = store.tick(name, backend)
    return result


def test_crash_after_effect_reconciles_without_duplicate_dispatch(tmp_path):
    store, backend = setup(tmp_path)
    backend.crash = "environment"
    with pytest.raises(Crash):
        store.tick("eko", backend)
    assert json.loads((store.directory("eko") / "job.json").read_text())["steps"]["environment"]["state"] == "dispatching"
    backend.crash = None
    reopened = ob.JobStore(store.root)
    assert advance(reopened, backend)["active"] is True
    assert len(backend.calls) == len(ob.STAGES)
    assert reopened.tick("eko", backend)["active"] is True
    assert len(backend.calls) == len(ob.STAGES)


def test_wait_resumes_original_job_and_revocation_prevents_next_effect(tmp_path):
    store, backend = setup(tmp_path)
    backend.wait = "matrix"
    result = advance(store, backend, count=4)
    assert result["state"] == "waiting"
    assert result["completed_steps"] == list(ob.STAGES[:3])
    backend.granted = False
    backend.wait = None
    assert store.tick("eko", backend)["reason"] == "host_authorization_required"
    assert len(backend.calls) == 3
    backend.granted = True
    assert advance(store, backend, count=5)["active"] is True


def test_existing_identity_conflict_is_visible_and_stops_before_acceptance(tmp_path):
    store, backend = setup(tmp_path)
    advance(store, backend, count=3)
    def conflict(*args):
        raise ob.OnboardingError('existing_identity_conflict')
    backend.observe = conflict
    result = store.tick('eko', backend)
    assert result['reason'] == 'existing_identity_conflict'
    assert result['completed_steps'] == list(ob.STAGES[:3]) and len(backend.calls) == 3


def test_uncertain_welcome_is_never_automatically_replayed(tmp_path):
    store, backend = setup(tmp_path)
    advance(store, backend, count=6)
    backend.uncertain = "welcome"
    for _ in range(3):
        result = store.tick("eko", backend)
        assert result["reason"] == "uncertain_external_effect"
        assert result["active"] is False
    assert all(stage != "welcome" for _, stage, _ in backend.calls)


def test_replay_is_exact_and_owner_isolation_hides_job(tmp_path):
    store, backend = setup(tmp_path)
    assert store.submit(plan(), backend) == store.status("eko", owner="sai")
    with pytest.raises(ob.OnboardingError, match="onboarding_plan_conflict"):
        store.submit(plan(owner="ani"), backend)
    with pytest.raises(ob.OnboardingError, match="onboarding_job_not_found"):
        store.status("eko", owner="ani")


def test_two_beings_progress_independently_and_same_being_is_locked(tmp_path):
    store, backend = setup(tmp_path)
    store.submit(plan("oliva", "ani"), backend)
    entered, release = threading.Event(), threading.Event()
    original = backend.execute

    def blocked(value, stage, operation_id):
        if value["name"] == "eko":
            entered.set()
            assert release.wait(timeout=3)
        original(value, stage, operation_id)

    backend.execute = blocked
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(store.tick, "eko", backend)
        assert entered.wait(timeout=3)
        try:
            with pytest.raises(ob.being_seed.SeedError, match="seed_operation_in_progress"):
                store.tick("eko", backend)
            assert store.tick("oliva", backend)["completed_steps"] == ["environment"]
        finally:
            release.set()
        assert pending.result()["completed_steps"] == ["environment"]


@pytest.mark.parametrize("stage,facts", [("environment", {"root_gib": 8, "home_gib": 21}),
                                          ("welcome", {}), ("acceptance", {})])
def test_verified_flag_alone_cannot_complete_a_stage(tmp_path, stage, facts):
    store, backend = setup(tmp_path)
    advance(store, backend, count=ob.STAGES.index(stage)) if stage != "environment" else None
    backend.observe = lambda *args: ob.Observation("complete", {"verified": True, **facts})
    result = store.tick("eko", backend)
    assert result["state"] == "attention-required"
    assert result["reason"] == "verification_failed"
    assert result["active"] is False


def test_private_exception_and_extra_facts_do_not_enter_progress(tmp_path):
    store, backend = setup(tmp_path)
    def fail(*args):
        raise RuntimeError("secret-token and /private/account/cache")
    backend.execute = fail
    result = store.tick("eko", backend)
    raw = (store.directory("eko") / "job.json").read_text()
    assert result["reason"] == "backend_unavailable"
    assert "secret-token" not in raw and "/private/" not in raw
    backend.observe = lambda *args: ob.Observation("complete", {"verified": True, "credential": "secret-token"})
    assert store.tick("eko", backend)["reason"] == "verification_failed"


def test_forged_completion_and_insecure_store_are_refused(tmp_path):
    store, backend = setup(tmp_path)
    path = store.directory("eko") / "job.json"
    record = json.loads(path.read_text())
    record.update(state="complete", stage=None)
    path.write_text(json.dumps(record))
    with pytest.raises(ob.OnboardingError, match="invalid_onboarding_job"):
        store.status("eko", owner="sai")
    store.root.chmod(0o777)
    with pytest.raises(ob.OnboardingError, match="private_onboarding_directory_required"):
        store.submit(plan("oliva", "ani"), backend)


def test_browser_requirement_is_owner_selected():
    facts = dict.fromkeys(ob.ACCEPTANCE, True)
    assert not ob.JobStore.accepted(plan(), facts)
    assert ob.JobStore.accepted(plan(browser=False), facts)


def test_access_readiness_advances_to_listener_but_does_not_prove_real_owner_ssh(tmp_path):
    store, backend = setup(tmp_path)
    backend.wait = 'acceptance'
    result = advance(store, backend)
    assert result['completed_steps'] == list(ob.STAGES[:-1])
    assert result['active'] is False
    assert ob.STAGE_FACTS['access'] == dict(ssh_ready=True, provider_verified=True)
    assert 'ssh_verified' in ob.ACCEPTANCE


def test_conversation_job_has_distinct_technical_completion_without_telegram(tmp_path):
    from clusterctl.onboarding_progress import validate
    value=plan(browser=False)
    value['schema']=ob.CONVERSATION_PLAN_SCHEMA
    class WebBackend(FixtureBackend):
        def observe(self, plan, stage, operation_id):
            result=super().observe(plan,stage,operation_id)
            if result.state=='complete' and stage in {'access', 'acceptance'}:
                result.facts['provider_configured'] = True
            if result.state=='complete' and stage=='acceptance':
                result.facts.update(conversation_verified=True,shared_login_verified=True,
                    native_running_verified=True,tribe_membership_verified=True)
            return result
    backend=WebBackend()
    store=ob.JobStore(tmp_path/'jobs')
    store.submit(value,backend)
    for _ in ob.CONVERSATION_STAGES:
        result=validate(store.tick('eko',backend))
    assert result['schema']==ob.CONVERSATION_JOB_SCHEMA and result['state']=='complete'
    assert result['completed_steps']==list(ob.CONVERSATION_STAGES)
    assert [stage for _,stage,_ in backend.calls]==list(ob.CONVERSATION_STAGES)
    assert 'telegram' not in store._load('eko')['steps']
    assert not ob.JobStore.accepted(value,dict.fromkeys(ob.ACCEPTANCE,True))
    assert store.tick('eko',backend)==result


def test_existing_job_cannot_be_reinterpreted_as_conversation_or_change_old_receipts(tmp_path):
    store,backend=setup(tmp_path)
    advance(store,backend)
    path=store.directory('eko')/'job.json'
    before=path.read_bytes()
    changed=plan()
    changed['schema']=ob.CONVERSATION_PLAN_SCHEMA
    with pytest.raises(ob.OnboardingError,match='onboarding_plan_conflict'):
        store.submit(changed,backend)
    assert path.read_bytes()==before
    assert store.status('eko',owner='sai')['schema']==ob.SCHEMA


def test_conversation_progress_rejects_legacy_stage_or_mixed_prefix():
    from clusterctl.onboarding_progress import validate
    value=plan()
    value['schema']=ob.CONVERSATION_PLAN_SCHEMA
    row={'schema':ob.CONVERSATION_JOB_SCHEMA,'name':'eko','owner':'sai',
        'plan_digest':ob.digest(value),'state':'ready','stage':'identity','reason':None,
        'completed_steps':['environment','context','memory'],'active':False,'updated_ms':1}
    assert validate(row)==row
    for steps,next_stage in [(['environment','context','memory','matrix'],'access'),
                             (['environment','context','memory','identity','access','telegram'],'welcome')]:
        with pytest.raises(ob.OnboardingError):
            validate({**row,'completed_steps':steps,'stage':next_stage})


def test_finite_worker_finishes_only_selected_original_job(tmp_path):
    import time
    from clusterctl.onboarding_worker import Worker
    store, backend = setup(tmp_path)
    peer = plan()
    peer['name'] = 'peer'
    store.submit(peer, backend)
    peer_before = (store.directory('peer')/'job.json').read_bytes()
    worker = Worker(store, lambda: backend,
        plans=lambda: (_ for _ in ()).throw(AssertionError('No unrelated intake')))
    status, result = worker.until('eko', deadline=time.monotonic()+2)
    assert status == 0 and result['state'] == 'complete'
    assert (store.directory('peer')/'job.json').read_bytes() == peer_before
    assert all(name == 'eko' for name, _, _ in backend.calls)


def test_finite_worker_returns_missing_input_without_polling_it(tmp_path):
    import time
    from clusterctl.onboarding_worker import Worker
    store, backend = setup(tmp_path)
    backend.wait = 'context'
    status, result = Worker(store, lambda: backend).until('eko', deadline=time.monotonic()+2)
    assert status == 2 and result['stage'] == 'context'
    assert result['reason'] == 'human_contact_required'
    assert len(backend.calls) == 1


def test_foreground_process_deadline_preserves_retained_intent(tmp_path):
    import sys
    from clusterctl.onboarding_worker import supervise
    marker = tmp_path/'retained-original-intent'
    code = 'from pathlib import Path;import time;Path('+repr(str(marker))+').write_text("same-operation");time.sleep(20)'
    status, result = supervise([sys.executable, '-c', code], seconds=.3)
    assert status == 2 and result['reason'] == 'foreground_deadline_expired'
    assert 'external effects may continue' in result['effect']
    assert marker.read_text() == 'same-operation'
    assert result['elapsed_seconds'] < 4


def test_explicit_time_extension_resumes_original_checkpoints(tmp_path):
    import time
    from clusterctl.onboarding_worker import ForegroundRun, Worker
    store, backend = setup(tmp_path)
    original = store._load('eko')
    control = ForegroundRun(store, 'eko', original['plan_digest'])
    initial = control.prepare(.02)
    backend.wait = 'context'
    status, result = Worker(store, lambda: backend).until('eko', deadline=time.monotonic()+1)
    assert status == 2 and result['completed_steps'] == ['environment']
    environment = store._load('eko')['steps']['environment'].copy()
    # Expiry changes no native job state, facts or effect identity.
    control.update(deadline_epoch=time.time()-1, phase='attention-required')
    same = control.prepare(600)
    assert same['deadline_epoch'] < time.time(), 'Ordinary retry cannot silently add time'
    extended = control.prepare(600, extend=10)
    assert extended['started_epoch'] == initial['started_epoch']
    assert extended['original_deadline_epoch'] == initial['original_deadline_epoch']
    assert extended['added_seconds'] == 10 and extended['extension_count'] == 1
    backend.wait = None
    status, result = Worker(store, lambda: backend).until('eko',
        deadline=lambda: time.monotonic()+control.remaining())
    assert status == 0 and result['state'] == 'complete'
    assert store._load('eko')['steps']['environment'] == environment
    assert sum(stage == 'environment' for _, stage, _ in backend.calls) == 1
    assert all(step['operation_id'] == original['steps'][stage]['operation_id']
               for stage, step in store._load('eko')['steps'].items())


def test_live_extension_changes_deadline_of_same_supervised_process(tmp_path):
    import sys
    import threading
    import time
    from clusterctl.onboarding_worker import ForegroundRun, supervise
    store, _ = setup(tmp_path)
    control = ForegroundRun(store, 'eko', store._load('eko')['plan_digest'])
    control.prepare(.3)
    pid_file = tmp_path/'only-worker'
    code = ('from pathlib import Path;import os,time,json;Path('+repr(str(pid_file))+').write_text(str(os.getpid()));'
            'time.sleep(.6);print(json.dumps({"schema":"cluster-onboarding-foreground/v1","state":"complete"}))')
    def extend():
        time.sleep(.1)
        control.prepare(600, extend=2)
    extension = threading.Thread(target=extend)
    extension.start()
    status, result = supervise([sys.executable, '-c', code], seconds=.3,
        remaining=control.remaining, started_child=control.child_started)
    extension.join(timeout=3)
    assert status == 0 and result['state'] == 'complete'
    assert int(pid_file.read_text()) == control.read()['child']['pid']
    assert control.read()['extension_count'] == 1


def test_time_extension_racing_expiry_keeps_single_continuation_owner(tmp_path):
    import os
    import time
    from clusterctl.onboarding_worker import ForegroundRun
    store, _ = setup(tmp_path)
    control = ForegroundRun(store, 'eko', store._load('eko')['plan_digest'])
    control.prepare(.01)
    lease = control.claim()
    assert lease is not None
    control.update(deadline_epoch=time.time()-1)
    result = {'state': 'attention-required', 'reason': 'foreground_deadline_expired'}
    control.prepare(600, extend=10)
    assert control.finish(result, lease) is False
    assert control.claim() is None, 'The original supervisor still owns continuation'
    control.update(deadline_epoch=time.time()-1)
    assert control.finish(result, lease) is True
    replacement = control.claim()
    assert replacement is not None
    os.close(replacement)
    assert control.read()['extension_count'] == 1


def test_foreground_failure_keeps_exact_operation_and_redacts_private_error(tmp_path):
    import json
    import time
    from clusterctl.onboarding_worker import Worker
    store, backend = setup(tmp_path)
    reason = 'conversation_native_engine_unconfirmed'
    def execute(*args):
        raise ob.OnboardingError(reason)
    backend.execute = execute
    status, result = Worker(store, lambda: backend).until('eko', deadline=time.monotonic()+2)
    assert status == 3 and result['diagnostic']['code'] == reason
    assert result['diagnostic']['operation_id'] == store._load('eko')['steps']['environment']['operation_id']
    reason = 'private-secret /private/source'
    status, result = Worker(store, lambda: backend).until('eko', deadline=time.monotonic()+2)
    assert result['diagnostic']['code'] == 'unclassified_refusal'
    assert 'private-secret' not in json.dumps(result)
