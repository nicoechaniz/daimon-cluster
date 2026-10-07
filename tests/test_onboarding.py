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
