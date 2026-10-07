"""Same-portal decisions are scoped to the pair and exact host proposal."""
import dataclasses
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from clusterctl import being_seed, onboarding_consent
from clusterctl.onboarding import JobStore, Observation, OnboardingError
from clusterctl.onboarding_host import HostBackend
from clusterctl.onboarding_worker import Worker
from tests.test_being_seed import KEY, http_server
from tests.test_onboarding import plan
from tests.test_onboarding_host import configured


def proposal(tmp_path, state):
    being_seed.create(state, dict(name="eko", label="Eko", mode="import"), owner="sai", key=KEY)
    state.chmod(0o700)
    root = tmp_path / "progress"
    root.mkdir(mode=0o750)
    reviews = onboarding_consent.Reviews(root, worker_uid=os.geteuid())
    value = onboarding_consent.review(plan(), "Source principles, attributed separately from Eko's own SOUL.\n")
    reviews.publish(value)
    decision = dict(review_digest=value["review_digest"], inheritance_approved=True, matrix_identity_mode="existing")
    return reviews, value, decision


def test_real_http_owner_scope_retry_conflict_and_changed_plan(tmp_path):
    state = tmp_path / "state"
    with http_server(state) as (server, request):
        reviews, value, decision = proposal(tmp_path, state)
        server.deps = dataclasses.replace(server.deps, seed_only=True,
            onboarding_progress=str(reviews.root), onboarding_worker_uid=os.geteuid())
        endpoint = "/v1/seeds/eko/onboarding/review"
        assert request(endpoint, owner="ani")[0] == 404
        assert request(endpoint, "POST", decision, owner="ani")[0] == 404
        assert request(endpoint, owner="reader")[0] == 403
        status, headers, fetched = request(endpoint, owner="sai")
        assert status == 200 and headers["Cache-Control"] == "no-store"
        assert fetched == dict(review=value, recorded=False, matrix_identity_mode=None)
        assert request(endpoint, "POST", {**decision, "inheritance_approved": False}, owner="sai")[0] == 409
        assert request(endpoint, "POST", {**decision, "command": "fixture private value"}, owner="sai")[0] == 409
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: request(endpoint, "POST", decision, owner="sai"), range(2)))
        assert all(response[0] in {200, 409} for response in responses)
        assert request(endpoint, "POST", decision, owner="sai")[2]["recorded"] is True
        assert request(endpoint, "POST", {**decision, "matrix_identity_mode": "first"}, owner="sai")[0] == 409
        assert request(endpoint, owner="sai")[2]["recorded"] is True
        # A different host plan has a different review; old consent never follows it.
        reviews.publish(onboarding_consent.review(plan(browser=False), value["source_text"]))
        assert request(endpoint, owner="sai")[2]["recorded"] is False
        assert request(endpoint, "POST", decision, owner="sai")[0] == 409
        assert request("/v1/seeds/eko/onboarding", owner="sai")[2]["active"] is False


def test_decision_cannot_publish_review_issue_host_grant_or_change_owner(tmp_path):
    state = tmp_path / "state"
    reviews, value, decision = proposal(tmp_path, state)
    with pytest.raises(being_seed.SeedError, match="seed_not_found"):
        onboarding_consent.submit(state, "eko", decision, owner="*", reviews=reviews)
    onboarding_consent.submit(state, "eko", decision, owner="sai", reviews=reviews)
    path = state / "being-seeds/eko" / ("consent-" + value["review_digest"] + ".json")
    before = path.read_bytes()
    assert onboarding_consent.read(state, value, intake_uid=os.geteuid())["matrix_identity_mode"] == "existing"
    data = json.loads(before)
    path.write_text(json.dumps({**data, "owner": "ani"}))
    with pytest.raises(OnboardingError, match="invalid_onboarding_consent"):
        onboarding_consent.read(state, value, intake_uid=os.geteuid())
    path.write_bytes(before)
    path.chmod(0o640)
    with pytest.raises(OnboardingError, match="private_onboarding_consent_required"):
        onboarding_consent.read(state, value, intake_uid=os.geteuid())
    path.chmod(0o600)
    os.link(path, path.with_name("linked"))
    with pytest.raises(OnboardingError, match="private_onboarding_consent_required"):
        onboarding_consent.read(state, value, intake_uid=os.geteuid())
    assert not list(state.rglob("*grant*"))


def test_worker_waits_before_inheritance_then_resumes_after_portal_decision(tmp_path, monkeypatch):
    config, value, incus, _ = configured(tmp_path)
    state = tmp_path / "state"
    reviews, _, decision = proposal(tmp_path, state)
    code = tmp_path / "code"
    code.mkdir(mode=0o700)
    (code / "inheritance.md").write_text("The exact qualified Source context.\n")
    config = dataclasses.replace(config, progress=reviews.root, code=code,
        consent_state=state, consent_uid=os.geteuid(), inputs=tmp_path / "inputs", views=tmp_path / "views")
    monkeypatch.setattr("clusterctl.onboarding_release.verify", lambda *a, **kw: None)
    backend = HostBackend(config, run=incus)
    completed = set()
    monkeypatch.setattr(backend, "_guest_observe", lambda p, stage: Observation("complete",
        dict(verified=True, context_verified=True)) if stage in completed else Observation("absent", safe_to_execute=True))
    monkeypatch.setattr(backend, "_guest_execute", lambda p, stage: completed.add(stage))
    worker = Worker(JobStore(config.jobs), lambda: backend, plans=config.approved_plans)
    worker.once()
    result = worker.once()[0]
    assert result["stage"] == "context" and result["reason"] == "identity_authorization_required"
    assert not completed
    with pytest.raises(OnboardingError, match="identity_authorization_required"):
        backend.execute(value, "context", "unused")
    # The worker's qualified Source context supersedes any earlier proposal.
    current = reviews.read("eko", owner="sai")
    decision["review_digest"] = current["review_digest"]
    onboarding_consent.submit(state, "eko", decision, owner="sai", reviews=reviews)
    # New objects simulate service restart; no active model conversation is involved.
    result = Worker(JobStore(config.jobs), lambda: backend).once()[0]
    assert result["completed_steps"] == ["environment", "context"]
    assert len(incus.calls) == 4 and completed == {"context"}
    being_seed._write(config.grants / "eko.json", dict(schema="cluster-onboarding-host-grant/v1", plan=value, revoked=True))
    assert backend.observe(value, "matrix", "unused").reason == "host_authorization_required"


def test_live_context_cannot_bypass_missing_consent_configuration(tmp_path):
    _, value, incus, backend = configured(tmp_path)
    assert backend.observe(value, "context", "unused").reason == "identity_authorization_required"
    with pytest.raises(OnboardingError, match="identity_authorization_required"):
        backend.execute(value, "context", "unused")
    assert incus.calls == []


def test_disposable_exception_requires_host_flag_and_cannot_enroll(tmp_path):
    config, _, incus, backend = configured(tmp_path)
    value = plan(name="qualify-context")
    assert not backend._consented(value, stage="context")
    backend = HostBackend(dataclasses.replace(config, qualification=True), run=incus)
    assert backend._consented(value, stage="context")
    assert not backend._consented(plan(), stage="context")
    assert not backend._consented(value, stage="matrix")
    assert incus.calls == []


def test_cli_uses_the_same_review_and_consent_store(tmp_path, capsys):
    from clusterctl.cli import run

    state = tmp_path / "state"
    reviews, value, decision = proposal(tmp_path, state)
    common = ["--config", "configs/clusterctl.yaml", "--state-dir", str(state), "seed", "--owner", "sai"]
    args = ["eko", "--reviews", str(reviews.root), "--worker-uid", str(os.geteuid())]
    assert run(common + ["review", *args]) == 0
    assert json.loads(capsys.readouterr().out)["review"] == value
    path = tmp_path / "decision.json"
    being_seed._write(path, decision)
    assert run(common + ["consent", *args, "--file", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["recorded"] is True
    assert onboarding_consent.read(state, value, intake_uid=os.geteuid()) is not None
