"""The HTTP tier can read redacted progress, never manufacture host receipts."""
import dataclasses
import json
import os
import threading
import time

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import STAGES, JobStore, OnboardingError
from clusterctl.onboarding_progress import Progress
from clusterctl.onboarding_worker import Worker
from tests.test_onboarding import FixtureBackend, plan
from tests.test_being_seed import KEY, http_server


def progress(tmp_path):
    path = tmp_path / "progress"
    path.mkdir(mode=0o750)
    return Progress(path, worker_uid=os.geteuid())


def test_worker_publishes_closed_progress_and_owner_mismatch_is_hidden(tmp_path):
    projection = progress(tmp_path)
    backend = FixtureBackend()
    store = JobStore(tmp_path / "jobs")
    worker = Worker(store, lambda: backend, publish=projection.publish, plans=lambda: [plan()])
    for _ in range(8):
        worker.once()
    value = projection.read("eko", owner="sai")
    assert value["active"] and value["completed_steps"] == list(STAGES)
    with pytest.raises(OnboardingError, match="onboarding_job_not_found"):
        projection.read("eko", owner="ani")
    assert (projection.root / "eko.json").stat().st_mode & 0o777 == 0o640
    assert "plan" not in value and "account_profile" not in json.dumps(value)


def test_untrusted_permissions_and_unknown_private_fields_are_refused(tmp_path):
    projection = progress(tmp_path)
    store = JobStore(tmp_path / "jobs")
    value = store.submit(plan(), FixtureBackend())
    projection.publish(value)
    path = projection.root / "eko.json"
    path.chmod(0o660)
    with pytest.raises(OnboardingError, match="trusted_onboarding_progress_required"):
        projection.read("eko", owner="sai")
    path.chmod(0o640)
    path.write_text(json.dumps({**value, "token": "fixture-private-token"}))
    with pytest.raises(OnboardingError, match="invalid_onboarding_progress"):
        projection.read("eko", owner="sai")


def test_actual_http_progress_never_exposes_another_owner_or_false_completion(tmp_path):
    projection = progress(tmp_path)
    store = JobStore(tmp_path / "jobs")
    backend = FixtureBackend()
    projection.publish(store.submit(plan(), backend))
    state = tmp_path / "intake"
    with http_server(state) as (server, request):
        server.deps = dataclasses.replace(server.deps, onboarding_progress=str(projection.root),
                                          onboarding_worker_uid=os.geteuid(), seed_only=True)
        being_seed.create(state, dict(name="eko", label="Eko", mode="import"), owner="sai", key=KEY)
        assert request("/v1/seeds/eko/onboarding", owner="ani")[0] == 404
        status, _, value = request("/v1/seeds/eko/onboarding", owner="sai")
        assert status == 200 and value["stage"] == "environment" and value["active"] is False
        value["active"] = True
        (projection.root / "eko.json").write_text(json.dumps(value))
        assert request("/v1/seeds/eko/onboarding", owner="sai")[0] == 409
        status, _, listing = request("/v1/seeds", owner="sai")
        assert status == 200 and listing["items"][0]["active"] is False
        assert listing["items"][0]["onboarding"]["state"] == "attention-required"
        assert "plan_digest" not in json.dumps(listing)


def test_service_loop_does_not_starve_a_third_job_or_repeat_a_running_job(tmp_path):
    backend = FixtureBackend()
    store = JobStore(tmp_path / "jobs")
    for name in ("eko", "oliva", "third"):
        store.submit(plan(name=name), backend)
    entered, unblock, third, stop = (threading.Event() for _ in range(4))
    original = backend.execute
    def dispatch(value, stage, operation_id):
        if value["name"] == "eko" and stage == "environment":
            entered.set()
            assert unblock.wait(timeout=4)
        if value["name"] == "third":
            third.set()
        original(value, stage, operation_id)
    backend.execute = dispatch
    worker = Worker(store, lambda: backend, concurrency=2)
    thread = threading.Thread(target=worker.run, args=(stop,), kwargs={"interval": 0.1})
    thread.start()
    try:
        assert entered.wait(timeout=3)
        assert third.wait(timeout=3)
        time.sleep(0.15)
        assert not any(name == "eko" for name, *_ in backend.calls)
    finally:
        stop.set()
        unblock.set()
        thread.join(timeout=4)
    assert not thread.is_alive()
    assert sum(name == "eko" and stage == "environment" for name, stage, _ in backend.calls) == 1
