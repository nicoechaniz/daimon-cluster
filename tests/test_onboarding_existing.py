"""Actual native same-Root enrollment with isolated Root and receiving custody."""

import json
import os
import subprocess
import sys
import time

import pytest

from clusterctl import onboarding_existing, onboarding_peer
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_custody import document
from clusterctl.onboarding_target import Target
from tests.test_onboarding_target import receiving, files


@pytest.fixture
def sealed_signer(tmp_path, monkeypatch):
    import shutil
    from pathlib import Path
    from clusterd import seed_handlers

    source = Path(seed_handlers.__file__).resolve().parents[1]
    captured = tmp_path / "sealed-signer-code"
    (captured / "clusterd").mkdir(parents=True)
    (captured / "clusterctl").mkdir()
    for name in seed_handlers.SIGNER_MODULES:
        path = captured / "clusterctl" / (name + ".py")
        shutil.copyfile(source / "clusterctl" / (name + ".py"), path)
        path.chmod(0o644)
    monkeypatch.setattr(
        seed_handlers, "__file__", str(captured / "clusterd/seed_handlers.py")
    )
    return captured


def existing(tmp_path):
    ceremony, old_plan, original = receiving(tmp_path)
    original.code_uid = os.geteuid()
    request = original.prepare()
    original.activate(ceremony.authorize_target(old_plan, request))
    original.apply_credential(
        ceremony.authorize_credential(old_plan, original.credential_request())
    )
    identity = onboarding_peer.identity(original)
    root = ceremony.root / digest(old_plan)
    plan = {**old_plan, "name": "qualify-additional"}
    route = dict(
        embodiment_id=identity["document"]["origin"]["embodiment_id"],
        endpoint="http://127.0.0.1:19287/dm-peer/v1",
        timeout_ms=5000,
    )
    base = onboarding_existing.base_packet(
        plan,
        identity,
        [route],
        expected_being_ref=identity["document"]["authority"]["manifest"]["being_ref"],
    )
    home = tmp_path / "additional-home"
    home.mkdir(mode=0o700)
    return original, root, Target(home, plan, base)


def enrollment(root, target, tmp_path):
    from daimon_matrix import canonical, keystore, operator_rebirth

    request = target.prepare()
    now = time.time_ns() // 1_000_000
    intent = operator_rebirth.create_distributed_enrollment_intent(
        request,
        target._base(),
        issued_at_ms=now,
        expires_at_ms=now + 3600000,
        nonce=os.urandom(32),
    )
    paths = {
        name: tmp_path / (name + ".json")
        for name in ("authority", "request", "intent", "share")
    }
    for name, value in (
        ("authority", target.genesis["identity"]["document"]["authority"]),
        ("request", request),
        ("intent", intent),
    ):
        keystore._atomic_write(paths[name], canonical.canonical_bytes(value))
    descriptor = os.open(root / "root.unlock", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "daimon_matrix.operator_rebirth",
                "enrollment-share",
                "--authority",
                str(paths["authority"]),
                "--request",
                str(paths["request"]),
                "--intent",
                str(paths["intent"]),
                "--holder",
                str(root / "root"),
                "--password-fd",
                str(descriptor),
                "--output",
                str(paths["share"]),
            ],
            pass_fds=(descriptor,),
            check=True,
            capture_output=True,
        )
    finally:
        os.close(descriptor)
    return operator_rebirth.aggregate_distributed_enrollment(
        intent,
        request,
        target._base(),
        [document(paths["share"])],
        observed_at_ms=time.time_ns() // 1_000_000,
    )


def test_native_existing_root_enrollment_retains_original_members_and_fresh_custody(
    tmp_path,
):
    original, root, target = existing(tmp_path)
    source = files(original.root)
    held = files(root / "root")
    before = target._base()
    activation = enrollment(root, target, tmp_path)
    prepared = files(target.preparation)
    result = target.activate(activation)
    assert result["phase"] == "credential-pending"
    bundle = target.document_bundle()
    assert bundle["schema"] == "dm.runtime.bundle/v8"
    assert bundle["manifest"]["being_ref"] == before.state.being_ref
    assert bundle["manifest"]["revision"] == before.manifest.value["revision"] + 1
    assert all(
        row in bundle["manifest"]["embodiments"]
        for row in before.manifest.value["embodiments"]
    )
    assert (
        len(bundle["manifest"]["embodiments"])
        == len(before.manifest.value["embodiments"]) + 1
    )
    assert bundle["local_origin"] != original.document_bundle()["local_origin"]
    assert (target.package / "runtime/custody.json").read_bytes() != (
        original.package / "runtime/custody.json"
    ).read_bytes()
    assert not list(target.home.rglob("holder.json"))
    assert not list(target.home.rglob("root.unlock"))
    receiving_write = target.package / "runtime/own-later-state"
    receiving_write.write_bytes(b"Preserved receiving write")
    published = files(target.package)
    assert target.activate(activation) == result
    assert files(target.package) == published and files(target.preparation) == prepared
    assert files(original.root) == source and files(root / "root") == held


def test_lost_native_additional_activation_ack_reconciles_without_replacing_keys(
    tmp_path, monkeypatch
):
    from daimon_matrix import operator_rebirth

    original, root, target = existing(tmp_path)
    activation = enrollment(root, target, tmp_path)
    actual = operator_rebirth.activate_target_runtime

    def lost(*args, **kwargs):
        actual(*args, **kwargs)
        raise RuntimeError("lost acknowledgement after native publication")

    monkeypatch.setattr(operator_rebirth, "activate_target_runtime", lost)
    with pytest.raises(RuntimeError):
        target.activate(activation)
    published = files(target.package)
    observed = target.observe()
    assert observed["receipt"]["origin"] == activation["body"]["origin"]
    assert target.activate(activation) == observed
    assert files(target.package) == published
    assert (
        original.document_bundle()["manifest"]["being_ref"]
        == target.document_bundle()["manifest"]["being_ref"]
    )


def test_existing_root_base_rejects_other_identity_routes_and_source_capabilities(
    tmp_path,
):
    _, _, target = existing(tmp_path)
    import copy

    for change in ("root", "route", "capability", "plan", "signature"):
        value = copy.deepcopy(target.genesis)
        if change == "root":
            value["expected_being_ref"] = "dm:being:v1:" + "a" * 43
        elif change == "route":
            value["routes"][0]["embodiment_id"] = "embodiment:unrelated"
        elif change == "capability":
            value["capabilities"] = {"unrelated": "must not enter target"}
        elif change == "plan":
            value["plan_digest"] = "0" * 64
        else:
            value["identity"]["document"]["runtime_id"] += "-forged"
        with pytest.raises(OnboardingError, match="existing_onboarding_base_rejected"):
            Target(target.home, target.plan, value)
    assert not target.root.exists()
    projection = onboarding_existing.public_base_bundle(target.genesis, target.plan)
    assert (
        projection["capabilities"] == []
        and projection["operator_capability_binding"] is None
    )
    assert "private.key" not in json.dumps(target.genesis)


@pytest.mark.parametrize("custody_kind", ["holder", "root-custody"])
def test_owner_handoff_completes_native_v2_and_admission_without_host_root_keys(
    tmp_path,
    sealed_signer,
    custody_kind,
    monkeypatch,
):
    from types import SimpleNamespace
    from clusterctl import onboarding_enrollment as exchange
    from clusterctl.onboarding_local_body import Requests
    from tests.test_onboarding_local_body import request as local_request

    original, holder_root, target = existing(tmp_path)
    signing_path = holder_root / "root"
    if custody_kind == "root-custody":
        # Reproduce the historical offline Root+Recovery layout in a separate
        # owner process. The host and receiving actor never see these seeds.
        signing_path = tmp_path / "offline-root.json"
        public = tmp_path / "public-authority.json"
        from daimon_matrix import canonical, keystore

        keystore._atomic_write(
            public, canonical.canonical_bytes(onboarding_existing.public_base_bundle(target.genesis, target.plan))
        )
        fds = [os.open(holder_root / (role + ".unlock"), os.O_RDONLY | os.O_NOFOLLOW)
               for role in ("root", "recovery")]
        try:
            subprocess.run(
                [sys.executable, "-B", "-c", """
import json, os, sys
from pathlib import Path
from daimon_matrix import keystore, operator_rebirth as native
from daimon_matrix.operator_first_embodiment import _password
authority = native.authority_from_runtime_bundle(json.loads(Path(sys.argv[1]).read_bytes()))
root = Path(sys.argv[2])
root_password = bytes(_password(int(sys.argv[4])))
recovery_password = bytes(_password(int(sys.argv[5])))
seeds = {
    'root.signing.v1:root': native._single_holder_seed(
        root / 'root', authority, lambda: bytearray(root_password),
        allowed_prefixes=('root.signing.v1:',), code='fixture_root'),
    'recovery.signing.v1:recovery': native._single_holder_seed(
        root / 'recovery', authority, lambda: bytearray(recovery_password),
        allowed_prefixes=('recovery.signing.v1:',), code='fixture_recovery'),
}
destination = Path(sys.argv[3])
keystore.EncryptedKeystore.create(destination, lambda: bytearray(root_password),
    control_head=authority.state.head, secrets=seeds)
keystore.EncryptedKeystore.create(destination.with_name('mixed-body.json'),
    lambda: bytearray(root_password), control_head=authority.state.head,
    secrets={**seeds, 'body.signing.v1:forbidden': os.urandom(32)})
""", str(public), str(holder_root), str(signing_path), *map(str, fds)],
                pass_fds=tuple(fds), check=True, capture_output=True,
            )
        finally:
            for fd in fds:
                os.close(fd)
    signing_before = files(signing_path.parent) if signing_path.is_dir() else signing_path.read_bytes()
    state = tmp_path / "portal-state"
    state.mkdir(mode=0o700)
    progress = tmp_path / "progress"
    progress.mkdir(mode=0o750)
    root = tmp_path / "host-custody"
    root.mkdir(mode=0o700)
    host = SimpleNamespace(
        config=SimpleNamespace(
            custody=root,
            consent_state=state,
            consent_uid=os.geteuid(),
            progress=progress,
        ),
        _decision=lambda plan: {"matrix_identity_mode": "existing"},
    )
    ceremony = exchange.ExistingEnrollment(host)
    task = local_request(
        target.plan["name"], target.plan["owner"], target.genesis["expected_being_ref"]
    )
    Requests(progress, worker_uid=os.geteuid()).publish(task)
    assert ceremony.observe(target.plan) == {"waiting": True}
    source = dict(
        schema=exchange.SOURCE,
        request_id=task["request_id"],
        identity=target.genesis["identity"],
        routes=target.genesis["routes"],
    )
    exchange.submit(state, task, None, source)
    ceremony.prepare(target.plan, identity_mode="existing")
    assert ceremony.observe(target.plan)["ready"]

    # Exercise the actual host reconciliation method across both waiting
    # points. Only the Incus transport is replaced by the local receiving actor.
    from dataclasses import replace
    from clusterctl import being_seed
    from clusterctl.onboarding_host import HostBackend
    from tests.test_onboarding_host import configured

    host_fixture = tmp_path / "backend"
    host_fixture.mkdir()
    config, _, incus, _ = configured(host_fixture)
    views = host_fixture / "views"
    views.mkdir(mode=0o700)
    backend = HostBackend(replace(config, views=views), run=incus)
    # This receiving actor runs as the test owner, not an Incus UID-1000
    # account. Qualify real publication for that actor on every CI runner;
    # actual root/guest ownership stays covered by the privileged host tests.
    from clusterctl import onboarding_mounts
    monkeypatch.setattr(onboarding_mounts, "GUEST_UID", os.geteuid())
    monkeypatch.setattr(onboarding_mounts, "GUEST_GID", os.getegid())
    being_seed._write(
        config.grants / (target.plan["name"] + ".json"),
        dict(
            schema="cluster-onboarding-host-grant/v1", plan=target.plan, revoked=False
        ),
    )
    backend.execute(target.plan, "environment", "test")
    public = views / digest(target.plan) / "matrix-public"

    def receiving_call(plan, action):
        if action == "prepare":
            target.prepare()
        elif action == "activate":
            target.activate(document(public / "activation.json"))
        elif action == "credential-prepare":
            proposal = target.credential_request()
            return {**target.observe(), "request": proposal}
        elif action == "credential-apply":
            target.apply_credential(document(public / "credential-response.json"))
        else:
            assert action == "observe"
        return target.observe()

    backend._target_call = receiving_call

    # Exercise the actual downloadable local signer, including its captured
    # imports, rather than accidentally relying on the development checkout.
    import io
    import zipfile
    from clusterd.seed_handlers import local_body_tool

    tool = local_body_tool(None, None, "existing_root_signer.zip")
    assert tool.status == 200
    extracted = tmp_path / "local-signer"
    extracted.mkdir(mode=0o700)
    with zipfile.ZipFile(io.BytesIO(tool.body)) as archive:
        archive.extractall(extracted)
        for info in archive.infolist():
            if not info.is_dir():
                # Python's convenience extractor ignores ZIP Unix modes.
                # Honor the actual captured mode, as the native unzip tool does.
                (extracted / info.filename).chmod((info.external_attr >> 16) & 0o777)

    def answer():
        frame = exchange.Handoffs(progress, worker_uid=os.geteuid()).read(
            target.plan["name"], owner=target.plan["owner"]
        )
        path = progress / (target.plan["name"] + exchange.Handoffs.suffix)
        # Read-model files permit the portal group. Copy bounded public bytes
        # into the local holder's private working directory, never the holder.
        from daimon_matrix import canonical, keystore

        private = tmp_path / (frame["phase"] + "-private-handoff.json")
        keystore._atomic_write(
            private,
            canonical.canonical_bytes(
                document(path)
                if path.stat().st_mode & 0o077 == 0
                else json.loads(path.read_bytes())
            ),
        )
        output = tmp_path / (frame["phase"] + "-reply.json")
        fd = os.open(holder_root / "root.unlock", os.O_RDONLY | os.O_NOFOLLOW)
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "clusterctl.onboarding_enrollment_root",
                    "--handoff",
                    str(private),
                    "--" + custody_kind,
                    str(signing_path),
                    "--password-fd",
                    str(fd),
                    "--output",
                    str(output),
                ],
                pass_fds=(fd,),
                capture_output=True,
                cwd=extracted,
            )
        finally:
            os.close(fd)
        assert result.returncode == 0, result.stderr
        if custody_kind == "root-custody":
            # A mixed runtime/Root store must never substitute for the owner's
            # offline authority, even when it contains a valid Root key.
            bad_output = tmp_path / (frame["phase"] + "-rejected.json")
            fd = os.open(holder_root / "root.unlock", os.O_RDONLY | os.O_NOFOLLOW)
            try:
                refused = subprocess.run(
                    [sys.executable, "-B", "-m", "clusterctl.onboarding_enrollment_root",
                     "--handoff", str(private), "--root-custody",
                     str(signing_path.with_name("mixed-body.json")), "--password-fd",
                     str(fd), "--output", str(bad_output)],
                    pass_fds=(fd,), capture_output=True, cwd=extracted,
                )
            finally:
                os.close(fd)
            assert refused.returncode == 1 and not bad_output.exists()
            assert not refused.stdout and not refused.stderr
        exchange.submit(state, task, frame, document(output))
        assert not ceremony.observe(target.plan)["waiting"]

    old_files, held = files(original.root), files(holder_root / "root")
    assert backend._matrix_execute(target.plan, ceremony) is False
    requested = target.prepare()
    assert ceremony.observe(target.plan)["waiting"]
    answer()
    activation = ceremony.authorize_target(target.plan, requested)
    assert ceremony.authorize_target(target.plan, requested) == activation
    assert backend._matrix_execute(target.plan, ceremony) is False
    assert target.observe()["phase"] == "credential-pending"
    proposed = target.credential_request()
    assert ceremony.authorize_credential(target.plan, proposed) is None
    answer()
    response = ceremony.authorize_credential(target.plan, proposed)
    assert backend._matrix_execute(target.plan, ceremony) is True
    assert target.observe()["phase"] == "v8"
    assert ceremony.authorize_credential(target.plan, proposed) == response
    assert target.apply_credential(response)["phase"] == "v8"
    coordinates = ceremony.admission_coordinates(target.plan)
    assert coordinates["being_ref"] == target.genesis["expected_being_ref"]
    assert coordinates["manifest_hash"] != target._base().manifest.digest
    assert (
        len(target.document_bundle()["authority_history"])
        == len(original.document_bundle()["authority_history"]) + 2
    )
    assert files(original.root) == old_files and files(holder_root / "root") == held
    assert not list(root.rglob("holder.json")) and not list(root.rglob("*.unlock"))
    assert (files(signing_path.parent) if signing_path.is_dir() else signing_path.read_bytes()) == signing_before


def test_existing_enrollment_api_reuses_access_and_rejects_other_owner_and_forged_source(
    tmp_path,
    sealed_signer,
):
    import copy
    import dataclasses
    import hashlib
    import io
    import zipfile
    from clusterctl import onboarding_enrollment as exchange
    from clusterctl.onboarding_local_body import Requests
    from tests.test_onboarding_local_body import request as local_request
    from tests.test_being_seed import http_server

    _, _, target = existing(tmp_path)
    progress = tmp_path / "api-progress"
    progress.mkdir(mode=0o750)
    task = local_request(
        target.plan["name"], "ani", target.genesis["expected_being_ref"]
    )
    Requests(progress, worker_uid=os.geteuid()).publish(task)
    source = dict(
        schema=exchange.SOURCE,
        request_id=task["request_id"],
        identity=target.genesis["identity"],
        routes=target.genesis["routes"],
    )
    with http_server(tmp_path / "api-state") as (server, http):
        server.deps = dataclasses.replace(
            server.deps,
            seed_only=True,
            onboarding_progress=str(progress),
            onboarding_worker_uid=os.geteuid(),
        )
        endpoint = "/v1/onboarding/local-body/" + target.plan["name"] + "/enrollment"
        code, headers, status = http(endpoint)
        assert code == 200 and headers["Cache-Control"] == "no-store"
        assert status["handoff"] is None and not status["source_received"]
        assert http(endpoint, owner="sai")[0] == 404
        assert http(endpoint, owner="reader")[0] == 403
        assert http(endpoint, extra={"Authorization": ""})[0] == 401
        assert http(endpoint, "POST", source, owner="sai")[0] == 404
        forged = copy.deepcopy(source)
        forged["identity"]["document"]["runtime_id"] += "-forged"
        assert http(endpoint, "POST", forged)[0] == 400
        assert http(endpoint, "POST", {**source, "custody": "unrelated"})[0] == 400
        assert http(endpoint, "POST", source)[2] == {
            "stored": True,
            "host_verified": False,
        }
        assert http(endpoint, "POST", source)[0] == 200
        assert http(endpoint)[2]["source_received"]
        assert (
            http(
                endpoint,
                "POST",
                {
                    "schema": exchange.REPLY,
                    "request_digest": "0" * 64,
                    "response": {"shares": []},
                },
            )[0]
            == 400
        )
        assert not list((tmp_path / "api-state").rglob("custody.json"))
        assert "existing-enrollment-panel" in http("/v1/onboarding")[2]
        assert (
            "existing_enrollment" in http("/v1/onboarding?format=json")[2]["requests"]
        )

        code, headers, raw = http(
            "/v1/onboarding/local-body/tools/existing_root_signer.zip"
        )
        assert (
            code == 200
            and hashlib.sha256(raw).hexdigest() == headers["X-Content-SHA256"]
        )
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            assert "clusterctl/onboarding_enrollment_root.py" in archive.namelist()
            assert not any(
                "custody.json" in name or name.endswith(".unlock")
                for name in archive.namelist()
            )


def test_expired_request_renews_same_keys_and_recovers_partial_publication(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from clusterctl import onboarding_enrollment as exchange, onboarding_target
    from clusterctl.onboarding_local_body import Requests
    from tests.test_onboarding_local_body import request as local_request
    from daimon_matrix import keystore, operator_rebirth

    original, holder, target = existing(tmp_path)
    state, progress, custody = (tmp_path / name for name in ("intake", "progress", "custody-existing"))
    for directory in (state, progress, custody):
        directory.mkdir(mode=0o700)
    host = SimpleNamespace(config=SimpleNamespace(custody=custody, consent_state=state,
        consent_uid=os.geteuid(), progress=progress),
        _decision=lambda plan: {"matrix_identity_mode": "existing"})
    ceremony = exchange.ExistingEnrollment(host)
    task = local_request(target.plan["name"], target.plan["owner"], target.genesis["expected_being_ref"])
    Requests(progress, worker_uid=os.geteuid()).publish(task)
    exchange.submit(state, task, None, dict(schema=exchange.SOURCE, request_id=task["request_id"],
        identity=target.genesis["identity"], routes=target.genesis["routes"]))
    ceremony.prepare(target.plan, identity_mode="existing")
    before = target.prepare()
    assert ceremony.authorize_target(target.plan, before) is None
    first = exchange.Handoffs(progress, worker_uid=os.geteuid()).read(target.plan["name"], owner=target.plan["owner"])
    private_keys = {name: raw for name, raw in files(target.preparation).items()
                    if name not in {"request.json", "preparation.json"}}
    source_before, holder_before = files(original.root), files(holder)
    future = max(before["body"]["expires_at_ms"], first["payload"]["intent"]["body"]["expires_at_ms"]) + 1
    clock = SimpleNamespace(time_ns=lambda: future * 1_000_000)
    monkeypatch.setattr(exchange, "time", clock)
    monkeypatch.setattr(onboarding_target, "time", clock)
    assert not ceremony.observe(target.plan)["waiting"]
    actual = keystore._atomic_write

    def interrupted(path, raw):
        if path == target.preparation / "request.json":
            raise RuntimeError("lost acknowledgement during renewed publication")
        return actual(path, raw)

    monkeypatch.setattr(keystore, "_atomic_write", interrupted)
    with pytest.raises(RuntimeError, match="lost acknowledgement"):
        target.prepare()
    monkeypatch.setattr(keystore, "_atomic_write", actual)
    # The worker observes before executing; observation must reconcile the
    # transaction rather than strand a partially published native request.
    renewed = target.observe()["request"]
    assert target.prepare() == renewed
    assert renewed["body"]["origin"] == before["body"]["origin"]
    assert renewed["body"]["credential"] == before["body"]["credential"]
    assert renewed["request_id"] != before["request_id"]
    operator_rebirth.validate_enrollment_request(renewed, target._base(), observed_at_ms=future)
    assert ceremony.authorize_target(target.plan, renewed) is None
    second = exchange.Handoffs(progress, worker_uid=os.geteuid()).read(target.plan["name"], owner=target.plan["owner"])
    assert second["request_digest"] != first["request_digest"]
    assert second["payload"]["target_request"] == renewed
    assert ceremony.authorize_target(target.plan, renewed) is None
    assert len(list((ceremony.root / digest(target.plan)).glob("*.expired-request.json"))) == 1
    assert len(list((ceremony.root / digest(target.plan)).glob("*.expired-intent.json"))) == 1
    assert {name: raw for name, raw in files(target.preparation).items()
            if name not in {"request.json", "preparation.json"}} == private_keys
    assert files(original.root) == source_before and files(holder) == holder_before
