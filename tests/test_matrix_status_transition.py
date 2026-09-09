"""Synthetic unit-development only; real Matrix APIs, never installed qualification.

DM_LEGACY_SOURCE must name the digest-verified 915c56c src tree. No network,
metadata overrides, live constructors, or automatic fixture downloads.
"""
import hashlib
import importlib
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest
from daimon_matrix import operator_runtime_upgrade as upgrade
from daimon_matrix.canonical import canonical_bytes

PASSWORD = b"synthetic-status-transition-password"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def journey(tmp_path):
    legacy = Path(os.environ["DM_LEGACY_SOURCE"])
    assert upgrade._inventory(upgrade._snapshot(legacy, private=False)) == upgrade.LEGACY_SOURCE_SHA256
    script = '''
import os, sys, json, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from daimon_matrix.operator_bootstrap import _create
from daimon_matrix.runtime import load_runtime
os.umask(0o077)
p = Path(sys.argv[2])
profile = p / "profile.json"
profile.write_text(json.dumps(dict(schema="dm.operator.bootstrap-profile/v1", embodiments=[dict(label=x, body_ref="body:synthetic-"+x, principal_id="synthetic-"+x, listen_host="127.0.0.1", listen_port=47001+i, advertised_endpoint=f"http://127.0.0.1:{47001+i}/dm-peer/v1") for i,x in enumerate(("alpha","beta"))])))
def fd(secret=b"synthetic-status-transition-password"):
    r,w=os.pipe(); os.write(w,secret); os.close(w); return r
_create(p/"ceremony", profile, fd(b"synthetic-root-password"), [f"alpha={fd()}", f"beta={fd(b'synthetic-beta-password')}"])
r=p/"ceremony/runtimes/alpha"
load_runtime(r,"runtime.json",lambda:bytearray(b"synthetic-status-transition-password"),clock=lambda:time.time_ns()//1000000)
(r/".daimon-matrixd.lock").touch(mode=0o600)
'''
    subprocess.run([sys.executable, "-I", "-B", "-c", script, str(legacy), str(tmp_path)], check=True, capture_output=True)
    import json
    runtime = tmp_path / "ceremony/runtimes/alpha"
    bundle = json.loads((runtime / "runtime.json").read_bytes())
    # Preserve native bootstrap output, never reconstruct/relabel client bytes.
    native_pair = tmp_path / "ceremony/host-clients/alpha"
    legacy_client_load(legacy, native_pair)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    from clusterctl.matrix_host import matrix_client_root
    target = matrix_client_root(state, bundle["local_origin"]["embodiment_id"])
    target.parent.mkdir(mode=0o700)
    upgrade._copy(upgrade._snapshot(native_pair), target)
    old = upgrade.inventory_digest(target)
    transaction = runtime.parent / "upgrade"
    upgrade.stage(source=runtime, transaction=transaction, legacy_source=legacy, legacy_sha256=upgrade.LEGACY_SOURCE_SHA256, expected_source_sha256=upgrade.inventory_digest(runtime), expected_counter=bundle["keystore"]["counter"], expected_control_head=bundle["control_head"], expected_being_ref=bundle["manifest"]["being_ref"], expected_origin=bundle["local_origin"], password=PASSWORD, expires_at_ms=time.time_ns()//1000000+3600000, externally_quiesced=True)
    forward_pin = sha((transaction / "ready.json").read_bytes())
    upgrade.publish(source=runtime, transaction=transaction, expected_receipt_sha256=forward_pin, password=PASSWORD, externally_quiesced=True)
    return dict(runtime=runtime, upgrade_transaction=transaction, transaction=target.parent / "transition", target=target, expected_target_sha256=old, expected_upgrade_sha256=sha((transaction / "published.json").read_bytes()), expected_origin=bundle["local_origin"], expected_being_ref=bundle["manifest"]["being_ref"], externally_quiesced=True)


def legacy_client_load(legacy, target):
    """Use the complete pinned loader in an isolated process, not our schema model."""
    assert upgrade._inventory(upgrade._snapshot(legacy, private=False)) == upgrade.LEGACY_SOURCE_SHA256
    script = '''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from daimon_matrix.client import ClientConfig
p = Path(sys.argv[2])
config = ClientConfig.load(p / "client.json", (p / "capability.key").read_bytes())
assert config.expected_server
'''
    return subprocess.run([sys.executable, "-I", "-B", "-c", script, str(legacy), str(target)], check=True, capture_output=True)


def test_native_legacy_v1_stages_without_rewriting_bytes(journey):
    import json
    original = upgrade._snapshot(journey["target"])
    assert json.loads(original["client.json"])["schema"] == "dm.local.client-config/v1"
    legacy_client_load(Path(os.environ["DM_LEGACY_SOURCE"]), journey["target"])
    result = module().stage(**journey)
    assert result["state"] == "stopped-staged"
    assert upgrade._snapshot(journey["target"]) == original
    assert upgrade._snapshot(journey["transaction"] / "checkpoint") == original


@pytest.mark.parametrize("case", ["v2-missing-history", "v2-empty-history", "v2-nonempty-history", "unknown-field", "origin", "key", "methods", "expired", "future", "revoked"])
def test_legacy_closed_contract_refuses_without_staging(journey, case):
    import json
    from daimon_matrix.local_api import create_capability
    target = journey["target"]
    config = json.loads((target / "client.json").read_bytes())
    if case.startswith("v2-"):
        config["schema"] = "dm.local.client-config/v2"
        if case != "v2-missing-history":
            config["historical_servers"] = []
        if case == "v2-nonempty-history":
            old = dict(config["expected_server"], incarnation_id="incarnation:synthetic-retired")
            config["historical_servers"] = [dict(server=old, retired_at_ms=1)]
    elif case == "unknown-field":
        config["unknown"] = True
    elif case == "origin":
        config["expected_server"]["principal_id"] = "synthetic-wrong"
    elif case == "key":
        (target / "capability.key").write_bytes(os.urandom(32))
    else:
        descriptor = config["capability"]
        before, after = descriptor["not_before_ms"], descriptor["not_after_ms"]
        now = time.time_ns() // 1_000_000
        if case == "expired":
            before, after = now - 10000, now - 1
        elif case == "future":
            before, after = now + 100000, now + 200000
        config["capability"] = create_capability(
            (target / "capability.key").read_bytes(), client_id=descriptor["client_id"],
            methods=["runtime.status"] if case == "methods" else descriptor["methods"],
            not_before_ms=before, not_after_ms=after,
            status="revoked" if case == "revoked" else "active").descriptor
    rewrite(target / "client.json", config)
    legacy = Path(os.environ["DM_LEGACY_SOURCE"])
    if case == "v2-missing-history":
        # This was the invalid draft fixture. The real loader rejects it too.
        with pytest.raises(subprocess.CalledProcessError) as rejected:
            legacy_client_load(legacy, target)
        assert b"invalid_client_config" in rejected.value.stderr
    elif case in ("v2-empty-history", "v2-nonempty-history"):
        # Valid for legacy Matrix, deliberately unsupported by this bounded helper.
        legacy_client_load(legacy, target)
    journey["expected_target_sha256"] = upgrade.inventory_digest(target)
    runtime_before = upgrade.inventory_digest(journey["runtime"])
    with pytest.raises(module().TransitionError):
        module().stage(**journey)
    assert not journey["transaction"].exists()
    assert upgrade.inventory_digest(target) == journey["expected_target_sha256"]
    assert upgrade.inventory_digest(journey["runtime"]) == runtime_before


def legacy_status_calls(legacy, runtime, target):
    """Actual pinned client/socket/dispatch after reverse; synthetic state only."""
    assert upgrade._inventory(upgrade._snapshot(legacy, private=False)) == upgrade.LEGACY_SOURCE_SHA256
    script = '''
import os, sys, socket, tempfile, threading, time, uuid
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from daimon_matrix.client import ClientConfig, LocalClient
from daimon_matrix.daemon import _bind_private_socket, serve_connection
from daimon_matrix.runtime import load_runtime
os.umask(0o077)
r, p = Path(sys.argv[2]), Path(sys.argv[3])
config = ClientConfig.load(p / "client.json", (p / "capability.key").read_bytes())
methods = {"runtime.status", "scope.me", "scope.we", "scope.we.diff", "scope.we.sync-plan"}
assert set(config.capability.methods) == methods
runtime = load_runtime(r, "runtime.json", lambda: bytearray(b"synthetic-status-transition-password"), clock=lambda: time.time_ns() // 1000000)
with tempfile.TemporaryDirectory(prefix="dm-v1-socket-") as directory:
    path = Path(directory) / "status.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        _bind_private_socket(listener, path)
        listener.listen(1)
        listener.settimeout(10)
        client = LocalClient(path, config)
        for method in sorted(methods):
            errors = []
            def serve():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        serve_connection(runtime, connection)
                except Exception as error:
                    errors.append(error)
            worker = threading.Thread(target=serve)
            worker.start()
            try:
                params = {"limit": 1, "request_id": str(uuid.uuid4())} if method == "scope.we.sync-plan" else {}
                _, response = client.invoke(method, params)
                assert response["ok"] is True, (method, response["error"])
                assert response["server"] == config.expected_server
                print(method + " ok", flush=True)
            finally:
                worker.join(timeout=15)
                assert not worker.is_alive()
            assert not errors, errors
'''
    completed = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(legacy), str(runtime), str(target)], check=True, capture_output=True, timeout=90)
    assert completed.stdout.decode().splitlines() == [method + " ok" for method in sorted(("runtime.status", "scope.me", "scope.we", "scope.we.diff", "scope.we.sync-plan"))]


def module():
    try:
        return importlib.import_module("clusterctl.matrix_status_transition")
    except ModuleNotFoundError:
        pytest.fail("missing owner-local status transition implementation")


def rewrite(path, value):
    path.write_bytes(canonical_bytes(value))


def repin_runtime(journey):
    import json
    txn = journey["upgrade_transaction"]
    ready = json.loads((txn / "ready.json").read_bytes())
    ready["successor_sha256"] = upgrade.inventory_digest(journey["runtime"])
    rewrite(txn / "ready.json", ready)
    published = json.loads((txn / "published.json").read_bytes())
    published["successor_sha256"] = ready["successor_sha256"]
    published["ready_sha256"] = sha((txn / "ready.json").read_bytes())
    rewrite(txn / "published.json", published)
    journey["expected_upgrade_sha256"] = sha((txn / "published.json").read_bytes())


@pytest.mark.parametrize("case", ["origin", "methods", "key", "runtime_id", "label", "signature"])
def test_stage_independently_rejects_invalid_authority_even_when_inventory_repinned(journey, case):
    import json
    from daimon_matrix.local_api import create_capability
    m = module()
    source = journey["runtime"] / "host-clients/status"
    config = json.loads((source / "client.json").read_bytes())
    if case == "origin":
        config["expected_server"]["principal_id"] = "synthetic-wrong"
    elif case == "methods":
        cap = create_capability((source / "capability.key").read_bytes(), client_id=config["capability"]["client_id"], methods=["runtime.status"], not_before_ms=config["capability"]["not_before_ms"], not_after_ms=config["capability"]["not_after_ms"])
        config["capability"] = cap.descriptor
    elif case == "key":
        (source / "capability.key").write_bytes(os.urandom(32))
    elif case == "runtime_id":
        config["runtime_id"] = "dm:runtime:v1:" + "A" * 43
    elif case == "label":
        config["runtime_label"] = "other"
    else:
        bundle = json.loads((journey["runtime"] / "runtime.json").read_bytes())
        bundle["operator_capability_binding"]["signature"]["value"] = "A" * 86
        rewrite(journey["runtime"] / "runtime.json", bundle)
    rewrite(source / "client.json", config)
    repin_runtime(journey)
    with pytest.raises(ValueError):
        m.stage(**journey)
    assert not journey["transaction"].exists()
    assert upgrade.inventory_digest(journey["target"]) == journey["expected_target_sha256"]


@pytest.mark.parametrize("case", ["target-name", "transaction-parent", "changed-runtime-during-validation", "changed-target-during-validation", "concurrent-owner"])
def test_stage_path_and_cas_guards(journey, case, monkeypatch):
    m = module()
    if case == "target-name":
        old = journey["target"]
        journey["target"] = old.with_name("wrong-target")
        old.rename(journey["target"])
    elif case == "transaction-parent":
        journey["transaction"] = journey["runtime"].parent / "misplaced"
    elif case == "concurrent-owner":
        import fcntl
        lock = os.open(journey["target"].parent, os.O_RDONLY | os.O_DIRECTORY)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    else:
        original = m._validate_pair
        changed = False
        def change(*args, **kwargs):
            nonlocal changed
            original(*args, **kwargs)
            if not changed:
                changed = True
                root = journey["runtime"] if case == "changed-runtime-during-validation" else journey["target"]
                upgrade._write(root / "unexpected", b"changed")
        monkeypatch.setattr(m, "_validate_pair", change)
    try:
        with pytest.raises((ValueError, OSError)):
            m.stage(**journey)
        assert not (journey["transaction"] / "ready.json").exists()
    finally:
        if case == "concurrent-owner":
            os.close(lock)


def test_stage_exact_retry(journey):
    m = module()
    ready = m.stage(**journey)
    assert m.stage(**journey) == ready


@pytest.mark.parametrize("case", ["runtime", "candidate", "target", "receipt", "lock"])
def test_publish_final_cas_after_validation(journey, case, monkeypatch):
    m = module()
    m.stage(**journey)
    args = publication_args(journey)
    original = m._validate_pair
    changed = False
    lock = None
    if case == "lock":
        import fcntl
        lock = os.open(journey["target"].parent, os.O_RDONLY | os.O_DIRECTORY)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    else:
        def change(*a, **kw):
            nonlocal changed
            original(*a, **kw)
            if not changed:
                changed = True
                if case == "receipt":
                    (journey["transaction"] / "ready.json").write_bytes(b"{}")
                else:
                    root = journey[case] if case != "candidate" else journey["transaction"] / "candidate"
                    upgrade._write(root / "changed", b"CAS conflict")
        monkeypatch.setattr(m, "_validate_pair", change)
    try:
        with pytest.raises((ValueError, OSError)):
            m.publish(**args)
        assert upgrade.inventory_digest(journey["transaction"] / "checkpoint") == journey["expected_target_sha256"]
        assert not (journey["transaction"] / "published.json").exists()
        # A pre-exchange conflict must not publish the new pair.
        assert (journey["target"] / "client.json").read_bytes() == (journey["transaction"] / "checkpoint/client.json").read_bytes()
    finally:
        if lock is not None:
            os.close(lock)


@pytest.mark.parametrize("case", ["state", "counter", "checkpoint", "extra"])
def test_stage_rejects_re_pinned_nonpublication(journey, case):
    import json
    m = module()
    txn = journey["upgrade_transaction"]
    pub = json.loads((txn / "published.json").read_bytes())
    if case == "state":
        pub["state"] = "staged"
    elif case == "counter":
        pub["counter_after"] += 1
    elif case == "extra":
        pub["extra"] = True
    else:
        upgrade._write(txn / "checkpoint/changed", b"not the checkpoint")
    rewrite(txn / "published.json", pub)
    journey["expected_upgrade_sha256"] = sha((txn / "published.json").read_bytes())
    with pytest.raises(ValueError):
        m.stage(**journey)
    assert not journey["transaction"].exists()


@pytest.mark.parametrize("boundary", ["exchange-return", "exchange-fsync", "receipt-write"])
def test_interrupted_publish_exact_retry(journey, boundary, monkeypatch):
    m = module()
    ready = m.stage(**journey)
    args = publication_args(journey)
    before = upgrade.inventory_digest(journey["runtime"])
    with monkeypatch.context() as fault:
        if boundary == "exchange-return":
            original = upgrade._exchange
            def exchange(a, b):
                original(a, b)
                raise OSError("synthetic lost return")
            fault.setattr(upgrade, "_exchange", exchange)
        elif boundary == "exchange-fsync":
            original = os.fsync
            def sync(fd):
                original(fd)
                raise OSError("synthetic fsync interruption")
            fault.setattr(os, "fsync", sync)
        else:
            original = upgrade._write
            def write(path, raw):
                if "published" in path.name:
                    original(path, raw[:10])
                    raise OSError("synthetic short receipt")
                original(path, raw)
            fault.setattr(upgrade, "_write", write)
        with pytest.raises(OSError):
            m.publish(**args)
    result = m.publish(**args)
    assert result["state"] == "stopped-published"
    assert m.publish(**args) == result
    assert upgrade.inventory_digest(journey["target"]) == ready["new_sha256"]
    assert upgrade.inventory_digest(journey["transaction"] / "checkpoint") == ready["old_sha256"]
    assert upgrade.inventory_digest(journey["runtime"]) == before


def rollback_runtime(journey):
    txn = journey["upgrade_transaction"]
    args = dict(source=journey["runtime"], transaction=txn, expected_receipt_sha256=sha((txn / "ready.json").read_bytes()), password=PASSWORD, externally_quiesced=True)
    upgrade.stage_rollback(**args)
    args["expected_receipt_sha256"] = sha((txn / "rollback-ready.json").read_bytes())
    upgrade.publish_rollback(**args)
    return sha((txn / "rolled-back.json").read_bytes())


def test_reverse_requires_real_monotonic_runtime_rollback(journey):
    m = module()
    ready = m.stage(**journey)
    m.publish(**publication_args(journey))
    assert hasattr(m, "rollback"), "missing independently verified reverse transition"
    before = upgrade.inventory_digest(journey["target"])
    with pytest.raises((ValueError, KeyError, OSError)):
        m.rollback(**publication_args(journey), expected_rollback_sha256="0" * 64, password=PASSWORD)
    assert upgrade.inventory_digest(journey["target"]) == before
    rollback_pin = rollback_runtime(journey)
    runtime_before = upgrade.inventory_digest(journey["runtime"])
    result = m.rollback(**publication_args(journey), expected_rollback_sha256=rollback_pin, password=PASSWORD)
    assert result["state"] == "stopped-rolled-back"
    assert upgrade.inventory_digest(journey["target"]) == ready["old_sha256"]
    assert upgrade.inventory_digest(journey["transaction"] / "checkpoint") == ready["old_sha256"]
    assert upgrade.inventory_digest(journey["runtime"]) == runtime_before
    assert m.rollback(**publication_args(journey), expected_rollback_sha256=rollback_pin, password=PASSWORD) == result
    # Never acknowledge the forward sidecar against a reverse runtime.
    with pytest.raises(ValueError):
        m.publish(**publication_args(journey))
    # Exact-byte evidence and replay are established BEFORE any status effect.
    original = upgrade._snapshot(journey["transaction"] / "checkpoint")
    assert upgrade._snapshot(journey["target"]) == original
    legacy = Path(os.environ["DM_LEGACY_SOURCE"])
    legacy_client_load(legacy, journey["target"])
    legacy_status_calls(legacy, journey["runtime"], journey["target"])
    assert upgrade._snapshot(journey["target"]) == original
    assert upgrade._snapshot(journey["transaction"] / "checkpoint") == original
    # Reads record ledger effects: do not turn this into post-effect downgrade proof.
    after_calls = upgrade.inventory_digest(journey["runtime"])
    assert after_calls != runtime_before
    with pytest.raises(ValueError):
        m.rollback(**publication_args(journey), expected_rollback_sha256=rollback_pin, password=PASSWORD)
    assert upgrade.inventory_digest(journey["runtime"]) == after_calls
    assert upgrade._snapshot(journey["target"]) == original


def test_owner_cli_digest_bound_request_and_bounded_failure(journey, capsys):
    m = module()
    assert hasattr(m, "main"), "missing owner-local CLI"
    request = dict(journey)
    del request["externally_quiesced"]
    request = {k: str(v) if isinstance(v, Path) else v for k, v in request.items()}
    path = journey["transaction"].parent / "request.json"
    upgrade._write(path, canonical_bytes(request))
    args = ["stage", "--request", str(path), "--request-sha256", sha(path.read_bytes()), "--externally-quiesced"]
    assert m.main(args) == 0
    assert "stopped-staged" in capsys.readouterr().out
    args = ["publish", "--transaction", str(journey["transaction"]), "--ready-sha256", publication_args(journey)["expected_receipt_sha256"], "--externally-quiesced"]
    assert m.main(args) == 0
    assert "stopped-published" in capsys.readouterr().out
    args[4] = "invalid-pin"
    assert m.main(args) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "status_transition_rejected; keep ALL consumers externally fenced; retain evidence\n"
    assert (journey["target"] / "capability.key").read_bytes().hex() not in output.err


@pytest.mark.parametrize("operation", ["stage", "publish"])
def test_replaced_sidecar_parent_is_not_a_cas_match(journey, operation, monkeypatch):
    import shutil
    m = module()
    if operation == "publish":
        m.stage(**journey)
        args = publication_args(journey)
    else:
        args = journey
    parent = journey["target"].parent
    original = m._validate_pair
    changed = False
    def replace(*a, **kw):
        nonlocal changed
        original(*a, **kw)
        if not changed:
            changed = True
            retired = parent.with_name("preserved-parent")
            parent.rename(retired)
            shutil.copytree(retired, parent)
    monkeypatch.setattr(m, "_validate_pair", replace)
    with pytest.raises(ValueError):
        getattr(m, operation)(**args)
    assert upgrade.inventory_digest(journey["target"]) == journey["expected_target_sha256"]
    assert not (journey["transaction"] / "published.json").exists()


@pytest.mark.parametrize("committed", [False, True])
def test_expiry_at_final_publication_boundary(journey, committed, monkeypatch):
    import json
    m = module()
    m.stage(**journey)
    args = publication_args(journey)
    expires = json.loads((journey["runtime"] / "host-clients/status/client.json").read_bytes())["capability"]["not_after_ms"]
    if committed:
        result = m.publish(**args)
        monkeypatch.setattr(time, "time_ns", lambda: expires * 1_000_000)
        def forbidden(*a):
            pytest.fail("committed expired replay attempted exchange")
        monkeypatch.setattr(upgrade, "_exchange", forbidden)
        assert m.publish(**args) == result
    else:
        original = m._forward_context
        calls = 0
        def context(*a, **kw):
            nonlocal calls
            result = original(*a, **kw)
            calls += 1
            if calls == 2:
                monkeypatch.setattr(time, "time_ns", lambda: expires * 1_000_000)
            return result
        monkeypatch.setattr(m, "_forward_context", context)
        with pytest.raises(ValueError):
            m.publish(**args)
        assert upgrade.inventory_digest(journey["target"]) == journey["expected_target_sha256"]
        assert not (journey["transaction"] / "published.json").exists()


@pytest.mark.parametrize("boundary", ["exchange-return", "receipt-write", "expiry-before-exchange", "expired-committed"])
def test_reverse_interruption_and_expiry(journey, boundary, monkeypatch):
    import json
    m = module()
    ready = m.stage(**journey)
    m.publish(**publication_args(journey))
    pin = rollback_runtime(journey)
    args = dict(publication_args(journey), expected_rollback_sha256=pin, password=PASSWORD)
    before = upgrade.inventory_digest(journey["runtime"])
    if boundary == "expired-committed":
        result = m.rollback(**args)
    expires = json.loads((journey["transaction"] / "checkpoint/client.json").read_bytes())["capability"]["not_after_ms"]
    with monkeypatch.context() as fault:
        if boundary == "exchange-return":
            original = upgrade._exchange
            def exchange(a, b):
                original(a, b)
                raise OSError("synthetic lost reverse exchange return")
            fault.setattr(upgrade, "_exchange", exchange)
        elif boundary == "receipt-write":
            original = upgrade._write
            def write(path, raw):
                if "rolled-back" in path.name:
                    original(path, raw[:10])
                    raise OSError("synthetic partial reverse receipt")
                original(path, raw)
            fault.setattr(upgrade, "_write", write)
        elif boundary == "expiry-before-exchange":
            original = m._reverse_context
            calls = 0
            def context(*a):
                nonlocal calls
                value = original(*a)
                calls += 1
                if calls == 2:
                    fault.setattr(time, "time_ns", lambda: expires * 1_000_000)
                return value
            fault.setattr(m, "_reverse_context", context)
        else:
            fault.setattr(time, "time_ns", lambda: expires * 1_000_000)
            def forbidden(*a):
                pytest.fail("expired committed reverse exchanged again")
            fault.setattr(upgrade, "_exchange", forbidden)
            assert m.rollback(**args) == result
        if boundary != "expired-committed":
            with pytest.raises((ValueError, OSError)):
                m.rollback(**args)
            if boundary == "expiry-before-exchange":
                assert upgrade.inventory_digest(journey["target"]) == ready["new_sha256"]
    result = m.rollback(**args)
    assert result["state"] == "stopped-rolled-back"
    assert upgrade.inventory_digest(journey["runtime"]) == before
    assert upgrade.inventory_digest(journey["target"]) == ready["old_sha256"]
    assert upgrade.inventory_digest(journey["transaction"] / "checkpoint") == ready["old_sha256"]


@pytest.mark.parametrize("case", ["source-mode", "source-symlink", "source-hardlink", "target-mode", "target-symlink", "ancestor-symlink", "receipt-mode", "changed-source", "changed-candidate", "changed-receipt", "changed-target", "changed-published"])
def test_existing_filesystem_and_digest_refusals(journey, case):
    m = module()
    args = journey
    operation = m.stage
    target = journey["target"]
    if case.startswith("changed-"):
        m.stage(**journey)
        args = publication_args(journey)
        operation = m.publish
        paths = {"changed-source": journey["runtime"] / "runtime.json", "changed-candidate": journey["transaction"] / "candidate/client.json", "changed-receipt": journey["transaction"] / "ready.json", "changed-target": target / "client.json", "changed-published": journey["transaction"] / "published.json"}
        if case == "changed-published":
            m.publish(**args)
        paths[case].write_bytes(b"{}")
    elif case in ("target-mode", "receipt-mode", "source-mode"):
        path = {"target-mode": target, "receipt-mode": journey["upgrade_transaction"] / "published.json", "source-mode": journey["runtime"] / "host-clients/status/capability.key"}[case]
        path.chmod(0o755 if path.is_dir() else 0o644)
    elif case == "source-hardlink":
        os.link(journey["runtime"] / "host-clients/status/capability.key", target.parent / "preserved-hardlink")
    else:
        path = {"source-symlink": journey["runtime"] / "host-clients/status/capability.key", "target-symlink": target, "ancestor-symlink": target.parent}[case]
        preserved = path.with_name(path.name + ".preserved")
        path.rename(preserved)
        path.symlink_to(preserved)
    with pytest.raises((ValueError, OSError, KeyError)):
        operation(**args)


@pytest.mark.parametrize("case", ["receipt", "runtime", "checkpoint", "password"])
def test_reverse_refuses_changed_authorization(journey, case):
    m = module()
    m.stage(**journey)
    m.publish(**publication_args(journey))
    pin = rollback_runtime(journey)
    args = dict(publication_args(journey), expected_rollback_sha256=pin, password=PASSWORD)
    before = upgrade.inventory_digest(journey["target"])
    if case == "password":
        args["password"] = b"wrong-synthetic-password"
    else:
        root = {"receipt": journey["upgrade_transaction"] / "rolled-back.json", "runtime": journey["runtime"] / "runtime.json", "checkpoint": journey["transaction"] / "checkpoint/client.json"}[case]
        root.write_bytes(b"{}")
    with pytest.raises((ValueError, OSError, KeyError)):
        m.rollback(**args)
    assert upgrade.inventory_digest(journey["target"]) == before
    assert not (journey["transaction"] / "rolled-back.json").exists()


def publication_args(journey):
    return dict(transaction=journey["transaction"], expected_receipt_sha256=sha((journey["transaction"] / "ready.json").read_bytes()), externally_quiesced=True)


def test_publish_exchange_and_exact_retry_preserve_original_evidence(journey):
    m = module()
    ready = m.stage(**journey)
    assert hasattr(m, "publish"), "missing atomic publication"
    before = upgrade.inventory_digest(journey["runtime"])
    result = m.publish(**publication_args(journey))
    assert result["state"] == "stopped-published"
    assert result["runtime_sha256"] == before
    assert upgrade.inventory_digest(journey["target"]) == ready["new_sha256"]
    for name in ("checkpoint", "candidate"):
        assert upgrade.inventory_digest(journey["transaction"] / name) == ready["old_sha256"]
    assert m.publish(**publication_args(journey)) == result
    assert upgrade.inventory_digest(journey["runtime"]) == before


def test_stage_exact_private_pair_preserves_runtime_and_external(journey):
    m = module()
    runtime_before = upgrade.inventory_digest(journey["runtime"])
    receipt = m.stage(**journey)
    txn = journey["transaction"]
    assert receipt["state"] == "stopped-staged"
    assert upgrade.inventory_digest(journey["target"]) == journey["expected_target_sha256"]
    assert upgrade.inventory_digest(txn / "checkpoint") == journey["expected_target_sha256"]
    assert upgrade._snapshot(txn / "candidate") == upgrade._snapshot(journey["runtime"] / "host-clients/status")
    assert upgrade.inventory_digest(journey["runtime"]) == runtime_before
    assert (txn / "ready.json").read_bytes() == canonical_bytes(receipt)
