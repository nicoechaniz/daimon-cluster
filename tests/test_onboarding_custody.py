"""Actual isolated native holder processes, crash replay and unchanged identity."""
import hashlib
import json
import os

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_custody import FirstCustody, GRANT_SCHEMA, ROLES, document
from tests.test_onboarding import plan


def fixture(tmp_path, run=None):
    root, grants = tmp_path / "custody", tmp_path / "custody-grants"
    root.mkdir(mode=0o700)
    grants.mkdir(mode=0o700)
    value = plan(name="qualify-genesis")
    grant = dict(schema=GRANT_SCHEMA, plan_digest=digest(value), ceremony="first-matrix-identity",
                 execution_uid=os.geteuid(), source_binding_digest="a" * 64, owner_instruction_digest="b" * 64,
                 roles=ROLES, revoked=False)
    being_seed._write(grants / (value["name"] + ".json"), grant)
    return FirstCustody(root, grants, run=run), value, grant


def test_real_native_genesis_is_preserved_through_an_uncertain_acknowledgement(tmp_path):
    commands = []
    crashed = []
    def execute(arguments, password):
        FirstCustody._run(arguments, password)
        commands.append((arguments, password))
        if arguments[0] == "aggregate" and not crashed:
            crashed.append(True)
            raise RuntimeError("transport failed after native publication")
    ceremony, value, _ = fixture(tmp_path, run=execute)
    with pytest.raises(RuntimeError):
        ceremony.prepare(value, identity_mode="first")
    first = ceremony.observe(value)
    assert first["enrolled"] is False and first["backup_restore_verified"] is False
    directory = ceremony.root / digest(value)
    preserved = {path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in directory.rglob("*") if path.is_file()}
    completed = ceremony.prepare(value, identity_mode="first")
    assert completed == {**first, "backup_restore_verified": True}
    assert {path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in directory.rglob("*") if path.is_file()}.items() >= preserved.items()
    # Each holder subprocess has exactly one private holder path and its own FD.
    for argv, password in commands:
        if argv[0] in {"sign", "create-holder", "backup-restore"}:
            role = "root" if "root.unlock" == password.name else "recovery"
            assert str(directory / role) in argv or (argv[0] == "backup-restore" and role in argv)
            assert str(directory / ("recovery" if role == "root" else "root")) not in argv
        else:
            assert password is None
    assert "unlock" not in json.dumps(first) and "holder.json" not in json.dumps(first)


def test_existing_identity_and_wrong_or_missing_grant_create_no_keys(tmp_path):
    commands = []
    ceremony, value, grant = fixture(tmp_path, run=lambda *args: commands.append(args))
    for mode in ("existing", "", "FIRST"):
        with pytest.raises(OnboardingError, match="identity_authorization_required"):
            ceremony.prepare(value, identity_mode=mode)
    assert not list(ceremony.root.iterdir()) and not commands
    for change in ({"revoked": True}, {"plan_digest": "c" * 64}, {"roles": ["root"]},
                   {"execution_uid": True}, {"source_binding_digest": "not an authenticated binding"}):
        being_seed._write(ceremony.grants / (value["name"] + ".json"), {**grant, **change})
        assert not ceremony.authorize(value)
        with pytest.raises(OnboardingError):
            ceremony.prepare(value, identity_mode="first")
    assert not list(ceremony.root.iterdir()) and not commands


def test_revoked_grant_stops_between_holder_processes_and_preserves_first(tmp_path):
    ceremony, value, grant = fixture(tmp_path)
    def revoke(arguments, password):
        FirstCustody._run(arguments, password)
        being_seed._write(ceremony.grants / (value["name"] + ".json"), {**grant, "revoked": True})
    ceremony.run = revoke
    with pytest.raises(OnboardingError, match="identity_authorization_required"):
        ceremony.prepare(value, identity_mode="first")
    root = ceremony.root / digest(value)
    assert (root / "root/holder.json").is_file()
    assert not (root / "recovery").exists() and not (root / "genesis.json").exists()
    descriptor = document(root / "root/descriptor.json")
    being_seed._write(ceremony.grants / (value["name"] + ".json"), grant)
    ceremony.run = FirstCustody._run
    result = ceremony.prepare(value, identity_mode="first")
    assert result["being_ref"].startswith("dm:being:v1:")
    assert document(root / "root/descriptor.json") == descriptor


def test_foreign_intent_does_not_get_signed_and_missing_unlock_does_not_rekey(tmp_path):
    ceremony, value, _ = fixture(tmp_path)
    ceremony.prepare(value, identity_mode="first")
    root = ceremony.root / digest(value)
    original = document(root / "root/descriptor.json")
    intent = document(root / "intent.json")
    intent["prepared_genesis"]["body"]["created_at_ms"] += 1
    being_seed._write(root / "intent.json", intent)
    with pytest.raises(OnboardingError, match="onboarding_custody_intent_conflict"):
        ceremony.prepare(value, identity_mode="first")
    (root / "root.unlock").unlink()
    with pytest.raises(OnboardingError, match="existing_onboarding_custody_preserved"):
        ceremony.prepare(value, identity_mode="first")
    assert document(root / "root/descriptor.json") == original


def test_interrupted_initial_plan_and_unlock_publication_reconcile(tmp_path):
    ceremony, value, _ = fixture(tmp_path)
    root = ceremony.root / digest(value)
    root.mkdir(mode=0o700)
    temporary = root / ("plan.json." + "a" * 32)
    temporary.write_bytes(b'{"interrupted')
    temporary.chmod(0o600)
    assert ceremony.observe(value) is None
    result = ceremony.prepare(value, identity_mode="first")
    preserved = temporary.read_bytes()
    os.link(root / "root.unlock", root / (".root.unlock-" + "b" * 16))
    assert ceremony.prepare(value, identity_mode="first") == result
    assert (root / "root.unlock").stat().st_nlink == 1
    assert temporary.read_bytes() == preserved
    os.link(root / "root.unlock", root / "foreign-alias")
    with pytest.raises(OnboardingError, match="private_onboarding_custody_required"):
        ceremony.prepare(value, identity_mode="first")
    assert (root / "foreign-alias").exists()


def test_host_job_dispatches_native_ceremony_without_claiming_body_enrollment(tmp_path, monkeypatch):
    import dataclasses

    from clusterctl import onboarding_consent
    from clusterctl.onboarding_host import HostBackend
    from tests.test_onboarding_consent import proposal
    from tests.test_onboarding_host import configured

    config, value, incus, _ = configured(tmp_path)
    state = tmp_path / "intake"
    reviews, proposed, decision = proposal(tmp_path, state)
    code = tmp_path / "qualified-code"
    code.mkdir(mode=0o700)
    (code / "inheritance.md").write_text(proposed["source_text"])
    monkeypatch.setattr("clusterctl.onboarding_release.verify", lambda *a, **kw: None)
    decision["matrix_identity_mode"] = "first"
    onboarding_consent.submit(state, value["name"], decision, owner=value["owner"], reviews=reviews)
    custody, grants = tmp_path / "custody", tmp_path / "custody-grants"
    custody.mkdir(mode=0o700)
    grants.mkdir(mode=0o700)
    config = dataclasses.replace(config, code=code, progress=reviews.root,
        consent_state=state, consent_uid=os.geteuid(), custody=custody, custody_grants=grants)
    backend = HostBackend(config, run=incus)
    assert backend.observe(value, "matrix", "fixture-operation").reason == "identity_authorization_required"
    assert not list(custody.iterdir())
    being_seed._write(grants / (value["name"] + ".json"), dict(schema=GRANT_SCHEMA,
        plan_digest=digest(value), ceremony="first-matrix-identity", execution_uid=os.geteuid(),
        source_binding_digest="a" * 64, owner_instruction_digest="b" * 64, roles=ROLES, revoked=False))
    assert backend.observe(value, "matrix", "fixture-operation").state == "absent"
    backend.execute(value, "matrix", "fixture-operation")
    result = backend.observe(value, "matrix", "fixture-operation")
    assert result.state == "waiting" and result.reason == "backend_unavailable" and not result.facts
    receipt = FirstCustody(custody, grants).observe(value)
    assert receipt["enrolled"] is False and receipt["backup_restore_verified"] is True
    # No Incus runtime, provider or Telegram dispatch can be inferred from genesis.
    assert incus.calls == []


def test_uncertain_backup_acknowledgement_resumes_without_replacing_the_backup(tmp_path):
    crashed = []
    def execute(arguments, password):
        FirstCustody._run(arguments, password)
        if arguments[0] == "backup-restore" and arguments[-1] == "root" and not crashed:
            crashed.append(True)
            raise RuntimeError("backup completed before acknowledgement was lost")
    ceremony, value, _ = fixture(tmp_path, run=execute)
    with pytest.raises(RuntimeError):
        ceremony.prepare(value, identity_mode="first")
    root = ceremony.root / digest(value)
    from clusterctl.onboarding_holder_backup import inventory
    preserved = inventory(root / "backup-root")
    assert ceremony.observe(value)["backup_restore_verified"] is False
    result = ceremony.prepare(value, identity_mode="first")
    assert result["backup_restore_verified"] is True
    assert inventory(root / "backup-root") == inventory(root / "restore-root") == preserved
    assert result["enrolled"] is False


def test_native_restore_interruption_reconciles_counter_and_proves_a_signature(tmp_path, monkeypatch):
    from daimon_matrix import keystore
    from clusterctl.onboarding_holder_backup import backup_restore, inventory

    def stop_before_backup(arguments, password):
        if arguments[0] == "backup-restore":
            raise RuntimeError("stopped before backup")
        FirstCustody._run(arguments, password)
    ceremony, value, _ = fixture(tmp_path, run=stop_before_backup)
    with pytest.raises(RuntimeError):
        ceremony.prepare(value, identity_mode="first")
    root = ceremony.root / digest(value)
    def reader():
        return bytearray((root / "root.unlock").read_bytes())
    original = keystore._write_highwater
    def fail_before_counter(path, counter):
        if path.parent.name == "restore-root":
            raise RuntimeError("native ciphertext published before counter")
        return original(path, counter)
    with monkeypatch.context() as patch:
        patch.setattr(keystore, "_write_highwater", fail_before_counter)
        with pytest.raises(RuntimeError):
            backup_restore(root, "root", reader)
    assert (root / "restore-root/holder.json").exists()
    assert not (root / "restore-root/.holder.json.highwater").exists()
    assert ceremony.observe(value)["backup_restore_verified"] is False
    backup_restore(root, "root", reader)
    assert inventory(root / "restore-root") == inventory(root / "backup-root")
    ceremony.run = FirstCustody._run
    assert ceremony.prepare(value, identity_mode="first")["backup_restore_verified"] is True


def test_conflicting_backup_or_extra_unlock_is_refused_without_replacement(tmp_path):
    from clusterctl.onboarding_holder_backup import inventory

    ceremony, value, _ = fixture(tmp_path)
    ceremony.prepare(value, identity_mode="first")
    root = ceremony.root / digest(value)
    original = inventory(root / "root")
    ciphertext = root / "backup-root/holder.json"
    changed = ciphertext.read_bytes() + b"unexpected bytes"
    ciphertext.write_bytes(changed)
    with pytest.raises(OnboardingError, match="native_onboarding_custody_refused"):
        ceremony.prepare(value, identity_mode="first")
    assert ciphertext.read_bytes() == changed and inventory(root / "root") == original
    extra = root / "backup-recovery/unlock"
    extra.write_bytes(b"fixture extra file")
    extra.chmod(0o600)
    with pytest.raises(OnboardingError, match="onboarding_holder_backup_conflict"):
        inventory(root / "backup-recovery")
    assert extra.exists()
