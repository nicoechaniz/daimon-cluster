"""Provisioning prepare/confirm tests (issue #12) — fake adapter only."""
import hashlib
import json
from pathlib import Path

import pytest
import yaml

from clusterctl.adapters import FakeAdapter
from clusterctl.cli import run
from clusterctl import audit as audit_mod

UUID1 = "11111111-1111-1111-1111-111111111111"
UUID2 = "22222222-2222-2222-2222-222222222222"


@pytest.fixture()
def state_dir(tmp_path):
    return tmp_path / "state"


def _run(state_dir, *argv, adapter=None):
    ad = adapter if adapter is not None else FakeAdapter()
    code = run(["--state-dir", str(state_dir), *argv], adapter=ad)
    return code, ad


def _prepare(state_dir, name="daimon-x", key=UUID1, adapter=None, extra=()):
    return _run(state_dir, "provision", "prepare", name,
                "--species", "t", "--requested-by", "alice", "--sponsor", "bob",
                "--idempotency-key", key, "--json", *extra, adapter=adapter)


def _token_file(state_dir, token):
    return state_dir / "confirmations" / f"{token}.json"


def _prepare_and_get_token(state_dir, adapter=None, capsys=None):
    code, ad = _prepare(state_dir, adapter=adapter)
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    return out["token"], ad, out


# --------------------------------------------------------------------------
# prepare
# --------------------------------------------------------------------------

def test_prepare_happy_path(state_dir, capsys):
    code, ad = _prepare(state_dir)
    assert code == 0
    out = json.loads(capsys.readouterr().out)

    # spec written with the pending state
    spec = yaml.safe_load((state_dir / "instances" / "daimon-x.yaml").read_text())
    assert spec["state"] == "provisioned-pending-activation"
    assert spec["governance"] == {"requested_by": "alice", "sponsor": "bob"}

    # token file shape (confirmation/v1)
    token = out["token"]
    data = json.loads(_token_file(state_dir, token).read_text())
    assert data["schema"] == "confirmation/v1"
    assert data["operation"] == "provision-activate"
    assert data["target"] == "daimon-x"
    assert data["ttl_s"] == 900
    assert data["used"] is False
    entry = data["artifacts"]["directory_entry"]
    assert entry["identity"] == "daimon-x@daimonmatrix"
    assert entry["host_broker"] == "10.10.20.69:8685"
    assert entry["pubkey"].startswith("ssh-ed25519 ")
    assert entry["fingerprint"].startswith("SHA256:")
    assert out["directory_entry"] == entry

    # audit carries the fingerprint (never key material)
    events = [
        json.loads(line)
        for line in (state_dir / "audit.jsonl").read_text().splitlines()
    ]
    ok = [e for e in events if e["action"] == "provision-prepare" and e["result"] == "ok"]
    assert ok and ok[-1]["detail"]["key_fingerprint"] == entry["fingerprint"]
    assert ok[-1]["detail"]["requested_by"] == "alice"
    assert ok[-1]["detail"]["sponsor"] == "bob"

    # container was created, started, volume ensured, exec used for keys
    ops = [m[0] for m in ad.mutation_log]
    assert "create_instance" in ops and "start" in ops
    assert "ensure_volume" in ops and "exec" in ops

    # NO private key material anywhere under state_dir
    for p in Path(state_dir).rglob("*"):
        if p.is_file():
            assert "PRIVATE KEY" not in p.read_bytes().decode("utf-8", "replace"), p


def test_prepare_sponsor_equals_requester_rejected(state_dir, capsys):
    code, _ = _run(state_dir, "provision", "prepare", "daimon-x",
                   "--species", "t", "--requested-by", "alice", "--sponsor", "alice",
                   "--idempotency-key", UUID1)
    assert code == 6
    assert not (state_dir / "instances" / "daimon-x.yaml").exists()


def test_prepare_duplicate_name_rejected(state_dir, capsys):
    _prepare(state_dir)
    capsys.readouterr()
    code, _ = _prepare(state_dir, key=UUID2)
    assert code == 6


def test_prepare_idempotent_replay(state_dir, capsys):
    code1, adapter = _prepare(state_dir)
    out1 = json.loads(capsys.readouterr().out)
    code2, _ = _prepare(state_dir, adapter=adapter)
    out2 = json.loads(capsys.readouterr().out)
    assert code1 == 0 and code2 == 0
    assert out2.get("idempotent-replay") is True
    assert out2["token"] == out1["token"]


def test_prepare_seed_manifest_sha256_mismatch_rejected(state_dir, tmp_path, capsys):
    source = tmp_path / "SOUL.md"
    source.write_text("hello daimon")
    wrong = "0" * 64
    manifest = tmp_path / "seed.yaml"
    manifest.write_text(yaml.safe_dump({
        "schema": "seed-manifest/v1",
        "target": "daimon-x@daimonmatrix",
        "curated_by": "alice",
        "items": [{"kind": "soul", "source": str(source), "sha256": wrong}],
    }))
    code, _ = _prepare(state_dir, extra=("--seed-manifest", str(manifest)))
    assert code == 6
    # rejected before any effect: no spec, no container
    assert not (state_dir / "instances" / "daimon-x.yaml").exists()


def test_prepare_seed_manifest_happy_path(state_dir, tmp_path, capsys):
    source = tmp_path / "SOUL.md"
    content = b"# SOUL\nunborn-but-ready\n"
    source.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    manifest = tmp_path / "seed.yaml"
    manifest.write_text(yaml.safe_dump({
        "schema": "seed-manifest/v1",
        "curated_by": "alice",
        "items": [{"kind": "soul", "source": str(source), "sha256": digest}],
    }))
    code, ad = _prepare(state_dir, extra=("--seed-manifest", str(manifest)))
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["seed_staged"] == 1
    # staging went through adapter.exec into the container
    exec_calls = [m for m in ad.mutation_log if m[0] == "exec"]
    assert any("SOUL.md" in " ".join(m[2]) for m in exec_calls)
    assert any("SEED-PROVENANCE" in " ".join(m[2]) for m in exec_calls)


def test_prepare_creation_failure_reverses(state_dir, capsys):
    ad = FakeAdapter(fail_create=True)
    code, _ = _prepare(state_dir, adapter=ad)
    assert code == 10
    spec = yaml.safe_load((state_dir / "instances" / "daimon-x.yaml").read_text())
    assert spec["state"] == "creation-failed"
    ops = [m[0] for m in ad.mutation_log]
    assert "delete" in ops and "delete_volume" in ops
    events = [
        json.loads(line)
        for line in (state_dir / "audit.jsonl").read_text().splitlines()
    ]
    assert any(e["action"] == "provision-prepare" and e["result"] == "error" for e in events)


def test_prepare_volume_failure_reverses(state_dir, capsys):
    ad = FakeAdapter(fail_volume=True)
    code, _ = _prepare(state_dir, adapter=ad)
    assert code == 10
    spec = yaml.safe_load((state_dir / "instances" / "daimon-x.yaml").read_text())
    assert spec["state"] == "creation-failed"
    ops = [m[0] for m in ad.mutation_log]
    assert "ensure_volume" in ops and "delete" in ops and "delete_volume" in ops


# --------------------------------------------------------------------------
# confirm
# --------------------------------------------------------------------------

def test_confirm_happy_path(state_dir, capsys):
    token, _, prep_out = _prepare_and_get_token(state_dir, capsys=capsys)
    code, _ = _run(state_dir, "provision", "confirm", "--token", token, "--json")
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == "ok"
    assert out["state"] == "active-pending-directory"
    assert out["directory_entry"] == prep_out["directory_entry"]
    # token consumed + spec flipped
    assert json.loads(_token_file(state_dir, token).read_text())["used"] is True
    spec = yaml.safe_load((state_dir / "instances" / "daimon-x.yaml").read_text())
    assert spec["state"] == "active-pending-directory"


def test_confirm_expired_token(state_dir, capsys):
    token, _, _ = _prepare_and_get_token(state_dir, capsys=capsys)
    path = _token_file(state_dir, token)
    data = json.loads(path.read_text())
    data["created_ms"] = audit_mod.now_ms() - (901 * 1000)
    path.write_text(json.dumps(data))
    code, _ = _run(state_dir, "provision", "confirm", "--token", token)
    assert code == 6
    assert "expired" in capsys.readouterr().err


def test_confirm_replay_idempotent(state_dir, capsys):
    token, _, _ = _prepare_and_get_token(state_dir, capsys=capsys)
    code1, _ = _run(state_dir, "provision", "confirm", "--token", token, "--json")
    out1 = json.loads(capsys.readouterr().out)
    code2, _ = _run(state_dir, "provision", "confirm", "--token", token, "--json")
    out2 = json.loads(capsys.readouterr().out)
    assert code1 == 0 and code2 == 0
    assert out2["already_confirmed"] is True
    assert out2["directory_entry"] == out1["directory_entry"]


def test_confirm_unknown_token(state_dir, capsys):
    code, _ = _run(state_dir, "provision", "confirm",
                   "--token", "99999999-9999-9999-9999-999999999999")
    assert code == 3
