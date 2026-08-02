"""Resource-fence registry tests (issue #27): acquire, renew, CAS and TTL.

Covers: signature verification, epoch monotonicity, CAS rejection on
stale epoch, TTL enforcement, garbage collection, and the clusterd
The legacy imports below are compatibility aliases; public API naming is
``resource-fence/v1`` and ``GET /v1/resource-fences``.
"""

import json
import time

import pytest

from clusterctl.leases import (
    FakeSigner,
    InvalidSignature,
    LeaseConflict,
    LeaseNotFound,
    LeaseStore,
    SSHSigner,
    now_ms,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def store(tmp_path):
    """LeaseStore backed by tmp_path/state/leases/."""
    return LeaseStore(tmp_path / "state")


@pytest.fixture()
def pubkey():
    return "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGfakekey12345"


@pytest.fixture()
def fingerprint():
    return "SHA256:abc123def456abc123def456abc123def456abc123def456"


DAIMON = "eko@daimonmatrix"
DAIMON2 = "oliva@daimonmatrix"


# ---------------------------------------------------------------------------
# acquire
# ---------------------------------------------------------------------------


class TestAcquire:
    def test_acquire_returns_lease_with_correct_fields(self, store, pubkey, fingerprint):
        lease = store.acquire(DAIMON, pubkey, fingerprint)
        assert lease["schema"] == "resource-fence/v1"
        assert lease["resource_ref"] == DAIMON
        assert lease["holder_pubkey"] == pubkey
        assert lease["fingerprint"] == fingerprint
        assert lease["epoch"] == 0
        assert lease["ttl_s"] == 3600
        assert lease["renewer"] == "self"
        assert isinstance(lease["created_ms"], int)
        assert lease["created_ms"] > 0
        assert lease["signature"].startswith("FAKE:")
        assert len(lease["signature"]) > 6

    def test_acquire_custom_ttl_and_renewer(self, store, pubkey, fingerprint):
        lease = store.acquire(DAIMON, pubkey, fingerprint, ttl_s=60, renewer="steward")
        assert lease["ttl_s"] == 60
        assert lease["renewer"] == "steward"

    def test_acquire_persists_to_disk(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint)
        path = store._lease_path(DAIMON)
        assert path.is_file()
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert raw["resource_ref"] == DAIMON
        assert raw["epoch"] == 0


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


class TestStatus:
    def test_status_valid_after_acquire(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint)
        st = store.status(DAIMON)
        assert st["resource_ref"] == DAIMON
        assert st["present"] is True
        assert st["expired"] is False
        assert st["expires_in_ms"] > 0
        assert st["renewer"] == "self"
        assert st["last_epoch"] == 0

    def test_status_missing_daimon(self, store):
        st = store.status("unknown@daimonmatrix")
        assert st["present"] is False
        assert st["expired"] is True
        assert st["expires_in_ms"] == 0
        assert st["renewer"] is None
        assert st["last_epoch"] is None

    def test_status_expired_lease(self, store, pubkey, fingerprint):
        # Acquire with 0 TTL — expires immediately.
        store.acquire(DAIMON, pubkey, fingerprint, ttl_s=0)
        time.sleep(0.001)  # let clock tick past created_ms
        st = store.status(DAIMON)
        assert st["present"] is True
        assert st["expired"] is True
        assert st["expires_in_ms"] == 0


# ---------------------------------------------------------------------------
# renew
# ---------------------------------------------------------------------------


class TestRenew:
    def test_renew_increments_epoch(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint)
        renewed = store.renew(DAIMON, "/fake/privkey")
        assert renewed is not None
        assert renewed["epoch"] == 1

    def test_renew_updates_created_ms(self, store, pubkey, fingerprint):
        lease = store.acquire(DAIMON, pubkey, fingerprint)
        created1 = lease["created_ms"]
        time.sleep(0.01)
        renewed = store.renew(DAIMON, "/fake/privkey")
        assert renewed["created_ms"] > created1

    def test_renew_changes_ttl_when_provided(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint, ttl_s=120)
        renewed = store.renew(DAIMON, "/fake/privkey", new_ttl_s=600)
        assert renewed["ttl_s"] == 600

    def test_renew_keeps_ttl_when_not_provided(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint, ttl_s=120)
        renewed = store.renew(DAIMON, "/fake/privkey")
        assert renewed["ttl_s"] == 120

    def test_renew_persists_updated_epoch(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint)
        store.renew(DAIMON, "/fake/privkey")
        store.renew(DAIMON, "/fake/privkey")
        st = store.status(DAIMON)
        assert st["last_epoch"] == 2

    def test_renew_returns_none_for_missing_lease(self, store):
        result = store.renew("unknown@daimonmatrix", "/fake/privkey")
        assert result is None

    def test_renew_returns_none_for_expired_lease(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint, ttl_s=0)
        time.sleep(0.001)
        result = store.renew(DAIMON, "/fake/privkey")
        assert result is None

    def test_renew_verifies_existing_signature(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint)
        # Corrupt the signature on disk
        path = store._lease_path(DAIMON)
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["signature"] = "FAKE:00000000000000000000000000000000"
        path.write_text(json.dumps(raw, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        with pytest.raises(InvalidSignature, match="invalid signature"):
            store.renew(DAIMON, "/fake/privkey")


# ---------------------------------------------------------------------------
# release
# ---------------------------------------------------------------------------


class TestRelease:
    def test_release_removes_file(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint)
        assert store._lease_path(DAIMON).is_file()
        store.release(DAIMON)
        assert not store._lease_path(DAIMON).is_file()

    def test_release_raises_on_missing(self, store):
        with pytest.raises(LeaseNotFound, match="no resource fence"):
            store.release("unknown@daimonmatrix")

    def test_release_raises_on_invalid_signature(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint)
        path = store._lease_path(DAIMON)
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["signature"] = "FAKE:00000000000000000000000000000000"
        path.write_text(json.dumps(raw, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        with pytest.raises(InvalidSignature, match="invalid signature"):
            store.release(DAIMON)


# ---------------------------------------------------------------------------
# CAS fencing
# ---------------------------------------------------------------------------


class TestCASFencing:
    def test_acquire_rejects_unexpired_lease(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint)
        with pytest.raises(LeaseConflict):
            store.acquire(DAIMON, pubkey, fingerprint)

    def test_expired_lease_does_not_block_reacquire(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint, ttl_s=0)
        time.sleep(0.001)
        # Should succeed without reusing an old fencing epoch.
        lease = store.acquire(DAIMON, pubkey, fingerprint)
        assert lease["epoch"] == 1
        assert lease["resource_ref"] == DAIMON

    def test_acquire_after_release_succeeds(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint)
        store.release(DAIMON)
        # Release removed the file — acquire should succeed.
        lease = store.acquire(DAIMON, pubkey, fingerprint)
        assert lease["epoch"] == 1

    def test_restore_rollback_does_not_reuse_intermediate_epoch(self, store, pubkey, fingerprint):
        original = store.acquire(DAIMON, pubkey, fingerprint)
        renewed = store.renew(DAIMON, "/fake/privkey")
        assert renewed["epoch"] == 1
        store.restore(DAIMON, original)
        after_rollback = store.renew(DAIMON, "/fake/privkey")
        assert after_rollback["epoch"] == 2


# ---------------------------------------------------------------------------
# signature verification
# ---------------------------------------------------------------------------


class TestSignatureVerification:
    def test_fake_signer_verify_valid(self, store, pubkey, fingerprint):
        lease = store.acquire(DAIMON, pubkey, fingerprint)
        assert store._verify(lease) is True

    def test_fake_signer_rejects_forged(self, store, pubkey, fingerprint):
        lease = store.acquire(DAIMON, pubkey, fingerprint)
        forged = dict(lease)
        forged["signature"] = "FAKE:00000000000000000000000000000000"
        assert store._verify(forged) is False

    def test_fake_signer_rejects_missing_signature(self, store, pubkey, fingerprint):
        lease = store.acquire(DAIMON, pubkey, fingerprint)
        forged = dict(lease)
        del forged["signature"]
        assert store._verify(forged) is False

    def test_fake_signer_rejects_tampered_body(self, store, pubkey, fingerprint):
        lease = store.acquire(DAIMON, pubkey, fingerprint)
        forged = dict(lease)
        forged["epoch"] = 999  # tampered epoch — signature no longer matches
        assert store._verify(forged) is False

    def test_signature_is_deterministic(self, store, pubkey, fingerprint):
        """Same lease body produces the same fake signature."""
        from clusterctl.leases import _canonical

        body = {
            "schema": "resource-fence/v1",
            "resource_ref": DAIMON,
            "holder_embodiment_id": "unbound",
            "holder_pubkey": pubkey,
            "fingerprint": fingerprint,
            "epoch": 0,
            "created_ms": 1000000,
            "ttl_s": 3600,
            "renewer": "self",
        }
        sig1 = store._signer.sign(_canonical(body))
        sig2 = store._signer.sign(_canonical(body))
        assert sig1 == sig2
        assert sig1.startswith("FAKE:")


# ---------------------------------------------------------------------------
# list_all + garbage collection
# ---------------------------------------------------------------------------


class TestListAll:
    def test_list_all_empty(self, store):
        assert store.list_all() == []

    def test_list_all_includes_active_leases(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint)
        store.acquire(DAIMON2, pubkey, fingerprint)
        result = store.list_all()
        assert len(result) == 2
        ids = {st["resource_ref"] for st in result}
        assert ids == {DAIMON, DAIMON2}

    def test_list_all_includes_expired_leases(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint, ttl_s=0)
        time.sleep(0.001)
        result = store.list_all()
        assert len(result) == 1
        assert result[0]["expired"] is True
        assert result[0]["present"] is True  # file still on disk


class TestGarbageCollection:
    def test_collect_garbage_removes_expired(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint, ttl_s=0)
        time.sleep(0.001)
        removed = store.collect_garbage()
        assert removed == 1
        assert not store._lease_path(DAIMON).is_file()

    def test_collect_garbage_keeps_active(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint, ttl_s=3600)
        removed = store.collect_garbage()
        assert removed == 0
        assert store._lease_path(DAIMON).is_file()

    def test_collect_garbage_empty_dir(self, store):
        removed = store.collect_garbage()
        assert removed == 0


# ---------------------------------------------------------------------------
# SSHSigner placeholder
# ---------------------------------------------------------------------------


class TestSSHSigner:
    def test_ssh_signer_produces_distinguishable_sig(self, pubkey, fingerprint):
        signer = SSHSigner("/path/to/key")
        lease = {
            "schema": "resource-fence/v1",
            "resource_ref": DAIMON,
            "identity_pubkey": pubkey,
            "fingerprint": fingerprint,
            "epoch": 0,
            "created_ms": 1,
            "ttl_s": 3600,
            "renewer": "self",
        }
        from clusterctl.leases import _canonical

        sig = signer.sign(_canonical(lease))
        assert sig.startswith("SSH:")
        assert len(sig) > 4

    def test_ssh_verify_not_implemented(self, pubkey, fingerprint):
        signer = SSHSigner("/path/to/key")
        with pytest.raises(NotImplementedError):
            signer.verify(b"data", "sig", pubkey)


# ---------------------------------------------------------------------------
# Multi-daimon independence
# ---------------------------------------------------------------------------


class TestMultiDaimon:
    def test_independent_acquisitions(self, store, pubkey, fingerprint):
        lease1 = store.acquire(DAIMON, pubkey, fingerprint)
        lease2 = store.acquire(DAIMON2, pubkey, fingerprint)
        assert lease1["resource_ref"] == DAIMON
        assert lease2["resource_ref"] == DAIMON2
        assert lease1["epoch"] == 0
        assert lease2["epoch"] == 0

    def test_renew_independent(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint)
        store.acquire(DAIMON2, pubkey, fingerprint)
        store.renew(DAIMON, "/fake/privkey")
        assert store.status(DAIMON)["last_epoch"] == 1
        assert store.status(DAIMON2)["last_epoch"] == 0

    def test_release_independent(self, store, pubkey, fingerprint):
        store.acquire(DAIMON, pubkey, fingerprint)
        store.acquire(DAIMON2, pubkey, fingerprint)
        store.release(DAIMON)
        st1 = store.status(DAIMON)
        st2 = store.status(DAIMON2)
        assert st1["present"] is False
        assert st2["present"] is True
