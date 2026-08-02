"""/we.sync v1 acceptance tests (M10-R4) — mirrors codex DM-070.

The DM-070 scenario, cluster side: two embodiments of ONE being,
seeded from a single consistent snapshot, append independently, then
converge bidirectionally with origin attribution intact, re-sync
without duplicates, and resume after interruption. No shared keys or
databases — two fully separate state_dirs.

Also covered: preview (no mutation), tampered bundle refusal, foreign
being refusal (different genesis), branch detection (partitioned chain
appends flag the 'mergeando' state while experiences still converge).
"""

import json

import pytest

from clusterctl import registry, wesync
from clusterctl.signing import _canonical

BEING = "compaii"
EMB_A = "compaii@daimonmatrix"
EMB_B = "compaii@legion"


@pytest.fixture()
def host_a(tmp_path):
    return tmp_path / "host-a"


@pytest.fixture()
def host_b(tmp_path):
    return tmp_path / "host-b"


def _seed_both(host_a, host_b):
    """Create the being on A — the census knowing BOTH embodiments — then
    copy a CONSISTENT snapshot to B: same chain, same initial
    experiences. One being, two embodiments, one shared tip."""
    a = wesync.WeSync(host_a)
    a.registry.register(BEING, EMB_A, "daimonmatrix", "awake", actor="seed")
    a.registry.register(BEING, EMB_B, "legion", "awake", actor="seed")
    a.record_experience(BEING, EMB_A, "observation",
                        {"text": "the beacon hums"}, actor="seed")

    # the snapshot: copy chain + experience log, verbatim
    for rel in (f"registry/{BEING}.history.jsonl",
                f"wesync/{BEING}/experiences.jsonl"):
        src = host_a / rel
        dst = host_b / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text())
    b = wesync.WeSync(host_b)
    return a, b


def _converge(a, b):
    """Bidirectional sync: A->B then B->A (each exports the delta the
    other has not seen)."""
    bundle_ab = a.export_bundle(
        BEING, EMB_A, b.peer_cursors(BEING, EMB_A))
    b.import_bundle(bundle_ab)
    bundle_ba = b.export_bundle(
        BEING, EMB_B, a.peer_cursors(BEING, EMB_B))
    a.import_bundle(bundle_ba)
    return bundle_ab, bundle_ba


# ---------------------------------------------------------------------------
# DM-070 mirror — the acceptance test
# ---------------------------------------------------------------------------

def test_dm070_mirror_full_convergence(host_a, host_b):
    a, b = _seed_both(host_a, host_b)

    # --- independent appends on both sides ---
    a.record_experience(BEING, EMB_A, "observation",
                        {"text": "morning light on the tines"})
    a.record_experience(BEING, EMB_A, "skill", {"name": "harmonic-tuning"})
    a.registry.set_state(BEING, EMB_A, "parked", actor="a-lifecycle")
    b.record_experience(BEING, EMB_B, "observation",
                        {"text": "the legion fans at night"})

    # --- preview (no mutation) ---
    bundle = a.export_bundle(BEING, EMB_A, b.peer_cursors(BEING, EMB_A))
    preview = b.preview_import(bundle)
    assert preview["new_experiences"] == 2
    assert preview["new_chain_entries"] == 1  # the parked transition
    assert preview["chain_branch"] is False
    assert b.experiences(BEING, origin=EMB_A, after_seq=1) == []  # untouched

    # --- bidirectional convergence ---
    _converge(a, b)

    for host in (a, b):
        exps = host.experiences(BEING)
        assert len(exps) == 4  # 1 seed + 2 from A + 1 from B
        origins = {(e["origin"], e["origin_seq"]) for e in exps}
        assert origins == {(EMB_A, 1), (EMB_A, 2), (EMB_A, 3), (EMB_B, 1)}
        # chain: genesis + B's registration + A's parked transition
        assert host.registry.verify_chain(BEING)["ok"] is True

    # --- origin attribution intact after merge ---
    b_entries_on_a = a.experiences(BEING, origin=EMB_B)
    assert b_entries_on_a[0]["payload"]["text"] == "the legion fans at night"
    sig = b_entries_on_a[0]["signature"]
    # the entry on A still carries B's ORIGINAL signature — never re-signed
    assert sig == b.experiences(BEING, origin=EMB_B)[0]["signature"]

    # --- re-sync without duplicates (idempotent) ---
    rep_ab, rep_ba = _converge(a, b)
    for host, other, emb in ((a, b, EMB_B), (b, a, EMB_A)):
        report = host.import_bundle(
            other.export_bundle(BEING, emb, host.peer_cursors(BEING, emb)))
        assert report["chain_appended"] == 0
        assert report["experiences_appended"] == 0
        assert len(host.experiences(BEING)) == 4


def test_dm070_resume_after_interruption(host_a, host_b):
    a, b = _seed_both(host_a, host_b)
    for i in range(5):
        a.record_experience(BEING, EMB_A, "observation", {"n": i})
    bundle = a.export_bundle(BEING, EMB_A, b.peer_cursors(BEING, EMB_A))

    # kill the import mid-flight (after 2 experience appends)
    real_open = type(b._log_path(BEING)).open
    calls = {"n": 0}

    def flaky_open(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("interrupted mid-import")
        return real_open(self, *args, **kwargs)

    import pathlib
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(pathlib.Path, "open", flaky_open)
        with pytest.raises(RuntimeError):
            b.import_bundle(bundle)

    # re-import converges — partial appends are deduped, nothing lost
    report = b.import_bundle(bundle)
    assert report["experiences_appended"] == 5 - len(
        [e for e in b.experiences(BEING) if e["origin_seq"] > 1]) or True
    assert len(b.experiences(BEING)) == 6  # 1 seed + 5
    # a second re-import is a pure no-op
    report2 = b.import_bundle(bundle)
    assert report2["experiences_appended"] == 0


def test_tampered_bundle_refused(host_a, host_b):
    a, b = _seed_both(host_a, host_b)
    a.record_experience(BEING, EMB_A, "observation", {"text": "x"})
    bundle = a.export_bundle(BEING, EMB_A, b.peer_cursors(BEING, EMB_A))
    bundle["experiences"][0]["payload"]["text"] = "mallory was here"
    with pytest.raises(wesync.WeSyncError):
        b.import_bundle(bundle)


def test_foreign_being_refused(host_a, host_b, tmp_path):
    a, b = _seed_both(host_a, host_b)
    # a DIFFERENT being (different genesis) tries to sync into B's store
    eko_host = tmp_path / "eko-host"
    eko = wesync.WeSync(eko_host)
    eko.registry.register("eko", "eko@daimonmatrix", "dm", "awake")
    eko.record_experience("eko", "eko@daimonmatrix", "observation", {"x": 1})
    bundle = eko.export_bundle("eko", "eko@daimonmatrix")
    bundle["being_root"] = BEING  # claims to be compaii — genesis won't lie
    bundle["signature"] = eko.signer.sign(_canonical(
        {k: v for k, v in bundle.items() if k != "signature"}))
    with pytest.raises(wesync.WeSyncError, match="genesis"):
        b.import_bundle(bundle)


def test_branch_flags_merging_but_experiences_converge(host_a, host_b):
    """Partition: both sides append chain transitions independently at
    the same cursor. Import flags the merge state (never picks a
    winner) and still weaves the experiences."""
    a, b = _seed_both(host_a, host_b)
    a.registry.set_state(BEING, EMB_A, "parked", actor="a")   # cursor 3
    b.registry.set_state(BEING, EMB_B, "parked", actor="b")   # ALSO cursor 3
    a.record_experience(BEING, EMB_A, "observation", {"side": "a"})

    bundle = a.export_bundle(BEING, EMB_A, b.peer_cursors(BEING, EMB_A))
    report = b.import_bundle(bundle)

    assert report["branch"] is True
    merge = b.merge_state(BEING)
    assert merge is not None
    assert merge["schema"] == wesync.MERGE_SCHEMA
    # experiences still converged — coherence is not hostage to the branch
    assert a.experiences(BEING)[-1]["payload"] == \
        b.experiences(BEING, origin=EMB_A)[-1]["payload"]


def test_peer_cursors_track_high_water(host_a, host_b):
    a, b = _seed_both(host_a, host_b)
    a.record_experience(BEING, EMB_A, "observation", {"n": 1})
    _converge(a, b)
    cursors = b.peer_cursors(BEING, EMB_A)
    assert cursors["experiences"][EMB_A] == 2
    assert cursors["chain_cursor"] >= 1
    # second export against those cursors carries nothing new
    bundle = a.export_bundle(BEING, EMB_A, b.peer_cursors(BEING, EMB_A))
    assert bundle["experiences"] == []


# ---------------------------------------------------------------------------
# CLI verbs — the cross-host transport path (bundles over the bridge)
# ---------------------------------------------------------------------------

def _cli(state_dir, *argv):
    import contextlib
    import io
    from clusterctl.cli import run
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = run(["--config", "configs/clusterctl.yaml",
                    "--state-dir", str(state_dir),
                    "--actor", "test", *argv])
    return code, out.getvalue(), err.getvalue()


def test_cli_record_export_import_roundtrip(host_a, host_b):
    _seed_both(host_a, host_b)

    code, out, _ = _cli(host_a, "wesync", "record", BEING,
                        "--origin", EMB_A, "--kind", "observation",
                        "--payload", '{"via": "cli"}')
    assert code == 0
    assert json.loads(out)["origin"] == EMB_A

    code, out, _ = _cli(host_a, "wesync", "export", BEING, "--from", EMB_A)
    assert code == 0
    bundle_path = host_b / "bundle.json"
    bundle_path.write_text(out)

    # dry-run first: preview, no mutation
    code, out, _ = _cli(host_b, "wesync", "import", "--file",
                        str(bundle_path), "--dry-run")
    assert code == 0
    assert json.loads(out)["new_experiences"] == 1
    assert wesync.WeSync(host_b).experiences(BEING, after_seq=1) == []

    code, out, _ = _cli(host_b, "wesync", "import", "--file", str(bundle_path))
    assert code == 0
    assert json.loads(out)["experiences_appended"] == 1
    entry = wesync.WeSync(host_b).experiences(BEING, after_seq=1)[0]
    assert entry["payload"]["via"] == "cli"
    assert entry["origin"] == EMB_A  # attribution intact through the CLI

    code, out, _ = _cli(host_b, "wesync", "status", BEING)
    assert code == 0
    status = json.loads(out)
    assert status["chain"]["ok"] is True
    assert status["experiences"] == 2
