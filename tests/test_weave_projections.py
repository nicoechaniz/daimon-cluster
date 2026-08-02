from types import SimpleNamespace

import pytest

from weave.projections import GitIdentityAdapter, HMKAdapter, ProjectionError


def event(kind, subject, payload, event_id="11111111-1111-4111-8111-111111111111"):
    return {"event_id": event_id, "kind": kind, "subject": subject, "payload": payload}


def test_git_identity_requires_preview_and_human_confirmation(tmp_path):
    adapter = GitIdentityAdapter(tmp_path / "gitconfig")
    preview = adapter.preview(event(
        "configuration.proposed", "github.identity",
        {"name": "CompAII Legion", "email": "compaii@legion", "secret_slot_ref": "github/legion"},
    ))
    assert preview.authority == "human"
    assert preview.changes["user.email"]["after"] == "compaii@legion"
    with pytest.raises(ProjectionError, match="confirmation"):
        adapter.apply(preview, confirm=False, actor="compaii@legion")
    receipt = adapter.apply(preview, confirm=True, actor="human:nico")
    assert receipt["result"] == "applied"
    assert receipt["observed_postcondition"]["user.name"] == "CompAII Legion"
    assert "secret" not in str(receipt).lower()


def test_hmk_projection_uses_public_command_and_origin_marker():
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    adapter = HMKAdapter("memoryctl.py", runner=runner)
    source = event("experience.observed", "live drill", {"summary": "both embodiments answered"})
    preview = adapter.preview(source)
    receipt = adapter.apply(preview, actor="compaii@legion")
    assert calls[0][0:2] == ["memoryctl.py", "add-text"]
    assert source["event_id"] in " ".join(calls[0])
    assert receipt["authority"] == "daimon"
