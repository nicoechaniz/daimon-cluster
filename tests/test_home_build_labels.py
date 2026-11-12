"""Requested UI provenance stays distinct from private content and launch grants."""

from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPRedirectHandler

import pytest

from clusterctl.homes.build_label import digest, stamp
from clusterctl.homes.service import handler
from clusterctl.homes.registry import version_digest
from tests.test_home_gateway import serving
from tests.test_home_passkeys import approved
from tests.test_home_passkeys import system  # noqa: F401, F811 - pytest fixture
from tests.test_home_launcher import populated, publish_owner_link


def test_ui_hash_follows_served_bytes_not_absolute_release_path(tmp_path):
    a = tmp_path / "one"
    b = tmp_path / "two"
    a.mkdir()
    b.mkdir()
    for root in (a, b):
        (root / "app.js").write_text("export const ui=1")
    before = digest([a / "app.js"])
    assert digest([b / "app.js"]) == before
    (b / "app.js").write_text("export const ui=2")
    assert digest([b / "app.js"]) != before
    body = stamp(b"<html><head></head><body><h1>Apps</h1></body></html>", before)
    assert body.count(b"data-app-build=") == 1 and before.encode() in body
    assert stamp(body, before) == body and b"/app-build.css?v=" in body
    with pytest.raises(ValueError):
        stamp(body, "<script>")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def test_stable_alias_observes_current_publication_and_never_accepts_a_destination(
    system,  # noqa: F811 - pytest fixture
):
    app, _ = system
    states = populated(app)
    entry = publish_owner_link(app, states, "https://service.example.test/first/")
    entry["application"] = {"schema": "dm.application/v1", "mode": "shared"}
    entry["version_ref"] = version_digest(entry)
    app.registry.register(
        home="one",
        owner="owner",
        state=states["one"],
        expected_revision=2,
        known_actor=app.authority.actor,
        known_tribe=lambda _: False,
    )
    opener = build_opener(NoRedirect)
    with serving(handler(app)) as base:
        alias = "/apps/open/" + entry["id"]

        def location(path, token=None):
            headers = {"Host": "one.example.test"}
            if token:
                headers["Cookie"] = "__Host-home=" + token
            with pytest.raises(HTTPError) as result:
                opener.open(Request(base + path, headers=headers))
            try:
                return result.value.code, result.value.headers.get("Location")
            finally:
                result.value.close()

        assert location(alias + "?url=https://untrusted.example/") == (
            302,
            "https://service.example.test/first/",
        )
        entry["url"] = "https://service.example.test/latest/"
        entry["version_ref"] = version_digest(entry)
        app.registry.register(
            home="one",
            owner="owner",
            state=states["one"],
            expected_revision=3,
            known_actor=app.authority.actor,
            known_tribe=lambda _: False,
        )
        assert location(alias) == (302, "https://service.example.test/latest/")
        entry["visibility"] = "human"
        entry["version_ref"] = version_digest(entry)
        app.registry.register(
            home="one",
            owner="owner",
            state=states["one"],
            expected_revision=4,
            known_actor=app.authority.actor,
            known_tribe=lambda _: False,
        )
        assert location(alias)[0] == 404
        token, _ = approved(app)
        assert location(alias, token) == (302, "https://service.example.test/latest/")
        app.sessions.revoke(home="one", token=token)
        assert location(alias, token)[0] == 404
        with opener.open(
            Request(base + "/apps/", headers={"Host": "one.example.test"})
        ) as response:
            assert b"data-app-build=" in response.read()
        with opener.open(
            Request(base + "/app-build.css", headers={"Host": "one.example.test"})
        ) as response:
            assert b".app-build" in response.read()
