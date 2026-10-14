"""Selected landing pointers keep the resource authority and reader fences."""

from copy import deepcopy
import urllib.request
import urllib.error
import pytest
from clusterctl.homes.service import Application, handler
from clusterctl.homes.sessions import Sessions
from clusterctl.homes.registry import version_digest
from test_home_gateway import Authority, selected, key, serving


def fixture(tmp_path, visibility="human"):
    authority = Authority()
    entry = selected(
        "a" * 32,
        visibility,
        files=["index.html", "journal/day/index.html"],
        title="Private fictional home",
    )
    state = {"schema": 1, "entries": [entry]}

    class Backend:
        def state(self):
            return state

    home = {
        "name": "Fixture",
        "public_url": "https://one.example",
        "vpn_url": "https://private-one.example",
        "owner_being_ref": "owner-one",
        "owner_revision": "v1",
        "owner_token_file": key(tmp_path, "owner", "fixture-owner"),
    }
    app = Application(
        {
            "homes": {"one": home},
            "content_public_url": "https://content.example",
            "content_vpn_url": "https://private-content.example",
        },
        authority,
        Sessions(tmp_path / "state"),
        backends={"one": Backend()},
    )
    app.owner("one", "fixture-owner", "sync", {})
    payload = {
        "expected_revision": 0,
        "resource": entry["artifact_ref"],
        "version": entry["version_ref"],
        "routes": {},
    }
    return app, state, entry, payload


def test_owner_selects_accepted_version_with_cas_history_and_explicit_clear(tmp_path):
    app, state, entry, payload = fixture(tmp_path)
    result = app.owner("one", "fixture-owner", "home-root-select", payload)
    assert (
        result["revision"] == 1
        and result["selection"]["version"] == entry["version_ref"]
    )
    assert (
        result["selection"]["routes"]["/journal/day/index.html"]
        == "journal/day/index.html"
    )
    assert (
        app.owner("one", "fixture-owner", "home-root-select", payload)["status"]
        == "unchanged"
    )
    with pytest.raises(ValueError, match="owner_denied"):
        app.owner("one", "not-an-owner", "home-root-select", payload)
    clear = {"expected_revision": 0, "resource": None, "version": None, "routes": {}}
    with pytest.raises(ValueError, match="revision_conflict"):
        app.owner("one", "fixture-owner", "home-root-select", clear)
    clear["expected_revision"] = 1
    assert (
        app.owner("one", "fixture-owner", "home-root-select", clear)["selection"]
        is None
    )
    with app.sessions.connect() as db:
        assert db.execute("SELECT count(*) FROM home_root_history").fetchone()[0] == 2


def test_root_read_requires_current_and_selected_version_audiences(tmp_path):
    app, state, entry, payload = fixture(tmp_path)
    app.owner("one", "fixture-owner", "home-root-select", payload)
    human = app.authority.actor("human-one")
    assert app.roots.entry("one", "/", human, False)
    assert not app.roots.entry("one", "/", None, False)
    assert not app.roots.entry("one", "/", app.authority.actor("human-two"), False)
    previous = deepcopy(entry)
    entry["versions"] = [previous]
    entry["visibility"] = "public"
    entry["updated_at"] = "new"
    entry["version_ref"] = version_digest(entry)
    app.owner("one", "fixture-owner", "sync", {})
    assert not app.roots.entry(
        "one", "/", None, False
    )  # Private old version stays private.
    assert (
        app.roots.entry("one", "/", human, False)[0]["version"]
        == previous["version_ref"]
    )
    # A serving manifest different from the committed projection cannot render.
    state["entries"][0]["title"] = "Unaccepted local edit"
    assert not app.roots.entry("one", "/", human, False)


def test_aliases_are_bounded_to_published_home_pages_and_cannot_override_authority_routes(
    tmp_path,
):
    app, state, entry, payload = fixture(tmp_path)
    for routes in [
        {"/access": "index.html"},
        {"/owner/one/sync": "index.html"},
        {"/blog/../secret.html": "index.html"},
        {"/blog/day.html": "secret.html"},
        {"/": "journal/day/index.html"},
    ]:
        with pytest.raises(ValueError, match="root_route"):
            app.owner(
                "one",
                "fixture-owner",
                "home-root-select",
                {**payload, "routes": routes},
            )
    assert app.roots.read("one")["revision"] == 0
    result = app.owner(
        "one",
        "fixture-owner",
        "home-root-select",
        {
            **payload,
            "routes": {
                "/blog/old-day.html": "journal/day/index.html",
                "/blog/": "index.html",
                "/blog/index.html": "index.html",
            },
        },
    )
    assert (
        result["selection"]["routes"]["/blog/old-day.html"] == "journal/day/index.html"
    )


def test_actual_root_http_hides_private_titles_until_identification_and_retains_sandbox(
    tmp_path,
):
    app, state, entry, payload = fixture(tmp_path)
    app.owner("one", "fixture-owner", "home-root-select", payload)
    person = app.authority.actor("human-one")
    token = app.sessions.issue(home="one", origin="https://one.example", subject=person)
    with serving(handler(app)) as url:

        def get(path, credential=""):
            headers = {"Host": "one.example", "X-Daimon-Home": "one"}
            if credential:
                headers["Authorization"] = "Bearer " + credential
            try:
                with urllib.request.urlopen(
                    urllib.request.Request(url + path, headers=headers)
                ) as response:
                    return response.status, response.read().decode()
            except urllib.error.HTTPError as response:
                return response.code, response.read().decode()

        code, body = get("/")
        assert (
            code == 200 and "Sign in" in body and "Private fictional home" not in body
        )
        code, body = get("/", token)
        assert code == 200 and "Private fictional home" in body and "home-root" in body
        assert 'sandbox="allow-scripts"' in body and "allow-same-origin" not in body
        assert "data-root-routes=" in body and "/home-root.js" in body
        code, body = get("/journal/day/index.html", token)
        assert code == 200 and "journal/day/index.html" in body
        assert get("/journal/day/index.html")[0] == 404
        assert get("/home", token)[0] == 200
