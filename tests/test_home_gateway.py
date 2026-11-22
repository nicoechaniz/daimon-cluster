"""Shared authority, publication crash boundaries and actual HTTP audience reads."""

from contextlib import closing, contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import urllib.error
import urllib.request

import pytest

from clusterctl.homes.policy import Actor
from clusterctl.homes.registry import Registry, version_digest
from clusterctl.homes.service import Application, handler, return_target, auth_controls, key_page
from clusterctl.homes.sessions import Sessions


def test_trusted_related_work_navigation():
    """Opaque content may offer a link, never navigate or grant its destination."""
    import subprocess
    from pathlib import Path

    subprocess.run(['node', '--test', 'tests/js/home-related-work.cjs'],
                   cwd=Path(__file__).resolve().parents[1], check=True)


@contextmanager
def serving(cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def selected(ref, visibility, **fields):
    result = {
        "id": ref[0:8],
        "artifact_ref": ref,
        "visibility": visibility,
        "recipients": [],
        "tribes": [],
        "title": "Restricted title " + ref,
        "summary": "Description",
        "kind": "artifact",
        "revision": "1" * 64,
        "version_ref": ref + "1" * 32,
        "object": "object",
        "entrypoint": "index.html",
        "files": ["index.html", "data.txt"],
        "versions": [],
        **fields,
    }
    result["version_ref"] = version_digest(result)
    return result


def key(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(value)
    path.chmod(0o600)
    return str(path)


class Authority:
    def __init__(self):
        self.people = {
            ref: Actor(ref, kind, "v1", ref)
            for ref, kind in [
                ("owner-one", "being"),
                ("owner-two", "being"),
                ("human-one", "human"),
                ("human-two", "human"),
            ]
        }
        self.members = {"owner-one", "human-one"}

    def actors(self):
        return self.people

    def actor(self, ref):
        return self.people.get(ref)

    def paired_human(self, home):
        return {"one": "human-one", "two": "human-two"}.get(home)

    def tribes(self):
        return {"tribe": {"founder_principal_id": "owner-one"}}

    def tribe_member(self, home, tribe, actor):
        return tribe == "tribe" and actor.ref in self.members


def test_shared_registry_cas_ownership_and_failed_projection(tmp_path):
    sessions = Sessions(tmp_path / "authority")
    registry = Registry(sessions)
    state = {"schema": 1, "entries": [selected("a" * 32, "public")]}

    def register(home, revision, value):
        return registry.register(
            home=home,
            owner=home,
            state=value,
            expected_revision=revision,
            known_actor=lambda _: True,
            known_tribe=lambda _: True,
        )

    receipt = register("one", 0, state)
    assert receipt["revision"] == 1 and registry.current("one", observed_state=state)
    assert register("one", 0, state)["status"] == "unchanged"
    changed = deepcopy(state)
    changed["entries"][0]["visibility"] = "human"
    changed["entries"][0]["version_ref"] = version_digest(changed["entries"][0])
    assert registry.current("one", observed_state=changed) is None
    with pytest.raises(ValueError, match="revision_conflict"):
        register("one", 0, changed)
    assert register("one", 1, changed)["revision"] == 2
    assert registry.current("one", observed_state=state) is None
    with pytest.raises(ValueError, match="owner_conflict"):
        register("two", 0, state)
    assert registry.revision("two") == 0
    register("one", 2, {"schema": 1, "entries": []})
    # Removal never relinquishes identity to another owner; history stays.
    with pytest.raises(ValueError, match="owner_conflict"):
        register("two", 0, state)
    with closing(sessions.connect()) as db:
        assert (
            db.execute(
                "SELECT count(*) FROM publication_history WHERE home=?", ("one",)
            ).fetchone()[0]
            == 3
        )


def test_current_and_historical_audiences_both_required(tmp_path):
    authority = Authority()
    entry = selected("a" * 32, "public")
    old = selected("a" * 32, "human")
    old["revision"] = "0" * 64
    old["version_ref"] = version_digest(old)
    entry["versions"] = [old]
    state = {"schema": 1, "entries": [entry]}

    class Bytes:
        def state(self):
            return state

    app = Application(
        {"homes": {"one": {"owner_being_ref": "owner-one"}}},
        authority,
        Sessions(tmp_path),
        backends={"one": Bytes()},
    )
    app.registry.register(
        home="one",
        owner="owner-one",
        state=state,
        expected_revision=0,
        known_actor=authority.actor,
        known_tribe=lambda _: True,
    )
    assert app.selected("one", "a" * 32, "current", None)
    assert not app.selected("one", "a" * 32, old["version_ref"], None)
    assert app.selected(
        "one", "a" * 32, old["version_ref"], authority.actor("human-one")
    )
    # Even a matching retained manifest cannot transfer to another paired human.
    app.homes["one"]["owner_being_ref"] = "owner-two"
    assert not app.publication("one")["entries"]
    with pytest.raises(ValueError, match="owner_conflict"):
        Application(app.config, authority, app.sessions, backends=app.backends)
    app.homes["one"]["owner_being_ref"] = "owner-one"
    state["entries"][0]["visibility"] = "human"
    # Local changes alone cannot open or retain the old serving projection.
    assert not app.selected("one", "a" * 32, "current", authority.actor("human-one"))


def test_historical_grant_cannot_be_rewritten_by_local_publisher(tmp_path):
    authority = Authority()
    registry = Registry(Sessions(tmp_path))
    original = selected("a" * 32, "human")
    current = selected("a" * 32, "public")
    current["versions"] = [original]
    state = {"schema": 1, "entries": [current]}
    registry.register(
        home="one",
        owner="owner-one",
        state=state,
        expected_revision=0,
        known_actor=authority.actor,
        known_tribe=lambda _: True,
    )
    altered = deepcopy(state)
    altered["entries"][0]["versions"][0]["visibility"] = "public"
    with pytest.raises(ValueError, match="immutable_version"):
        registry.register(
            home="one",
            owner="owner-one",
            state=altered,
            expected_revision=1,
            known_actor=authority.actor,
            known_tribe=lambda _: True,
        )
    retained = registry.version(
        home="one", resource="a" * 32, version=original["version_ref"]
    )
    assert retained["visibility"] == "human"
    assert registry.revision("one") == 1


def test_artifact_child_read_follows_parent_revocation_and_clock(tmp_path):
    now = [1000]
    sessions = Sessions(tmp_path, clock=lambda: now[0])
    person = Actor("human-one", "human", "v1", "Person")
    origin = "https://one.example"
    content = "https://artifacts.example"
    parent = sessions.issue(home="one", origin=origin, subject=person, ttl=60)
    child = sessions.content_read(
        home="one",
        origin=origin,
        content_origin=content,
        resource="a" * 32,
        version="b" * 64,
        subject=person,
        parent_token=parent,
    )
    assert (
        sessions.resolve_content(child, content_origin=content)["actor"] == person.ref
    )
    assert sessions.resolve_content(child, content_origin=origin) is None
    with pytest.raises(ValueError):
        sessions.content_read(
            home="one",
            origin=origin,
            content_origin=content,
            resource="a" * 32,
            version="b" * 64,
            subject=person,
            parent_token="invalid",
        )
    sessions.revoke(home="one", token=parent)
    assert sessions.resolve_content(child, content_origin=content) is None
    public = sessions.content_read(
        home="one",
        origin=origin,
        content_origin=content,
        resource="a" * 32,
        version="b" * 64,
        subject=None,
        parent_token=None,
        ttl=30,
    )
    now[0] = 1100
    assert sessions.resolve_content(public, content_origin=content) is None
    now[0] = 1001
    assert sessions.resolve_content(public, content_origin=content) is None


def test_http_catalog_files_ranges_and_revocation_use_same_authority(tmp_path):
    authority = Authority()
    entries = [
        selected(chr(ord("a") + i) * 32, audience, **extra)
        for i, (audience, extra) in enumerate(
            [
                ("public", {}),
                ("vpn", {}),
                ("human", {}),
                ("individual", {"recipients": ["human-two"]}),
                ("tribe", {"tribes": ["tribe"]}),
            ]
        )
    ]
    # Private model discovery must use the same filtered projection as reads.
    entries[3]["files"].extend(["gallery.json", "review-live.json"])
    entries[3]["version_ref"] = version_digest(entries[3])
    media_file = "media/" + "e" * 64 + ".wav"
    entries[0]["files"].append(media_file)
    entries[0]["version_ref"] = version_digest(entries[0])
    state = {"schema": 1, "entries": entries}

    class Origin(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            assert self.headers.get("Authorization") == "Bearer content-reader"
            body = (
                json.dumps(state).encode()
                if self.path == "/_home/state"
                else b"<p>Selected bytes</p>"
            )
            code = 200
            if self.headers.get("Range"):
                body = body[:4]
                code = 206
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            if self.path != "/_home/state":
                self.send_header("X-Home-Version", self.path.split("/")[4])
            self.send_header(
                "Content-Type",
                "application/json" if self.path == "/_home/state" else "text/html",
            )
            if code == 206:
                self.send_header("Content-Range", "bytes 0-3/21")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

    with serving(Origin) as backend:
        home = {
            "backend": backend,
            "gateway_token_file": key(tmp_path, "reader", "content-reader"),
            "owner_token_file": key(tmp_path, "owner", "home-owner"),
            "owner_being_ref": "owner-one",
            "owner_revision": "v1",
            "public_url": "https://one.example",
            "vpn_url": "https://private-one.example",
            "name": "Home",
        }
        app = Application(
            {"homes": {"one": home}, "content_public_url": "https://content.example", "content_vpn_url": "https://private-content.example"}, authority, Sessions(tmp_path / "state")
        )
        app.owner("one", "home-owner", "sync", {})
        token = app.sessions.issue(
            home="one", origin=home["public_url"], subject=authority.actor("human-one")
        )
        other = app.sessions.issue(
            home="one", origin=home["public_url"], subject=authority.actor("human-two")
        )
        with serving(handler(app)) as gateway:

            def get(path, token="", vpn=False, method="GET", extra=None):
                headers = {
                    "Host": "private-one.example" if vpn else "one.example",
                    "X-Daimon-Home": "one",
                    "X-Daimon-Vpn": "1" if vpn else "0",
                }
                if token:
                    headers["Authorization"] = "Bearer " + token
                headers.update(extra or {})
                try:
                    with urllib.request.urlopen(
                        urllib.request.Request(
                            gateway + path, headers=headers, method=method
                        )
                    ) as response:
                        return response.status, response.read(), response.headers
                except urllib.error.HTTPError as error:
                    return error.code, error.read(), error.headers

            def visible(credential="", vpn=False):
                return json.loads(get("/catalog.json", credential, vpn)[1])["entries"]

            assert not any(e["model_review"] for e in visible())
            assert not any(e["model_review"] for e in visible(token))
            reviews = [e for e in visible(other) if e["model_review"]]
            assert [e["resource_ref"] for e in reviews] == ["dm:resource:v1:" + "d" * 32]
            assert len(visible()) == 1
            assert len(visible(vpn=True)) == 2
            assert {e["visibility"] for e in visible(token)} == {
                "public",
                "human",
                "tribe",
            }
            assert {e["visibility"] for e in visible(other)} == {"public", "individual"}
            assert b"Restricted title c" not in get("/")[1]
            # Work presentation uses the same selected-resource evaluator and
            # isolated child context, with no publication controls around it.
            view = "/view/" + "a" * 32
            assert b"Selected files" in get(view)[1]
            code, body, _ = get(view + "?display=work")
            assert code == 200 and b'class="work-view"' in body
            assert b'sandbox="allow-scripts"' in body
            assert b"https://content.example/r/" in body
            assert b"Selected files" not in body and b"Versions available" not in body
            assert b"/work-view.js" in body
            assert b"/work-live-review.js" in body
            assert b'data-live-review="current"' in body
            assert b'data-live-review="pinned"' in get(view + "?display=work&version=" + entries[0]["version_ref"])[1]
            assert ("data-download-root=\"/works/" + "a" * 32 + "/" + entries[0]["version_ref"] + "/\"").encode() in body
            assert media_file.encode() in body
            private_view = "/view/" + "c" * 32 + "?display=work"
            assert get(private_view)[0] == 404
            assert get(private_view, token)[0] == 200
            assert get(view + "?display=unknown")[0] == 404
            # Project is a navigation candidate, validated later by the reader catalog.
            assert get(view + "?display=work&project=" + "a" * 32)[0] == 200
            assert get(view + "?display=work&project=../private")[0] == 404
            assert get(view + "?display=work&project=" + "a" * 32 + "&project=" + "b" * 32)[0] == 404
            assert get(view + "?display=work&display=details")[0] == 404
            assert get(view + "?display=work&version=" + "0" * 64)[0] == 404
            # Trusted application descriptors reuse this exact visitor's grant
            # and immutable version, while leaving active content isolated.
            review = '/access/review-source/' + 'd' * 32 + '/' + entries[3]['version_ref']
            assert get(review)[0] == 404
            assert get(review, token)[0] == 404
            code, payload, headers = get(review, other)
            descriptor = json.loads(payload)
            assert code == 200 and headers['Cache-Control'] == 'no-store'
            assert descriptor['schema'] == 'dm.home-review-source/v1'
            assert descriptor['version'] == entries[3]['version_ref']
            assert descriptor['frame']['sandbox'] == 'allow-scripts'
            assert descriptor['frame']['src'].startswith('https://content.example/r/')
            assert descriptor['adapter_handshake'] == 'required'
            assert 'recipients' not in descriptor and 'title' not in descriptor
            scope = {'actor_ref': 'human-two', 'resource': 'd' * 32, 'version': entries[3]['version_ref']}
            decision = app.owner('one', 'home-owner', 'check-review-access', scope)
            assert decision == {'schema': 'dm.review-access/v1', **scope, 'allowed': True}
            assert not app.owner('one', 'home-owner', 'check-review-access', {**scope, 'actor_ref': 'human-one'})['allowed']
            assert not app.owner('one', 'home-owner', 'check-review-access', {**scope, 'version': '0' * 64})['allowed']
            with pytest.raises(ValueError):
                app.owner('one', other, 'check-review-access', scope)
            with pytest.raises(ValueError):
                app.owner('one', 'home-owner', 'check-review-access', {**scope, 'actor_ref': 'human-one', 'url': 'https://other.example'})
            assert get(review.replace(entries[3]['version_ref'], 'current'), other)[0] == 404
            assert get(review + '?url=https://other.example', other)[0] == 404
            assert get('/access/review-source/' + 'a' * 32 + '/' + entries[0]['version_ref'])[0] == 404
            # Expiring the parent reader also prevents minting a new renderer
            # context; the table/application cannot substitute its own identity.
            assert get('/access/logout', other, method='POST', extra={
                'Origin': home['public_url'], 'Content-Length': '0'})[0] == 200
            assert get(review, other)[0] == 404
            assert get("/work-view.js")[2]["Content-Type"].startswith("text/javascript")
            assert get("/work-live-review.js")[2]["Content-Type"].startswith("text/javascript")
            # Trusted pages preserve same-origin browser form proofs without
            # disclosing referrers to another origin. Uploaded bytes retain
            # their independent no-referrer/sandbox policy below.
            assert get('/access')[2]['Referrer-Policy'] == 'same-origin'
            path = "/works/" + "c" * 32 + "/current/index.html"
            assert get(path)[0] == 404 and get(path, method="HEAD")[0] == 404
            assert get(path, extra={"Range": "bytes=0-3"})[0] == 404
            code, body, headers = get(path, token, extra={"Range": "bytes=0-3"})
            assert code == 206 and body == b"<p>S"
            assert headers["X-Home-Version"] == entries[2]["version_ref"]
            assert "sandbox" in headers["Content-Security-Policy"]
            assert headers["Content-Disposition"] == "attachment"
            assert headers['Referrer-Policy'] == 'no-referrer'
            assert "default-src 'none'" in headers["Content-Security-Policy"]
            assert get(path, token, extra={"Origin": "null"})[0] == 404
            assert get("/_home/state", token)[0] == 404
            assert get(path, token, extra={"Host": "other.example"})[0] == 404
            authority.members.clear()
            assert {e["visibility"] for e in visible(token)} == {"public", "human"}
            assert get('/access/logout', token, method='POST', extra={
                'Origin':'null','Content-Length':'0'})[0] == 403
            assert get(path, token)[0] == 200
            assert get('/access/logout', token, method='POST', extra={
                'Origin':'https://one.example','Content-Length':'0'})[0] == 200
            assert get(path, token)[0] == 404
            # A browser form navigates back to the current anonymous home,
            # retaining API JSON compatibility and private-read revocation.
            browser_token = app.sessions.issue(
                home="one", origin=home["public_url"],
                subject=authority.actor("human-one"),
            )
            assert get(path, browser_token)[0] == 200
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None
            request = urllib.request.Request(gateway + '/access/logout', data=b'',
                headers={'Host':'one.example', 'Origin':'https://one.example',
                         'Accept':'text/html', 'Authorization':'Bearer ' + browser_token})
            with pytest.raises(urllib.error.HTTPError) as redirect:
                urllib.request.build_opener(NoRedirect).open(request)
            assert redirect.value.code == 303
            assert redirect.value.headers['Location'] == '/?signed-out=1'
            assert 'Max-Age=0' in redirect.value.headers['Set-Cookie']
            assert redirect.value.headers['Cache-Control'] == 'no-store'
            redirect.value.close()
            assert get(path, browser_token)[0] == 404
            landing = get('/?signed-out=1')[1]
            assert 'You’re signed out'.encode() in landing
            assert b'Restricted title c' not in landing
            # A local publisher changing a public object without registering it
            # cannot retain access through either direct or legacy URLs.
            state["entries"][0]["visibility"] = "human"
            assert visible() == []
            assert get("/artifacts/aaaaaaaa/index.html")[0] == 404


def test_human_endpoint_reuses_current_pair_and_routes_without_identity_or_delivery(tmp_path):
    authority = Authority()
    homes = {
        name: {
            "owner_being_ref": "owner-" + name,
            "owner_revision": "v1",
            "owner_token_file": key(tmp_path, name, "credential-" + name),
            "public_url": "https://" + name + ".example",
        }
        for name in ("one", "two")
    }
    app = Application(
        {"homes": homes}, authority, Sessions(tmp_path / "state"),
        backends={name: object() for name in homes},
        miniapp_receivers={"one": {"conversation": "https://one.example/interaction/"}},
    )
    result = app.owner("one", "credential-one", "human-endpoint", {})
    assert result["scope"] == "/human"
    assert result["owner_being_ref"] == "owner-one"
    assert result["human"]["ref"] == "human-one"
    assert result["applications"] == [{"capability": "conversation", "url": "https://one.example/interaction/", "state": "configured"}]
    assert result["human_presence"] == "not-observed"
    assert result["delivery"] == "not-requested"
    assert result["native_membership"] == "not-implied"
    assert result["route_state"] == "configured"
    assert "credential" not in json.dumps(result)
    # No fallback to another home or an author's bot when this pair has no route.
    other = app.owner("two", "credential-two", "human-endpoint", {})
    assert other["human"]["ref"] == "human-two"
    assert other["applications"] == [] and other["route_state"] == "unconfigured"
    for token in ("", "reader", "credential-two"):
        with pytest.raises(ValueError):
            app.owner("one", token, "human-endpoint", {})
    for payload in ({"home": "two"}, [], None):
        with pytest.raises(ValueError, match="human_endpoint_takes_no_selector"):
            app.owner("one", "credential-one", "human-endpoint", payload)
    # The current authority, not a retained endpoint response, selects the pair.
    authority.paired_human = lambda _: "human-two"
    assert app.owner("one", "credential-one", "human-endpoint", {})["human"]["ref"] == "human-two"
    del authority.people["human-two"]
    with pytest.raises(ValueError, match="home_pairing_unavailable"):
        app.owner("one", "credential-one", "human-endpoint", {})
    authority.paired_human = lambda _: "owner-one"
    with pytest.raises(ValueError, match="home_pairing_unavailable"):
        app.owner("one", "credential-one", "human-endpoint", {})


def test_owner_identity_approval_and_shared_roster_are_not_reader_powers(tmp_path):
    authority = Authority()

    class Empty:
        def state(self):
            return {"schema": 1, "entries": []}

    homes = {
        name: {
            "owner_being_ref": "owner-" + name,
            "owner_revision": "v1",
            "owner_token_file": key(tmp_path, name, "credential-" + name),
        }
        for name in ("one", "two")
    }
    app = Application(
        {"homes": homes},
        authority,
        Sessions(tmp_path / "state"),
        backends={name: Empty() for name in homes},
    )
    request, proof = app.sessions.request(home="one", origin="https://one.example")
    app.owner(
        "two",
        "credential-two",
        "approve-browser",
        {"home": "one", "code": request["code"]},
    )
    _, token = app.sessions.claim(
        home="one",
        origin="https://one.example",
        code=request["code"],
        proof=proof,
        current_actor=app.policy.current,
    )
    assert app.identity(token, "one", "https://one.example").ref == "human-two"
    with pytest.raises(ValueError):
        app.owner("one", token, "sync", {})
    with pytest.raises(ValueError):
        app.owner("one", "credential-two", "sync", {})
    payload = {
        "tribe": "tribe",
        "expected_revision": 0,
        "readers": ["human-two"],
        "revoked": False,
        "expires_at_ms": None,
    }
    with pytest.raises(ValueError, match="founder_required"):
        app.owner("two", "credential-two", "tribe-readers", payload)
    app.owner("one", "credential-one", "tribe-readers", payload)
    assert app.registry.rosters()["tribe"]["readers"] == ["human-two"]
    payload.update(expected_revision=1, readers=[], revoked=True)
    app.owner("one", "credential-one", "tribe-readers", payload)
    assert app.registry.rosters()["tribe"]["revoked"] is True


@pytest.mark.parametrize('destination', ['https://other.example/', '//other.example/',
    '/\\other.example/', '/%5cother.example/', '/%2fother.example/', '/hello%0a'])
def test_browser_return_cannot_escape_home_origin(destination):
    with pytest.raises(ValueError, match='invalid_home_return'):
        return_target(destination)


def test_direct_passkey_control_and_registration_refresh_notice():
    from types import SimpleNamespace
    controls, scripts = auth_controls(None, False, True, '/view/resource?version=older')
    assert 'data-reload="true"' in controls and '>Sign in</button>' in controls
    assert 'data-code-login' in controls and '/passkeys.js' in scripts
    app = SimpleNamespace(passkeys=SimpleNamespace(list=lambda subject: [
        {'id':'credential', 'label':'My phone'}]))
    page = key_page(app, Actor('human', 'human', 'v1', 'Human'), registered=True)
    assert b'Access key saved.' in page and b'data-revoke="credential"' in page


def test_browser_code_claim_returns_to_same_local_destination(tmp_path):
    class Empty:
        def state(self): return {'schema':1, 'entries':[]}
    authority = Authority()
    home = {'owner_being_ref':'owner-one', 'owner_revision':'v1',
        'public_url':'https://one.example', 'vpn_url':'https://private-one.example',
        'name':'Home'}
    app = Application({'homes':{'one':home}}, authority, Sessions(tmp_path/'state'),
                      backends={'one':Empty()})
    request, proof = app.sessions.request(home='one',origin=home['public_url'])
    app.sessions.approve(home='one',code=request['code'],subject=authority.actor('human-one'))
    from urllib.parse import urlencode
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    with serving(handler(app)) as root:
        payload = urlencode({'code':request['code'],'return':'/view/resource?version=older#part'}).encode()
        headers = {'Host':'one.example','Origin':home['public_url'],
                   'Accept':'text/html','Cookie':'__Host-home-proof='+proof}
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.build_opener(NoRedirect).open(urllib.request.Request(
                root+'/access/claim',data=payload,headers=headers))
        try:
            assert err.value.code==303
            assert err.value.headers['Location']=='/view/resource?version=older#part'
            assert '__Host-home=' in err.value.headers['Set-Cookie']
        finally:
            err.value.close()


def test_owner_publication_uses_one_request_local_actor_catalog(tmp_path):
    class CountedAuthority(Authority):
        def __init__(self):
            super().__init__()
            self.reads = 0

        def actors(self):
            self.reads += 1
            return dict(self.people)

    authority = CountedAuthority()
    entry = selected('f' * 32, 'individual', recipients=['owner-one', 'human-one', 'human-two'])

    class Bytes:
        def state(self):
            return {'schema': 1, 'entries': [entry]}

    home = {'owner_being_ref': 'owner-one', 'owner_revision': 'v1',
            'owner_token_file': key(tmp_path, 'owner', 'credential')}
    app = Application({'homes': {'one': home}}, authority,
                      Sessions(tmp_path / 'state'), backends={'one': Bytes()})
    audience = {k: entry[k] for k in ('visibility', 'recipients', 'tribes')}
    app.owner('one', 'credential', 'validate-audience', audience)
    assert authority.reads == 1
    app.owner('one', 'credential', 'sync', {})
    assert authority.reads == 2
    # No cached grant survives a later request. Actual audience validation still
    # rejects a recipient that disappeared after the preceding publication.
    del authority.people['human-two']
    with pytest.raises(ValueError):
        app.owner('one', 'credential', 'sync', {})
    assert authority.reads == 3


def test_http_proof_snapshot_reuses_actor_reads_but_not_later_revocation(tmp_path, monkeypatch):
    from clusterctl.homes.authority import NativeAuthority
    from tests.test_home_passkeys import system, approved
    # Use the existing gateway/session/publication fixture, not a second auth path.
    app, _ = system.__wrapped__(tmp_path)
    class Proofs(NativeAuthority):
        def __init__(self, existing):
            super().__init__(tmp_path/'bindings', tmp_path/'relationships', app.homes)
            self.people = existing.people
            self.loads = 0
            self.paired_human, self.tribe_member = existing.paired_human, existing.tribe_member
        def _actors(self):
            self.loads += 1
            if getattr(self, 'invalid', False):
                raise ValueError('home_actor_authority_source_stale')
            return dict(self.people)
    authority = Proofs(app.authority)
    app.authority = authority
    app.policy.actor = authority.actor
    def login_route(request, application, method, *args):
        assert authority._read_snapshot.get() is None
        if request.path == '/signin':
            request.respond(200, {'login': method})
            return True
        return False
    monkeypatch.setattr('clusterctl.homes.login.routes', login_route)
    app.sso = object()
    token, _ = approved(app)
    state = {'schema':1,'entries':[
        selected(f'{i:032x}', 'individual', recipients=['human']) for i in range(1,21)]}
    app.backends['one'].state = lambda: state
    # Commit the exact fixture state through its actual owner publication path.
    app.registry.register(home='one',owner=app.homes['one']['owner_being_ref'],
        state=state,expected_revision=0, known_actor=authority.actor, known_tribe=lambda _: False)
    from http.client import HTTPConnection
    from urllib.parse import urlsplit
    with serving(handler(app)) as base:
        connection = HTTPConnection(urlsplit(base).netloc)
        headers = {'Host':'one.example.test','Cookie':'__Host-home='+token}
        before = authority.loads
        connection.request('GET','/catalog.json',headers=headers)
        response=connection.getresponse();body=json.loads(response.read())
        assert response.status==200 and len(body['entries'])==20
        assert authority.loads-before==1
        authority.people.pop('human')
        connection.request('GET','/catalog.json',headers=headers)
        response=connection.getresponse();body=json.loads(response.read())
        assert response.status==200 and body['entries']==[]
        assert authority.loads-before==2
        connection.request('HEAD','/catalog.json',headers=headers)
        response=connection.getresponse();assert response.status==200 and response.read()==b''
        assert authority.loads-before==3
        authority.invalid = True
        connection.request('GET','/catalog.json',headers=headers)
        response=connection.getresponse();response.read()
        assert response.status != 200  # No stale successful fallback.
        for method in ('GET', 'POST'):
            connection.request(method,'/signin',headers=headers)
            response=connection.getresponse();response.read()
            assert response.status==200
        connection.close()


def test_slow_connections_expire_without_blocking_authorized_reads(tmp_path):
    """Exercise both actual listeners, their real 30s inactivity bound and cleanup."""
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import ExitStack
    from http.client import HTTPConnection
    import socket
    import time
    from urllib.parse import urlsplit
    from tests.test_home_passkeys import system, approved

    app, _ = system.__wrapped__(tmp_path)
    token, _ = approved(app)
    finished = []
    observed_timeouts = []
    active = set()
    lock = threading.Lock()

    def tracked(owner):
        class Tracked(handler(app, owner=owner)):
            def setup(self):
                super().setup()
                with lock:
                    observed_timeouts.append(self.connection.gettimeout())
                    active.add(self.client_address)

            def finish(self):
                try:
                    super().finish()
                finally:
                    with lock:
                        active.discard(self.client_address)
                        finished.append(self.client_address)
        return Tracked

    with ExitStack() as stack:
        viewer = urlsplit(stack.enter_context(serving(tracked(False)))).netloc
        owner = urlsplit(stack.enter_context(serving(tracked(True)))).netloc
        slow = []
        for target in (viewer, owner):
            host, port = target.split(':')
            for payload in (
                b'GET / HTTP/1.1\r\nHost: one.example.test\r\nX-Incomplete:',
                b'GET / HTTP/1.1\r\nHost: one.example.test\r\nX-Other:',
                b'POST /access/claim HTTP/1.1\r\nHost: one.example.test\r\nContent-Length: 16\r\n\r\nx',
            ):
                connection = stack.enter_context(closing(socket.create_connection((host, int(port)), timeout=3)))
                slow.append(connection.getsockname())
                connection.sendall(payload)
        start = time.monotonic()

        def read(index):
            target = owner if index % 4 == 0 else viewer
            with closing(HTTPConnection(target, timeout=5)) as connection:
                connection.request('GET', '/catalog.json', headers={
                    'Host': 'one.example.test', 'Cookie': '__Host-home=' + token})
                response = connection.getresponse()
                body = json.loads(response.read())
                assert response.status == (404 if target == owner else 200)
                if target == viewer:
                    assert isinstance(body['entries'], list)
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(read, range(16)))
        # Fast reads must finish while the deliberately incomplete clients still
        # occupy their handlers, rather than waiting for the inactivity deadline.
        assert time.monotonic() - start < 10
        with lock:
            assert set(slow).issubset(active)

        deadline = start + 35
        while time.monotonic() < deadline:
            with lock:
                if set(slow).issubset(finished):
                    break
            time.sleep(0.05)
        with lock:
            assert set(slow).issubset(finished)
            assert not active
            assert observed_timeouts and set(observed_timeouts) == {30.0}


def test_installed_public_assets_ignore_identity_but_keep_origin_and_private_checks(tmp_path, monkeypatch):
    from http.client import HTTPConnection
    from urllib.parse import urlsplit
    from tests.test_home_passkeys import system, approved

    app, _ = system.__wrapped__(tmp_path)
    token, _ = approved(app)
    original = app.identity
    calls = []

    def identity(*args):
        calls.append(args)
        return original(*args)
    monkeypatch.setattr(app, 'identity', identity)
    assets = ['/home.css', '/work-live-review.js', '/work-view.js', '/home-style.js',
              '/artifact-style.js', '/home-miniapp-login.js', '/access-client.js',
              '/passkeys.js', '/fonts/space-grotesk-latin.woff2']
    with serving(handler(app)) as base:
        with closing(HTTPConnection(urlsplit(base).netloc, timeout=5)) as connection:
            def read(path, extra=None, method='GET'):
                connection.request(method, path, headers={'Host':'one.example.test', **(extra or {})})
                response = connection.getresponse()
                return response.status, response.read(), dict(response.getheaders())
            for path in assets:
                anonymous = read(path)
                assert anonymous[0] == 200
                for credentials in ({'Cookie':'__Host-home='+token},
                                    {'Authorization':'Bearer '+token},
                                    {'Cookie':'__Host-home=untrusted'}):
                    response = read(path, credentials)
                    assert response[:2] == anonymous[:2]
                head = read(path, {'Cookie':'__Host-home='+token}, 'HEAD')
                assert head[0] == 200 and head[1] == b''
                assert head[2]['Content-Length'] == str(len(anonymous[1]))
            assert calls == []  # Public installed bytes need no session/authority lookup.

            for headers in ({'Host':'unknown.example.test'},
                            {'Origin':'https://other.example.test'},
                            {'X-Daimon-Home':'unknown'}):
                assert read('/work-live-review.js', headers)[0] == 404
            assert calls == []

            # Personal identity is still resolved, including after revocation.
            cookie = {'Cookie':'__Host-home='+token}
            status, body, _ = read('/access/status', cookie)
            assert status == 200 and json.loads(body)['signed_in'] is True
            assert len(calls) == 1
            app.authority.people.pop('human')
            status, body, _ = read('/access/status', cookie)
            assert status == 200 and json.loads(body)['signed_in'] is False
            assert len(calls) == 2
            assert read('/access/identity', cookie)[0] == 401
            assert len(calls) == 3


@pytest.mark.parametrize('mode', ['conditional', 'old-broker', 'changed-body'])
def test_backend_conditional_wire_and_legacy_pairs(tmp_path, mode):
    from clusterctl.homes.registry import projection_digest
    from clusterctl.homes.service import Backend
    state = {'schema': 1, 'entries': []}
    digest = projection_digest(state)
    calls = []
    class Origin(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            assert self.headers.get('Authorization') == 'Bearer fixture'
            conditional = self.headers.get('If-None-Match')
            calls.append(conditional)
            tag = '"sha256-' + digest + '"'
            if mode == 'conditional' and conditional == tag:
                self.send_response(304);self.send_header('ETag', tag);self.end_headers();return
            body = json.dumps(state if mode != 'changed-body' else {'schema': 1, 'entries': [], 'changed': True}).encode()
            self.send_response(200);self.send_header('Content-Length', str(len(body)));self.end_headers();self.wfile.write(body)
    with serving(Origin) as url:
        backend = Backend({'backend': url, 'gateway_token_file': key(tmp_path, 'key', 'fixture')})
        result = backend.state_if_changed(digest, timeout=2)
        if mode == 'conditional': assert result is Backend.NOT_MODIFIED
        elif mode == 'old-broker': assert result == state
        else: assert result != state
        assert backend.state(timeout=2) is not None  # Old client/new broker uses full200.
    assert calls == ['"sha256-' + digest + '"', None]


@pytest.mark.parametrize('etag', [None, 'W/"sha256-' + 'a'*64 + '"', '"sha256-' + 'b'*64 + '"', 'duplicate'])
def test_backend_rejects_bad304_and_closes_response(tmp_path, monkeypatch, etag):
    from clusterctl.homes.service import Backend
    class Origin(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            self.send_response(304)
            if etag is not None:
                self.send_header('ETag', etag)
                if etag == 'duplicate': self.send_header('ETag', '"sha256-' + 'a'*64 + '"')
            self.end_headers()
    with serving(Origin) as url:
        backend = Backend({'backend': url, 'gateway_token_file': key(tmp_path, 'key', 'fixture')})
        errors = [];original = backend.open
        def opened(*args, **kwargs):
            try: return original(*args, **kwargs)
            except urllib.error.HTTPError as error: errors.append(error);raise
        monkeypatch.setattr(backend, 'open', opened)
        with pytest.raises(ValueError, match='invalid_state_digest_observation'):
            backend.state_if_changed('a'*64, timeout=2)
        assert errors and errors[0].fp.closed
        with pytest.raises(urllib.error.HTTPError) as result: backend.state(timeout=2)
        result.value.close()  # An unsolicited304 never authorizes reuse.


@pytest.mark.parametrize('change', ['unsynced-body', 'registry-update', 'withdrawal', 'owner', 'revocation', 'stable'])
def test_conditional_observation_preserves_final_registry_and_permission_checks(tmp_path, change):
    from clusterctl.homes.registry import projection_digest
    from clusterctl.homes.service import Backend
    authority = Authority()
    state = {'schema': 1, 'entries': [selected('a'*32, 'individual', recipients=['human-one'])]}
    changed = deepcopy(state);changed['entries'][0]['title'] = 'New checkpoint'
    changed['entries'][0]['version_ref'] = version_digest(changed['entries'][0])
    calls = []
    class Origin:
        def state_if_changed(self, digest, *, timeout=15):
            calls.append((digest, timeout))
            if change == 'unsynced-body': return changed
            if change in ('registry-update', 'withdrawal'):
                register(changed if change == 'registry-update' else {'schema': 1, 'entries': []}, 1)
            elif change == 'owner': app.homes['one']['owner_being_ref'] = 'owner-two'
            elif change == 'revocation': authority.people['human-one'] = Actor('human-one', 'human', 'v1', 'Disabled', enabled=False)
            return Backend.NOT_MODIFIED
    app = Application({'homes': {'one': {'owner_being_ref': 'owner-one'}}}, authority, Sessions(tmp_path), backends={'one': Origin()})
    def register(value, revision):
        return app.registry.register(home='one', owner='owner-one', state=value, expected_revision=revision, known_actor=authority.actor, known_tribe=lambda _: True)
    register(state, 0)
    human = authority.actor('human-one')
    if change == 'stable': assert app.entries('one', human)
    else: assert not app.entries('one', human)
    assert calls == [(projection_digest(state), 15)]


@pytest.mark.parametrize('body,status,reason', [(b'x'*65, 200, 'home_manifest_too_large'), (b'{', 200, ''), (b'{}', 202, 'invalid_state_observation_status')])
def test_conditional200_preserves_body_and_status_bounds(tmp_path, monkeypatch, body, status, reason):
    from clusterctl.homes import service
    monkeypatch.setattr(service, 'MAX_MANIFEST', 64)
    class Origin(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            self.send_response(status);self.send_header('Content-Length', str(len(body)))
            # A matching ETag never substitutes for validating a200 body.
            self.send_header('ETag', '"sha256-' + 'a'*64 + '"');self.end_headers();self.wfile.write(body)
    with serving(Origin) as url:
        backend = service.Backend({'backend': url, 'gateway_token_file': key(tmp_path, 'key', 'fixture')})
        with pytest.raises(ValueError, match=reason or None): backend.state_if_changed('a'*64, timeout=2)


def test_http_null200_never_acknowledges_committed_projection(tmp_path):
    from clusterctl.homes.service import Backend
    from clusterctl.homes.registry import projection_digest
    state = {'schema': 1, 'entries': [selected('a'*32, 'public')]}
    digest = projection_digest(state)
    class Origin(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            assert self.headers['If-None-Match'] == '"sha256-' + digest + '"'
            self.send_response(200);self.send_header('Content-Length', '4')
            self.send_header('ETag', '"sha256-' + digest + '"');self.end_headers();self.wfile.write(b'null')
    authority = Authority()
    with serving(Origin) as url:
        backend = Backend({'backend': url, 'gateway_token_file': key(tmp_path, 'key', 'fixture')})
        app = Application({'homes': {'one': {'owner_being_ref': 'owner-one'}}}, authority, Sessions(tmp_path/'authority'), backends={'one': backend})
        app.registry.register(home='one', owner='owner-one', state=state, expected_revision=0, known_actor=authority.actor, known_tribe=lambda _: True)
        assert not app.publication('one', timeout=2)['entries']


def test_login_only_home_has_no_artifact_broker(tmp_path):
    from clusterctl.homes.service import Backend
    authority = Authority()
    home = {"backend": None, "gateway_token_file": key(tmp_path, "reader", "reader"),
            "owner_token_file": key(tmp_path, "owner", "owner-key"),
            "owner_being_ref": "owner-one", "owner_revision": "v1",
            "public_url": "https://one.example", "vpn_url": "https://private-one.example",
            "name": "Login only"}
    backend = Backend(home)
    assert backend.state() == {"schema": 1, "entries": []}
    assert backend.state_if_changed("a" * 64) == backend.state()
    with pytest.raises(ValueError, match="home_artifact_backend_unconfigured"):
        backend.open("/private-history")
    app = Application({"homes": {"one": home}, "content_public_url": "https://content.example",
                       "content_vpn_url": "https://private-content.example"},
                      authority, Sessions(tmp_path / "state"))
    app.owner("one", "owner-key", "sync", {})
    assert app.owner("one", "owner-key", "human-endpoint", {})["human"]["ref"] == "human-one"
    token = app.sessions.issue(home="one", origin=home["public_url"], subject=authority.actor("human-one"))
    assert app.identity(token, "one", home["public_url"]).ref == "human-one"
    assert app.entries("one", authority.actor("human-one")) == []
    assert app.selected("one", "a" * 32, "current", authority.actor("human-one")) is None
    with serving(handler(app)) as gateway:
        with urllib.request.urlopen(urllib.request.Request(gateway + "/access/identity",
                 headers={"Host": "one.example", "Cookie": "__Host-home=" + token})) as response:
            assert response.status == 200
            assert json.load(response)["actor"]["ref"] == "human-one"


def test_preapproved_entry_link_keeps_pair_origin_and_current_authority(tmp_path):
    from urllib.parse import urlsplit, parse_qs
    now = [1000]
    authority = Authority()
    homes = {n: {'owner_being_ref':'owner-'+n, 'owner_revision':'v1',
        'owner_token_file':key(tmp_path,n,'credential-'+n),
        'public_url':'https://'+n+'.example', 'vpn_url':'https://private-'+n+'.example',
        'name':n} for n in ('one','two')}
    class Empty:
        def state(self):return {'schema':1,'entries':[]}
    app=Application({'homes':homes},authority,Sessions(tmp_path/'state',clock=lambda:now[0]),
        backends={n:Empty() for n in homes})
    with pytest.raises(ValueError):app.owner('one','credential-two','entry-link',{'return':'/interaction/'})
    with pytest.raises(ValueError):app.owner('one','credential-one','entry-link',{'return':'//foreign.example/'})
    link=app.owner('one','credential-one','entry-link',{'return':'/interaction/?view=conversation'})
    assert link['expires_at']==1000+604800
    parsed=urlsplit(link['url']);assert not parsed.query and parsed.path=='/access/entry'
    payload={k:v[0] for k,v in parse_qs(parsed.fragment).items()}
    with serving(handler(app)) as root:
        with urllib.request.urlopen(urllib.request.Request(root+'/access/entry',headers={'Host':'one.example'})) as r:
            assert r.status==200 and b'/access/entry.js' in r.read()
        def claim(host,origin):
            return urllib.request.urlopen(urllib.request.Request(root+'/access/entry',data=json.dumps(payload).encode(),headers={'Host':host,'Origin':origin,'Content-Type':'application/json'}))
        with pytest.raises(urllib.error.HTTPError):claim('two.example','https://two.example')
        with pytest.raises(urllib.error.HTTPError):claim('one.example','https://foreign.example')
        with claim('one.example','https://one.example') as r:
            assert json.load(r)['return']=='/interaction/?view=conversation'
            cookies=r.headers.get_all('Set-Cookie');assert all('HttpOnly' in c and 'Secure' in c for c in cookies)
            token=next(c.split(';')[0].split('=',1)[1] for c in cookies if c.startswith('__Host-home='))
            assert app.identity(token,'one','https://one.example').ref=='human-one'
            assert app.identity(token,'two','https://two.example') is None
        # Same exact proof retries its existing receipt, never another actor/session.
        with claim('one.example','https://one.example') as r:assert json.load(r)['status']=='approved'
        authority.people['human-one']=Actor('human-one','human','v2','Changed')
        with pytest.raises(urllib.error.HTTPError):claim('one.example','https://one.example')
        now[0]+=604801
        with pytest.raises(urllib.error.HTTPError):claim('one.example','https://one.example')
