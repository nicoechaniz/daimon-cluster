"""Stable link entrances use actual Home selection and HTTP/SSO paths."""
from copy import deepcopy
from http.client import HTTPConnection
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from clusterctl.homes.registry import version_digest
from clusterctl.homes.service import handler
from tests.test_home_gateway import selected, serving
from tests.test_home_passkeys import system
from tests.test_home_login import login_system, master


class Publication:
    def __init__(self):
        self.value = {'schema': 1, 'entries': []}
        self.revision = 0

    def state(self):
        return self.value


def publish(app, backend, entry):
    backend.value = {'schema': 1, 'entries': [entry]}
    receipt = app.registry.register(home='one', owner='owner', state=backend.value,
                          expected_revision=backend.revision,
                          known_actor=lambda ref: bool(app.authority.actor(ref)),
                          known_tribe=lambda _: False)
    backend.revision = receipt['revision']


def link(**fields):
    return selected('a' * 32, 'individual', kind='link', recipients=['human'],
                    url='https://destination.example/view/' + 'b' * 32 + '?version=' + 'c' * 64,
                    **fields)


def get(gateway, path, token=None, cookie=None):
    connection = HTTPConnection(urlsplit(gateway).netloc)
    headers = {'Host': 'one.example.test', 'X-Daimon-Home': 'one'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if cookie:
        headers['Cookie'] = cookie
    connection.request('GET', path, headers=headers)
    response = connection.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return result


def test_link_current_historical_and_revocation_use_existing_authority(system):
    app, _ = system
    backend = Publication()
    app.backends['one'] = backend
    first = link()
    publish(app, backend, first)
    human = app.sessions.issue(home='one', origin=app.homes['one']['public_url'],
                               subject=app.authority.actor('human'))
    other = app.sessions.issue(home='one', origin=app.homes['one']['public_url'],
                               subject=app.authority.actor('other'))
    path = '/view/' + first['artifact_ref']
    with serving(handler(app)) as gateway:
        for token in (None, other):
            status, headers, body = get(gateway, path, token)
            assert status == 404 and 'Location' not in headers
            assert first['url'].encode() not in body and first['title'].encode() not in body
        status, headers, body = get(gateway, path + '?display=work', human)
        assert status == 303 and headers['Location'] == first['url'] and body == b''
        assert headers['Cache-Control'] == 'no-store'
        second = deepcopy(first)
        second.update(url='https://destination.example/new?version=' + 'd' * 64,
                      recipients=['human', 'other'], versions=[deepcopy(first)])
        second['version_ref'] = version_digest(second)
        publish(app, backend, second)
        assert get(gateway, path, human)[1]['Location'] == second['url']
        historical = path + '?version=' + first['version_ref']
        assert get(gateway, historical, human)[1]['Location'] == first['url']
        # Current access is insufficient to read a historically private target.
        assert get(gateway, historical, other)[0] == 404
        revoked = deepcopy(second)
        revoked.update(recipients=['other'], versions=[deepcopy(first), deepcopy(second)])
        revoked['version_ref'] = version_digest(revoked)
        publish(app, backend, revoked)
        assert get(gateway, historical, human)[0] == 404
        app.sessions.revoke(home='one', token=other)
        assert get(gateway, path, other)[0] == 404


@pytest.mark.parametrize('target', ['javascript:alert(1)', '//example.test/x',
                                  'https://user:secret@example.test/x',
                                  'https://example.test/x\r\nLocation: https://other.test',
                                  'https://example.test/\\evil', 'https://example.test/é'])
def test_link_invalid_destination_never_reaches_location(system, target):
    app, _ = system
    backend = Publication()
    app.backends['one'] = backend
    entry = link()
    entry.update(url=target, visibility='public', recipients=[])
    entry['version_ref'] = version_digest(entry)
    publish(app, backend, entry)
    with serving(handler(app)) as gateway:
        status, headers, _ = get(gateway, '/view/' + entry['artifact_ref'])
        assert status == 404 and 'Location' not in headers


def test_link_exact_historical_entrance_survives_shared_login(login_system):
    app, _ = login_system
    backend = Publication()
    app.backends['one'] = backend
    entry = link()
    publish(app, backend, entry)
    destination = '/view/' + entry['artifact_ref'] + '?display=work&version=' + entry['version_ref']
    token, _ = master(app)
    with serving(handler(app)) as gateway:
        status, headers, _ = get(gateway, '/access/sso/start?' + urlencode({'return': destination}))
        assert status == 303
        proof = headers['Set-Cookie'].split(';')[0]
        request = parse_qs(urlsplit(headers['Location']).query)['request'][0]
        _, secret = app.sso.response(request, token)
        connection = HTTPConnection(urlsplit(gateway).netloc)
        connection.request('POST', '/access/sso/finish', urlencode({'request': request, 'response': secret}),
                           {'Host': 'one.example.test', 'Origin': app.sso.origin, 'Cookie': proof})
        response = connection.getresponse()
        response.read()
        assert response.status == 303 and response.getheader('Location') == destination
        cookie = next(value.split(';')[0] for name, value in response.getheaders()
                      if name == 'Set-Cookie' and value.startswith('__Host-home='))
        connection.close()
        status, headers, _ = get(gateway, destination, cookie=cookie)
        assert status == 303 and headers['Location'] == entry['url']
