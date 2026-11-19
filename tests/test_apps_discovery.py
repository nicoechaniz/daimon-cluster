from urllib.parse import urlsplit,parse_qs
from html import unescape
import re
from clusterctl.homes.launcher import page
from tests.test_home_passkeys import system
from tests.test_home_login import login_system
from tests.test_home_launcher import populated

def test_anonymous_apps_offer_existing_shared_login_without_private_metadata(login_system):
    app,_=login_system;populated(app)
    body=page(app,'one',None,False).decode()
    target=unescape(re.search(r'data-apps-sign-in href="([^"]+)"',body).group(1))
    url=urlsplit(target)
    assert url.scheme+'://'+url.netloc==app.homes['one']['public_url']
    assert url.path=='/access/sso/start' and parse_qs(url.query)=={'return':['/apps/']}
    assert 'Entrar para ver tus aplicaciones compartidas' in body
    assert 'PrivateOwn' not in body and 'PrivateOther' not in body

def test_authorized_apps_keep_existing_card_and_hide_signin_prompt(login_system):
    app,_=login_system;populated(app)
    body=page(app,'one',app.authority.actor('human'),False).decode()
    assert 'PrivateOwn' in body and 'PrivateOther' not in body
    assert 'data-apps-sign-in' not in body

def test_launcher_without_shared_login_or_vpn_does_not_advertise_sso(system):
    app,_=system;populated(app)
    assert 'data-apps-sign-in' not in page(app,'one',None,False).decode()
    app.sso=object()
    assert 'data-apps-sign-in' not in page(app,'one',None,True).decode()
