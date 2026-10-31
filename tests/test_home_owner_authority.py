"""Explicit same-owner authority continuity without key or browser-session reset."""
import json
from pathlib import Path

import pytest

from clusterctl.homes.host import accept_owner_authority
from clusterctl.homes.policy import Actor
from clusterctl.homes.provision import sha
from clusterctl.homes.service import Application
from clusterctl.homes.sessions import Sessions


def configuration(tmp_path):
    def key(name):
        p=tmp_path/name;p.write_text(name);p.chmod(0o600);return str(p)
    return {"schema":"dm.resource-access.host/v1", "state":str(tmp_path/'state'),
            "binding_source":str(tmp_path/'identities'),
            "relationship_store":str(tmp_path/'relationships'),
            "authority_source":str(tmp_path/'authority'),
            "viewer_port":8820,"owner_port":8821,
            "content_public_url":"https://content.example",
            "content_vpn_url":"https://private-content.example",
            "homes":{"one":{"name":"Home", "owner_being_ref":"being-one",
                    "owner_revision":"a"*64,"public_url":"https://one.example",
                    "vpn_url":"https://private-one.example", "backend":"http://127.0.0.1:8801",
                    "owner_token_file":key('owner'),"gateway_token_file":key('reader'),"ring":[]}}}


class Authority:
    revision='a'*64
    verified=0
    def __init__(self,*a,**kw):pass
    def authorities(self):
        type(self).verified+=1
        return {}
    def actor(self,ref):return Actor(ref,'being',self.revision,ref)
    def actors(self):return {'being-one':self.actor('being-one')}
    def tribes(self):return {}
    def paired_human(self,home):return 'human-one'
    def tribe_member(self,*a):return False


def test_real_owner_operation_needs_explicit_host_acceptance_preserves_credentials(tmp_path,monkeypatch):
    Authority.revision='a'*64;Authority.verified=0
    monkeypatch.setattr('clusterctl.homes.authority.NativeAuthority',Authority)
    cfg=configuration(tmp_path);p=tmp_path/'config.json';p.write_text(json.dumps(cfg));p.chmod(0o600)
    original=p.read_bytes();app=Application(cfg,Authority(),Sessions(Path(cfg['state'])))
    human=Actor('human-one','human','stable-human','Human')
    browser=app.sessions.issue(home='one',origin='https://one.example',subject=human)
    with app.sessions.connect() as db:credentials=[tuple(r) for r in db.execute('SELECT * FROM owner_credentials')]
    Authority.revision='b'*64
    with pytest.raises(ValueError,match='home_owner_binding_unavailable'):
        app.owner('one','owner','targets',{})
    with pytest.raises(ValueError,match='concurrent_gateway_configuration'):
        accept_owner_authority(p,'one',previous_digest='stale')
    assert Authority.verified==0
    result=accept_owner_authority(p,'one',previous_digest=sha(original))
    assert result['revision']=='b'*64 and Authority.verified==1
    assert app.owner('one','owner','targets',{})['actors'][0]['ref']=='being-one'
    assert p.read_bytes()==original and Path(cfg['homes']['one']['owner_token_file']).read_text()=='owner'
    assert app.sessions.resolve(browser,home='one',origin='https://one.example')['actor']==human.ref
    with app.sessions.connect() as db:assert [tuple(r) for r in db.execute('SELECT * FROM owner_credentials')]==credentials
    # No public/owner-local operation can grant this trusted host acceptance.
    with pytest.raises(ValueError):app.owner('one','owner','accept-owner-authority',{})
    Authority.revision='c'*64
    with pytest.raises(ValueError,match='home_owner_binding_unavailable'):app.owner('one','owner','targets',{})
    accept_owner_authority(p,'one',previous_digest=sha(original))
    assert app.owner('one','owner','targets',{})
    # Restart over the exact original config works without rebinding the token.
    restarted=Application(cfg,Authority(),Sessions(Path(cfg['state'])))
    assert restarted.owner('one','owner','targets',{})


def test_acceptance_cannot_rebind_home_actor_base_revision_or_revoked_key(tmp_path):
    s=Sessions(tmp_path/'state');s.register_owner(home='one',actor='being-one',revision='a',token='owner')
    owner=Actor('being-one','being','b','Owner')
    for change in [dict(home='two'),dict(subject=Actor('foreign','being','b','Foreign')),
                   dict(subject=Actor('being-one','human','b','Human')),
                   dict(subject=Actor('being-one','being','b','Disabled',False)),dict(binding_revision='wrong')]:
        kw=dict(home='one',subject=owner,binding_revision='a');kw.update(change)
        with pytest.raises(ValueError):s.accept_owner_authority('owner',**kw)
    with pytest.raises(ValueError,match='immutable'):
        s.register_owner(home='one',actor='being-one',revision='b',token='owner')
    s.accept_owner_authority('owner',home='one',subject=owner,binding_revision='a')
    assert s.owner('owner',home='one',subject=owner,binding_revision='a')
    assert not s.owner('owner',home='two',subject=owner,binding_revision='a')
    assert not s.owner('wrong',home='one',subject=owner,binding_revision='a')
    # Default API stays exact-revision; acceptance is explicit in the app path.
    assert not s.owner('owner',home='one',subject=owner)
    for i in range(100):s.accept_owner_authority('owner',home='one',subject=Actor('being-one','being',str(i),'Owner'),binding_revision='a')
    with s.connect() as db:
        assert db.execute('SELECT count(*) FROM owner_authority_acceptance').fetchone()[0]==1
        db.execute('UPDATE owner_credentials SET revoked=1')
    assert not s.owner('owner',home='one',subject=Actor('being-one','being','99','Owner'),binding_revision='a')
    with pytest.raises(ValueError):s.accept_owner_authority('owner',home='one',subject=owner,binding_revision='a')
