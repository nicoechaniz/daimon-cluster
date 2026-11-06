"""Actual HTTP note capture routes keep the selected source's current authority."""
import base64
import json
import urllib.request
import urllib.error
from copy import deepcopy
import pytest
from clusterctl.homes.service import handler
from clusterctl.homes.review_notes import ReviewNotes
from tests.test_home_gateway import selected, serving
from tests.test_home_passkeys import system, approved

PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII='


def test_note_http_save_retry_read_delete_and_current_source_revocation(system, monkeypatch):
    app, _ = system
    entry = selected('a'*32, 'individual', recipients=['human'],
                     files=['index.html','gallery.json','review-live.json'])
    state = {'schema':1,'entries':[entry]}
    app.backends['one'].state = lambda: state
    app.registry.register(home='one',owner='owner',state=state,expected_revision=0,
                          known_actor=app.authority.actor,known_tribe=lambda _:False)
    token, _ = approved(app)
    other, _ = approved(app, actor='other')
    snapshot = {'schema':'dm.review-3d-state/v1','model':{'resource':entry['artifact_ref'],
        'publicationVersion':entry['version_ref'],'id':'scene','version':'b'*64}}
    payload = {'operation':'1'*32,'snapshot':snapshot,'image':'data:image/png;base64,'+PNG}
    with serving(handler(app)) as base:
        def request(path, data=None, credential=token, origin='https://one.example.test'):
            headers={'Host':'one.example.test','Origin':origin,'Content-Type':'application/json'}
            if credential:headers['Cookie']='__Host-home='+credential
            req=urllib.request.Request(base+path,data=None if data is None else json.dumps(data).encode(),headers=headers)
            try:
                with urllib.request.urlopen(req) as response:return response.status,response.read(),response.headers
            except urllib.error.HTTPError as response:
                with response:return response.code,response.read(),response.headers
        code, body, _ = request('/review-notes',payload)
        assert code==200,body
        path=json.loads(body)['url'].removeprefix('https://one.example.test')
        assert request('/review-notes',payload)[1]==body
        code, data, headers=request(path+'/image.png')
        assert code==200 and data==base64.b64decode(PNG) and headers['Cache-Control']=='no-store'
        assert request(path+'/metadata.json')[0]==200
        assert request(path+'/image.png',credential=other)[0]!=200
        assert request(path+'/image.png',credential='')[0]!=200
        assert request('/review-notes',payload,origin='https://foreign.example')[0]!=200
        changed=deepcopy(payload);changed['snapshot']['model']['id']='different'
        assert request('/review-notes',changed)[0]!=200
        monkeypatch.setattr('clusterctl.homes.review_notes.MAX_RECORDS',1)
        changed=deepcopy(payload);changed['operation']='2'*32
        assert request('/review-notes',changed)[0]!=200
        assert request(path+'/delete',{},credential=other)[0]!=200
        # Paired human actor disappearance invalidates the saved image's read.
        human=app.authority.people.pop('human')
        assert request(path+'/image.png')[0]!=200
        app.authority.people['human']=human
        # No redirect following on deletion: inspect the actual retained absence.
        store=ReviewNotes(app.sessions);store.delete('one',path.rsplit('/',1)[1],human.ref)
        assert request(path+'/image.png')[0]!=200
        assert request('/review-notes',changed)[0]==200  # Explicit deletion frees quota.


def test_note_input_bounds_do_not_store_invalid_images(system):
    app,_=system;store=ReviewNotes(app.sessions)
    valid={'operation':'1'*32,'snapshot':{'schema':'dm.review-3d-state/v1',
        'model':{'resource':'a'*32,'publicationVersion':'b'*64}},'image':'data:image/png;base64,'+PNG}
    for image in ('data:image/svg+xml;base64,AAAA','data:image/png;base64,garbage',
                  'data:image/png;base64,'+'A'*(4*1024*1024+100)):
        with pytest.raises(ValueError):store.save('one','human',dict(valid,image=image))
    huge=bytearray(base64.b64decode(PNG));huge[16:24]=(2000001).to_bytes(4,'big')+(1).to_bytes(4,'big')
    with pytest.raises(ValueError,match='dimensions'):store.save('one','human',dict(valid,image='data:image/png;base64,'+base64.b64encode(huge).decode()))
