"""Authenticated private seed intake; public HTML contains no owner state."""
from __future__ import annotations

import base64
import hashlib
import time

from clusterctl import being_seed

from . import handlers


def _owner(ctx):
    return (ctx.token_record or {}).get("owner", "*")


def _call(deps, ctx, fn, *args, **kwargs):
    try:
        return handlers.Response(200, fn(handlers._state_dir(deps), *args, owner=_owner(ctx), **kwargs))
    except being_seed.SeedError as error:
        return handlers._error(error.status, str(error), "seed", "intake", ctx.request_id)
    except (OSError, ValueError, KeyError, TypeError):
        return handlers._error(409, "seed_operation_requires_attention", "seed", "intake", ctx.request_id)


def list_seeds(deps, ctx, query=None, **params):
    def build():
        rows = being_seed.list_seeds(handlers._state_dir(deps), owner=_owner(ctx))
        return rows, int(time.time() * 1000), False
    return handlers._page_or_resume(deps, ctx, query=query, kind="seeds", filters=None, build=build)


def create_seed(deps, ctx, _body=None, **params):
    return _call(deps, ctx, being_seed.create, _body, key=ctx.idempotency_key)


def upload_seed(deps, ctx, seed, _stream, _length, _sha256, _transfer_encoding=None, **params):
    if _transfer_encoding:
        return handlers.Response(400, {"error": "content_length_upload_required"})
    try:
        length = int(_length)
    except (ValueError, TypeError):
        return handlers.Response(411, {"error": "content_length_upload_required"})
    return _call(deps, ctx, being_seed.upload, seed, stream=_stream, length=length, sha256=_sha256)


def discover_seed(deps, ctx, seed, **params):
    return _call(deps, ctx, being_seed.discovery, seed)


def prepare_seed(deps, ctx, seed, _body=None, **params):
    if not isinstance(_body, dict) or set(_body) != {"selection"}:
        return handlers.Response(400, {"error": "explicit_receiving_selection_required"})
    return _call(deps, ctx, being_seed.prepare, seed, _body["selection"])


def seed_connections(deps, ctx, seed, _body=None, **params):
    return _call(deps, ctx, being_seed.connections, seed, _body)


def seed_ui(deps, ctx, **params):
    digest = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    policy = ("default-src 'none'; script-src 'sha256-" + digest
              + "'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
    return handlers.Response(200, HTML.replace("<!--SCRIPT-->", "<script>" + SCRIPT + "</script>"),
                             "text/html; charset=utf-8", {"Content-Security-Policy": policy,
                             "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"})


HTML = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Daimon Cluster — seed intake</title>
<style>body{font:16px system-ui;max-width:820px;margin:30px auto;padding:16px;background:#111827;color:#eee}
label{display:block;margin-top:12px}input,select,textarea,button{font:inherit;padding:8px;box-sizing:border-box;max-width:100%}
input:not([type=checkbox]),textarea{width:100%}textarea{min-height:140px}button{margin:12px 8px 8px 0}
pre{white-space:pre-wrap;overflow-wrap:anywhere}section{border-top:1px solid #526070;margin-top:24px}</style>
<h1>Bring your daimon to the cluster</h1>
<p>Continue an existing being or prepare a new one. This prepares private context; the body becomes active after its connection and runtime checks.</p>
<label>Private access token <input id="token" type="password" autocomplete="off"></label>
<p>Use the private HTTPS address provided by your host. Tokens and bot credentials stay in this page's memory.</p>
<section><h2>1. Choose the starting point</h2>
<label>Environment name <input id="name" placeholder="eko" pattern="[a-z0-9][a-z0-9-]{0,30}"></label>
<label>Daimon name <input id="label" placeholder="Eko"></label>
<label>Starting point <select id="mode"><option value="import">Import an existing daimon</option><option value="new">Start a new daimon</option></select></label>
<label><input id="browser" type="checkbox" checked> Request Chromium, a minimal display and Kimi WebBridge</label>
<div id="new-fields" hidden><label>Initial SOUL: who they are and their relationship with their humans <textarea id="soul"></textarea></label></div>
<button id="create">Prepare intake</button><button id="refresh">Refresh progress</button>
<section id="import-fields"><h2>2. Deliver the portable seed</h2>
<label>Archive (.tgz or .zip, up to 512 MiB) <input id="archive" type="file" accept=".tgz,.tar.gz,.zip"></label>
<label>SHA-256 from your exporter <input id="sha256" maxlength="64"></label>
<button id="upload">Upload and verify candidates</button>
<label>Receiving selection — check the SOUL, memory stores, historical skills and declared coverage <textarea id="selection"></textarea></label></section>
<button id="prepare">Prepare preserved context</button>
<section><h2>3. Private connection data</h2>
<p>The host needs bot data before enrolling an owner-facing body. Supplying data does not start a bot or replace a running consumer. Provider login is completed freshly in the receiving environment.</p>
<label>Telegram bot token <input id="bot-token" type="password" autocomplete="off"></label>
<label>Authorized Telegram chat/user ID <input id="chat-id" inputmode="numeric"></label>
<label>Telegram topic ID (optional) <input id="topic-id" inputmode="numeric"></label>
<label>Your public SSH key (never a private key) <textarea id="ssh-key"></textarea></label>
<button id="connections">Deliver connection data</button></section>
<p id="message" role="status"></p><pre id="progress"></pre><!--SCRIPT--></html>"""

SCRIPT = """
const field=id=>document.getElementById(id);
const requestKeys=new Map();
function requestKey(){const name=field('name').value.trim();if(!requestKeys.has(name))requestKeys.set(name,crypto.randomUUID());return requestKeys.get(name)}
const selectedName=()=>encodeURIComponent(field('name').value.trim());
async function api(path,method='GET',body=null,headers={}){
  if(location.hostname!=='localhost' && location.hostname!=='127.0.0.1' && location.protocol!=='https:')throw Error('Use the private HTTPS address');
  headers.Authorization='Bearer '+field('token').value.trim();
  let options={method,headers,credentials:'omit'};
  if(body!==null){if(body instanceof File){options.body=body;headers['Content-Type']='application/octet-stream'}
    else{headers['Content-Type']='application/json';options.body=JSON.stringify(body)}}
  const response=await fetch(path,options);const data=await response.json();
  if(!response.ok)throw Error(data.error||'Request failed');return data;
}
async function action(fn){field('message').textContent='Working…';try{const data=await fn();
  field('progress').textContent=JSON.stringify(data,null,2);field('message').textContent='Saved. See verified progress and pending steps below.';
}catch(error){field('message').textContent=error.message}}
field('mode').onchange=()=>{const isNew=field('mode').value==='new';field('new-fields').hidden=!isNew;field('import-fields').hidden=isNew};
field('create').onclick=()=>action(()=>{let value={name:field('name').value.trim(),label:field('label').value.trim(),mode:field('mode').value,browser:field('browser').checked};
  if(value.mode==='new')value.soul=field('soul').value;return api('/v1/seeds','POST',value,{'Idempotency-Key':requestKey()})});
field('refresh').onclick=()=>action(()=>api('/v1/seeds'));
field('upload').onclick=()=>action(async()=>{const archive=field('archive').files[0];if(!archive)throw Error('Choose the portable seed archive');
  if(archive.size>512*1024*1024)throw Error('Archive exceeds 512 MiB');
  await api('/v1/seeds/'+selectedName()+'/archive','POST',archive,{'X-Archive-SHA256':field('sha256').value.trim()});
  const selection=await api('/v1/seeds/'+selectedName()+'/selection');field('selection').value=JSON.stringify(selection,null,2);
  return {uploaded:true,receiving_selection:'Review the selection before preparing context'};});
field('prepare').onclick=()=>action(()=>api('/v1/seeds/'+selectedName()+'/prepare','POST',
  {selection:field('mode').value==='new'?null:JSON.parse(field('selection').value)}));
field('connections').onclick=()=>action(async()=>{let data={};
  if(field('bot-token').value)data.telegram_bot_token=field('bot-token').value.trim();
  for(const pair of [['chat-id','telegram_chat_id'],['topic-id','telegram_topic_id']])if(field(pair[0]).value)data[pair[1]]=Number(field(pair[0]).value);
  if(field('ssh-key').value)data.ssh_public_key=field('ssh-key').value.trim();
  const result=await api('/v1/seeds/'+selectedName()+'/connections','POST',data);field('bot-token').value='';return result;});
"""
