"""Execute the opt-in bridge with real digest/stream behavior and fake transport."""
from pathlib import Path
import shutil
import subprocess
import pytest


def test_live_review_same_resource_version_bounds_and_lifecycle():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node required')
    source = Path(__file__).resolve().parents[1] / 'clusterctl/homes/assets/work-live-review.js'
    fixture = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert'),{webcrypto}=require('crypto');
(async()=>{
const child={},listeners={},docListeners={},calls=[],messages=[],digestJobs=[],timers=new Map();let tid=0,next='b'.repeat(64),bad=false;
const resource='a'.repeat(32),gallery=JSON.stringify({scenes:[{title:'updated'}]}),hash=Buffer.from(await webcrypto.subtle.digest('SHA-256',Buffer.from(gallery))).toString('hex');
const frame={dataset:{liveReview:'current',downloadRoot:'/works/'+resource+'/'+'b'.repeat(64)+'/'},contentWindow:{postMessage:m=>messages.push(m)}};
const document={hidden:false,addEventListener:(n,f)=>docListeners[n]=f};
const context={window:{addEventListener:(n,f)=>listeners[n]=f},document,Uint8Array,TextDecoder,AbortController,crypto:{subtle:{digest:(...args)=>{const p=webcrypto.subtle.digest(...args);digestJobs.push(p);return p;}}},
setTimeout:(f,d)=>{timers.set(++tid,{f,d});return tid},clearTimeout:id=>timers.delete(id),fetch:async url=>{calls.push(url);const manifest=url.endsWith('review-live.json');return new Response(manifest?JSON.stringify({schema:'dm.review-live/v1',gallery:'gallery.json',sha256:bad?'0'.repeat(64):hash}):gallery,{headers:{'X-Home-Version':next}})}};
vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'),context);context.installLiveReview(frame);
const flush=async()=>{for(let i=0;i<8;i++)await new Promise(r=>setImmediate(r));await Promise.all(digestJobs);await new Promise(r=>setImmediate(r));};
const updates=()=>messages.filter(m=>m.type==='home-artifact:review-update');
const send=(enabled,source=frame.contentWindow,origin='null')=>listeners.message({source,origin,data:{type:'home-artifact:live-review',enabled,resource:'evil',path:'secret'}});
send(true,child);send(true,frame.contentWindow,'https://evil.example');await flush();assert.equal(calls.length,0);
send(true);await flush();assert.equal(calls.length,1);assert.equal(updates().length,0);assert.equal(messages.at(-1).type,'home-artifact:review-current');assert.equal([...timers.values()][0].d,10000);
next='c'.repeat(64);{const [id,timer]=[...timers.entries()][0];timers.delete(id);timer.f();}await flush();assert.equal(calls.length,3);assert.equal(updates().length,1);assert.equal(updates()[0].version,next);assert.equal(calls[2],'/works/'+resource+'/'+next+'/gallery.json');
// A failed integrity check must preserve the previously posted model.
send(false);next='d'.repeat(64);bad=true;send(true);await flush();assert.equal(updates().length,1);assert.equal(messages.at(-1).type,'home-artifact:review-error');
document.hidden=true;docListeners.visibilitychange();assert.equal(timers.size,0);
const before=calls.length;send(true);await flush();assert.equal(calls.length,before);
document.hidden=false;bad=false;docListeners.visibilitychange();await flush();assert.equal(updates().length,2);
// Manual refresh repeats only the small manifest when version is unchanged.
const checks=calls.length,changed=updates().length;send(true);await flush();assert.equal(calls.length,checks+1);assert.equal(updates().length,changed);assert.equal(messages.at(-1).type,'home-artifact:review-current');
send(false);assert.equal(timers.size,0);assert(calls.every(url=>url.startsWith('/works/'+resource+'/')));
// Manifest and geometry limits are enforced, including streamed payloads.
})();
'''
    subprocess.run([node, '-e', fixture, str(source)], check=True, capture_output=True, text=True)


def test_live_review_rejects_denial_oversize_and_pinned_views():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node required')
    source = Path(__file__).resolve().parents[1] / 'clusterctl/homes/assets/work-live-review.js'
    fixture = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
(async()=>{for(const mode of ['denied','oversize-header','oversize-stream','pinned']){
 let calls=0,cancelled=0;const events={},messages=[],child={postMessage:m=>messages.push(m)};
 const frame={contentWindow:child,dataset:{liveReview:mode==='pinned'?'pinned':'current',downloadRoot:'/works/'+'a'.repeat(32)+'/'+'b'.repeat(64)+'/'}};
 const context={window:{addEventListener:(n,f)=>events[n]=f},document:{hidden:false,addEventListener(){}},Uint8Array,TextDecoder,AbortController,
 setTimeout:()=>1,clearTimeout(){},fetch:async()=>{calls++;return {ok:mode!=='denied',headers:{get:n=>n==='Content-Length'&&mode==='oversize-header'?'20000':null},body:{cancel:async()=>{cancelled++},getReader:()=>({read:async()=>({done:false,value:new Uint8Array(20000)}),cancel:async()=>{cancelled++}})}}}};
 vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'),context);context.installLiveReview(frame);
 if(mode==='pinned'){events.message({source:child,origin:'null',data:{type:'home-artifact:live-review',enabled:true}});assert.equal(calls,0);continue;}
 events.message({source:child,origin:'null',data:{type:'home-artifact:live-review',enabled:true}});
 for(let i=0;i<8;i++)await new Promise(r=>setImmediate(r));
 assert.equal(calls,1);assert.equal(messages.filter(m=>m.type==='home-artifact:review-update').length,0);assert.equal(messages.at(-1).type,'home-artifact:review-error');assert.equal(cancelled,1,mode);
}})();
'''
    subprocess.run([node, '-e', fixture, str(source)], check=True, capture_output=True, text=True)


def test_review_selector_uses_reader_catalog_and_commits_only_accepted_switch():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node required')
    source = Path(__file__).resolve().parents[1] / 'clusterctl/homes/assets/work-live-review.js'
    fixture = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert'),{webcrypto}=require('crypto');
(async()=>{
 const a='a'.repeat(32),b='b'.repeat(32),v='1'.repeat(64),w='2'.repeat(64),events={},docs={},messages=[],calls=[],timers=new Map();let tid=0,deny=false;
 const payload=JSON.stringify({scenes:[{title:'Allowed private scene'}]}),hash=Buffer.from(await webcrypto.subtle.digest('SHA-256',Buffer.from(payload))).toString('hex');
 const frame={dataset:{liveReview:'current',downloadRoot:'/works/'+a+'/'+v+'/'},contentWindow:{postMessage:m=>messages.push(m)}};
 const context={window:{addEventListener:(k,f)=>events[k]=f},document:{hidden:false,addEventListener:(k,f)=>docs[k]=f},Uint8Array,TextDecoder,AbortController,crypto:webcrypto,
 setTimeout:(f,d)=>{timers.set(++tid,{f,d});return tid},clearTimeout:id=>timers.delete(id),fetch:async url=>{
  calls.push(url);if(url==='/catalog.json')return new Response(JSON.stringify({entries:[{kind:'artifact',model_review:true,resource_ref:'dm:resource:v1:'+a,title:'Shared'},{kind:'artifact',model_review:true,resource_ref:'dm:resource:v1:'+b,title:'Permitted private'},{kind:'link',model_review:true,resource_ref:'dm:resource:v1:'+'c'.repeat(32),title:'Not a model'}]}));
  if(deny&&url.includes(b))return new Response('Denied',{status:404});
  const version=url.includes(b)?w:v;
  return new Response(url.endsWith('review-live.json')?JSON.stringify({schema:'dm.review-live/v1',gallery:'gallery.json',sha256:hash}):payload,{headers:{'X-Home-Version':version}});
 }};
 vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'),context);context.installLiveReview(frame);
 const send=(data,source=frame.contentWindow,origin='null')=>events.message({source,origin,data});
 const flush=async()=>{for(let i=0;i<20;i++)await new Promise(r=>setImmediate(r));};
 const waitFor=async predicate=>{const end=Date.now()+2000;while(!predicate()){if(Date.now()>end)throw Error('Expected bridge state timed out');await new Promise(r=>setTimeout(r,2));}};
 const choose=resource=>send({type:'home-artifact:review-select',resource});
 const switched=resource=>messages.at(-1)?.type==='home-artifact:review-update'&&messages.at(-1).resource===resource;
 choose(b);await flush();assert.equal(calls.length,0,'uncatalogued resource cannot trigger a read');
 send({type:'home-artifact:review-catalog'},{});await flush();assert.equal(calls.length,0);
 send({type:'home-artifact:review-catalog'});await flush();assert.equal(messages.at(-1).entries.length,2);
 choose('c'.repeat(32));await flush();assert.equal(calls.length,1,'links are not readable gallery targets');
 choose(b);await waitFor(()=>switched(b));let update=messages.at(-1);assert.equal(update.type,'home-artifact:review-update');assert.equal(update.resource,b);
 const current=()=>messages.filter(m=>m.type==='home-artifact:review-current').at(-1);
 assert(!current(),'selected target is not committed before child validation');
 send({type:'home-artifact:review-applied',...update, type:'home-artifact:review-applied',requestId:'forged',accepted:true});await flush();assert(!current());
 send({type:'home-artifact:review-applied',requestId:update.requestId,resource:b,version:w,accepted:true});await flush();assert.equal(current().resource,b);
 send({type:'home-artifact:live-review',enabled:true});await flush();assert.equal(calls.at(-1),'/works/'+b+'/current/review-live.json','live refresh follows the accepted resource');
 choose(a);await waitFor(()=>switched(a));update=messages.at(-1);
 send({type:'home-artifact:review-applied',requestId:update.requestId,resource:a,version:v,accepted:false});await flush();assert.equal(messages.at(-1).type,'home-artifact:review-error');
 send({type:'home-artifact:live-review',enabled:true});await flush();assert.equal(current().resource,b,'invalid target preserves current resource');
 // Same target/version also needs an acknowledgment, rather than hanging.
 choose(b);await waitFor(()=>switched(b));update=messages.at(-1);send({type:'home-artifact:review-applied',requestId:update.requestId,resource:b,version:w,accepted:true});await flush();assert.equal(current().resource,b);
 choose(a);await waitFor(()=>switched(a));const cancelled=messages.at(-1).requestId;
 context.document.hidden=true;docs.visibilitychange();await flush();assert(messages.some(m=>m.type==='home-artifact:review-cancel'&&m.requestId===cancelled));assert.equal(current().resource,b);assert.equal(timers.size,0);const count=calls.length;choose(a);await flush();assert.equal(calls.length,count);
})();
'''
    subprocess.run([node, '-e', fixture, str(source)], check=True, capture_output=True, text=True)


def test_pinned_review_hydrates_only_exact_revision_and_requires_commit():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node required')
    source = Path(__file__).resolve().parents[1] / 'clusterctl/homes/assets/work-live-review.js'
    fixture = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert'),{webcrypto}=require('crypto');
(async()=>{for(const mode of ['valid','denied','wrong-version','bad-hash','reject','hidden']){
 const a='a'.repeat(32),v='1'.repeat(64),events={},docs={},calls=[],messages=[],timers=new Map();let tid=0;
 const data=JSON.stringify({scenes:[{title:'Pinned fixture'}]}),hash=Buffer.from(await webcrypto.subtle.digest('SHA-256',Buffer.from(data))).toString('hex');
 const frame={dataset:{liveReview:'pinned',downloadRoot:'/works/'+a+'/'+v+'/'},contentWindow:{postMessage:m=>messages.push(m)}};
 const document={hidden:false,addEventListener:(k,f)=>docs[k]=f};
 const context={window:{addEventListener:(k,f)=>events[k]=f},document,Uint8Array,TextDecoder,AbortController,crypto:webcrypto,setTimeout:(f,d)=>{timers.set(++tid,{f,d});return tid},clearTimeout:id=>timers.delete(id),fetch:async url=>{calls.push(url);return new Response(mode==='denied'?'Denied':url.endsWith('review-live.json')?JSON.stringify({schema:'dm.review-live/v1',gallery:'gallery.json',sha256:mode==='bad-hash'?'0'.repeat(64):hash}):data,{status:mode==='denied'?404:200,headers:{'X-Home-Version':mode==='wrong-version'?'2'.repeat(64):v}})}};
 vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'),context);context.installLiveReview(frame);
 const send=(data,source=frame.contentWindow,origin='null')=>events.message({data,source,origin});
 const flush=async()=>{for(let i=0;i<25;i++)await new Promise(r=>setImmediate(r))};
 const waitFor=async predicate=>{const end=Date.now()+2000;while(!predicate()){if(Date.now()>end)throw Error('Pinned bridge state timed out');await new Promise(r=>setTimeout(r,2));}};
 send({type:'home-artifact:review-select',resource:a});send({type:'home-artifact:review-catalog'});send({type:'home-artifact:live-review',enabled:true});send({type:'home-artifact:review-load-pinned',path:'evil'});send({type:'home-artifact:review-load-pinned'},{});await flush();assert.equal(calls.length,0);
 send({type:'home-artifact:review-load-pinned'});await waitFor(()=>messages.some(m=>['home-artifact:review-update','home-artifact:review-error'].includes(m.type)));
 const update=messages.find(m=>m.type==='home-artifact:review-update');
 if(['denied','wrong-version','bad-hash'].includes(mode)){assert(!update,mode);assert.equal(messages.at(-1).type,'home-artifact:review-error');assert.equal(timers.size,0);continue;}
 assert(update&&update.pinned&&update.switching,mode);assert.equal(update.version,v);assert(!messages.some(m=>m.type==='home-artifact:review-commit'));
 if(mode==='hidden'){document.hidden=true;docs.visibilitychange();await flush();assert(messages.some(m=>m.type==='home-artifact:review-cancel'));assert(!messages.some(m=>m.type==='home-artifact:review-commit'));assert.equal(timers.size,0);continue;}
 send({type:'home-artifact:review-applied',requestId:update.requestId,version:v,resource:a,accepted:mode!=='reject'});await flush();
 assert.equal(messages.some(m=>m.type==='home-artifact:review-commit'),mode==='valid');assert.equal(timers.size,0);
 const n=calls.length;send({type:'home-artifact:review-load-pinned'});await flush();if(mode==='valid'){assert.equal(calls.length,n);assert.equal(messages.at(-1).type,'home-artifact:review-current')}
 assert(calls.every(url=>url.startsWith('/works/'+a+'/'+v+'/')));
}})();
'''
    subprocess.run([node, '-e', fixture, str(source)], check=True, capture_output=True, text=True)


def test_packed_gallery_decoder_preserves_geometry_and_rejects_corruption():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node required')
    source = Path(__file__).resolve().parents[1] / 'clusterctl/homes/assets/work-live-review.js'
    fixture = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert'),{webcrypto}=require('crypto'),zlib=require('zlib');
(async()=>{
 const context={Uint8Array,DataView,Blob,DecompressionStream,atob,crypto:webcrypto};
 vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'),context);
 const raw=Buffer.alloc(72);let cursor=0;
 for(const d of [[0,0,0],[100,0,0],[-100,100,0],[0,-100,100]])for(const n of d){raw.writeInt32LE(n,cursor);cursor+=4}
 for(const d of [[0,1,2],[0,2,3],[0,3,1],[1,2,1]])for(const n of d){raw.writeUInt16LE(n,cursor);cursor+=2}
 const wrap=async bytes=>({schema:'dm.review-packed/v1',scenes:[{units:'mm',parts:[{id:'tetra',label:'tetra',color:'#123456',mesh:{origin:[1,2,3],scale:.01,vertices:4,triangles:4}}]}],buffer:{encoding:'gzip/i32-delta-xyz+u16-delta-tri/le',size:72,sha256:Buffer.from(await webcrypto.subtle.digest('SHA-256',bytes)).toString('hex'),data:zlib.gzipSync(bytes).toString('base64')}});
 const packed=await wrap(raw),decode=p=>context.decodeReviewGallery(p),copy=()=>JSON.parse(JSON.stringify(packed));
 const output=await decode(packed),part=output.scenes[0].parts[0];
 assert.deepStrictEqual(JSON.parse(JSON.stringify(part.vertices)),[[1,2,3],[2,2,3],[1,3,3],[1,2,4]]);
 assert.deepStrictEqual(JSON.parse(JSON.stringify(part.faces)),[[0,1,2],[0,2,3],[0,3,1],[1,3,2]]);assert(!part.mesh);
 const plain={scenes:[]};assert.strictEqual(await decode(plain),plain);
 let bad=copy();bad.buffer.sha256='0'.repeat(64);await assert.rejects(decode(bad),/digest/);
 bad=copy();bad.buffer.size++;await assert.rejects(decode(bad),/size/);
 bad=copy();bad.scenes[0].parts[0].mesh.vertices=65536;await assert.rejects(decode(bad),/mesh/);
 bad=copy();bad.buffer.encoding='external-url';await assert.rejects(decode(bad),/Invalid/);
 bad=copy();bad.scenes[0].parts[0].mesh.scale=0;await assert.rejects(decode(bad),/mesh/);
 const invalid=Buffer.from(raw);invalid.writeUInt16LE(65535,50);await assert.rejects(decode(await wrap(invalid)),/index/);
 const bomb=Buffer.alloc(8192);bad=await wrap(bomb);await assert.rejects(decode(bad),/exceeds/);
})();
'''
    subprocess.run([node, '-e', fixture, str(source)], check=True,
                   capture_output=True, text=True, timeout=20)
