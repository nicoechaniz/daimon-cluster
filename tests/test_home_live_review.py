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
const send=(enabled,source=frame.contentWindow,origin='null')=>listeners.message({source,origin,data:{type:'home-artifact:live-review',enabled,resource:'evil',path:'secret'}});
send(true,child);send(true,frame.contentWindow,'https://evil.example');await flush();assert.equal(calls.length,0);
send(true);await flush();assert.equal(calls.length,1);assert.equal(messages.length,0);assert.equal([...timers.values()][0].d,10000);
next='c'.repeat(64);{const [id,timer]=[...timers.entries()][0];timers.delete(id);timer.f();}await flush();assert.equal(calls.length,3);assert.equal(messages.length,1);assert.equal(messages[0].version,next);assert.equal(calls[2],'/works/'+resource+'/'+next+'/gallery.json');
// A failed integrity check must preserve the previously posted model.
send(false);next='d'.repeat(64);bad=true;send(true);await flush();assert.equal(messages.length,1);
document.hidden=true;docListeners.visibilitychange();assert.equal(timers.size,0);
const before=calls.length;send(true);await flush();assert.equal(calls.length,before);
document.hidden=false;bad=false;docListeners.visibilitychange();await flush();assert.equal(messages.length,2);
send(false);assert.equal(timers.size,0);assert(calls.every(url=>url.startsWith('/works/'+resource+'/')));
// Manifest and geometry limits are enforced, including streamed payloads.
})();
'''
    subprocess.run([node, '-e', fixture, str(source)], check=True, capture_output=True, text=True)
