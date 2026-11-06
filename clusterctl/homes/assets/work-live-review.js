// Authorized review updates. Child selection is restricted to the current reader catalog.
'use strict';
// Optional bounded packed display meshes; same fixed gallery/resource authority.
async function decodeReviewGallery(data) {
  if (data?.schema !== 'dm.review-packed/v1') return data;
  const limit = 25 * 1024 * 1024, buffer = data.buffer;
  if (!buffer || buffer.encoding !== 'gzip/i32-delta-xyz+u16-delta-tri/le'
      || !Number.isInteger(buffer.size) || buffer.size < 1 || buffer.size > limit
      || !/^[a-f0-9]{64}$/.test(buffer.sha256 || '')
      || typeof buffer.data !== 'string' || buffer.data.length > Math.ceil(limit / 3) * 4
      || buffer.data.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(buffer.data)
      || !Array.isArray(data.scenes) || !data.scenes.length || data.scenes.length > 64)
    throw Error('Invalid packed gallery');
  let expected = 0;
  for (const scene of data.scenes) {
    if (!Array.isArray(scene.parts) || !scene.parts.length || scene.parts.length > 256) throw Error('Invalid packed parts');
    let triangles = 0;
    for (const part of scene.parts) {
      const m = part.mesh;
      if (!m || !Array.isArray(m.origin) || m.origin.length !== 3
          || !m.origin.every(n => Number.isFinite(n) && Math.abs(n) <= 1e9)
          || !Number.isFinite(m.scale) || m.scale <= 0 || m.scale > 1
          || !Number.isInteger(m.vertices) || m.vertices < 3 || m.vertices > 65535
          || !Number.isInteger(m.triangles) || m.triangles < 1 || m.triangles > 300000)
        throw Error('Invalid packed mesh');
      triangles += m.triangles; expected += m.vertices * 12 + m.triangles * 6;
      if (triangles > 300000 || expected > limit) throw Error('Packed geometry budget');
    }
  }
  if (expected !== buffer.size) throw Error('Packed size mismatch');
  const compressed = Uint8Array.from(atob(buffer.data), c => c.charCodeAt(0));
  const stream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'));
  const reader = stream.getReader(), chunks = []; let size = 0;
  try {
    for (;;) {
      const {done, value} = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > expected) throw Error('Expanded packed gallery exceeds limit');
      chunks.push(value);
    }
  } catch (error) { await reader.cancel(); throw error; }
  if (size !== expected) throw Error('Truncated packed gallery');
  const raw = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) {raw.set(chunk, offset); offset += chunk.byteLength;}
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)), b => b.toString(16).padStart(2,'0')).join('');
  if (digest !== buffer.sha256) throw Error('Packed geometry digest mismatch');
  const view = new DataView(raw.buffer), meshes = new Map(), scenes = []; let cursor = 0;
  for (const scene of data.scenes) {
   const parts = [];
   for (const part of scene.parts) {
    const m = part.mesh, start = cursor, end = start + m.vertices * 12 + m.triangles * 6;
    const encoded = raw.subarray(start, end);
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',encoded)), b => b.toString(16).padStart(2,'0')).join('');
    const key = JSON.stringify([m.origin,m.scale,m.vertices,m.triangles]) + ':' + hash;
    const shared = meshes.get(key), {mesh, ...metadata} = part;
    // Exact encoded bytes and coordinate interpretation must match. Sharing only
    // immutable geometry avoids serializing duplicate meshes across the iframe;
    // part/scene metadata remains independent. This map exists for this decode only.
    if (shared && encoded.every((value,index)=>value===raw[shared.start+index])) {
      cursor = end;
      parts.push({...metadata,vertices:shared.vertices,faces:shared.faces});
      continue;
    }
    const previous = [0,0,0], vertices = [], faces = [];
    for (let i=0; i<m.vertices; i++) {
      const vertex = [];
      for (let k=0; k<3; k++) {
        previous[k] += view.getInt32(cursor,true); cursor += 4;
        const n = m.origin[k] + previous[k] * m.scale;
        if (!Number.isSafeInteger(previous[k]) || previous[k] < 0 || previous[k] > 2147483647
            || !Number.isFinite(n) || Math.abs(n) > 1e9) throw Error('Packed vertex range');
        vertex.push(n);
      }
      vertices.push(vertex);
    }
    let a = 0;
    for (let i=0; i<m.triangles; i++) {
      a += view.getUint16(cursor,true); const b = a + view.getUint16(cursor+2,true), c = a + view.getUint16(cursor+4,true); cursor += 6;
      if (a >= m.vertices || b >= m.vertices || c >= m.vertices) throw Error('Packed triangle index');
      faces.push([a,b,c]);
    }
    meshes.set(key,{start,vertices,faces});
    parts.push({...metadata,vertices,faces});
   }
   scenes.push({...scene,parts});
  }
  if (cursor !== size) throw Error('Unused packed geometry');
  return {scenes, navigation:data.navigation || {}};
}

// Optional index metadata never authorizes a path or substitutes for geometry.
function reviewSceneMetadata(scene) {
  const text = (value, max=8192) => typeof value === 'string' && value.trim() && value.length <= max;
  if (!scene || scene.units !== 'mm' || !text(scene.id,180)
      || !/^[a-f0-9]{64}$/.test(scene.version || '')
      || !['title','note','scope','status'].every(k=>text(scene[k]))
      || typeof scene.dimensions !== 'string' || scene.dimensions.length > 8192
      || scene.assembly !== false || !Array.isArray(scene.parts)
      || !scene.parts.length || scene.parts.length > 256) throw Error('Invalid scene metadata');
  const ids = new Set();
  const parts = scene.parts.map(part=>{
    if (!text(part.id,180) || ids.has(part.id) || !text(part.label)
        || !/^#[a-fA-F0-9]{6}$/.test(part.color || '')) throw Error('Invalid part metadata');
    ids.add(part.id);
    const value = {id:part.id,label:part.label,color:part.color};
    if (part.centerline !== undefined) {
      if (!Array.isArray(part.centerline) || part.centerline.length !== 2
          || !part.centerline.every(v=>Array.isArray(v)&&v.length===3&&v.every(n=>Number.isFinite(n)&&Math.abs(n)<=1e9))) throw Error('Invalid metadata centerline');
      value.centerline = part.centerline.map(v=>[...v]);
    }
    return value;
  });
  return {id:scene.id,version:scene.version,title:scene.title,note:scene.note,scope:scene.scope,
    status:scene.status,units:'mm',dimensions:scene.dimensions,assembly:false,parts};
}
function validateReviewSceneIndex(data) {
  if (data?.schema !== 'dm.review-scene-index/v1' || !Array.isArray(data.entries)
      || !data.entries.length || data.entries.length > 64) throw Error('Invalid scene index');
  const ids = new Set();
  const entries = data.entries.map((entry,i)=>{
    if (entry.file !== 'scene-'+String(i).padStart(3,'0')+'.json'
        || !/^[a-f0-9]{64}$/.test(entry.sha256 || '')
        || entry.scene?.parts?.some(p=>['mesh','vertices','faces','triangles'].some(k=>k in p))) throw Error('Invalid scene path or digest');
    const scene = reviewSceneMetadata(entry.scene);
    if (ids.has(scene.id)) throw Error('Duplicate scene ID');
    ids.add(scene.id);return {scene,file:entry.file,sha256:entry.sha256};
  });
  if (!ids.has(data.initial)) throw Error('Invalid initial scene');
  return {schema:data.schema,initial:data.initial,entries};
}
function matchReviewScene(entry, gallery) {
  if (!Array.isArray(gallery?.scenes) || gallery.scenes.length !== 1
      || JSON.stringify(reviewSceneMetadata(gallery.scenes[0])) !== JSON.stringify(entry.scene))
    throw Error('Scene geometry metadata mismatch');
  return gallery.scenes[0];
}

// Opt-in iframe representation, not a second geometry or authorization cache.
// Bound allocation BEFORE stringify; packed input can expand substantially.
function reviewJSONBytes(text, maxBytes = 4 * 1024 * 1024) {
  let size=0;
  for(let i=0;i<text.length;i++) {
    const c=text.charCodeAt(i);
    if(c<128)size++;
    else if(c<2048)size+=2;
    else if(c>=0xd800&&c<=0xdbff&&i+1<text.length&&text.charCodeAt(i+1)>=0xdc00&&text.charCodeAt(i+1)<=0xdfff){size+=4;i++;}
    else size+=3;
    if(size>maxBytes)return Infinity;
  }
  return size;
}
function reviewGalleryJSON(gallery, maxBytes = 4 * 1024 * 1024) {
  if(!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>32*1024*1024)return null;
  let size = 0, nodes = 0;
  const add = n => {size += n; return size <= maxBytes;};
  function string(value) {
    if (!add(2)) return false;
    for (let i=0;i<value.length;i++) {
      const c=value.charCodeAt(i);
      if (c===34 || c===92 || c===8 || c===9 || c===10 || c===12 || c===13) {if(!add(2))return false;}
      else if(c<32) {if(!add(6))return false;}
      else if(c<128) {if(!add(1))return false;}
      else if(c<2048) {if(!add(2))return false;}
      else if(c>=0xd800 && c<=0xdbff && i+1<value.length && value.charCodeAt(i+1)>=0xdc00 && value.charCodeAt(i+1)<=0xdfff) {i++;if(!add(4))return false;}
      else if(c>=0xd800 && c<=0xdfff) {if(!add(6))return false;}
      else if(!add(3))return false;
    }
    return true;
  }
  function visit(value, depth) {
    if (++nodes>4000000 || depth>32) return false;
    if(value===null)return add(4);
    if(typeof value==='string')return string(value);
    if(typeof value==='number')return Number.isFinite(value)&&!Object.is(value,-0)&&add(String(value).length);
    if(typeof value==='boolean')return add(value?4:5);
    if(Array.isArray(value)) {
      if(!add(2+Math.max(0,value.length-1)))return false;
      for(const item of value)if(!visit(item,depth+1))return false;
      return true;
    }
    if(typeof value!=='object'||(Object.getPrototypeOf(value)!==null&&Object.getPrototypeOf(value)!==Object.prototype)||!add(2))return false;
    let first=true;
    for(const key of Object.keys(value)) {
      const descriptor=Object.getOwnPropertyDescriptor(value,key);
      if(!descriptor || !('value' in descriptor) || !add(first?1:2) || !string(key) || !visit(descriptor.value,depth+1))return false;
      first=false;
    }
    return true;
  }
  if(!visit(gallery,0))return null;
  const text=JSON.stringify(gallery);
  if(typeof text!=='string'||text.length>size||reviewJSONBytes(text,maxBytes)!==size)return null;
  return text;
}

// A legacy enabled-only child accepts at most 4 MiB. Invalid explicit limits
// disable text; an advertised allowance never overrides our own hard ceiling.
function reviewJSONAllowance(message) {
  if(message.enabled!==true)return 0;
  if(!Object.hasOwn(message,'maxBytes'))return 4*1024*1024;
  return Number.isSafeInteger(message.maxBytes)&&message.maxBytes>0
    ?Math.min(message.maxBytes,32*1024*1024):0;
}

// Mount-local retained geometry only; never a browser storage or authorization cache.
function createReviewCache(maxEntries = 3, maxBytes = 48 * 1024 * 1024) {
  const entries = new Map(); let retained = 0;
  const remove = key => {const old=entries.get(key);if(old){retained-=old.cost;entries.delete(key);}};
  return {
    get(key) {const item=entries.get(key);if(item){entries.delete(key);entries.set(key,item);}return item;},
    put(key, resource, gallery, wireBytes) {
      // Nested JS triplets and metadata cost more than their wire/buffer bytes.
      // Conservative accounting bounds retained entries, not total browser heap.
      let cost = wireBytes * 4;
      if (!Number.isSafeInteger(cost) || cost < 1 || !Array.isArray(gallery?.scenes)
          || !gallery.scenes.length || gallery.scenes.length > 64) return;
      for (const scene of gallery.scenes) {
        if (!Array.isArray(scene.parts) || scene.parts.length > 256) return;
        for (const part of scene.parts) {
          if (!Array.isArray(part.vertices) || !Array.isArray(part.faces)) return;
          cost += 128 * (part.vertices.length + part.faces.length);
          if (!Number.isSafeInteger(cost) || cost > maxBytes) return;
        }
      }
      if (cost > maxBytes) return; // Large scenes remain usable, without retention.
      remove(key);
      while (entries.size >= maxEntries || retained + cost > maxBytes) remove(entries.keys().next().value);
      entries.set(key,{resource,gallery,wireBytes,cost});retained+=cost;
    },
    evictResource(resource) {for(const [key,item] of entries)if(item.resource===resource)remove(key);},
    clear() {entries.clear();retained=0;},
  };
}

function installLiveReview(frame) {
  const root = frame.dataset.downloadRoot || '';
  const match = /^\/works\/([a-f0-9]{32})\/([a-f0-9]{64})\/$/.exec(root);
  if (!match) return;
  const current = frame.dataset.liveReview === 'current';
  let resource = match[1], target = null, catalog = new Map(), catalogPending = null, acknowledgment = null, serial = 0;
  let version = match[2], wanted = false, timer = null, pending = null, requestTimeout = null, delay = 10000, immediate = false;
  // A URL selects only a candidate. The authenticated reader catalog must admit
  // it before any model request; pinned views ignore both URL and saved choice.
  const preferenceKey = 'dm.review-project:' + match[1];
  let initialProject = null, initialResolved = true;
  if (current) {
    try {
      const query = new URL(window.location.href).searchParams.get('project');
      const candidate = query || window.localStorage?.getItem(preferenceKey);
      if (/^[a-f0-9]{32}$/.test(candidate || '')) {initialProject = candidate; initialResolved = false;}
    } catch (_) { /* Storage is optional; ordinary model loading still works. */ }
  }
  function rememberProject() {
    try {window.localStorage?.setItem(preferenceKey, resource);} catch (_) {}
    try {
      const url = new URL(window.location.href); url.searchParams.set('project', resource);
      window.history.replaceState(null, '', url.pathname + url.search + url.hash);
    } catch (_) {}
  }
  const geometryCache = createReviewCache();
  let sceneSupport = false, selectedScene = null, activeIndex = null;
  let disposed = false;
  const listeners = [];
  const listen = (target, type, callback) => { target.addEventListener(type, callback); listeners.push([target,type,callback]); };
  let jsonLimit=0;
  const post = data => {
    if(disposed)return;
    if(jsonLimit && data.type==='home-artifact:review-update' && data.gallery) {
      const text=reviewGalleryJSON(data.gallery,jsonLimit);
      if(text!==null) {const {gallery,...envelope}=data;data={...envelope,galleryJSON:text};}
    }
    frame.contentWindow.postMessage(data, '*');
  };
  function dispose() {
    if (disposed) return;
    disposed = true; wanted = false; geometryCache.clear(); cancel(); if (catalogPending) catalogPending.abort();
    for (const [target,type,callback] of listeners.splice(0)) target.removeEventListener(type,callback);
  }
  async function list() {
    if (document.hidden || catalogPending) return;
    const controller = new AbortController(); catalogPending = controller;
    const deadline = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch('/catalog.json', {cache:'no-store', signal:controller.signal});
      const data = JSON.parse(new TextDecoder().decode(await bytes(response, 1024 * 1024)));
      if (!Array.isArray(data.entries) || data.entries.length > 2048) throw Error('Invalid catalog');
      const entries = data.entries.filter(e => e.model_review === true && e.kind === 'artifact'
        && /^dm:resource:v1:[a-f0-9]{32}$/.test(e.resource_ref || '')
        && typeof e.title === 'string' && e.title.length <= 180).slice(0,64)
        .map(e => ({resource:e.resource_ref.slice(15), title:e.title}));
      if (controller.signal.aborted || document.hidden) return;
      catalog = new Map(entries.map(e => [e.resource,e]));
      const resumeInitial = !initialResolved;
      if (resumeInitial) {
        initialResolved = true;
        if (catalog.has(initialProject)) target = {resource:initialProject, initial:true};
        initialProject = null;
      }
      post({type:'home-artifact:review-catalog', entries, resource});
      if (resumeInitial && wanted && !pending) poll();
    } catch (error) {
      if (!controller.signal.aborted) {
        post({type:'home-artifact:review-catalog-error'});
        // No candidate fetch on failed authorization discovery. Preserve the
        // ordinary resource route and let a later explicit selector retry.
        initialResolved = true; initialProject = null;
        if (wanted && !pending) poll();
      }
    }
    finally { clearTimeout(deadline); if (catalogPending === controller) catalogPending = null; }
  }
  function cancel() {
    clearTimeout(timer); timer = null; clearTimeout(requestTimeout); requestTimeout = null;
    if (pending) pending.abort();
    if (acknowledgment) { post({type:'home-artifact:review-cancel',requestId:acknowledgment.requestId}); acknowledgment.resolve(false); acknowledgment = null; }
  }
  async function bytes(response, limit) {
    if (!response.ok || Number(response.headers.get('Content-Length')) > limit) {
      await response.body?.cancel(); throw Error('Review unavailable');
    }
    const reader = response.body.getReader(); let size = 0; const chunks = [];
    try {
      for (;;) {
        const {done, value} = await reader.read(); if (done) break;
        size += value.byteLength;
        if (size > limit) throw Error('Review exceeds limit');
        chunks.push(value);
      }
    } catch (error) { await reader.cancel(); throw error; }
    const result = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
    return result;
  }
  const digest = async data => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',data)),b=>b.toString(16).padStart(2,'0')).join('');
  async function loadGallery(manifest, candidateResource, next, signal, requestedScene=null) {
    const prefix = '/works/'+candidateResource+'/'+next+'/';
    async function readFile(file, sha, limit) {
      const response = await fetch(prefix+file,{cache:'no-store',signal});
      if ([401,403,404].includes(response.status)) geometryCache.evictResource(candidateResource);
      if (response.headers.get('X-Home-Version') !== next) throw Error('Review version changed');
      const data = await bytes(response,limit);
      if (await digest(data) !== sha) throw Error('Review payload mismatch');
      return data;
    }
    if (sceneSupport && manifest.scene_index) {
      const descriptor = manifest.scene_index;
      if (descriptor.file !== 'scene-index.json' || !/^[a-f0-9]{64}$/.test(descriptor.sha256 || '')) throw Error('Invalid scene index reference');
      const indexKey = candidateResource+':'+next+':'+descriptor.sha256;
      const index = activeIndex?.key === indexKey ? activeIndex.index : validateReviewSceneIndex(
        JSON.parse(new TextDecoder().decode(await readFile(descriptor.file,descriptor.sha256,256*1024))));
      const id = requestedScene || (candidateResource === resource && index.entries.some(e=>e.scene.id===selectedScene) ? selectedScene : index.initial);
      const entry = index.entries.find(e=>e.scene.id===id);
      if (!entry) throw Error('Scene unavailable');
      const key = indexKey+':'+entry.sha256, cached = geometryCache.get(key);
      let retained = cached?.gallery, wireBytes = cached?.wireBytes;
      if (!retained) {
        const data = await readFile(entry.file,entry.sha256,25*1024*1024);wireBytes=data.byteLength;
        retained = await decodeReviewGallery(JSON.parse(new TextDecoder().decode(data)));
      }
      const scene = matchReviewScene(entry,retained);
      return {key,wireBytes,retained,index:{key:indexKey,index,resource:candidateResource,version:next},
        gallery:{sceneIndex:true,activeScene:id,scenes:index.entries.map(e=>e.scene.id===id?scene:{...e.scene,deferred:true})}};
    }
    if (requestedScene) throw Error('Scene loading unavailable');
    const key=candidateResource+':'+next+':'+manifest.sha256,cached=geometryCache.get(key);
    if (cached) return {key,wireBytes:cached.wireBytes,retained:cached.gallery,gallery:cached.gallery,index:null};
    const data=await readFile('gallery.json',manifest.sha256,25*1024*1024);
    const gallery=await decodeReviewGallery(JSON.parse(new TextDecoder().decode(data)));
    return {key,wireBytes:data.byteLength,retained:gallery,gallery,index:null};
  }
  function acceptReply(message) {
    const expected=acknowledgment?.phase==='commit'?'home-artifact:review-committed':'home-artifact:review-applied';
    if(message?.type!==expected||!acknowledgment||message.requestId!==acknowledgment.requestId
        ||message.resource!==acknowledgment.resource||message.version!==acknowledgment.version)return false;
    const resolve=acknowledgment.resolve;acknowledgment=null;resolve(message.accepted===true);return true;
  }
  async function commit(requestId,nextResource,next,confirm) {
    let accepted=null;
    if(confirm)accepted=new Promise(resolve=>{acknowledgment={phase:'commit',requestId,resource:nextResource,version:next,resolve}});
    post({type:'home-artifact:review-commit',requestId,resource:nextResource,version:next});
    if(accepted&&!await accepted)throw Error('Review commit superseded');
  }
  function cancelScene(message) {
    if(message?.type!=='home-artifact:review-scene-cancel'||!target?.prepare
        ||message.intent!==target.sceneIntent)return false;
    cancel();target=null;return true;
  }
  function support(message) {
    if(message?.type==='home-artifact:review-json-support' && typeof message.enabled==='boolean') {jsonLimit=reviewJSONAllowance(message);return true;}
    if (message?.type !== 'home-artifact:review-scene-support' || message.enabled !== true) return false;
    sceneSupport=true;
    if (typeof message.scene === 'string' && message.scene.length <= 180) selectedScene=message.scene;
    return true;
  }
  function sceneIntent(message) {
    if (!sceneSupport || message?.type !== 'home-artifact:review-scene'
        || document.hidden || message.resource !== resource || message.version !== version
        || typeof message.intent !== 'string' || !/^[0-9]{1,16}$/.test(message.intent)
        || !activeIndex?.index.entries.some(e=>e.scene.id===message.scene)) return null;
    return {resource,scene:message.scene,sceneIntent:message.intent,prepare:true,expectedVersion:version};
  }
  // Historical views may hydrate only their original immutable gallery.
  // No catalog, current-version lookup, resource switch or recurring timer.
  if (!current) {
    let loaded = false;
    async function hydrate(requested=null) {
      if (document.hidden || pending) return;
      if (loaded && !requested) { post({type:'home-artifact:review-current',version,resource}); return; }
      const controller = new AbortController(); pending = controller;
      const deadline = setTimeout(() => {controller.abort();if(acknowledgment){post({type:'home-artifact:review-cancel',requestId:acknowledgment.requestId});acknowledgment.resolve(false);acknowledgment=null;}}, 20000);
      try {
        const response = await fetch(root + 'review-live.json', {cache:'no-store',signal:controller.signal});
        if (response.headers.get('X-Home-Version') !== version) throw Error('Pinned version mismatch');
        const manifest = JSON.parse(new TextDecoder().decode(await bytes(response,16384)));
        if (manifest.schema !== 'dm.review-live/v1' || manifest.gallery !== 'gallery.json' || !/^[a-f0-9]{64}$/.test(manifest.sha256 || '')) throw Error('Invalid pinned manifest');
        const result = await loadGallery(manifest,resource,version,controller.signal,requested?.scene);
        const gallery=result.gallery;
        if (controller.signal.aborted || document.hidden) return;
        const requestId = String(++serial);
        const accepted = new Promise(resolve=>{acknowledgment={requestId,resource,version,resolve}});
        post({type:'home-artifact:review-update',version,resource,gallery,requestId,switching:true,pinned:true,prepareOnly:!!requested,sceneIntent:requested?.sceneIntent});
        if (!await accepted || controller.signal.aborted || document.hidden) throw Error('Pinned review not accepted');
        await commit(requestId,resource,version,!!result.index);
        geometryCache.put(result.key,resource,result.retained,result.wireBytes);activeIndex=result.index;
        if (!requested) selectedScene=gallery.activeScene || selectedScene;
        if (target === requested) target=null;loaded = true;
      } catch (error) { if (!controller.signal.aborted) post({type:'home-artifact:review-error'}); }
      finally { clearTimeout(deadline); pending = null;if(target&&target!==requested&&!document.hidden)hydrate(target); }
    }
    listen(window, 'message',event=>{
      if (event.source !== frame.contentWindow || event.origin !== 'null') return;
      if(support(event.data))return;
      const intent=sceneIntent(event.data);if(intent){cancel();target=intent;if(!pending)hydrate(intent);return;}
      if(acceptReply(event.data)||cancelScene(event.data))return;
      if (event.data?.type === 'home-artifact:review-load-pinned' && Object.keys(event.data).length === 1) hydrate();
    });
    listen(document, 'visibilitychange',()=>{if(document.hidden) cancel()});
    listen(window, 'pagehide',()=>{cancel()});
    return {dispose};
  }
  async function poll() {
    if (!wanted || document.hidden || pending) return;
    if (!initialResolved) {list(); return;}
    const controller = new AbortController(); pending = controller; immediate = false;
    requestTimeout = setTimeout(() => { controller.abort(); if (acknowledgment) { post({type:'home-artifact:review-cancel',requestId:acknowledgment.requestId}); acknowledgment.resolve(false); acknowledgment = null; } }, 20000);
    const requested = target, candidateResource = requested?.resource || resource;
    try {
      if (requested) post({type:'home-artifact:review-progress',stage:'authorizing'});
      const response = await fetch('/works/' + candidateResource + '/current/review-live.json', {cache:'no-store', signal:controller.signal});
      if ([401,403,404].includes(response.status)) geometryCache.evictResource(candidateResource);
      const next = response.headers.get('X-Home-Version');
      const manifest = JSON.parse(new TextDecoder().decode(await bytes(response, 16384)));
      if (!/^[a-f0-9]{64}$/.test(next || '') || manifest.schema !== 'dm.review-live/v1' || manifest.gallery !== 'gallery.json' || !/^[a-f0-9]{64}$/.test(manifest.sha256 || '')) throw Error('Invalid review manifest');
      if (requested || next !== version) {
        // Every cache hit follows this freshly authorized manifest response.
        if (requested?.expectedVersion && requested.expectedVersion !== next) throw Error('Scene publication changed');
        if (requested) post({type:'home-artifact:review-progress',stage:'downloading'});
        const result=await loadGallery(manifest,candidateResource,next,controller.signal,requested?.scene);
        const gallery=result.gallery;
        if (!wanted || document.hidden || controller.signal.aborted) return;
        if (requested || gallery.sceneIndex) {
          const requestId = String(++serial);
          const accepted = new Promise(resolve => { acknowledgment = {requestId, resource:candidateResource, version:next, resolve}; });
          post({type:'home-artifact:review-update',version:next,resource:candidateResource,gallery,requestId,switching:true,prepareOnly:!!requested?.prepare,sceneIntent:requested?.sceneIntent,preserveState:!requested&&candidateResource===resource});
          if (!await accepted || controller.signal.aborted) throw Error('Review not accepted');
          await commit(requestId,candidateResource,next,!!result.index);
          if(controller.signal.aborted)throw Error('Review commit cancelled');
          geometryCache.put(result.key,candidateResource,result.retained,result.wireBytes);
          activeIndex=result.index;if(!requested?.prepare)selectedScene=gallery.activeScene||selectedScene;
          resource = candidateResource; rememberProject();
          if (target === requested) target = null;
        } else post({type:'home-artifact:review-update',version:next,resource,gallery});
        version = next;
      }
      delay = 10000;
      if (wanted && !document.hidden && !controller.signal.aborted) frame.contentWindow.postMessage({type:'home-artifact:review-current',version,resource}, '*');
    } catch (error) {
      if (target === requested) target = null;
      if (!controller.signal.aborted) { delay = Math.min(delay * 2, 60000); frame.contentWindow.postMessage({type:'home-artifact:review-error'}, '*'); }
    } finally {
      clearTimeout(requestTimeout); requestTimeout = null; pending = null;
      if (wanted && !document.hidden) timer = setTimeout(poll, immediate ? 0 : delay);
    }
  }
  listen(window, 'message', event => {
    if (event.source !== frame.contentWindow || event.origin !== 'null') return;
    const message = event.data;
    if(support(message))return;
    const intent=sceneIntent(message);if(intent){cancel();target=intent;wanted=true;immediate=true;if(!pending)poll();return;}
    if (message?.type === 'home-artifact:review-catalog') { list(); return; }
    if(acceptReply(message)||cancelScene(message))return;
    if (message?.type === 'home-artifact:review-select') {
      if (document.hidden || !catalog.has(message.resource)) return;
      if (target?.initial && message.resource === resource) return; // Ignore child bootstrap hydration while the explicit target loads.
      initialResolved = true; initialProject = null;
      cancel(); target = {resource:message.resource}; wanted = true; immediate = true;
      if (!pending) poll(); return;
    }
    if (message?.type !== 'home-artifact:live-review' || typeof message.enabled !== 'boolean') return;
    wanted = event.data.enabled; immediate = wanted; cancel();
    if (wanted && !document.hidden && !pending) poll();
  });
  listen(document, 'visibilitychange', () => { if (document.hidden && catalogPending) catalogPending.abort(); immediate = !document.hidden; cancel(); if (wanted && !document.hidden && !pending) poll(); });
  listen(window, 'pagehide', () => { geometryCache.clear(); cancel(); if (catalogPending) catalogPending.abort(); });
  listen(window, 'pageshow', () => { if (wanted && !document.hidden && !pending) poll(); });
  return {dispose};
}

// Trusted applications reuse the pinned hydrator and the same opaque child.
// Descriptors come from the home gateway, never artifact postMessage data.
const pinnedReviewMounts = new WeakMap();
globalThis.DaimonHomeReview = Object.freeze({
  schema: 'dm.home-review-parent/v1',
  mountPinned(frame, selectedSource) {
    if (pinnedReviewMounts.has(frame)) throw Error('Pinned source already mounted');
    const serialized = JSON.stringify(selectedSource);
    if (!serialized || new TextEncoder().encode(serialized).length > 8192) throw Error('Invalid pinned source');
    const source = JSON.parse(serialized);
    if (source?.schema !== 'dm.home-review-source/v1'
        || !/^[a-f0-9]{32}$/.test(source.resource || '')
        || !/^[a-f0-9]{64}$/.test(source.version || '')
        || source.frame?.sandbox !== 'allow-scripts'
        || source.hydration?.manifest !== 'review-live.json'
        || source.hydration?.gallery !== 'gallery.json'
        || source.adapter_handshake !== 'required') throw Error('Invalid pinned source');
    const origin = new URL(source.content_origin), src = new URL(source.frame.src);
    if (origin.protocol !== 'https:' || origin.origin !== source.content_origin
        || src.origin !== origin.origin || src.username || src.password || src.search || src.hash
        || !/^\/r\/[A-Za-z0-9_-]{43}\//.test(src.pathname)) throw Error('Invalid isolated context');
    frame.setAttribute('sandbox', 'allow-scripts');
    frame.dataset.downloadRoot = '/works/' + source.resource + '/' + source.version + '/';
    frame.dataset.liveReview = 'pinned';
    const hydration = installLiveReview(frame);
    const loaded = () => frame.contentWindow.postMessage({
      type:'home-artifact:capabilities', downloads:false, reviewPacked:true, reviewScenes:true, reviewJSON:true,
      reviewPinned:true, liveReview:false, reviewCatalog:false, reviewContext:true,
      resource:source.resource,
    }, '*');
    frame.addEventListener('load', loaded);
    pinnedReviewMounts.set(frame, true);
    frame.src = src.href;
    let disposed = false;
    return {dispose() {
      if (disposed) return;
      disposed = true; frame.removeEventListener('load', loaded); hydration.dispose();
      pinnedReviewMounts.delete(frame);
      frame.removeAttribute('src');
    }};
  },
});
