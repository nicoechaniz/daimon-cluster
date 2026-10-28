// Authorized review updates. Child selection is restricted to the current reader catalog.
'use strict';
function installLiveReview(frame) {
  const root = frame.dataset.downloadRoot || '';
  const match = /^\/works\/([a-f0-9]{32})\/([a-f0-9]{64})\/$/.exec(root);
  if (!match || frame.dataset.liveReview !== 'current') return;
  let resource = match[1], target = null, catalog = new Map(), catalogPending = null, acknowledgment = null, serial = 0;
  let version = match[2], wanted = false, timer = null, pending = null, requestTimeout = null, delay = 10000, immediate = false;
  const post = data => frame.contentWindow.postMessage(data, '*');
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
      post({type:'home-artifact:review-catalog', entries, resource});
    } catch (error) { if (!controller.signal.aborted) post({type:'home-artifact:review-catalog-error'}); }
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
  async function poll() {
    if (!wanted || document.hidden || pending) return;
    const controller = new AbortController(); pending = controller; immediate = false;
    requestTimeout = setTimeout(() => { controller.abort(); if (acknowledgment) { post({type:'home-artifact:review-cancel',requestId:acknowledgment.requestId}); acknowledgment.resolve(false); acknowledgment = null; } }, 20000);
    const requested = target, candidateResource = requested?.resource || resource;
    try {
      const response = await fetch('/works/' + candidateResource + '/current/review-live.json', {cache:'no-store', signal:controller.signal});
      const next = response.headers.get('X-Home-Version');
      const manifest = JSON.parse(new TextDecoder().decode(await bytes(response, 16384)));
      if (!/^[a-f0-9]{64}$/.test(next || '') || manifest.schema !== 'dm.review-live/v1' || manifest.gallery !== 'gallery.json' || !/^[a-f0-9]{64}$/.test(manifest.sha256 || '')) throw Error('Invalid review manifest');
      if (requested || next !== version) {
        const response = await fetch('/works/' + candidateResource + '/' + next + '/gallery.json', {cache:'no-store', signal:controller.signal});
        if (response.headers.get('X-Home-Version') !== next) throw Error('Review version changed');
        const data = await bytes(response, 25 * 1024 * 1024);
        const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', data)), b => b.toString(16).padStart(2,'0')).join('');
        if (digest !== manifest.sha256) throw Error('Review payload mismatch');
        const gallery = JSON.parse(new TextDecoder().decode(data));
        if (!wanted || document.hidden || controller.signal.aborted) return;
        if (requested) {
          const requestId = String(++serial);
          const accepted = new Promise(resolve => { acknowledgment = {requestId, resource:candidateResource, version:next, resolve}; });
          post({type:'home-artifact:review-update',version:next,resource:candidateResource,gallery,requestId,switching:true});
          if (!await accepted || controller.signal.aborted) throw Error('Review not accepted');
          resource = candidateResource;
          post({type:'home-artifact:review-commit',requestId,resource,version:next});
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
  window.addEventListener('message', event => {
    if (event.source !== frame.contentWindow || event.origin !== 'null') return;
    const message = event.data;
    if (message?.type === 'home-artifact:review-catalog') { list(); return; }
    if (message?.type === 'home-artifact:review-applied') {
      if (acknowledgment && message.requestId === acknowledgment.requestId
          && message.resource === acknowledgment.resource && message.version === acknowledgment.version) {
        const resolve = acknowledgment.resolve; acknowledgment = null; resolve(message.accepted === true);
      }
      return;
    }
    if (message?.type === 'home-artifact:review-select') {
      if (document.hidden || !catalog.has(message.resource)) return;
      cancel(); target = {resource:message.resource}; wanted = true; immediate = true;
      if (!pending) poll(); return;
    }
    if (message?.type !== 'home-artifact:live-review' || typeof message.enabled !== 'boolean') return;
    wanted = event.data.enabled; immediate = wanted; cancel();
    if (wanted && !document.hidden && !pending) poll();
  });
  document.addEventListener('visibilitychange', () => { if (document.hidden && catalogPending) catalogPending.abort(); immediate = !document.hidden; cancel(); if (wanted && !document.hidden && !pending) poll(); });
  window.addEventListener('pagehide', () => { cancel(); if (catalogPending) catalogPending.abort(); });
  window.addEventListener('pageshow', () => { if (wanted && !document.hidden && !pending) poll(); });
}
