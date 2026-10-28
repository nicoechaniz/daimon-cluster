// Same-resource, opt-in review updates. No URLs or resource IDs come from a child.
'use strict';
function installLiveReview(frame) {
  const root = frame.dataset.downloadRoot || '';
  const match = /^\/works\/([a-f0-9]{32})\/([a-f0-9]{64})\/$/.exec(root);
  if (!match || frame.dataset.liveReview !== 'current') return;
  const resource = match[1];
  let version = match[2], wanted = false, timer = null, pending = null, requestTimeout = null, delay = 10000, immediate = false;
  function cancel() {
    clearTimeout(timer); timer = null; clearTimeout(requestTimeout); requestTimeout = null;
    if (pending) pending.abort();
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
    requestTimeout = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch('/works/' + resource + '/current/review-live.json', {cache:'no-store', signal:controller.signal});
      const next = response.headers.get('X-Home-Version');
      const manifest = JSON.parse(new TextDecoder().decode(await bytes(response, 16384)));
      if (!/^[a-f0-9]{64}$/.test(next || '') || manifest.schema !== 'dm.review-live/v1' || manifest.gallery !== 'gallery.json' || !/^[a-f0-9]{64}$/.test(manifest.sha256 || '')) throw Error('Invalid review manifest');
      if (next !== version) {
        const response = await fetch('/works/' + resource + '/' + next + '/gallery.json', {cache:'no-store', signal:controller.signal});
        if (response.headers.get('X-Home-Version') !== next) throw Error('Review version changed');
        const data = await bytes(response, 25 * 1024 * 1024);
        const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', data)), b => b.toString(16).padStart(2,'0')).join('');
        if (digest !== manifest.sha256) throw Error('Review payload mismatch');
        const gallery = JSON.parse(new TextDecoder().decode(data));
        if (!wanted || document.hidden || controller.signal.aborted) return;
        frame.contentWindow.postMessage({type:'home-artifact:review-update',version:next,gallery}, '*');
        version = next;
      }
      delay = 10000;
      if (wanted && !document.hidden && !controller.signal.aborted) frame.contentWindow.postMessage({type:'home-artifact:review-current',version}, '*');
    } catch (error) {
      if (!controller.signal.aborted) { delay = Math.min(delay * 2, 60000); frame.contentWindow.postMessage({type:'home-artifact:review-error'}, '*'); }
    } finally {
      clearTimeout(requestTimeout); requestTimeout = null; pending = null;
      if (wanted && !document.hidden) timer = setTimeout(poll, immediate ? 0 : delay);
    }
  }
  window.addEventListener('message', event => {
    if (event.source !== frame.contentWindow || event.origin !== 'null' || event.data?.type !== 'home-artifact:live-review' || typeof event.data.enabled !== 'boolean') return;
    wanted = event.data.enabled; immediate = wanted; cancel();
    if (wanted && !document.hidden && !pending) poll();
  });
  document.addEventListener('visibilitychange', () => { immediate = !document.hidden; cancel(); if (wanted && !document.hidden && !pending) poll(); });
  window.addEventListener('pagehide', cancel);
  window.addEventListener('pageshow', () => { if (wanted && !document.hidden && !pending) poll(); });
}
