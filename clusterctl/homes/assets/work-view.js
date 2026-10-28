// This bridge carries fragments and selected media downloads within one work.
// Messages cannot select another resource, change audience or invoke owner APIs.
'use strict';
const frame = document.querySelector('iframe[data-src]');
const validFragment = value => typeof value === 'string' && value.length < 2048 && /^(?:#[A-Za-z0-9/_-]*)?$/.test(value);
if (frame) {
  function openFragment() {
    if (!validFragment(location.hash)) return;
    const source = new URL(frame.dataset.src);
    if (source.href + location.hash !== frame.src) {
      source.hash = location.hash;
      frame.src = source.href;
    }
  }
  openFragment();
  frame.addEventListener('load', () => {
    frame.contentWindow.postMessage({type:'home-artifact:capabilities', downloads:true, reviewPacked:typeof decodeReviewGallery === 'function', reviewPinned:typeof installLiveReview === 'function' && frame.dataset.liveReview !== 'current', liveReview:frame.dataset.liveReview === 'current' && typeof installLiveReview === 'function', reviewCatalog:frame.dataset.liveReview === 'current' && typeof installLiveReview === 'function', resource:(/^\/works\/([a-f0-9]{32})\//.exec(frame.dataset.downloadRoot || '') || [])[1]}, '*');
  });
  window.addEventListener('hashchange', openFragment);
  window.addEventListener('message', event => {
    if (event.source !== frame.contentWindow || event.origin !== 'null') return;
    if (event.data?.type === 'home-artifact:download') {
      const path = event.data.path;
      if (typeof path !== 'string' || !/^media\/[a-f0-9]{64}\.[a-z0-9]{1,8}$/.test(path)) return;
      let files;
      try { files = JSON.parse(frame.dataset.downloadFiles); } catch { return; }
      if (!Array.isArray(files) || !files.includes(path)) return;
      const root = frame.dataset.downloadRoot;
      if (!/^\/works\/[a-f0-9]{32}\/[a-f0-9]{64}\/$/.test(root || '')) return;
      const link = document.createElement('a');
      link.href = root + path;
      link.download = path.slice(6);
      link.rel = 'noopener';
      document.body.append(link);
      link.click();
      link.remove();
      return;
    }
    if (event.data?.type !== 'home-artifact:fragment' || !validFragment(event.data.fragment)) return;
    history.replaceState(null, '', location.pathname + location.search + event.data.fragment);
  });
}

if (frame && typeof installLiveReview === 'function') installLiveReview(frame);
