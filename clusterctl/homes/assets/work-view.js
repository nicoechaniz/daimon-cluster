// The opaque child may offer one same-home related work in the trusted header.
// It cannot navigate the parent, change audience or invoke owner APIs.
'use strict';
const frame = document.querySelector('iframe[data-src]');
const validFragment = value => typeof value === 'string' && value.length < 2048 && /^(?:#[A-Za-z0-9/_-]*)?$/.test(value);
if (frame) {
  let related;
  function clearRelated() {
    related?.remove();
    related = undefined;
    document.body.classList.remove('has-related-work');
  }
  function offerRelated(data) {
    if (related || typeof data.resource !== 'string' || !/^[a-f0-9]{32}$/.test(data.resource)) return;
    if (typeof data.label !== 'string' || !data.label.trim() || data.label.length > 80) return;
    related = document.createElement('nav');
    related.className = 'work-related-action';
    related.setAttribute('aria-label', 'Related work');
    const link = document.createElement('a');
    link.href = '/view/' + data.resource + '?display=work';
    link.textContent = data.label;
    // Only an ordinary user click on this outer link navigates. No postMessage
    // performs a click or bypasses the destination's current audience checks.
    related.append(link);
    frame.before(related);
    document.body.classList.add('has-related-work');
  }
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
    clearRelated();
    frame.contentWindow.postMessage({type:'home-artifact:capabilities', relatedWork:true, downloads:true, reviewContext:true, reviewPacked:typeof decodeReviewGallery === 'function', reviewScenes:typeof validateReviewSceneIndex === 'function', reviewJSON:typeof reviewGalleryJSON === 'function', reviewPinned:typeof installLiveReview === 'function' && frame.dataset.liveReview !== 'current', liveReview:frame.dataset.liveReview === 'current' && typeof installLiveReview === 'function', reviewCatalog:frame.dataset.liveReview === 'current' && typeof installLiveReview === 'function', resource:(/^\/works\/([a-f0-9]{32})\//.exec(frame.dataset.downloadRoot || '') || [])[1]}, '*');
  });
  window.addEventListener('hashchange', openFragment);
  window.addEventListener('message', event => {
    if (event.source !== frame.contentWindow || event.origin !== 'null') return;
    if (event.data?.type === 'home-artifact:related-work') {
      offerRelated(event.data);
      return;
    }
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
