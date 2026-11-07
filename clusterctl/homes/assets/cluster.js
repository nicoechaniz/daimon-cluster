'use strict';
(() => {
  const byId = id => document.getElementById(id);
  let busy = false, last = null;
  function card(row, planned) {
    const article = document.createElement('article'); article.className = 'fleet-card';
    const badge = document.createElement('span'); badge.className = 'state';
    const current = !planned && row.lease_expires_at_ms > Date.now();
    badge.textContent = planned ? 'Planned' : current ? 'Admitted' : 'Observation expired';
    if (!current) badge.classList.add('stale');
    article.append(badge);
    const name = document.createElement('h3'); name.textContent = row.name; article.append(name);
    for (const text of [row.host, row.hosting, planned ? 'Not created or authenticated yet.' : 'Current signed admission; no model response requested.']) {
      const p = document.createElement('p'); p.textContent = text; article.append(p);
    }
    return article;
  }
  function render(data) {
    byId('instances').replaceChildren(...data.instances.map(row => card(row, false)));
    byId('planned').replaceChildren(...data.planned.map(row => card(row, true)));
    byId('count').textContent = data.instances.length + ' observed';
    byId('coverage').textContent = data.partial ? 'Partial inventory: some admissions could not be observed.' : 'Current local Cluster admissions. Unregistered or other-Cluster bodies are outside this inventory.';
    byId('checked').textContent = 'Source checked ' + new Date(data.observed_at_ms).toLocaleString();
  }
  async function refresh() {
    if (busy || document.hidden) return;
    busy = true; byId('refresh').disabled = true;
    try {
      const response = await fetch('/cluster/api/fleet', {credentials:'same-origin', cache:'no-store', headers:{Accept:'application/json'}});
      byId('signin').hidden = response.status !== 401;
      if ([401,403].includes(response.status)) { last = null; byId('instances').replaceChildren(); byId('planned').replaceChildren(); byId('count').textContent = ''; }
      if (response.status === 401) throw new Error('Sign in with our shared login to view the inventory.');
      if (response.status === 403) throw new Error('This account has no Cluster inventory grant.');
      if (!response.ok) throw new Error('Inventory unavailable. Previous observations may have expired.');
      last = await response.json(); render(last); byId('status').textContent = 'Connected · updates every 10 seconds while visible';
    } catch (error) {
      if (last) render(last); byId('status').textContent = error.message;
    } finally { busy = false; byId('refresh').disabled = false; }
  }
  byId('refresh').addEventListener('click', refresh);
  byId('signin').addEventListener('click', async () => {
    try { await window.DaimonHomeAccess.createClient().signIn(); await refresh(); }
    catch (error) { byId('status').textContent = error.message; }
  });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
  setInterval(refresh, 10000); refresh();
})();
