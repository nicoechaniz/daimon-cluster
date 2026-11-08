'use strict';
(() => {
  const byId = id => document.getElementById(id);
  let busy = false, last = null, selectedHost = null;
  function card(row, planned) {
    const article = document.createElement('article'); article.className = 'fleet-card';
    const badge = document.createElement('span'); badge.className = 'state';
    const current = !planned && row.lease_expires_at_ms > Date.now();
    badge.textContent = planned ? 'Planned' : current ? 'Admitted' : 'Observation expired';
    if (!current) badge.classList.add('stale');
    article.append(badge);
    const name = document.createElement('h3'); name.textContent = row.name; article.append(name);
    for (const text of [row.host, row.hosting, planned ? 'Native admission pending; preparation is tracked separately.' : 'Current signed admission; no model response requested.']) {
      const p = document.createElement('p'); p.textContent = text; article.append(p);
    }
    return article;
  }
  const node = (tag, text, css) => {
    const element = document.createElement(tag); element.textContent = text;
    if (css) element.className = css; return element;
  };
  const gib = bytes => Number.isFinite(bytes) ? (bytes / 1073741824).toFixed(1) + ' GiB' : 'Unknown';
  const dated = at => at ? new Date(at).toLocaleString() : 'Not observed';
  function meter(label, used, total, suffix) {
    const box = node('div', '', 'resource-meter');
    box.append(node('span', label), node('strong', suffix));
    if (Number.isFinite(used) && Number.isFinite(total) && total > 0) {
      const bar = document.createElement('meter'); bar.min = 0; bar.max = total;
      bar.value = Math.max(0, Math.min(total, used)); bar.setAttribute('aria-label', label);
      box.append(bar);
    }
    return box;
  }
  function map(data) {
    const observation = data.observability || {}, targets = observation.health?.targets || [];
    const names = new Set(targets.map(t => t.label));
    for (const row of [...data.instances, ...data.planned]) names.add(row.host);
    if (!selectedHost || !names.has(selectedHost)) selectedHost = [...names][0];
    const cards = [...names].map(name => {
      const target = targets.find(t => t.label === name), reading = target?.reading;
      const recent = target?.state === 'available' && Date.now() - Date.parse(reading?.observed_at) < 300000;
      const button = node('button', '', 'host-node'); button.type = 'button';
      button.setAttribute('aria-pressed', String(name === selectedHost));
      button.append(node('span', recent ? 'Recent reading' : reading ? 'Dated reading' : 'Metrics unavailable', 'state' + (recent ? '' : ' stale')),
        node('h3', name), node('p', target?.scope || 'Placement from operator inventory'));
      const incidents = (observation.alerts || []).filter(row => row.resource_ref === target?.id);
      if (incidents.length) button.append(node('span', incidents.length + ' open incident(s)', 'state stale'));
      const members = [...data.instances, ...data.planned].filter(t => t.host === name);
      const chips = node('div', '', 'host-members');
      for (const member of members) chips.append(node('span', member.name, 'member-chip'));
      if (!members.length) chips.append(node('span', 'No direct admission in this scope', 'muted'));
      button.append(chips);
      if (reading?.cpu) button.append(node('p', 'CPU ' + (reading.cpu.percent ?? '—') + '% · ' + reading.cpu.logical_capacity + ' logical CPUs'));
      button.addEventListener('click', () => { selectedHost = name; map(data); }); return button;
    });
    byId('hosts').replaceChildren(...cards);
    const target = targets.find(t => t.label === selectedHost), reading = target?.reading;
    const detail = byId('host-detail'); detail.replaceChildren(node('h3', selectedHost || 'Resource observations'));
    if (!reading) { detail.append(node('p', 'No resource reading is available for this placement. Availability and capacity remain unknown.')); return; }
    detail.append(node('p', 'Observed ' + dated(reading.observed_at) + ' · ' + target.scope, 'muted'));
    if (target.state !== 'available') detail.append(node('p', 'Latest attempt failed. The reading below is retained with its original date.', 'state stale'));
    const grid = node('div', '', 'resource-grid'), memory = reading.memory;
    grid.append(meter('CPU · ' + (reading.cpu?.interval_seconds ?? '?') + ' s sample', reading.cpu?.percent, 100, (reading.cpu?.percent ?? 'Unknown') + '%'));
    if (memory?.kind === 'host') grid.append(meter('Memory · available cache included', memory.total_bytes - memory.available_bytes, memory.total_bytes,
      gib(memory.total_bytes - memory.available_bytes) + ' / ' + gib(memory.total_bytes)));
    else if (memory) grid.append(meter('Memory · cgroup allowance', memory.current_bytes, memory.limit_bytes, gib(memory.current_bytes) + ' / ' + gib(memory.limit_bytes)));
    for (const disk of reading.disks || []) grid.append(meter(disk.label, disk.total_bytes - disk.available_bytes, disk.total_bytes,
      disk.unavailable ? 'Unavailable' : gib(disk.available_bytes) + ' available / ' + gib(disk.total_bytes)));
    detail.append(grid);
    for (const service of reading.services || []) detail.append(node('p', service.label + ': ' + (service.active || 'unavailable') + ' · application readiness not checked', 'muted'));
  }
  function alerts(data) {
    const observation = data.observability || {}, rows = observation.alerts || [];
    byId('alert-status').textContent = observation.alerts_state === 'observed'
      ? rows.length + ' open' + (observation.alerts_partial ? ' · partial list' : ' · scoped view') : 'Alert source ' + (observation.alerts_state || 'unconfigured');
    const cards = rows.map(row => {
      const article = node('article', '', 'alert-card ' + (row.severity === 'critical' ? 'critical' : ''));
      article.append(node('span', row.severity + ' · ' + row.resource_ref, 'state'), node('h3', row.summary),
        node('p', row.action), node('p', row.producer_id + ' · ' + (row.acknowledged ? 'Acknowledged; still open' : 'Unacknowledged')
          + ' · ' + row.freshness + ' · updated ' + dated(row.updated_at * 1000), 'muted'));
      return article;
    });
    if (!cards.length) cards.push(node('p', observation.alerts_state === 'observed'
      ? 'No open incidents in this credential’s receiving scope. Other hosts may have separate coverage.'
      : 'No alert observation available. This does not establish that the hosts are healthy.', 'muted'));
    byId('alerts').replaceChildren(...cards);
  }
  function render(data) {
    map(data); alerts(data);
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
      if ([401,403].includes(response.status)) { last = null; for (const id of ['hosts','host-detail','alerts']) byId(id).replaceChildren(); byId('alert-status').textContent = ''; byId('instances').replaceChildren(); byId('planned').replaceChildren(); byId('count').textContent = ''; }
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
