'use strict';
(() => {
  const byId = id => document.getElementById(id);
  let busy = false, last = null, selectedHost = null;
  function card(row, planned) {
    const article = document.createElement('article'); article.className = 'fleet-card';
    const badge = document.createElement('span'); badge.className = 'state';
    const current = !planned && row.lease_expires_at_ms > Date.now();
    badge.textContent = planned ? (row.physical_state ? 'Virtual ' + row.physical_state : 'Not observed') : current ? 'Admitted' : 'Observation expired';
    if (!current) badge.classList.add('stale');
    article.append(badge);
    const name = document.createElement('h3'); name.textContent = row.name; article.append(name);
    for (const text of [row.host, row.hosting, planned ? 'Onboarding: ' + (row.stage || 'not observed') + ' · ' + (row.job_state || 'unknown') : 'Current signed admission; no model response requested.']) {
      const p = document.createElement('p'); p.textContent = text; article.append(p);
    }
    if (planned) {
      if (row.physical_state === 'running' && !Object.keys(row.services || {}).length) article.append(node('p', 'Service observation unavailable', 'state stale'));
      for (const [service, state] of Object.entries(row.services || {})) article.append(node('p', service.replace('.service', '') + ': ' + state));
      article.append(node('p', 'Physical observation: ' + dated(row.observed_at_ms) + '. Matrix admission remains separate.', 'muted'));
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
    for (const row of [...data.instances, ...data.planned]) {
      // An unknown placement is a missing field, never another physical host.
      if (row.host && row.host !== 'Placement unverified') names.add(row.host);
    }
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
  function usage(data) {
    const value = data.usage || {}, accounts = value.accounts || [], rows = value.daimons || [];
    byId('usage-status').textContent = rows.length ? 'Native counters · refreshed at most once a minute' : 'Usage source unavailable';
    byId('usage-coverage').textContent = value.coverage || 'No token observation available. Missing data is not zero usage.';
    byId('usage-daimons').replaceChildren(...rows.map(row => {
      const box = node('article', '', 'fleet-card');
      box.append(node('h3', row.name), node('strong', row.total_tokens == null ? 'Unavailable' : row.total_tokens.toLocaleString() + ' tokens'),
        node('p', row.conversations + ' recorded conversations · ' + row.bodies + ' observed body/bodies'),
        node('p', row.partial ? 'Partial coverage · ' + row.unavailable_bodies + ' unavailable body/bodies' : 'Selected native databases observed', 'muted'),
        node('p', 'Recorded since ' + dated(row.since ? row.since * 1000 : null) + ' · checked ' + dated(row.observed_at_ms), 'muted'));
      return box;
    }));
    byId('usage-accounts').replaceChildren(...accounts.map(row => {
      const box = node('article', '', 'fleet-card');
      box.append(node('h3', row.label), node('p', (row.plan || 'Plan unavailable') + ' · ' + row.daimons.join(', ')));
      for (const window of row.windows || []) {
        const minutes = window.window_minutes;
        const label = minutes === 10080 ? 'Weekly' : minutes % 1440 === 0 ? minutes / 1440 + ' days' : minutes % 60 === 0 ? minutes / 60 + ' hours' : minutes + ' minutes';
        box.append(meter(window.limit + ' · ' + label, window.used_percent, 100, window.used_percent + '% used'),
          node('p', 'Resets ' + dated(window.resets_at ? window.resets_at * 1000 : null), 'muted'));
      }
      if (!row.windows?.length) box.append(node('p', 'Allowance windows unavailable'));
      if (row.ordinary_usage_allowed === false) box.append(node('p', 'Ordinary allowance unavailable', 'state stale'));
      if (row.reset_credits != null) box.append(node('p', row.reset_credits + ' reset credit(s) available'));
      box.append(node('p', 'Checked ' + dated(row.observed_at_ms), 'muted'));
      return box;
    }));
    if (!accounts.length) byId('usage-accounts').append(node('p', 'Account windows unavailable. Missing data does not mean an unused allowance.', 'muted'));
    if (value.account_unavailable_sources) byId('usage-accounts').append(node('p', value.account_unavailable_sources + ' account source(s) unavailable.', 'muted'));
  }
  function render(data) {
    map(data); alerts(data); usage(data);
    byId('instances').replaceChildren(...data.instances.map(row => card(row, false)));
    byId('planned').replaceChildren(...data.planned.map(row => card(row, true)));
    byId('count').textContent = data.instances.length + ' admitted · ' + data.planned.length + ' virtual preparations';
    byId('preparation-status').textContent = data.preparation_state === 'unavailable' ? 'Current virtual observation unavailable; no fixed preparation status is substituted.' : data.preparation_state === 'partial' ? 'Some host observations are unavailable. Only current successful reads are shown.' : 'Current host/job observations · service activity does not establish human acceptance.';
    byId('coverage').textContent = data.partial ? 'Partial inventory: some admissions could not be observed.' : 'Current local Cluster admissions. Unregistered or other-Cluster bodies are outside this inventory.';
    byId('checked').textContent = 'Source checked ' + new Date(data.observed_at_ms).toLocaleString();
  }
  async function refresh() {
    if (busy || document.hidden) return;
    busy = true; byId('refresh').disabled = true;
    const started = Date.now(), controller = new AbortController();
    const loading = () => {
      const seconds = Math.floor((Date.now() - started) / 1000);
      byId('status').textContent = (last ? 'Updating current observations' : 'Checking hosts and account usage')
        + ' · ' + seconds + ' s' + (seconds >= 5 ? ' · remote reads can take a few seconds' : '');
    };
    loading();
    const progress = setInterval(loading, 1000);
    const deadline = setTimeout(() => controller.abort(), 55000);
    try {
      const response = await fetch('/cluster/api/fleet', {credentials:'same-origin', cache:'no-store', headers:{Accept:'application/json'}, signal:controller.signal});
      byId('signin').hidden = response.status !== 401;
      if ([401,403].includes(response.status)) { last = null; for (const id of ['hosts','host-detail','alerts','usage-daimons','usage-accounts']) byId(id).replaceChildren(); byId('alert-status').textContent = ''; byId('instances').replaceChildren(); byId('planned').replaceChildren(); byId('count').textContent = ''; }
      if (response.status === 401) throw new Error('Sign in with our shared login to view the inventory.');
      if (response.status === 403) throw new Error('This account has no Cluster inventory grant.');
      if (!response.ok) throw new Error('Inventory unavailable. Previous observations may have expired.');
      last = await response.json(); render(last); byId('status').textContent = 'Connected · updates every 10 seconds while visible';
    } catch (error) {
      if (last) render(last);
      byId('status').textContent = controller.signal.aborted
        ? 'The inventory read timed out. Refresh to try again; previous observations retain their dates.' : error.message;
    } finally {
      clearInterval(progress); clearTimeout(deadline);
      busy = false; byId('refresh').disabled = false;
    }
  }
  byId('refresh').addEventListener('click', refresh);
  byId('signin').addEventListener('click', async () => {
    try { await window.DaimonHomeAccess.createClient().signIn(); await refresh(); }
    catch (error) { byId('status').textContent = error.message; }
  });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
  setInterval(refresh, 10000); refresh();
})();
