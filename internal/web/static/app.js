(() => {
  'use strict';

  // Every value that comes from the network (domain names, client IPs) is
  // written with textContent, never innerHTML: any DNS client can choose the
  // names that end up in this page.
  const $ = (id) => document.getElementById(id);
  let token = sessionStorage.getItem('ariadns_token') || '';

  async function api(path, opts = {}, retried = false) {
    const headers = Object.assign({}, opts.headers || {});
    if (token) headers['Authorization'] = 'Bearer ' + token;
    const res = await fetch(path, Object.assign({}, opts, { headers, cache: 'no-store' }));
    if (res.status === 401) {
      if (retried) throw new Error('unauthorized');
      const t = window.prompt('API token required');
      if (!t) throw new Error('unauthorized');
      token = t;
      sessionStorage.setItem('ariadns_token', t);
      return api(path, opts, true);
    }
    if (!res.ok) throw new Error(res.status + ' ' + (await res.text()));
    return res.json();
  }

  const fmt = new Intl.NumberFormat();
  const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + '%' : '0%');
  const ms = (v) => (v < 10 ? v.toFixed(2) : v.toFixed(1));

  function uptime(sec) {
    const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    return (d ? d + 'd ' : '') + (h || d ? h + 'h ' : '') + m + 'm ' + (sec % 60) + 's';
  }

  function cell(text, cls) {
    const td = document.createElement('td');
    td.textContent = text;
    if (cls) td.className = cls;
    return td;
  }

  function tagCell(outcome) {
    const td = document.createElement('td');
    const s = document.createElement('span');
    s.className = 'tag ' + outcome;
    s.textContent = outcome;
    td.appendChild(s);
    return td;
  }

  function fill(tbody, rows) {
    tbody.replaceChildren(...rows);
  }

  function emptyRow(cols) {
    const tr = document.createElement('tr');
    const td = cell('no data yet', 'empty');
    td.colSpan = cols;
    tr.appendChild(td);
    return [tr];
  }

  function topTable(id, list) {
    const rows = list.map((c) => {
      const tr = document.createElement('tr');
      tr.append(cell(c.name), cell(fmt.format(c.count), 'num'));
      return tr;
    });
    fill($(id), rows.length ? rows : emptyRow(2));
  }

  function bars(id, data) {
    const entries = Object.entries(data);
    const max = Math.max(1, ...entries.map(([, v]) => v));
    const rows = entries.map(([k, v]) => {
      const row = document.createElement('div');
      row.className = 'row';
      const name = document.createElement('div');
      name.textContent = k;
      const track = document.createElement('div');
      track.className = 'track';
      const f = document.createElement('div');
      f.className = 'fill';
      f.style.width = (100 * v / max) + '%';
      track.appendChild(f);
      const n = document.createElement('div');
      n.className = 'n';
      n.textContent = fmt.format(v);
      row.append(name, track, n);
      return row;
    });
    $(id).replaceChildren(...rows);
  }

  function spark(values) {
    const cv = $('spark');
    const ctx = cv.getContext('2d');
    const w = cv.width, h = cv.height, pad = 6;
    ctx.clearRect(0, 0, w, h);
    const max = Math.max(1, ...values);
    ctx.strokeStyle = '#262d38';
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let i = 1; i < 4; i++) { const y = pad + (h - 2 * pad) * i / 4; ctx.moveTo(0, y); ctx.lineTo(w, y); }
    ctx.stroke();
    const step = w / (values.length - 1);
    const y = (v) => h - pad - (h - 2 * pad) * v / max;
    ctx.beginPath();
    values.forEach((v, i) => (i ? ctx.lineTo(i * step, y(v)) : ctx.moveTo(0, y(v))));
    ctx.strokeStyle = '#4cc2ff';
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
    ctx.fillStyle = 'rgba(76,194,255,0.12)';
    ctx.fill();
    ctx.fillStyle = '#8b98a8';
    ctx.font = '12px system-ui, sans-serif';
    ctx.fillText('peak ' + max + ' qps', 8, 16);
  }

  function render(d) {
    const s = d.stats;
    $('version').textContent = 'v' + d.version;
    $('uptime').textContent = 'up ' + uptime(s.uptime_sec);
    const st = $('status');
    st.textContent = 'live';
    st.className = 'pill ok';

    const o = s.outcomes;
    const served = s.total - (o.refused || 0) - (o.ratelimited || 0);
    $('c-total').textContent = fmt.format(s.total);
    $('c-blocked').textContent = pct(o.blocked || 0, served);
    $('c-cache').textContent = pct((o.cache || 0) + (o.stale || 0), served);
    $('c-lat').textContent = ms(s.latency_avg_ms) + ' / ' + ms(s.latency_p95_ms) + ' ms';
    const q = s.qps;
    $('c-qps').textContent = q.length ? q[q.length - 1] : 0;
    spark(q);
    bars('outcomes', o);
    bars('transports', s.transports);
    topTable('t-domains', s.top_domains || []);
    topTable('t-blocked', s.top_blocked || []);
    topTable('t-clients', s.top_clients || []);

    const urows = (d.upstreams || []).map((u) => {
      const tr = document.createElement('tr');
      const state = cell(u.up ? 'up' : 'down');
      state.title = u.last_error || '';
      tr.append(cell(u.name), state, cell(u.avg_rtt_ms ? ms(u.avg_rtt_ms) + ' ms' : '-', 'num'),
        cell(fmt.format(u.queries), 'num'), cell(fmt.format(u.failures), 'num'));
      return tr;
    });
    fill($('t-upstreams'), urows.length ? urows : emptyRow(5));

    const c = d.cache;
    $('footer').textContent =
      (c ? 'cache ' + fmt.format(c.entries) + ' entries - ' : 'cache off - ') +
      fmt.format(d.rules.blocked_domains) + ' blocked domains - ' +
      fmt.format(d.rules.local_hosts) + ' local hosts - ' +
      fmt.format(d.rules.forward_zones) + ' forward zones' +
      (d.shed ? ' - shed ' + fmt.format(d.shed) : '');
  }

  function renderRecent(list) {
    const rows = list.map((e) => {
      const tr = document.createElement('tr');
      tr.append(
        cell(new Date(e.time).toLocaleTimeString()),
        cell(e.client),
        cell(e.name || '.', 'name'),
        cell(e.qtype),
        cell(e.transport),
        cell(e.rcode || '-'),
        tagCell(e.outcome),
        cell(ms(e.latency_us / 1000), 'num'),
      );
      return tr;
    });
    fill($('t-recent'), rows.length ? rows : emptyRow(8));
  }

  async function tick() {
    try {
      const [stats, recent] = await Promise.all([api('api/stats'), api('api/queries?limit=40')]);
      render(stats);
      renderRecent(recent);
    } catch (err) {
      const st = $('status');
      st.textContent = err.message === 'unauthorized' ? 'unauthorized' : 'offline';
      st.className = 'pill bad';
    }
  }

  async function action(path, label) {
    try {
      await api(path, { method: 'POST' });
      $('status').textContent = label;
    } catch (err) {
      window.alert(label + ' failed: ' + err.message);
    }
    tick();
  }

  $('btn-flush').addEventListener('click', () => action('api/cache/flush', 'cache flushed'));
  $('btn-reload').addEventListener('click', () => action('api/reload', 'rules reloaded'));

  tick();
  setInterval(tick, 2000);
})();
