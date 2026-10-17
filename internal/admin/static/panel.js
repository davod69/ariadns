(() => {
  'use strict';
  const base = location.pathname.replace(/\/$/, '');
  const app = document.getElementById('app');
  const el = (tag, props, ...kids) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (k === 'class') e.className = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else e[k] = v;
    }
    for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(k));
    return e;
  };
  async function call(path, method = 'GET', body) {
    const r = await fetch(base + path, {
      method, credentials: 'same-origin', cache: 'no-store',
      headers: Object.assign({'X-Requested-With': 'ariadns'}, body ? {'Content-Type': 'application/json'} : {}),
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = null; try { data = await r.json(); } catch (e) {}
    if (r.status === 401 && path !== '/login') { showLogin(); throw new Error('login required'); }
    if (!r.ok) throw new Error((data && data.error) || r.statusText);
    return data;
  }
  const fmtBytes = n => { if (!n) return '0'; const u = ['B','KB','MB','GB','TB']; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return n.toFixed(i ? 2 : 0) + ' ' + u[i]; };
  const fmtDate = t => t ? new Date(t * 1000).toLocaleDateString() : 'never';

  function showLogin() {
    const err = el('div', {class: 'err'});
    const pw = el('input', {type: 'password', placeholder: 'Password', autocomplete: 'current-password', autofocus: true});
    const go = async () => { try { await call('/login', 'POST', {password: pw.value}); start(); } catch (e) { err.textContent = e.message; } };
    pw.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
    app.replaceChildren(el('div', {class: 'card login'}, el('h2', {}, 'ariadns'), pw, el('button', {class: 'b', onclick: go}, 'Sign in'), err));
  }

  const tabs = {};
  let current = 'overview';
  function shell() {
    const nav = el('nav', {}, Object.keys(tabs).map(k => el('button', {class: k === current ? 'on' : '', onclick: () => { current = k; render(); }}, tabs[k].title)));
    const out = el('button', {class: 'b sec sm', onclick: async () => { await call('/logout', 'POST'); showLogin(); }}, 'Sign out');
    const body = el('main', {});
    app.replaceChildren(el('header', {}, el('h1', {}, 'aria', el('span', {}, 'dns')), nav, el('span', {style: 'flex:1'}), out), body);
    return body;
  }
  async function render() { const body = shell(); try { await tabs[current].draw(body); } catch (e) { body.append(el('div', {class: 'err'}, e.message)); } }

  tabs.overview = {title: 'Overview', async draw(body) {
    const o = await call('/api/overview'); const s = o.stats || {};
    const stat = (l, v) => el('div', {class: 'card stat'}, el('div', {class: 'l'}, l), el('div', {class: 'v'}, String(v)));
    body.append(el('div', {class: 'grid'},
      stat('Version', o.version), stat('DNS queries', s.total ?? 0), stat('Relay: connections', o.relay ? o.relay.relayed : 0),
      stat('Relay: rejected', o.relay ? o.relay.rejected : 0), stat('Subscribers', o.subscribers ?? 0), stat('Public IP', o.public_ip || 'not set')),
      el('div', {class: 'card'}, el('h2', {}, 'Live statistics'), el('iframe', {src: base + '/dash/'})));
  }};

  tabs.subs = {title: 'Subscribers', async draw(body) {
    const list = await call('/api/subs');
    const msg = el('div', {class: 'msg'}), err = el('div', {class: 'err'});
    const f = {name: el('input', {placeholder: 'Name'}), ip: el('input', {placeholder: 'IP (optional)'}),
      gb: el('input', {type: 'number', min: 0, step: 'any', placeholder: 'GB limit (0 = none)', style: 'width:170px'}),
      days: el('input', {type: 'number', min: 0, placeholder: 'Days (0 = never)', style: 'width:150px'}),
      rb: el('input', {type: 'checkbox', checked: true})};
    const add = async () => { err.textContent = ''; try {
      await call('/api/subs', 'POST', {name: f.name.value, ip: f.ip.value, limit_gb: +f.gb.value || 0, days: +f.days.value || 0, self_rebind: f.rb.checked}); render();
    } catch (e) { err.textContent = e.message; } };
    body.append(el('div', {class: 'card'}, el('h2', {}, 'Add subscriber'),
      el('div', {class: 'row'}, f.name, f.ip, f.gb, f.days, el('label', {class: 'ck'}, f.rb, 'user may change own IP'), el('button', {class: 'b', onclick: add}, 'Add')),
      el('div', {class: 'mut'}, 'Leave IP empty and send the portal link: the user activates it from their own network.'), err));
    const act = (label, fn, cls) => el('button', {class: 'b sec sm ' + (cls || ''), onclick: async () => { try { await fn(); render(); } catch (e) { alert(e.message); } }}, label);
    const rows = list.map(v => {
      const link = location.origin + '/sub/' + v.token;
      const pct = v.limit_bytes ? Math.min(100, v.used_bytes * 100 / v.limit_bytes) : 0;
      return el('tr', {}, el('td', {}, v.name), el('td', {}, el('code', {}, v.ip || '—')),
        el('td', {}, el('span', {class: 'pill ' + v.status}, v.status)),
        el('td', {}, fmtBytes(v.used_bytes) + (v.limit_bytes ? ' / ' + fmtBytes(v.limit_bytes) : ''), v.limit_bytes ? el('div', {class: 'bar'}, el('i', {style: 'width:' + pct + '%'})) : null),
        el('td', {}, fmtDate(v.expires_at)),
        el('td', {}, el('div', {class: 'row', style: 'margin:0'},
          el('button', {class: 'b sec sm', onclick: () => { navigator.clipboard.writeText(link); msg.textContent = 'Portal link copied'; }}, 'Copy link'),
          act(v.enabled ? 'Disable' : 'Enable', () => call('/api/subs/' + v.id, 'PATCH', {enabled: !v.enabled})),
          act('+30d', () => call('/api/subs/' + v.id, 'PATCH', {extend_days: 30})),
          act('Reset traffic', () => call('/api/subs/' + v.id, 'PATCH', {reset_used: true})),
          act('Delete', async () => { if (confirm('Delete ' + v.name + '?')) await call('/api/subs/' + v.id, 'DELETE'); }, 'del'))));
    });
    body.append(el('div', {class: 'card'}, el('h2', {}, 'Subscribers (' + list.length + ')'), msg,
      list.length ? el('div', {style: 'overflow-x:auto'}, el('table', {}, el('thead', {}, el('tr', {}, ['Name','IP','Status','Traffic','Expires',''].map(h => el('th', {}, h)))), el('tbody', {}, rows))) : el('div', {class: 'mut'}, 'No subscribers yet.')));
  }};

  tabs.smart = {title: 'Routing', async draw(body) {
    const s = await call('/api/smart'); const msg = el('div', {class: 'msg'}), err = el('div', {class: 'err'});
    const ip = el('input', {value: s.public_ip || '', placeholder: 'e.g. 203.0.113.10'});
    const cust = el('textarea', {rows: 5, style: 'width:100%;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:8px'}, '');
    cust.value = (s.custom || []).join('\n');
    const boxes = s.categories.map(c => { const cb = el('input', {type: 'checkbox', checked: c.enabled}); cb.dataset.id = c.id; return el('label', {class: 'ck'}, cb, c.title, el('span', {class: 'mut'}, ' (' + c.domains + ' domains)')); });
    const save = async () => { err.textContent = ''; msg.textContent = ''; try {
      await call('/api/smart', 'PUT', {enabled: [...document.querySelectorAll('input[data-id]')].filter(x => x.checked).map(x => x.dataset.id),
        custom: cust.value.split(/\s+/).filter(Boolean), public_ip: ip.value.trim()});
      msg.textContent = 'Saved';
    } catch (e) { err.textContent = e.message; } };
    body.append(el('div', {class: 'card'}, el('h2', {}, 'Server public IPv4'), el('div', {class: 'mut'}, 'Clients are told to connect to this address for routed domains.'), el('div', {class: 'row'}, ip)),
      el('div', {class: 'card'}, el('h2', {}, 'Categories'), boxes),
      el('div', {class: 'card'}, el('h2', {}, 'Custom domains'), el('div', {class: 'mut'}, 'One per line. Subdomains are included.'), cust),
      el('div', {class: 'row'}, el('button', {class: 'b', onclick: save}, 'Save'), msg, err));
  }};

  tabs.account = {title: 'Account', async draw(body) {
    const cur = el('input', {type: 'password', placeholder: 'Current password', autocomplete: 'current-password'});
    const nw = el('input', {type: 'password', placeholder: 'New password (10+ chars)', autocomplete: 'new-password'});
    const msg = el('div', {class: 'msg'}), err = el('div', {class: 'err'});
    body.append(el('div', {class: 'card'}, el('h2', {}, 'Change password'), el('div', {class: 'row'}, cur, nw,
      el('button', {class: 'b', onclick: async () => { err.textContent = ''; msg.textContent = ''; try { await call('/api/admin/password', 'POST', {current: cur.value, new: nw.value}); msg.textContent = 'Changed. Signing out…'; setTimeout(showLogin, 1200); } catch (e) { err.textContent = e.message; } }}, 'Change')), msg, err));
  }};

  async function start() { try { await call('/api/me'); render(); } catch (e) { showLogin(); } }
  start();
})();
