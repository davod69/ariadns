(() => {
  'use strict';
  const base = location.pathname.replace(/\/$/, '');
  const app = document.getElementById('app');
  const el = (t, p, ...k) => { const e = document.createElement(t); Object.assign(e, p || {}); k.flat().forEach(x => e.append(x.nodeType ? x : document.createTextNode(x))); return e; };
  const fb = n => { if (!n) return '0'; const u = ['B','KB','MB','GB','TB']; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return n.toFixed(i ? 2 : 0) + ' ' + u[i]; };
  const line = (l, v) => el('div', {className: 'row'}, el('span', {className: 'mut', style: 'min-width:130px'}, l), v);
  async function load(rebind) {
    const r = await fetch(base + (rebind ? '/rebind' : '/info'), {method: rebind ? 'POST' : 'GET', headers: {'X-Requested-With': 'ariadns'}, cache: 'no-store'});
    const d = await r.json().catch(() => ({}));
    return {ok: r.ok, d};
  }
  async function draw(rebind) {
    const {ok, d} = await load(rebind);
    if (!ok && !d.name) { app.replaceChildren(el('div', {className: 'err'}, d.error || 'Not found')); return; }
    const err = el('div', {className: 'err'}, ok ? '' : d.error);
    const info = ok ? d : (await load(false)).d;
    const kids = [el('h2', {}, info.name), line('Status', el('span', {className: 'pill ' + info.status}, info.status)),
      line('Your IP', el('code', {}, info.your_ip)), line('Allowed IP', el('code', {}, info.ip || 'not set')),
      line('Traffic', fb(info.used_bytes) + (info.limit_bytes ? ' / ' + fb(info.limit_bytes) : ' (unlimited)')),
      line('Expires', info.expires_at ? new Date(info.expires_at * 1000).toLocaleDateString() : 'never'),
      line('DNS server', el('code', {}, info.dns_server || 'ask your provider'))];
    if (info.self_rebind && info.ip !== info.your_ip) kids.push(el('button', {className: 'b', onclick: () => draw(true)}, 'Use my current IP'));
    kids.push(err);
    app.replaceChildren(...kids);
  }
  draw(false);
})();
