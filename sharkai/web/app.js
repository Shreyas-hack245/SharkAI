'use strict';
/* SharkAI UI. All DOM is built with textContent / createElement, never HTML strings, so packet content cannot inject markup. */

const $ = (s, r = document) => r.querySelector(s);
const state = { cfg: null, cap: null, data: {}, tab: 'overview', pktFilter: '', pktOffset: 0, stream: null, chat: [] };

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'text') el.textContent = v;
    else if (k === 'style') Object.assign(el.style, v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
const svg = (tag, attrs = {}, ...kids) => {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  el.append(...kids); return el;
};
const fmtBytes = n => { let v = n; for (const u of ['B', 'KB', 'MB', 'GB']) { if (v < 1024 || u === 'GB') return u === 'B' ? `${v} B` : `${v.toFixed(1)} ${u}`; v /= 1024; } };
const fmtDur = s => s < 1 ? `${(s * 1000).toFixed(0)} ms` : s < 120 ? `${s.toFixed(2)} s` : `${(s / 60).toFixed(1)} min`;
const fmtTime = ts => new Date(ts * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');

async function api(path, opts = {}) {
  const init = { ...opts, headers: { 'X-SharkAI': '1', ...(opts.headers || {}) } };
  if (opts.json) { init.method = init.method || 'POST'; init.body = JSON.stringify(opts.json); init.headers['Content-Type'] = 'application/json'; }
  const res = await fetch(path, init);
  if (!res.ok) {
    let msg = res.statusText; try { const j = await res.json(); msg = j.detail || msg; if (j.kind === 'filter') { const e = new Error(msg); e.filter = true; throw e; } } catch (e) { if (e.filter) throw e; }
    throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg));
  }
  if (res.status === 204) return null;
  return (res.headers.get('content-type') || '').includes('json') ? res.json() : res.text();
}
const capApi = (p, o) => api(`/api/captures/${state.cap.meta.id}${p}`, o);
async function cached(key, path) { return state.data[key] ??= await capApi(path); }

/* ---------------- tiny safe markdown ---------------- */
function inline(text) {
  const out = []; const re = /(`[^`]+`)|(\*\*[^*]+\*\*)/g; let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(m[1] ? h('code', { text: m[1].slice(1, -1) }) : h('strong', { text: m[2].slice(2, -2) })); last = re.lastIndex;
  }
  if (last < text.length) out.push(text.slice(last)); return out;
}
function markdown(src) {
  const root = h('div'); let list = null, code = null;
  for (const line of src.split('\n')) {
    if (line.startsWith('```')) { if (code) { root.append(h('pre', { text: code.join('\n') })); code = null; } else code = []; continue; }
    if (code) { code.push(line); continue; }
    const li = line.match(/^\s*[-*] (.*)/);
    if (li) { if (!list) { list = h('ul'); root.append(list); } list.append(h('li', {}, inline(li[1]))); continue; }
    list = null;
    if (line.startsWith('> ')) root.append(h('p', { class: 'muted' }, inline(line.slice(2))));
    else if (line.trim()) root.append(h('p', {}, inline(line.replace(/^#+\s*/, ''))));
  }
  return root;
}

/* ---------------- generic table ---------------- */
function table(cols, rows, { onRow, rowClass, empty = 'Nothing to show.' } = {}) {
  if (!rows.length) return h('p', { class: 'muted', text: empty });
  const body = h('tbody');
  rows.forEach(r => {
    const tr = h('tr', { class: rowClass ? rowClass(r) : '' });
    if (onRow) { tr.tabIndex = 0; tr.addEventListener('click', () => onRow(r, tr)); tr.addEventListener('keydown', e => { if (e.key === 'Enter') onRow(r, tr); }); }
    cols.forEach(c => { const v = c.f(r); tr.append(h('td', { class: [c.num && 'num', c.mono && 'mono'].filter(Boolean).join(' ') }, v)); });
    body.append(tr);
  });
  return h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, cols.map(c => h('th', { class: c.num ? 'num' : '', text: c.h })))), body));
}

/* ---------------- setup, captures ---------------- */
async function init() {
  state.cfg = await api('/api/config');
  renderAiChip(); await refreshCaptures();
  const drop = $('#drop'), file = $('#file');
  file.addEventListener('change', () => file.files[0] && upload(file.files[0]));
  ['dragover', 'dragenter'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', e => e.dataTransfer.files[0] && upload(e.dataTransfer.files[0]));
  $('#ai-chip').addEventListener('click', async () => {
    const chip = $('#ai-chip'); const prev = chip.textContent; chip.textContent = 'Checking…';
    try { const r = await api('/api/ai/test', { method: 'POST' }); chip.textContent = r.ok ? `${prev} · reachable` : `${prev} · ${r.detail}`; } catch (e) { chip.textContent = e.message; }
    setTimeout(renderAiChip, 4000);
  });
}
function renderAiChip() {
  const a = state.cfg.ai, chip = $('#ai-chip');
  chip.className = `chip ai-chip ${a.configured ? 'on' : 'off'}`;
  chip.textContent = a.configured ? `AI: ${a.provider} / ${a.model}` : 'AI off · deterministic results';
}
async function refreshCaptures(selectId) {
  const list = await api('/api/captures'); const ul = $('#captures'); ul.replaceChildren();
  if (!list.length) ul.append(h('li', { class: 'muted', text: 'No captures yet.' }));
  list.forEach(m => ul.append(h('li', {}, h('div', { class: 'cap', 'aria-current': String(state.cap?.meta.id === m.id) },
    h('button', { class: 'cap-open', onclick: () => openCapture(m.id) },
      h('b', { text: m.name }), h('small', { text: m.status === 'ready' ? `${m.packets} packets · ${fmtBytes(m.size)}${m.flags ? ` · ${m.flags} flag${m.flags > 1 ? 's' : ''}` : ''}` : m.status + (m.error ? `: ${m.error}` : '') })),
    h('div', { class: 'row' }, h('small', { class: 'muted', text: m.format || '' }), h('button', { class: 'link', onclick: () => removeCapture(m) }, 'Delete'))))));
  if (selectId) openCapture(selectId);
}
async function upload(file) {
  const st = $('#upload-status'); st.textContent = `Uploading ${file.name} and analysing…`;
  const prefixes = $('#prefixes').value.split(',').map(s => s.trim()).filter(Boolean);
  const q = new URLSearchParams({ filename: file.name }); prefixes.forEach(p => q.append('flag_prefix', p));
  try { const meta = await api(`/api/captures?${q}`, { method: 'POST', body: file, headers: { 'Content-Type': 'application/octet-stream' } });
    st.textContent = `Analysed ${meta.name}.`; await refreshCaptures(meta.id);
  } catch (e) { st.textContent = `Upload failed: ${e.message}`; }
  $('#file').value = '';
}
async function removeCapture(m) {
  if (!confirm(`Delete "${m.name}" and all extracted data?`)) return;
  await api(`/api/captures/${m.id}`, { method: 'DELETE' });
  if (state.cap?.meta.id === m.id) { state.cap = null; $('#workspace').hidden = true; $('#empty').hidden = false; $('#current').textContent = ''; }
  refreshCaptures();
}
async function openCapture(id) {
  state.cap = await api(`/api/captures/${id}`); state.data = {}; state.chat = []; state.stream = null; state.pktFilter = ''; state.pktOffset = 0;
  $('#empty').hidden = true; $('#workspace').hidden = false; $('#current').textContent = `${state.cap.meta.name} · ${state.cap.meta.sha256.slice(0, 12)}…`;
  renderStats(); renderTabs(); setTab('overview'); refreshCaptures();
}
function renderStats() {
  const o = state.cap.overview; const s = $('#stats'); s.replaceChildren();
  [['packets', o.packets], ['hosts', o.hosts], ['streams', o.streams], ['duration', fmtDur(o.duration)], ['size', fmtBytes(o.bytes)], ['flags', o.flags, o.flags > 0], ['alerts', o.suspicious]]
    .forEach(([l, v, hot]) => s.append(h('div', { class: `stat${hot ? ' hot' : ''}` }, h('b', { text: String(v) }), h('span', { text: l }))));
}
const TABS = [['overview', 'Overview'], ['packets', 'Packets'], ['streams', 'Streams', o => o.streams], ['http', 'HTTP', o => o.http_transactions], ['dns', 'DNS', o => o.dns_messages],
  ['files', 'Files', o => o.files], ['iocs', 'IOCs', o => o.iocs], ['flags', 'Flags', o => o.flags, true], ['timeline', 'Timeline'], ['graph', 'Graph'], ['ask', 'Ask'], ['report', 'Report']];
function renderTabs() {
  const nav = $('#tabs'); nav.replaceChildren();
  TABS.forEach(([id, label, count, hot]) => {
    const n = count ? count(state.cap.overview) : null;
    nav.append(h('button', { class: 'tab', role: 'tab', id: `tab-${id}`, onclick: () => setTab(id) }, label, n ? h('span', { class: `n${hot && n ? ' hot' : ''}`, text: String(n) }) : null));
  });
}
async function setTab(id) {
  state.tab = id;
  document.querySelectorAll('.tab').forEach(t => t.setAttribute('aria-selected', String(t.id === `tab-${id}`)));
  const panel = $('#panel'); panel.replaceChildren(h('p', { class: 'muted', text: 'Loading…' }));
  try { const view = await VIEWS[id](); if (state.tab === id) panel.replaceChildren(view); }
  catch (e) { panel.replaceChildren(h('p', { class: 'err', text: e.message })); }
}
const goPackets = filter => { state.pktFilter = filter; state.pktOffset = 0; setTab('packets'); };
const goStream = id => { state.stream = id; setTab('streams'); };
const protoClass = p => 'p-' + String(p || '').toLowerCase().replace(/[^a-z0-9]/g, '');
const PROTO_COLORS = ['#0e6b73', '#9a5b00', '#6d4aa8', '#2a7f3d', '#b3365f', '#3c6fb0', '#8a8f3a', '#777'];

/* ---------------- views ---------------- */
const VIEWS = {
  async overview() {
    const o = state.cap.overview, a = state.data.analysis ??= { susp: await capApi('/suspicious'), flags: await capApi('/flags') };
    const total = o.protocols.reduce((s, p) => s + p.packets, 0) || 1;
    const bar = h('div', { class: 'protobar' }), legend = h('div', { class: 'legend' });
    o.protocols.slice(0, 8).forEach((p, i) => {
      bar.append(h('div', { title: `${p.name}: ${p.packets}`, style: { width: `${p.packets / total * 100}%`, background: PROTO_COLORS[i] } }));
      legend.append(h('span', {}, h('i', { style: { background: PROTO_COLORS[i] } }), `${p.name} ${p.packets}`));
    });
    const root = h('div');
    if (state.cap.warnings.length) root.append(...state.cap.warnings.map(w => h('p', { class: 'note', text: `Note: ${w}` })));
    if (a.flags.length) root.append(h('h2', { text: 'Flag candidates' }), h('div', { class: 'flags' }, a.flags.slice(0, 3).map(flagCard)), a.flags.length > 3 ? h('p', {}, h('a', { href: '#', onclick: e => { e.preventDefault(); setTab('flags'); } }, `All ${a.flags.length} flag candidates`)) : null);
    root.append(h('div', { class: 'metric-grid' },
      h('div', {}, h('h2', { text: 'Protocols' }), bar, legend,
        h('h2', { text: 'Top talkers' }), table([{ h: 'Host', f: r => r.ip, mono: true }, { h: 'Scope', f: r => r.scope }, { h: 'Packets', f: r => r.packets, num: true }, { h: 'Bytes', f: r => fmtBytes(r.bytes), num: true }],
          o.top_talkers, { onRow: r => goPackets(`ip.addr == ${r.ip}`) })),
      h('div', {}, h('h2', { text: 'Suspicious activity' }), a.susp.length ? h('ul', { class: 'alerts' }, a.susp.map(s => h('li', {}, h('span', { class: `tag ${s.severity}`, text: s.severity }), ' ', h('strong', { text: s.title }), h('div', { class: 'muted', text: s.detail }),
        s.packet ? h('button', { class: 'link', style: { color: 'var(--fin)' }, onclick: () => goPackets(`frame.number == ${s.packet}`) }, `Packet ${s.packet}`) : null))) : h('p', { class: 'muted', text: 'No heuristic alerts raised.' }),
        h('p', { class: 'muted', text: `${fmtTime(o.start)} → ${fmtTime(o.end)} · ${o.format}` }))));
    return root;
  },

  async packets() {
    const root = h('div'), err = h('p', { class: 'err', hidden: true }), tbl = h('div'), pager = h('div', { class: 'pager' }), detail = h('div');
    const input = h('input', { type: 'text', id: 'pf', value: state.pktFilter, placeholder: 'dns   ip.addr == 10.0.0.5 and tcp.port == 80   frame contains "flag"', autocomplete: 'off', spellcheck: 'false', maxlength: '300' });
    const help = await (state.data.help ??= api('/api/filters/help'));
    const load = async () => {
      state.pktFilter = input.value; err.hidden = true;
      try {
        const r = await capApi(`/packets?${new URLSearchParams({ filter: input.value, offset: state.pktOffset, limit: 200 })}`);
        tbl.replaceChildren(table([{ h: 'No.', f: p => p.n, num: true }, { h: 'Time', f: p => p.rel.toFixed(6), num: true, mono: true }, { h: 'Source', f: p => p.src, mono: true }, { h: 'Destination', f: p => p.dst, mono: true },
          { h: 'Protocol', f: p => p.proto }, { h: 'Len', f: p => p.length, num: true }, { h: 'Info', f: p => p.info }], r.packets,
          { rowClass: p => protoClass(p.l4 === 'TCP' || p.l4 === 'UDP' ? p.proto : p.l4), onRow: (p, tr) => { tbl.querySelectorAll('tr.sel').forEach(x => x.classList.remove('sel')); tr.classList.add('sel'); showPacket(p.n, detail); }, empty: 'No packets match this filter.' }));
        const end = Math.min(state.pktOffset + 200, r.total);
        pager.replaceChildren(h('span', { text: `${r.total ? state.pktOffset + 1 : 0}–${end} of ${r.total}` }),
          h('button', { class: 'btn alt', disabled: state.pktOffset === 0, onclick: () => { state.pktOffset = Math.max(0, state.pktOffset - 200); load(); } }, 'Previous'),
          h('button', { class: 'btn alt', disabled: end >= r.total, onclick: () => { state.pktOffset += 200; load(); } }, 'Next'));
      } catch (e) { err.textContent = e.filter ? `Filter not accepted: ${e.message}` : e.message; err.hidden = false; }
    };
    const apply = () => { state.pktOffset = 0; load(); };
    input.addEventListener('keydown', e => { if (e.key === 'Enter') apply(); });
    root.append(h('div', { class: 'bar' }, h('label', {}, 'Display filter (allowlisted fields only)', input), h('button', { class: 'btn', onclick: apply }, 'Apply'), h('button', { class: 'btn alt', onclick: () => { input.value = ''; apply(); } }, 'Clear')), err,
      h('div', { class: 'chips' }, help.examples.map(x => h('button', { type: 'button', onclick: () => { input.value = x; apply(); } }, x))),
      h('details', { class: 'note' }, h('summary', { text: 'Filter reference' }), h('p', { class: 'muted', text: `Operators: ${help.operators.join('  ')}.  Logic: ${help.logic.join('  ')}.  Protocols: ${help.protocols.join(', ')}.` }),
        table([{ h: 'Field', f: f => f.name, mono: true }, { h: 'Type', f: f => f.type }, { h: 'Meaning', f: f => f.description }], help.fields)),
      tbl, pager, detail);
    await load(); return root;
  },

  async streams() {
    const list = await cached('streams', '/streams'); const view = h('div'); let current = state.stream;
    const q = h('input', { class: 'in', type: 'text', placeholder: 'Filter streams (host, port, protocol)', 'aria-label': 'Filter streams' }); const lst = h('div', { class: 'list' });
    const renderList = () => {
      const t = q.value.toLowerCase();
      lst.replaceChildren(...list.filter(s => (s.bytes_c2s + s.bytes_s2c) > 0 && `${s.client} ${s.server} ${s.server_port} ${s.protocol}`.toLowerCase().includes(t)).map(s =>
        h('button', { 'aria-current': String(s.id === current), onclick: () => { current = s.id; state.stream = s.id; renderList(); show(); } },
          h('strong', { text: `#${s.id} ${s.protocol}` }), s.has_flag ? h('span', { class: 'tag flag', text: 'flag' }) : null, h('small', { text: `${s.client}:${s.client_port} → ${s.server}:${s.server_port}` }), h('small', { text: `${fmtBytes(s.bytes_c2s + s.bytes_s2c)} · ${s.state}` }))));
      if (!lst.children.length) lst.append(h('p', { class: 'muted', text: 'No streams with payload.' }));
    };
    let fmt = 'text';
    const show = async () => {
      if (current == null) { view.replaceChildren(h('p', { class: 'muted', text: 'Select a stream to follow it.' })); return; }
      view.replaceChildren(h('p', { class: 'muted', text: 'Loading…' }));
      try {
        const r = await capApi(`/streams/${current}?format=${fmt}`), s = r.stream, id = state.cap.meta.id;
        const flags = (await cached('flagsList', '/flags')).filter(f => f.locations.some(l => l.stream === s.id));
        const needles = flags.map(f => f.flag);
        view.replaceChildren(...[
          h('div', { class: 'bar' }, h('strong', { text: `Stream ${s.id}: ${s.client}:${s.client_port} → ${s.server}:${s.server_port}` }), h('span', { class: 'muted', text: `${s.protocol} · ${s.packets} packets · ${s.state}${s.gaps ? ` · ${s.gaps} gaps` : ''}${s.retransmits ? ` · ${s.retransmits} retransmits` : ''}` })),
          h('div', { class: 'bar' },
            h('button', { class: 'btn alt', 'aria-pressed': String(fmt === 'text'), onclick: () => { fmt = 'text'; show(); } }, 'Text'), h('button', { class: 'btn alt', onclick: () => { fmt = 'hex'; show(); } }, 'Hex'),
            h('button', { class: 'btn alt', onclick: () => goPackets(`tcp.stream == ${s.id}`) }, 'Show packets'),
            h('a', { class: 'btn alt', href: `/api/captures/${id}/streams/${s.id}/raw?dir=0` }, 'Download client bytes'), h('a', { class: 'btn alt', href: `/api/captures/${id}/streams/${s.id}/raw?dir=1` }, 'Download server bytes')),
          r.truncated ? h('p', { class: 'note', text: 'Output truncated; download the raw bytes for the full stream.' }) : null,
          h('div', { class: 'msgs' }, r.messages.map(m => h('div', { class: `msg ${m.dir ? 's2c' : 'c2s'}` },
            h('div', { class: 'meta' }, h('b', { text: m.dir ? 'server → client' : 'client → server' }), ` · packet ${m.packet} · ${m.length} bytes`),
            h('pre', {}, highlight(m.text, needles)))))].filter(Boolean));
      } catch (e) { view.replaceChildren(h('p', { class: 'err', text: e.message })); }
    };
    q.addEventListener('input', renderList); renderList(); show();
    return h('div', { class: 'split' }, h('div', {}, q, lst), view);
  },

  async http() {
    const rows = await cached('http', '/http'); const det = h('div');
    return h('div', {}, table([{ h: '#', f: r => r.id, num: true }, { h: 'Method', f: r => r.method || '–' }, { h: 'URL', f: r => r.url || r.uri, mono: true }, { h: 'Status', f: r => r.status || '–' },
      { h: 'Type', f: r => r.content_type || '–' }, { h: 'Bytes', f: r => r.resp_size, num: true }], rows, { empty: 'No HTTP transactions were reconstructed.',
      onRow: r => det.replaceChildren(h('div', { class: 'detail' }, h('strong', { text: `${r.method} ${r.url}` }),
        h('p', { class: 'muted', text: `Stream ${r.stream}, packet ${r.packet}, ${r.client} → ${r.server}:${r.server_port}` }), kv([['User-Agent', r.user_agent || '–'], ['Status', `${r.status} ${r.reason}`], ['Content-Encoding', r.content_encoding || '–'], ['Note', r.note || '–']]),
        h('details', { open: true }, h('summary', { text: 'Request headers' }), h('pre', { text: r.req_headers.map(([k, v]) => `${k}: ${v}`).join('\n') || '(none)' })),
        h('details', {}, h('summary', { text: 'Response headers' }), h('pre', { text: r.resp_headers.map(([k, v]) => `${k}: ${v}`).join('\n') || '(none)' })),
        r.req_preview ? h('details', {}, h('summary', { text: 'Request body preview' }), h('pre', { text: r.req_preview })) : null,
        r.resp_preview ? h('details', { open: true }, h('summary', { text: 'Response body preview' }), h('pre', { text: r.resp_preview })) : null,
        h('div', { class: 'bar' }, h('button', { class: 'btn alt', onclick: () => goStream(r.stream) }, 'Follow stream'), r.file_id ? h('a', { class: 'btn alt', href: `/api/captures/${state.cap.meta.id}/files/${r.file_id}` }, 'Download body') : null))) }), det);
  },

  async dns() {
    const root = h('div'), out = h('div'), q = h('input', { type: 'text', placeholder: 'Search names or answers', 'aria-label': 'Search DNS' });
    const load = async () => { const r = await capApi(`/dns?${new URLSearchParams({ q: q.value, limit: 500 })}`);
      out.replaceChildren(h('p', { class: 'muted', text: `${r.total} messages` }), table([{ h: 'Pkt', f: e => e.packet, num: true }, { h: 'Dir', f: e => e.response ? 'response' : 'query' }, { h: 'Name', f: e => e.qname, mono: true }, { h: 'Type', f: e => e.qtype },
        { h: 'From', f: e => e.src, mono: true }, { h: 'Result', f: e => e.response ? (e.answers.join(', ') || e.rcode) : '' }, { h: 'Via', f: e => e.transport }], r.items, { onRow: e => goPackets(`frame.number == ${e.packet}`), empty: 'No DNS messages.' })); };
    q.addEventListener('input', () => { clearTimeout(q._t); q._t = setTimeout(load, 200); });
    root.append(h('div', { class: 'bar' }, h('label', {}, 'Search', q)), out); await load(); return root;
  },

  async files() {
    const rows = await cached('files', '/files'); const id = state.cap.meta.id;
    return table([{ h: '#', f: r => r.id, num: true }, { h: 'Name', f: r => r.name }, { h: 'Type', f: r => r.type }, { h: 'Size', f: r => fmtBytes(r.size), num: true }, { h: 'Source', f: r => r.source },
      { h: 'SHA-256', f: r => r.sha256, mono: true }, { h: 'Preview', f: r => r.preview.slice(0, 60), mono: true },
      { h: '', f: r => h('span', {}, h('a', { href: `/api/captures/${id}/files/${r.id}`, text: 'Download' }), ' ', r.stream != null ? h('button', { class: 'link', style: { color: 'var(--fin)' }, onclick: () => goStream(r.stream) }, 'Stream') : null) }], rows, { empty: 'No files were extracted.' });
  },

  async iocs() {
    const [iocs, creds] = await Promise.all([cached('iocs', '/iocs'), cached('creds', '/credentials')]); let type = 'all'; const out = h('div'), chips = h('div', { class: 'chips' });
    const types = ['all', ...new Set(iocs.map(i => i.type))];
    const draw = () => {
      chips.replaceChildren(...types.map(t => h('button', { type: 'button', 'aria-pressed': String(t === type), onclick: () => { type = t; draw(); } }, t)));
      out.replaceChildren(table([{ h: 'Type', f: r => r.type }, { h: 'Value', f: r => r.value, mono: true }, { h: 'Scope', f: r => r.scope || '' }, { h: 'Count', f: r => r.count, num: true }, { h: 'Context', f: r => r.context }],
        iocs.filter(i => type === 'all' || i.type === type), { onRow: r => r.type === 'ip' ? goPackets(`ip.addr == ${r.value}`) : r.type === 'domain' ? goPackets(`dns.qry.name contains ${r.value}`) : goPackets(`frame.number == ${r.packet}`) }));
    };
    draw();
    return h('div', {}, creds.length ? [h('h2', { text: 'Cleartext credentials' }), table([{ h: 'Kind', f: c => c.kind }, { h: 'User', f: c => c.user, mono: true }, { h: 'Secret', f: c => c.secret, mono: true }, { h: 'Host', f: c => c.host }, { h: 'Packet', f: c => c.packet, num: true }], creds, { onRow: c => c.stream != null && goStream(c.stream) })] : null,
      h('h2', { text: 'Indicators' }), chips, out);
  },

  async flags() {
    const flags = await cached('flagsList', '/flags');
    const pf = state.cap.overview.flag_prefixes, input = h('input', { type: 'text', value: pf.join(', '), placeholder: 'mycorp, bsides', 'aria-label': 'Extra flag prefixes' });
    const rescan = h('div', { class: 'bar' }, h('label', {}, 'Extra flag prefixes for this capture (letters, digits, underscore)', input),
      h('button', { class: 'btn alt', onclick: async e => { e.target.disabled = true; try { await capApi('/reanalyze', { json: { flag_prefixes: input.value.split(',').map(s => s.trim()).filter(Boolean) } }); await openCapture(state.cap.meta.id); setTab('flags'); } catch (x) { alert(x.message); e.target.disabled = false; } } }, 'Re-analyse'));
    return h('div', {}, flags.length ? h('div', { class: 'flags' }, flags.map(flagCard)) : h('p', { class: 'note', text: 'No flags in common CTF formats were found in packets, streams, HTTP bodies, DNS or extracted files. Add your event prefix below, or try the frame contains filter.' }), h('h2', { text: 'Custom prefixes' }), rescan);
  },

  async timeline() {
    const t = await cached('timeline', '/timeline'); const kinds = [...new Set(t.events.map(e => e.kind))], on = new Set(kinds.filter(k => k !== 'dns')); const list = h('ul', { class: 'tl' }), chips = h('div', { class: 'chips' });
    const max = Math.max(1, ...t.buckets); const w = 600 / (t.buckets.length || 1);
    const spark = svg('svg', { class: 'spark', viewBox: '0 0 600 70', preserveAspectRatio: 'none', role: 'img', 'aria-label': 'Packets over time' }, ...t.buckets.map((b, i) => svg('rect', { x: i * w + 0.5, y: 70 - b / max * 66, width: Math.max(1, w - 1), height: b / max * 66 })));
    const draw = () => {
      chips.replaceChildren(...kinds.map(k => h('button', { type: 'button', 'aria-pressed': String(on.has(k)), onclick: () => { on.has(k) ? on.delete(k) : on.add(k); draw(); } }, k)));
      list.replaceChildren(...t.events.filter(e => on.has(e.kind)).slice(0, 600).map(e => h('li', { class: `sev-${e.severity} k-${e.kind}` }, h('span', { class: 't', text: `+${e.rel.toFixed(3)}s` }), h('strong', { text: e.title }), e.detail ? h('span', { class: 'muted', text: ` — ${e.detail}` }) : null,
        e.packet ? h('button', { class: 'link', style: { color: 'var(--fin)' }, onclick: () => goPackets(`frame.number == ${e.packet}`) }, `#${e.packet}`) : null)));
    };
    draw(); return h('div', {}, h('p', { class: 'muted', text: 'Packets per time slice' }), spark, chips, list);
  },

  async graph() {
    const g = await cached('graph', '/graph'); const side = h('div', { class: 'note', text: 'Select a host to see its traffic.' });
    if (!g.nodes.length) return h('p', { class: 'muted', text: 'No IP traffic to graph.' });
    const nodes = [...g.nodes].sort((a, b) => b.bytes - a.bytes), W = 800, H = 520, cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 70, maxB = Math.max(...nodes.map(n => n.bytes)), maxE = Math.max(...g.edges.map(e => e.bytes), 1);
    const pos = {}; nodes.forEach((n, i) => { const ang = i / nodes.length * 2 * Math.PI - Math.PI / 2; pos[n.id] = nodes.length === 1 ? [cx, cy] : [cx + R * Math.cos(ang), cy + R * Math.sin(ang)]; });
    const root = svg('svg', { class: 'graph', viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Host communication graph' });
    g.edges.forEach(e => root.append(svg('line', { x1: pos[e.source][0], y1: pos[e.source][1], x2: pos[e.target][0], y2: pos[e.target][1], 'stroke-width': 1 + e.bytes / maxE * 6 })));
    nodes.forEach(n => {
      const c = svg('circle', { cx: pos[n.id][0], cy: pos[n.id][1], r: 7 + n.bytes / maxB * 14, class: n.scope === 'public' ? 'pub' : '', tabindex: 0 });
      const pick = () => { root.querySelectorAll('circle').forEach(x => x.classList.remove('sel')); c.classList.add('sel');
        const peers = g.edges.filter(e => e.source === n.id || e.target === n.id);
        side.replaceChildren(h('strong', { text: n.id }), h('span', { class: 'muted', text: ` · ${n.scope} · ${n.packets} packets · ${fmtBytes(n.bytes)}` }),
          h('ul', {}, peers.map(e => h('li', { class: 'mono', text: `${e.source === n.id ? e.target : e.source} — ${e.packets} pkts, ${e.protocols.map(p => p.name).join('/')}` }))), h('button', { class: 'btn alt', onclick: () => goPackets(`ip.addr == ${n.id}`) }, 'Show packets')); };
      c.addEventListener('click', pick); c.addEventListener('keydown', e => e.key === 'Enter' && pick()); root.append(c, svg('text', { x: pos[n.id][0], y: pos[n.id][1] - 11 - n.bytes / maxB * 14, 'text-anchor': 'middle' }, n.id));
    });
    return h('div', {}, g.truncated ? h('p', { class: 'note', text: 'Graph shows the busiest hosts and links only.' }) : null, root, h('p', { class: 'muted', text: 'Teal = private address, amber = public. Line width = bytes exchanged.' }), side);
  },

  async ask() {
    const chat = h('div', { class: 'chat' }), ta = h('textarea', { rows: 2, placeholder: 'Ask about the capture, e.g. “Is there a flag?” or “What was downloaded over HTTP?”', 'aria-label': 'Question', maxlength: '1000' });
    const useAi = h('input', { type: 'checkbox', id: 'use-ai', checked: state.cfg.ai.configured, disabled: !state.cfg.ai.configured });
    const draw = () => chat.replaceChildren(...state.chat.map(t => t.role === 'user' ? h('div', { class: 'turn user', text: t.content }) : h('div', { class: 'turn bot' },
      h('div', { class: 'badge' }, t.mode === 'ai' ? h('b', { class: 'ai', text: `AI answer (${t.provider}/${t.model})` }) : h('b', { class: 'fb', text: 'Deterministic result' }), ` · evidence ${t.evidence_chars} chars`, t.fallback_reason && t.mode !== 'ai' ? ` · ${t.fallback_reason}` : ''),
      markdown(t.content), t.unknown_citations?.length ? h('p', { class: 'err', text: `The model cited IDs not in the evidence: ${t.unknown_citations.join(', ')}. Verify before relying on it.` }) : null)));
    const send = async q => {
      q = (q || ta.value).trim(); if (!q) return; ta.value = ''; state.chat.push({ role: 'user', content: q }); draw();
      const history = state.chat.slice(0, -1).filter(t => t.mode === 'ai' || t.role === 'user').map(t => ({ role: t.role, content: t.content }));
      try { const r = await capApi('/ask', { json: { question: q, use_ai: state.cfg.ai.configured ? useAi.checked : true, history } }); state.chat.push({ role: 'assistant', content: r.answer, ...r }); }
      catch (e) { state.chat.push({ role: 'assistant', content: `Request failed: ${e.message}`, mode: 'fallback' }); } draw(); chat.lastChild?.scrollIntoView({ block: 'nearest' });
    };
    ta.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } });
    const ev = h('div'); const evBtn = h('button', { class: 'btn alt', onclick: async () => { const q = ta.value || state.chat.filter(t => t.role === 'user').pop()?.content || 'summarize this capture';
      const r = await capApi(`/evidence?${new URLSearchParams({ question: q })}`); ev.replaceChildren(h('p', { class: 'muted', text: `Exactly what the AI would receive for “${q}” (${r.chars} chars). Raw packets are never included.` }), h('pre', { class: 'preview', text: JSON.stringify(r.evidence, null, 1) })); } }, 'Show evidence the AI would see');
    draw();
    return h('div', {}, state.cfg.ai.configured ? null : h('p', { class: 'note', text: 'No AI provider is configured, so answers are deterministic summaries of the analysis. Set up a provider in config.toml to get natural-language answers.' }),
      chat, h('div', { class: 'ask-row' }, ta, h('button', { class: 'btn', onclick: () => send() }, 'Ask')),
      h('div', { class: 'sugg chips' }, ['Is there a flag?', 'Summarize this capture', 'What was downloaded over HTTP?', 'Any suspicious DNS?', 'Were credentials sent in cleartext?', 'What happened first?'].map(s => h('button', { type: 'button', onclick: () => send(s) }, s))),
      h('div', { class: 'bar' }, h('label', { style: { flex: '0 0 auto', display: 'flex', gap: '6px', alignItems: 'center' } }, useAi, 'Use AI provider'), evBtn), ev);
  },

  async report() {
    const id = state.cap.meta.id; const redact = h('input', { type: 'checkbox', id: 'redact' }); const pre = h('pre', { class: 'preview', text: '' });
    const link = (fmt, label) => { const a = h('a', { class: 'btn', text: label }); const upd = () => a.href = `/api/captures/${id}/report?format=${fmt}&redact=${redact.checked}`; upd(); redact.addEventListener('change', upd); return a; };
    const preview = async () => { pre.textContent = await capApi(`/report?format=md&redact=${redact.checked}&download=false`); };
    return h('div', {}, h('p', { text: 'Reports are generated from the stored analysis, not by the AI, so they are identical every time.' }),
      h('div', { class: 'bar' }, link('md', 'Markdown'), link('json', 'JSON'), link('pdf', 'PDF'), h('label', { style: { flex: '0 0 auto', display: 'flex', gap: '6px', alignItems: 'center' } }, redact, 'Mask credential secrets'), h('button', { class: 'btn alt', onclick: preview }, 'Preview Markdown')), pre);
  },
};

/* ---------------- shared bits ---------------- */
function kv(pairs) { const dl = h('dl', { class: 'kv' }); pairs.forEach(([k, v]) => dl.append(h('dt', { text: k }), h('dd', { text: String(v) }))); return dl; }
function highlight(text, needles) {
  const found = needles.filter(n => n && text.includes(n)); if (!found.length) return text;
  const re = new RegExp(found.map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'g'); const out = []; let last = 0, m;
  while ((m = re.exec(text))) { out.push(text.slice(last, m.index), h('mark', { class: 'hl', text: m[0] })); last = re.lastIndex; }
  out.push(text.slice(last)); return out;
}
function flagCard(f) {
  const loc = f.locations[0];
  return h('div', { class: 'flagcard' }, h('div', { class: 'val', text: f.flag }),
    h('p', {}, `${f.confidence} confidence · ${f.encoding === 'plain' ? 'plain text' : f.encoding + ' decoded'} · ${f.locations.map(l => `${l.source}${l.packet ? ' pkt ' + l.packet : ''}${l.stream != null ? ' stream ' + l.stream : ''}${l.name ? ' ' + l.name : ''}`).join('; ')}`),
    f.context ? h('p', { class: 'mono muted', text: f.context }) : null,
    h('div', { class: 'actions' }, h('button', { class: 'btn alt', onclick: () => navigator.clipboard?.writeText(f.flag) }, 'Copy'),
      loc.stream != null ? h('button', { class: 'btn alt', onclick: () => goStream(loc.stream) }, `Follow stream ${loc.stream}`) : null,
      loc.packet ? h('button', { class: 'btn alt', onclick: () => goPackets(`frame.number == ${loc.packet}`) }, `Packet ${loc.packet}`) : null));
}
async function showPacket(n, into) {
  into.replaceChildren(h('p', { class: 'muted', text: 'Loading…' }));
  try {
    const d = await capApi(`/packets/${n}`);
    into.replaceChildren(h('div', { class: 'detail' }, h('strong', { text: `Packet ${n}: ${d.summary.info}` }),
      d.layers.map((l, i) => h('details', { open: i >= d.layers.length - 2 }, h('summary', { text: l.name }), kv(l.fields))),
      d.payload_text ? h('details', {}, h('summary', { text: 'Payload (text view)' }), h('pre', { text: d.payload_text })) : null,
      h('details', {}, h('summary', { text: `Hex dump${d.truncated ? ' (first 4096 bytes)' : ''}` }), h('pre', { class: 'hex', text: d.hex.join('\n') })),
      d.summary.stream != null ? h('button', { class: 'btn alt', onclick: () => goStream(d.summary.stream) }, `Follow TCP stream ${d.summary.stream}`) : null));
    into.scrollIntoView({ block: 'nearest' });
  } catch (e) { into.replaceChildren(h('p', { class: 'err', text: e.message })); }
}

init().catch(e => { $('#empty').append(h('p', { class: 'err', text: `Could not reach the SharkAI server: ${e.message}` })); });
