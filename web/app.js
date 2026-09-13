/* Dashboard controller: ingestion, panels, drill-down into the evidence. */

const $ = s => document.querySelector(s);
const el = (tag, cls, html) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (html != null) n.innerHTML = html;
  return n;
};
const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const inr = v => {
  if (v == null) return '—';
  const neg = v < 0; v = Math.abs(v);
  let [i, f] = Number(v).toFixed(2).split('.');
  if (i.length > 3) i = i.slice(0, -3).replace(/(\d)(?=(\d\d)+$)/g, '$1,') + ',' + i.slice(-3);
  return (neg ? '-' : '') + '₹' + i + (f !== '00' ? '.' + f : '');
};
const ts = s => {
  if (!s) return 'unknown time';
  const d = new Date(s);
  if (isNaN(d)) return s;
  return d.toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
};

const state = { caseId: null, data: null, eventById: new Map(), types: new Set(), graph: null };

/* ---------------------------------------------------------------- chrome */
function busy(on, text) {
  $('#busy').hidden = !on;
  if (text) $('#busy-text').textContent = text;
}
let toastTimer;
function toast(msg, bad) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast' + (bad ? ' bad' : '');
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, bad ? 7000 : 3800);
}

/* ------------------------------------------------------------- ingestion */
async function loadSample(auto) {
  busy(true, auto ? 'Loading the demonstration case — hashing exhibits and correlating…'
                  : 'Acquiring exhibits, hashing and correlating…');
  try {
    const res = await fetch('/api/case/sample', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ officer: $('#officer').value || 'UNSPECIFIED' }),
    });
    const js = await res.json();
    if (!res.ok) throw new Error(js.error || 'failed');
    await openCase(js.case_id);
    toast('Demo case ingested: ' + js.summary.exhibits.length + ' exhibits, '
      + js.summary.events + ' events in ' + js.summary.processing_ms + ' ms'
      + (auto ? ' — ingest your own evidence to replace it' : ''));
  } catch (e) {
    toast('Could not load the demo case: ' + e.message, true);
  } finally { busy(false); }
}

/* Open with something on screen: restore the case this server session is
   already working on, otherwise fall back to the demonstration case so the
   dashboard is never a blank canvas. Ingesting real evidence replaces it. */
async function showConfig() {
  try {
    const res = await fetch('/api/config');
    if (!res.ok) return;
    const cfg = await res.json();
    if (!cfg.public_demo) return;
    const banner = $('#demo-banner');
    banner.hidden = false;
    document.body.classList.add('has-banner');
    document.documentElement.style.setProperty(
      '--banner-h', banner.offsetHeight + 'px');
    if (state.graph) state.graph.resize();
  } catch (e) {
    /* config endpoint is optional */
  }
}

async function boot() {
  await showConfig();
  try {
    const res = await fetch('/api/cases');
    if (res.ok) {
      const js = await res.json();
      const cases = js.cases || [];
      if (cases.length) {
        await openCase(cases[cases.length - 1].case_id);
        if (state.graph) { state.graph.resize(); state.graph.fit(); }
        return;
      }
    }
  } catch (e) {
    /* server restarted or unreachable -- fall through to the demo case */
  }
  await loadSample(true);
}

async function uploadFiles(files) {
  if (!files || !files.length) return;
  busy(true, 'Hashing ' + files.length + ' exhibit(s) and correlating…');
  try {
    const fd = new FormData();
    fd.append('officer', $('#officer').value || 'UNSPECIFIED');
    for (const f of files) fd.append('files', f, f.name);
    const res = await fetch('/api/case/upload', { method: 'POST', body: fd });
    const js = await res.json();
    if (!res.ok) throw new Error(js.error || 'failed');
    await openCase(js.case_id);
    toast('Ingested ' + js.summary.exhibits.length + ' exhibit(s), '
      + js.summary.events + ' events in ' + js.summary.processing_ms + ' ms');
  } catch (e) {
    toast('Ingestion failed: ' + e.message, true);
  } finally { busy(false); }
}

async function openCase(id) {
  const res = await fetch(`/api/case/${id}/analysis`);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'analysis failed');
  state.caseId = id;
  state.data = data;
  state.eventById = new Map((data.events || []).map(e => [e.id, e]));
  render();
}

/* ---------------------------------------------------------------- render */
function render() {
  const d = state.data;
  const c = d.case, st = d.statistics;
  $('#caseline').textContent =
    `${c.case_id}  ·  ${c.officer}  ·  ${st.exhibits} exhibits, ${st.events_normalised} events, `
    + `${st.entities} entities, ${st.relationships} links  ·  analysed in ${st.processing_ms} ms`;
  $('#btn-json').disabled = false;
  $('#btn-pdf').disabled = false;
  $('#graph-empty').hidden = true;

  renderKpis(); renderExhibits(); renderTypeFilters();
  renderSuspects(); renderFindings(); renderTrail(); renderTimeline(); renderActions();

  if (!state.graph) {
    state.graph = new GraphView($('#graph'));
    state.graph.on('select', onSelectNode);
    state.graph.on('hover', onHoverNode);
  }
  state.graph.hideOrphans = $('#hide-orphans').checked;
  state.graph.setData(d.graph.nodes, d.graph.edges);
  applyFilters();
  state.graph.preheat();
  renderLegend();
}

function renderKpis() {
  const d = state.data, st = d.statistics;
  const items = [
    ['Amount defrauded', inr(st.amount_reported || d.victim.amount_debited_observed || 0), 'crit'],
    ['Value traced', inr(st.amount_traced || 0), 'accent'],
    ['Suspect clusters', st.suspect_clusters, ''],
    ['Correlation links', st.correlation_findings, ''],
  ];
  $('#kpis').innerHTML = items.map(([k, v, cls]) =>
    `<div class="kpi ${cls}"><b>${esc(v)}</b><span>${esc(k)}</span></div>`).join('');
}

function renderExhibits() {
  const box = $('#exhibits');
  const ex = state.data.evidentiary_integrity.exhibits;
  const ok = state.data.evidentiary_integrity.reverify || {};
  box.innerHTML = ex.map(e => `
    <div class="exhibit">
      <div class="row1">
        <span class="name" title="${esc(e.original_name)}">${esc(e.original_name)}</span>
        <span class="tag">${esc(e.artifact_type)}</span>
        <span class="tag ${ok[e.exhibit_id] ? 'ok' : 'bad'}">
          ${ok[e.exhibit_id] ? 'SHA‑256 OK' : 'MISMATCH'}</span>
      </div>
      <div class="meta">${e.exhibit_id} · ${e.records_extracted} records ·
        ${(e.size_bytes / 1024).toFixed(1)} KB · ${esc(e.parse_status)}</div>
      <div class="hash">${esc(e.sha256)}</div>
      ${(e.notes || []).map(n => `<div class="note">⚠ ${esc(n)}</div>`).join('')}
    </div>`).join('');
}

function renderTypeFilters() {
  const counts = {};
  state.data.graph.nodes.forEach(n => { counts[n.type] = (counts[n.type] || 0) + 1; });
  if (!state.types.size) Object.keys(counts).forEach(t => state.types.add(t));
  const box = $('#type-filters');
  box.innerHTML = '';
  Object.keys(counts).sort().forEach(t => {
    const chip = el('span', 'chip' + (state.types.has(t) ? ' on' : ''),
      `<i style="background:${TYPE_COLOR[t] || '#94a3b8'}"></i>${esc(t)}<span class="n">${counts[t]}</span>`);
    chip.onclick = () => {
      state.types.has(t) ? state.types.delete(t) : state.types.add(t);
      chip.classList.toggle('on');
      applyFilters();
    };
    box.appendChild(chip);
  });
}

function renderLegend() {
  const present = new Set(state.data.graph.nodes.map(n => n.type));
  $('#legend').innerHTML =
    [...present].sort().map(t =>
      `<span><i style="background:${TYPE_COLOR[t] || '#94a3b8'}"></i>${esc(t)}</span>`).join('')
    + '<span><i style="background:#22c55e"></i>fund flow</span>'
    + '<span><i style="background:#a78bfa"></i>same actor</span>'
    + '<span><i style="background:#22d3ee"></i>victim</span>';
}

function applyFilters() {
  if (!state.graph) return;
  const minRisk = +$('#minrisk').value;
  const moneyOnly = $('#money-only').checked;
  state.graph.hideOrphans = $('#hide-orphans').checked;
  const flowOnly = state.graph.mode === 'flow';
  state.graph.applyFilter(n =>
    state.types.has(n.type) && (n.victim || (n.score || 0) >= minRisk)
    && (!moneyOnly || n.type === 'ACCOUNT' || n.type === 'UPI' || n.type === 'PERSON')
    // Flow view answers one question -- where did the money go -- so it shows
    // only the nodes the fund trail actually passes through.
    && (!flowOnly || n.layer != null || n.victim));
  state.graph.kick(0.5);
}

/* ------------------------------------------------------------ right tabs */
function renderSuspects() {
  const box = $('#tab-suspects');
  const list = state.data.prime_suspects;
  if (!list.length) { box.innerHTML = '<p class="empty">No suspects scored.</p>'; return; }
  box.innerHTML = '';
  list.forEach((s, i) => {
    const ids = s.identifiers.map(x => x.value).slice(0, 4).join(' · ');
    const card = el('div', 'card', `
      <div class="head">
        <span class="rank">#${i + 1}</span>
        <span class="title">${esc(s.label)}</span>
        <span class="score b-${s.band}">${s.score}</span>
      </div>
      <div class="sub">
        ${s.holders.length ? esc(s.holders.join(', ')) + ' · ' : ''}
        ${s.layer != null ? 'layer ' + s.layer + ' · ' : ''}
        received ${inr(s.received)} · retained ${inr(s.retained)}
      </div>
      <div class="sub">${esc(ids)}</div>
      <ul>${s.reasons.slice(0, 3).map(r => `<li>${esc(r.text)}</li>`).join('')}</ul>`);
    card.onclick = () => { showNode(s.primary); state.graph.focus(s.primary); };
    box.appendChild(card);
  });
}

function renderFindings() {
  const box = $('#tab-findings');
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const list = [...state.data.correlation_findings]
    .sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  if (!list.length) { box.innerHTML = '<p class="empty">No cross-artifact links found.</p>'; return; }
  box.innerHTML = '';
  list.forEach(f => {
    const card = el('div', 'card', `
      <div class="head">
        <span class="title">${esc(f.title)}</span>
        <span class="score b-${f.severity}">${esc(f.severity)}</span>
      </div>
      <div class="sub">${esc(f.detail)}</div>
      <div class="sub conf">confidence ${esc(f.confidence)} · ${esc(f.category)} · ${esc(f.code)}</div>`);
    card.onclick = () => {
      const first = f.entities.find(e => state.graph.byId.has(e));
      if (first) { showNode(first); state.graph.focus(first); }
    };
    box.appendChild(card);
  });
}

function renderTrail() {
  const box = $('#tab-trail');
  const mt = state.data.money_trail;
  if (!mt.chains.length) { box.innerHTML = '<p class="empty">No fund flow traced.</p>'; return; }
  box.innerHTML = `<p class="sub" style="color:var(--muted);margin:0 0 10px">
    Origin: ${esc(mt.origins.join(', '))} · ${inr(mt.total_traced)} across ${mt.hops.length} hops</p>`;
  mt.chains.forEach(chain => {
    if (!chain.length) return;
    const div = el('div', 'chain');
    div.appendChild(el('div', 'node', esc(chain[0].from_label)));
    chain.forEach(h => {
      const lag = h.lag_minutes != null ? ` · +${Math.round(h.lag_minutes)} min` : '';
      div.appendChild(el('div', 'via',
        `↓ ${inr(h.amount)}${lag} · ${esc(ts(h.ts))}${h.rail ? ' · ' + esc(h.rail) : ''}`));
      const n = el('div', 'node' + (h.dest_cashout ? ' cash' : ''),
        esc(h.to_label) + (h.dest_cashout ? ` — CASH-OUT ${inr(h.dest_cashout)}` : ''));
      n.onclick = () => { showNode(h.to); state.graph.focus(h.to); };
      n.style.cursor = 'pointer';
      div.appendChild(n);
    });
    box.appendChild(div);
  });
  if (mt.cashouts.length) {
    const box2 = el('div', 'card');
    box2.innerHTML = '<div class="head"><span class="title">Cash-out points</span></div>'
      + mt.cashouts.map(c => `<div class="sub">${esc(c.label)} — ${inr(c.amount)}
         via ${esc(c.mode)} on ${esc(ts(c.ts))}</div>`).join('');
    box.appendChild(box2);
  }
}

function renderTimeline() {
  const box = $('#tab-timeline');
  box.innerHTML = '';
  const wrap = el('div', 'tl');
  state.data.timeline.forEach(t => {
    const item = el('div', 'tl-item' + (t.flags.length ? ' hot' : ''), `
      <div class="t">${esc(t.display)} · ${esc(t.kind)}</div>
      <div class="s">${esc(t.summary)}${t.amount ? ' · ' + inr(t.amount) : ''}</div>
      ${t.flags.map(f => `<div class="f">⚠ ${esc(f)}</div>`).join('')}
      <div class="c">${esc(t.cite)}</div>`);
    item.onclick = () => showEvent(t.event);
    wrap.appendChild(item);
  });
  box.appendChild(wrap);
}

function renderActions() {
  const box = $('#tab-actions');
  box.innerHTML = state.data.recommended_actions.map(a => `
    <div class="act ${esc(a.priority)}">
      <div class="p">${esc(a.priority)}</div>
      <div class="a">${esc(a.action)}</div>
      <div class="w"><b>To:</b> ${esc(a.authority)}</div>
      <div class="w">${esc(a.rationale)}</div>
    </div>`).join('');
}

/* ------------------------------------------------------------ node panel */
function onHoverNode(hit) {
  const tip = $('#tooltip');
  if (!hit) { tip.hidden = true; return; }
  const n = hit.node;
  tip.innerHTML = `<b>${esc(n.label)}</b>
    <i>${esc(n.type)}${n.victim ? ' · VICTIM' : ''}
    ${n.score ? ' · risk ' + n.score + '/100 (' + n.band + ')' : ''}</i>
    ${n.in_amount || n.out_amount
      ? `<i>in ${inr(n.in_amount)} · out ${inr(n.out_amount)}</i>` : ''}
    <i>${n.events} observation(s) in ${n.exhibits.join(', ') || 'n/a'}</i>`;
  tip.hidden = false;
  const wrap = $('#canvas-wrap').getBoundingClientRect();
  tip.style.left = Math.min(hit.x + 16, wrap.width - 320) + 'px';
  tip.style.top = Math.min(hit.y + 14, wrap.height - 110) + 'px';
}

function onSelectNode(node) {
  if (!node) { $('#detail').hidden = true; return; }
  showNode(node.id);
}

function showNode(id) {
  const n = state.data.graph.nodes.find(x => x.id === id);
  if (!n) return;
  state.graph.selected = id;
  state.graph.draw();
  $('#detail').hidden = false;
  $('#detail-title').textContent = n.label;
  $('#detail-sub').textContent =
    `${n.type}${n.victim ? ' · VICTIM' : ''} · risk ${n.score}/100 (${n.band})`
    + (n.layer != null ? ` · fund-flow layer ${n.layer}` : '');

  const body = $('#detail-body');
  body.innerHTML = '';

  const kv = [
    ['Identifier', n.value],
    ['First seen', n.first_seen ? ts(n.first_seen) : '—'],
    ['Last seen', n.last_seen ? ts(n.last_seen) : '—'],
  ];
  if (n.in_amount || n.out_amount) {
    kv.push(['Received', inr(n.in_amount)], ['Sent onward', inr(n.out_amount)],
            ['Retained', inr(n.in_amount - n.out_amount)]);
  }
  Object.entries(n.meta || {}).forEach(([k, v]) => {
    if (['display', 'risk'].includes(k)) return;
    kv.push([k.replace(/_/g, ' '), String(v).slice(0, 90)]);
  });
  kv.push(['Seen in', n.exhibits.join(', ') || '—'],
          ['Roles', n.roles.join(', ') || '—']);
  body.appendChild(el('h4', null, 'Entity'));
  body.appendChild(el('dl', 'kv',
    kv.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')));

  if (n.reasons && n.reasons.length) {
    body.appendChild(el('h4', null, `Why it scored ${n.score}/100`));
    n.reasons.forEach(r => {
      const div = el('div', 'reason',
        `<div class="r">${esc(r.text)}</div>
         <div class="m">+${r.points} pts · ${esc(r.code)}</div>`);
      if (r.evidence && r.evidence.length) {
        const line = el('div', 'm');
        r.evidence.slice(0, 6).forEach(evId => {
          const a = el('span', 'ev', evId);
          a.onclick = () => showEvent(evId, div);
          line.appendChild(a);
        });
        div.appendChild(line);
      }
      body.appendChild(div);
    });
  }

  const links = state.data.graph.edges.filter(e => e.src === id || e.dst === id);
  if (links.length) {
    body.appendChild(el('h4', null, `Relationships (${links.length})`));
    links.slice(0, 40).forEach(e => {
      const otherId = e.src === id ? e.dst : e.src;
      const other = state.data.graph.nodes.find(x => x.id === otherId);
      const dir = e.src === id ? '→' : '←';
      const row = el('div', 'reason',
        `<div class="r">${dir} ${esc(other ? other.label : otherId)}</div>
         <div class="m">${esc(e.rel)} · ${e.count} record(s)${e.amount ? ' · ' + inr(e.amount) : ''}</div>`);
      row.style.cursor = 'pointer';
      row.onclick = () => { showNode(otherId); state.graph.focus(otherId); };
      body.appendChild(row);
    });
  }
}

function showEvent(eventId, mount) {
  const ev = state.eventById.get(eventId);
  if (!ev) return;
  const html = `
    <div class="evbox">
      <div><b>${esc(ev.kind)}</b> · ${esc(ts(ev.ts))}</div>
      <div>${esc(ev.summary)}${ev.amount ? ' · ' + inr(ev.amount) : ''}</div>
      ${(ev.flags || []).map(f => `<div style="color:var(--high)">⚠ ${esc(f)}</div>`).join('')}
      ${ev.attrs && ev.attrs.narration ? `<div style="color:var(--muted)">${esc(ev.attrs.narration)}</div>` : ''}
      ${ev.attrs && ev.attrs.text ? `<div style="color:var(--muted)">${esc(String(ev.attrs.text).slice(0, 300))}</div>` : ''}
      <div class="cite">Source: ${esc(ev.cite)}</div>
    </div>`;
  if (mount) {
    const old = mount.querySelector('.evbox');
    if (old) old.remove();
    mount.insertAdjacentHTML('beforeend', html);
  } else {
    $('#detail').hidden = false;
    $('#detail-title').textContent = ev.summary;
    $('#detail-sub').textContent = ev.kind + ' · ' + ts(ev.ts);
    $('#detail-body').innerHTML = html;
  }
}

/* ----------------------------------------------------------------- wiring */
$('#btn-sample').onclick = () => loadSample(false);
$('#file-input').onchange = e => { uploadFiles(e.target.files); e.target.value = ''; };
$('#btn-json').onclick = () => window.open(`/api/case/${state.caseId}/report.json`, '_blank');
$('#btn-pdf').onclick = () => window.open(`/api/case/${state.caseId}/report.pdf`, '_blank');
$('#detail-close').onclick = () => {
  $('#detail').hidden = true;
  if (state.graph) { state.graph.selected = null; state.graph.draw(); }
};

$('#minrisk').oninput = e => { $('#minrisk-val').textContent = e.target.value; applyFilters(); };
$('#money-only').onchange = applyFilters;
$('#hide-orphans').onchange = applyFilters;
$('#btn-fit').onclick = () => state.graph && state.graph.fit();
$('#btn-relayout').onclick = () => { if (state.graph) { state.graph.kick(1); } };
$('#btn-flow').onclick = e => {
  if (!state.graph) return;
  const on = state.graph.mode !== 'flow';
  state.graph.mode = on ? 'flow' : 'force';
  e.target.classList.toggle('on', on);
  applyFilters();
  state.graph.preheat(220);
};

document.querySelectorAll('.tab').forEach(t => {
  t.onclick = () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === t));
    ['suspects', 'findings', 'trail', 'timeline', 'actions'].forEach(name => {
      $('#tab-' + name).hidden = name !== t.dataset.tab;
    });
  };
});

$('#search').oninput = e => {
  const q = e.target.value.trim().toLowerCase();
  if (!q || !state.graph) return;
  const hit = state.data.graph.nodes.find(n =>
    String(n.value).toLowerCase().includes(q) || n.label.toLowerCase().includes(q));
  if (hit) { state.graph.focus(hit.id); showNode(hit.id); }
};

/* drag & drop ingestion */
let dragDepth = 0;
window.addEventListener('dragenter', e => {
  e.preventDefault(); dragDepth++; $('#drop').hidden = false;
});
window.addEventListener('dragover', e => e.preventDefault());
window.addEventListener('dragleave', e => {
  e.preventDefault(); if (--dragDepth <= 0) { dragDepth = 0; $('#drop').hidden = true; }
});
window.addEventListener('drop', e => {
  e.preventDefault(); dragDepth = 0; $('#drop').hidden = true;
  if (e.dataTransfer && e.dataTransfer.files.length) uploadFiles(e.dataTransfer.files);
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') $('#detail-close').click();
});

boot();
