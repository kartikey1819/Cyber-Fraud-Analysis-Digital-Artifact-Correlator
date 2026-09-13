/* Canvas entity-graph renderer with a built-in force layout.
   No third-party library: the whole toolkit has to run on an offline
   workstation with nothing but a browser and a Python interpreter. */

const TYPE_COLOR = {
  PHONE:   '#38bdf8',
  ACCOUNT: '#34d399',
  UPI:     '#a78bfa',
  IMEI:    '#f59e0b',
  IMSI:    '#fbbf24',
  IP:      '#60a5fa',
  MAC:     '#f472b6',
  EMAIL:   '#22d3ee',
  DOMAIN:  '#fb7185',
  APK:     '#ef4444',
  DEVICE:  '#94a3b8',
  PERSON:  '#cbd5e1',
  CELL:    '#475569',
};

const BAND_COLOR = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#334155',
};

const REL_STYLE = {
  FUNDS:            { color: '#22c55e', width: 2.0, arrow: true },
  CALL:             { color: '#3b82f6', width: 1.1, arrow: true },
  SMS:              { color: '#6366f1', width: 1.0, arrow: true },
  USES_HANDSET:     { color: '#f59e0b', width: 1.2, arrow: false },
  SIM_IN_HANDSET:   { color: '#d97706', width: 1.0, arrow: false },
  USES_SIM:         { color: '#b45309', width: 0.8, arrow: false },
  USED_IP:          { color: '#2563eb', width: 0.8, arrow: false },
  TXN_FROM_IP:      { color: '#1d4ed8', width: 0.8, arrow: false },
  SENT_FROM_IP:     { color: '#1d4ed8', width: 0.8, arrow: false },
  LINKED_VPA:       { color: '#a78bfa', width: 1.6, arrow: false, dash: [4, 3] },
  REGISTERED_ON:    { color: '#8b5cf6', width: 1.4, arrow: false, dash: [4, 3] },
  DEVICE_INTERFACE: { color: '#ec4899', width: 1.2, arrow: false, dash: [4, 3] },
  HOLDS:            { color: '#64748b', width: 0.9, arrow: false, dash: [2, 3] },
  INSTALLED:        { color: '#ef4444', width: 1.3, arrow: true },
  CONTACTS:         { color: '#f43f5e', width: 1.1, arrow: true },
  CONNECTED_TO:     { color: '#475569', width: 0.7, arrow: true },
  SENT_LINK:        { color: '#fb7185', width: 1.2, arrow: true },
  LINKS_TO:         { color: '#fb7185', width: 1.2, arrow: true },
  DELIVERED:        { color: '#ef4444', width: 1.4, arrow: true },
  MENTIONS:         { color: '#475569', width: 0.7, arrow: true, dash: [2, 4] },
  SEEN_AT_CELL:     { color: '#334155', width: 0.6, arrow: false },
  EMAILED:          { color: '#22d3ee', width: 1.0, arrow: true },
  SPOOFS:           { color: '#ef4444', width: 1.4, arrow: false, dash: [5, 3] },
  ON_DOMAIN:        { color: '#475569', width: 0.7, arrow: false },
};
const REL_DEFAULT = { color: '#3f4c5f', width: 0.8, arrow: true };

const IDENTITY_RELS = new Set(['LINKED_VPA', 'REGISTERED_ON', 'DEVICE_INTERFACE', 'HOLDS']);

class GraphView {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.nodes = [];
    this.edges = [];
    this.visible = [];
    this.visibleEdges = [];
    this.byId = new Map();
    this.scale = 1;
    this.tx = 0;
    this.ty = 0;
    this.alpha = 0;
    this.mode = 'force';
    this.selected = null;
    this.hover = null;
    this.handlers = {};
    this.running = false;
    this._pointers = new Map();
    this._pinch = null;
    this._bind();
    this._observeSize();
    this.resize();
  }

  /** Refit when the canvas box changes (orientation flip, responsive
      reflow, window resize) so the graph is never drawn off-screen. */
  _observeSize() {
    if (typeof ResizeObserver === 'undefined') return;
    let last = null, timer = null;
    const ro = new ResizeObserver(entries => {
      const box = entries[0].contentRect;
      const key = Math.round(box.width) + 'x' + Math.round(box.height);
      if (key === last || box.width < 2 || box.height < 2) return;
      last = key;
      clearTimeout(timer);
      timer = setTimeout(() => { this.resize(); this.fit(); }, 120);
    });
    ro.observe(this.canvas.parentElement || this.canvas);
  }

  on(evt, fn) { (this.handlers[evt] = this.handlers[evt] || []).push(fn); }
  emit(evt, arg) { (this.handlers[evt] || []).forEach(f => f(arg)); }

  /* ------------------------------------------------------------- data */
  setData(nodes, edges) {
    const prev = this.byId;
    this.byId = new Map();
    this.nodes = nodes.map(n => {
      const old = prev.get(n.id);
      const node = Object.assign({}, n);
      node.x = old ? old.x : (Math.random() - 0.5) * 700;
      node.y = old ? old.y : (Math.random() - 0.5) * 520;
      node.vx = 0; node.vy = 0;
      node.r = 5 + Math.sqrt(Math.max(n.events || 1, 1)) * 1.1 + (n.score || 0) / 11;
      if (n.victim) node.r += 3;
      node.deg = 0;
      this.byId.set(n.id, node);
      return node;
    });
    this.edges = edges.filter(e => this.byId.has(e.src) && this.byId.has(e.dst))
      .map(e => Object.assign({}, e, {
        s: this.byId.get(e.src), t: this.byId.get(e.dst),
      }));
    this.edges.forEach(e => { e.s.deg++; e.t.deg++; });
    this.applyFilter(this._filter);
  }

  /** Settle the layout synchronously before the first paint. */
  preheat(iterations = 260) {
    this.alpha = 1;
    for (let i = 0; i < iterations; i++) {
      this.step();
      this.alpha *= 0.990;
    }
    this.alpha = 0.14;
    this.fit();
    this.kick(0.14);
  }

  applyFilter(filter) {
    this._filter = filter;
    const f = filter || (() => true);
    const hidden = new Set();
    this.nodes.forEach(n => { if (!f(n)) hidden.add(n.id); });
    this.visibleEdges = this.edges.filter(e => !hidden.has(e.src) && !hidden.has(e.dst));
    const connected = new Set();
    this.visibleEdges.forEach(e => { connected.add(e.src); connected.add(e.dst); });
    this.visible = this.nodes.filter(n =>
      !hidden.has(n.id) && (!this.hideOrphans || connected.has(n.id) || n.victim));
    this._assignLanes();
    this.draw();
  }

  /** In flow mode, stack each fund-flow layer into its own vertical lane so
      the victim -> mule -> cash-out chain reads left to right. */
  _assignLanes() {
    const buckets = new Map();
    for (const p of this.visible) {
      const layer = p.layer != null ? p.layer : -1;
      if (!buckets.has(layer)) buckets.set(layer, []);
      buckets.get(layer).push(p);
    }
    for (const [, group] of buckets) {
      group.sort((a, b) => (b.in_amount || 0) - (a.in_amount || 0) || a.label.localeCompare(b.label));
      const span = Math.max(group.length - 1, 1);
      group.forEach((p, i) => { p._laneY = (i - span / 2) * 120; });
    }
  }

  /* ----------------------------------------------------------- layout */
  kick(alpha) {
    this.alpha = Math.max(this.alpha, alpha);
    if (!this.running) { this.running = true; requestAnimationFrame(() => this.tick()); }
  }

  setMode(mode) { this.mode = mode; this.kick(0.9); }

  tick() {
    if (this.alpha > 0.004) {
      this.step();
      this.alpha *= 0.972;
      this.draw();
      requestAnimationFrame(() => this.tick());
    } else {
      this.running = false;
      this.draw();
    }
  }

  step() {
    const nodes = this.visible;
    const n = nodes.length;
    if (!n) return;
    const k = Math.max(76, 640 / Math.sqrt(n) + 48);   // ideal edge length
    const a = this.alpha;

    // repulsion (O(n^2) is fine at triage scale; graphs are capped at 600)
    for (let i = 0; i < n; i++) {
      const p = nodes[i];
      for (let j = i + 1; j < n; j++) {
        const q = nodes[j];
        let dx = p.x - q.x, dy = p.y - q.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 0.5; }
        if (d2 > 1440000) continue;   // ignore repulsion beyond ~1200px
        const d = Math.sqrt(d2);
        const f = (k * k) / d2 * a * 0.9;
        const fx = dx / d * f, fy = dy / d * f;
        p.vx += fx; p.vy += fy; q.vx -= fx; q.vy -= fy;
      }
    }

    // spring attraction
    for (const e of this.visibleEdges) {
      const p = e.s, q = e.t;
      const dx = q.x - p.x, dy = q.y - p.y;
      const d = Math.max(Math.sqrt(dx * dx + dy * dy), 0.6);
      const strength = IDENTITY_RELS.has(e.rel) ? 1.9 : (e.rel === 'FUNDS' ? 1.25 : 0.85);
      const f = (d * d) / k * a * 0.0042 * strength;
      const fx = dx / d * f, fy = dy / d * f;
      p.vx += fx; p.vy += fy; q.vx -= fx; q.vy -= fy;
    }

    // global cohesion + fund-flow lanes
    const flow = this.mode === 'flow';
    for (const p of nodes) {
      if (flow && p.layer != null) {
        const targetX = -520 + p.layer * 340;
        p.vx += (targetX - p.x) * a * 0.14;
        p.vy += ((p._laneY || 0) - p.y) * a * 0.06;
      } else if (flow) {
        // everything that is not on the money trail sits in a band below it
        p.vx += (0 - p.x) * a * 0.006;
        p.vy += (430 - p.y) * a * 0.05;
      } else {
        p.vx += (0 - p.x) * a * 0.010;
        p.vy += (0 - p.y) * a * 0.014;
      }
    }

    for (const p of nodes) {
      if (p.fixed) { p.vx = p.vy = 0; continue; }
      p.vx *= 0.82; p.vy *= 0.82;
      const sp = Math.hypot(p.vx, p.vy);
      if (sp > 26) { p.vx = p.vx / sp * 26; p.vy = p.vy / sp * 26; }
      p.x += p.vx; p.y += p.vy;
    }
  }

  fit() {
    const nodes = this.visible.length ? this.visible : this.nodes;
    if (!nodes.length) return;
    let minX = 1e9, minY = 1e9, maxX = -1e9, maxY = -1e9;
    for (const p of nodes) {
      minX = Math.min(minX, p.x - p.r); maxX = Math.max(maxX, p.x + p.r);
      minY = Math.min(minY, p.y - p.r); maxY = Math.max(maxY, p.y + p.r);
    }
    const w = this.canvas.clientWidth, h = this.canvas.clientHeight;
    const pad = 70;
    this.scale = Math.min(4, Math.max(0.12,
      Math.min((w - pad) / Math.max(maxX - minX, 1), (h - pad) / Math.max(maxY - minY, 1))));
    this.tx = w / 2 - (minX + maxX) / 2 * this.scale;
    this.ty = h / 2 - (minY + maxY) / 2 * this.scale;
    this.draw();
  }

  focus(id) {
    const node = this.byId.get(id);
    if (!node) return;
    this.selected = id;
    this.scale = Math.max(this.scale, 1.05);
    this.tx = this.canvas.clientWidth / 2 - node.x * this.scale;
    this.ty = this.canvas.clientHeight / 2 - node.y * this.scale;
    this.draw();
  }

  /* ------------------------------------------------------------- draw */
  resize() {
    const dpr = window.devicePixelRatio || 1;
    const w = this.canvas.clientWidth, h = this.canvas.clientHeight;
    this.canvas.width = Math.max(1, Math.round(w * dpr));
    this.canvas.height = Math.max(1, Math.round(h * dpr));
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.draw();
  }

  toWorld(px, py) {
    return { x: (px - this.tx) / this.scale, y: (py - this.ty) / this.scale };
  }

  neighborsOf(id) {
    const set = new Set([id]);
    for (const e of this.visibleEdges) {
      if (e.src === id) set.add(e.dst);
      else if (e.dst === id) set.add(e.src);
    }
    return set;
  }

  draw() {
    const ctx = this.ctx;
    const w = this.canvas.clientWidth, h = this.canvas.clientHeight;
    ctx.save();
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = '#0b0f16';
    ctx.fillRect(0, 0, w, h);
    ctx.translate(this.tx, this.ty);
    ctx.scale(this.scale, this.scale);

    const active = this.selected || this.hover;
    const near = active ? this.neighborsOf(active) : null;

    for (const e of this.visibleEdges) {
      const style = REL_STYLE[e.rel] || REL_DEFAULT;
      const lit = !near || near.has(e.src) && near.has(e.dst);
      ctx.globalAlpha = lit ? (near ? 0.95 : 0.55) : 0.07;
      ctx.strokeStyle = style.color;
      ctx.lineWidth = (style.width + (e.rel === 'FUNDS' ? Math.min(3.2, Math.log10((e.amount || 1) + 1) * 0.62) : 0)) / this.scale * Math.min(this.scale, 1.35);
      ctx.setLineDash(style.dash ? style.dash.map(v => v / this.scale) : []);
      this.drawEdge(ctx, e, style.arrow);
    }
    ctx.setLineDash([]);
    ctx.globalAlpha = 1;

    for (const p of this.visible) {
      const lit = !near || near.has(p.id);
      ctx.globalAlpha = lit ? 1 : 0.13;
      const color = TYPE_COLOR[p.type] || '#94a3b8';

      if (p.victim) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r + 4.5, 0, Math.PI * 2);
        ctx.strokeStyle = '#22d3ee';
        ctx.lineWidth = 1.4 / this.scale * Math.min(this.scale, 1.4);
        ctx.stroke();
      }
      if ((p.score || 0) >= 35) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r + 2.6, 0, Math.PI * 2);
        ctx.strokeStyle = BAND_COLOR[p.band] || '#334155';
        ctx.lineWidth = 2.4 / this.scale * Math.min(this.scale, 1.4);
        ctx.stroke();
      }
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      if (p.id === this.selected) {
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 2 / this.scale * Math.min(this.scale, 1.4);
        ctx.stroke();
      }

      // Label everything once zoomed in; when zoomed out, label only what an
      // officer is actually looking for, so the view does not turn to mush.
      const important = p.victim || (p.score || 0) >= 55 || p.deg >= 10;
      if (this.scale > 0.95 || important) {
        const size = 11 / this.scale;   // constant on screen, not in world units
        ctx.font = `${(p.score >= 55 || p.victim) ? '600 ' : ''}${size}px "Segoe UI", system-ui, sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        const label = p.label.length > 26 ? p.label.slice(0, 25) + '…' : p.label;
        const ty = p.y + p.r + 4;
        ctx.lineWidth = 3 / this.scale;
        ctx.strokeStyle = 'rgba(11,15,22,.9)';
        ctx.strokeText(label, p.x, ty);
        ctx.fillStyle = p.victim ? '#67e8f9' : (p.score >= 55 ? '#f8fafc' : '#9fb0c6');
        ctx.fillText(label, p.x, ty);
      }
    }
    ctx.globalAlpha = 1;
    ctx.restore();
  }

  drawEdge(ctx, e, arrow) {
    const p = e.s, q = e.t;
    const dx = q.x - p.x, dy = q.y - p.y;
    const d = Math.hypot(dx, dy) || 1;
    const ux = dx / d, uy = dy / d;
    const x1 = p.x + ux * p.r, y1 = p.y + uy * p.r;
    const x2 = q.x - ux * (q.r + (arrow ? 4.5 : 0));
    const y2 = q.y - uy * (q.r + (arrow ? 4.5 : 0));
    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.stroke();
    if (arrow && e.directed) {
      const a = 5.4 / Math.min(this.scale, 1.2), spread = 0.42;
      ctx.beginPath();
      ctx.moveTo(x2, y2);
      ctx.lineTo(x2 - a * Math.cos(Math.atan2(uy, ux) - spread),
                 y2 - a * Math.sin(Math.atan2(uy, ux) - spread));
      ctx.lineTo(x2 - a * Math.cos(Math.atan2(uy, ux) + spread),
                 y2 - a * Math.sin(Math.atan2(uy, ux) + spread));
      ctx.closePath();
      ctx.fillStyle = ctx.strokeStyle;
      ctx.fill();
    }
  }

  nodeAt(px, py) {
    const { x, y } = this.toWorld(px, py);
    let best = null, bestD = Infinity;
    for (const p of this.visible) {
      const d = Math.hypot(p.x - x, p.y - y);
      if (d <= p.r + 6 / this.scale && d < bestD) { best = p; bestD = d; }
    }
    return best;
  }

  /* ------------------------------------------------------- interaction */
  _bind() {
    const c = this.canvas;
    let dragNode = null, panning = false, last = null, moved = false;

    const pinchDist = () => {
      const [a, b] = [...this._pointers.values()];
      return Math.hypot(a.x - b.x, a.y - b.y);
    };
    const pinchMid = () => {
      const [a, b] = [...this._pointers.values()];
      return { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    };

    c.addEventListener('pointerdown', ev => {
      c.setPointerCapture(ev.pointerId);
      this._pointers.set(ev.pointerId, { x: ev.offsetX, y: ev.offsetY });
      if (this._pointers.size === 2) {
        // second finger down: abandon drag/pan and start a pinch
        if (dragNode) { dragNode.fixed = false; dragNode = null; }
        panning = false;
        c.classList.remove('grabbing');
        this._pinch = { dist: pinchDist(), scale: this.scale, mid: pinchMid() };
        moved = true;
        return;
      }
      last = { x: ev.offsetX, y: ev.offsetY };
      moved = false;
      const hit = this.nodeAt(ev.offsetX, ev.offsetY);
      if (hit) { dragNode = hit; hit.fixed = true; }
      else { panning = true; c.classList.add('grabbing'); }
    });

    c.addEventListener('pointermove', ev => {
      if (this._pointers.has(ev.pointerId)) {
        this._pointers.set(ev.pointerId, { x: ev.offsetX, y: ev.offsetY });
      }
      if (this._pinch && this._pointers.size >= 2) {
        const d = pinchDist();
        if (d > 4) {
          const next = Math.min(6, Math.max(0.08, this._pinch.scale * (d / this._pinch.dist)));
          const m = this._pinch.mid;
          const wx = (m.x - this.tx) / this.scale;
          const wy = (m.y - this.ty) / this.scale;
          this.scale = next;
          this.tx = m.x - wx * next;
          this.ty = m.y - wy * next;
          this.draw();
        }
        return;
      }
      if (dragNode) {
        const w = this.toWorld(ev.offsetX, ev.offsetY);
        dragNode.x = w.x; dragNode.y = w.y;
        moved = true;
        this.kick(0.18);
        this.draw();
        return;
      }
      if (panning) {
        this.tx += ev.offsetX - last.x;
        this.ty += ev.offsetY - last.y;
        last = { x: ev.offsetX, y: ev.offsetY };
        moved = true;
        this.draw();
        return;
      }
      const hit = this.nodeAt(ev.offsetX, ev.offsetY);
      const id = hit ? hit.id : null;
      if (id !== this.hover) {
        this.hover = id;
        this.draw();
      }
      this.emit('hover', hit ? { node: hit, x: ev.offsetX, y: ev.offsetY } : null);
    });

    const release = ev => {
      this._pointers.delete(ev.pointerId);
      if (this._pointers.size < 2) this._pinch = null;
      if (this._pointers.size > 0) { dragNode = null; panning = false; return; }
      if (dragNode) { dragNode.fixed = false; }
      if (!moved) {
        const hit = this.nodeAt(ev.offsetX, ev.offsetY);
        this.selected = hit ? hit.id : null;
        this.emit('select', hit || null);
        this.draw();
      }
      dragNode = null; panning = false;
      c.classList.remove('grabbing');
    };
    c.addEventListener('pointerup', release);
    c.addEventListener('pointercancel', ev => {
      this._pointers.delete(ev.pointerId);
      this._pinch = null;
      dragNode = null; panning = false;
    });
    c.addEventListener('pointerleave', () => {
      if (this.hover) { this.hover = null; this.draw(); }
      this.emit('hover', null);
    });

    c.addEventListener('wheel', ev => {
      ev.preventDefault();
      const factor = Math.exp(-ev.deltaY * 0.0013);
      const next = Math.min(6, Math.max(0.08, this.scale * factor));
      const wx = (ev.offsetX - this.tx) / this.scale;
      const wy = (ev.offsetY - this.ty) / this.scale;
      this.scale = next;
      this.tx = ev.offsetX - wx * next;
      this.ty = ev.offsetY - wy * next;
      this.draw();
    }, { passive: false });

    window.addEventListener('resize', () => this.resize());
    window.addEventListener('orientationchange', () => setTimeout(() => {
      this.resize(); this.fit();
    }, 250));
  }
}
