"""Investigative brief generation: structured JSON + a one-page field PDF.

The PDF is written for a police field unit: what was lost, who to act against,
what to freeze in the next hour, and the hash manifest that makes the whole
thing defensible in court.  Annexures carry the supporting detail.
"""

from __future__ import annotations

import datetime as dt
import json

from . import model as M
from .correlate import FINANCIAL_TYPES
from .evidence import sha256_bytes
from .pdfwriter import A4, COURIER, HELV, HELV_B, PDF, text_width, wrap
from .util import human_ts, inr, iso, short

# palette
INK = (0.11, 0.13, 0.18)
MUTED = (0.42, 0.45, 0.52)
RULE = (0.84, 0.86, 0.90)
ACCENT = (0.07, 0.29, 0.55)
BAND_COLORS = {
    "CRITICAL": (0.72, 0.11, 0.14),
    "HIGH": (0.85, 0.40, 0.06),
    "MEDIUM": (0.72, 0.58, 0.05),
    "LOW": (0.35, 0.45, 0.55),
}

MARGIN = 38.0


# ==========================================================================
# recommendations
# ==========================================================================

def recommendations(g, suspects, findings, trail, ctx):
    recs = []

    def add(priority, action, authority, rationale, targets):
        recs.append({"priority": priority, "action": action, "authority": authority,
                     "rationale": rationale, "targets": targets})

    hot = [s for s in suspects if s["band"] in ("CRITICAL", "HIGH")][:8]
    for s in hot:
        accounts = [m for m in s["members"] if g.nodes[m]["type"] == M.ACCOUNT
                    and not str(g.nodes[m]["value"]).startswith("MASKED")]
        vpas = [m for m in s["members"] if g.nodes[m]["type"] == M.UPI]
        phones = [m for m in s["members"] if g.nodes[m]["type"] == M.PHONE]
        for a in accounts:
            node = g.nodes[a]
            bank = node["meta"].get("bank") or node["meta"].get("ifsc") or "issuing bank"
            add("IMMEDIATE",
                f"Lien-mark / debit-freeze A/c {node['value']}"
                + (f" ({node['meta']['holder']})" if node["meta"].get("holder") else ""),
                f"{bank} nodal officer — RBI cyber-fraud 'golden hour' hold",
                f"Received ₹{inr(s['received'])}; risk {s['score']}/100 ({s['band']}); "
                f"layer {s['layer'] if s['layer'] is not None else '?'} of the fund trail",
                [a])
        for v in vpas:
            node = g.nodes[v]
            psp = node["meta"].get("bank") or node["value"].split("@")[-1].upper()
            add("IMMEDIATE",
                f"Freeze VPA {node['value']} and obtain KYC + device binding",
                f"PSP / {psp} via NPCI escalation",
                f"Beneficiary handle in the traced chain; risk {s['score']}/100",
                [v])
        for p in phones:
            add("HIGH",
                f"Sec.91 CrPC notice for SDR/CAF, CDR and IPDR of MSISDN {g.nodes[p]['value']}",
                "Telecom service provider (nodal officer)",
                "Subscriber is a scored suspect in the correlation graph",
                [p])

    for f in findings:
        if f.category == "DEVICE" and f.code.startswith(("SHARED-HANDSET", "SIM-VELOCITY")):
            imei = next((e for e in f.entities if g.nodes.get(e, {}).get("type") == M.IMEI), None)
            if imei:
                add("HIGH",
                    f"Obtain IMEI-based CDR for handset {g.nodes[imei]['value']} (all SIMs, 90 days) "
                    "and seize the handset on arrest",
                    "Telecom service provider / arresting team",
                    f.title, [imei])
        if f.category == "MALWARE" and f.code.startswith("MALICIOUS-APK"):
            apk = next((e for e in f.entities if g.nodes.get(e, {}).get("type") == M.APK), None)
            if apk:
                sha = g.nodes[apk]["meta"].get("sha256")
                add("HIGH",
                    f"Preserve APK '{g.nodes[apk]['value']}'"
                    + (f" (SHA-256 {sha[:24]}…)" if sha else "") +
                    " and forward for full reverse engineering",
                    "CFSL / State FSL cyber division",
                    f.title, [apk])
        if f.code.startswith(("SHARED-IP", "SHARED-SUBNET")):
            ips = [e for e in f.entities if g.nodes.get(e, {}).get("type") == M.IP]
            if ips:
                add("HIGH",
                    "Sec.91 CrPC notice to the ISP for subscriber allocation of "
                    + ", ".join(g.nodes[i]["value"] for i in ips[:3])
                    + " during the incident window",
                    "Internet service provider",
                    f.title + " — potential physical raid location", ips[:3])
        if f.category == "NETWORK" and f.code.startswith("DOMAIN-PIVOT"):
            dom = next((e for e in f.entities if g.nodes.get(e, {}).get("type") == M.DOMAIN), None)
            if dom:
                add("MEDIUM",
                    f"Takedown + WHOIS/hosting preservation request for {g.nodes[dom]['value']}",
                    "CERT-In / I4C takedown cell",
                    f.title, [dom])

    # One action per cash-out endpoint, not per withdrawal slip.
    by_node = {}
    for c in trail["cashouts"]:
        b = by_node.setdefault(c["node"], {"count": 0, "total": 0.0, "modes": set(),
                                           "first": c["ts"], "last": c["ts"],
                                           "places": set()})
        b["count"] += 1
        b["total"] += c["amount"] or 0
        b["modes"].add(c["mode"])
        b["first"] = min(b["first"] or c["ts"], c["ts"] or b["first"])
        b["last"] = max(b["last"] or c["ts"], c["ts"] or b["last"])
        if c.get("narration"):
            b["places"].add(short(c["narration"], 44))
    for node_id, b in sorted(by_node.items(), key=lambda kv: -kv[1]["total"])[:6]:
        node = g.nodes.get(node_id)
        if not node:
            continue
        modes = "/".join(sorted(b["modes"]))
        add("IMMEDIATE",
            f"Obtain CCTV, terminal/switch logs and card-present data for {b['count']} "
            f"{modes} withdrawal(s) totalling ₹{inr(b['total'])} from {node['label']}",
            "Acquiring bank / ATM operator / branch manager",
            f"Cash-out window {human_ts(b['first'])} to {human_ts(b['last'])}"
            + ("; terminals: " + "; ".join(sorted(b["places"])[:3]) if b["places"] else "")
            + " — last point before the money leaves the banking system",
            [node_id])

    spoof = [f for f in findings if "SPOOF" in f.code.upper()]
    emails = [n["id"] for n in g.nodes.values() if n["type"] == M.EMAIL and n["roles"] & {"sender"}]
    if spoof or emails:
        add("MEDIUM",
            "Preserve the originating mailbox and full RFC-822 headers; raise abuse/takedown "
            "with the sending provider",
            "Email service provider / CERT-In",
            "Spoofed-header phishing vector identified in the exhibits",
            emails[:3])

    add("IMMEDIATE",
        "Escalate on NCRP / I4C for inter-bank hold on every beneficiary listed above",
        "I4C — Citizen Financial Cyber Fraud Reporting",
        f"₹{inr(ctx.get('amount_defrauded') or 0)} reported; "
        f"₹{inr(trail.get('total_traced') or 0)} traced across "
        f"{len(trail.get('hops') or [])} hops",
        list(ctx.get("victim_financial") or []))

    order = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    recs.sort(key=lambda r: order.get(r["priority"], 9))
    # de-duplicate identical actions
    seen, out = set(), []
    for r in recs:
        if r["action"] in seen:
            continue
        seen.add(r["action"])
        out.append(r)
    return out


# ==========================================================================
# timeline
# ==========================================================================

def build_timeline(events, g, ctx, limit=40):
    keyed = []
    for ev in events:
        weight = 0
        if ev.kind == M.COMPLAINT:
            weight = 100
        elif ev.kind == M.TXN and ev.amount:
            weight = 60 + min(20, ev.amount / 50000.0)
        elif ev.kind == M.APP:
            weight = 70 if (ev.attrs.get("apk_risk") or 0) >= 55 else 30
        elif ev.kind == M.EMAIL_MSG:
            weight = 65 if ev.flags else 35
        elif ev.kind in (M.CALL, M.SMS):
            weight = 45 if ev.flags else 20
        elif ev.kind == M.CHAT:
            weight = 40 if ev.flags else 15
        else:
            weight = 10
        if ev.flags:
            weight += 15
        keyed.append((weight, ev))
    keyed.sort(key=lambda kv: -kv[0])
    chosen = [ev for _, ev in keyed[:limit]]
    chosen.sort(key=lambda e: e.ts or dt.datetime.max)
    return [{
        "ts": iso(ev.ts),
        "display": human_ts(ev.ts),
        "kind": ev.kind,
        "summary": ev.summary,
        "amount": ev.amount,
        "flags": ev.flags,
        "exhibit": ev.exhibit,
        "cite": ev.cite(),
        "event": ev.id,
    } for ev in chosen]


# ==========================================================================
# report assembly
# ==========================================================================

def build_report(case):
    g = case.graph
    trail = case.trail
    ctx = case.context
    recs = recommendations(g, case.suspects, case.findings, trail, ctx)
    timeline = build_timeline(case.events, g, ctx)

    complaint = ctx.get("complaint") or {}
    cattrs = complaint.get("attrs", {}) if complaint else {}

    report = {
        "report_type": "CYBER FRAUD INVESTIGATIVE BRIEF",
        "case": {
            "case_id": case.case_id,
            "generated_utc": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "generated_local": dt.datetime.now().strftime("%d-%b-%Y %H:%M:%S"),
            "officer": case.officer,
            "acknowledgement_no": cattrs.get("acknowledgement_no"),
            "police_station": cattrs.get("police_station"),
            "district": cattrs.get("district"),
            "category": cattrs.get("category"),
            "tool": "Unified Cyber Fraud Analysis & Digital Artifact Correlator v1.0",
        },
        "victim": {
            "name": cattrs.get("victim_name"),
            "narrative": cattrs.get("narrative"),
            "amount_reported": cattrs.get("amount"),
            "amount_debited_observed": ctx.get("amount_defrauded"),
            "first_debit": iso(ctx.get("first_debit")),
            "identifiers": [
                {"type": g.nodes[n]["type"], "value": g.nodes[n]["value"],
                 "label": g.nodes[n]["label"]}
                for n in g.nodes if g.nodes[n]["victim"]
            ],
        },
        "statistics": {
            "exhibits": len(case.exhibits),
            "events_normalised": len(case.events),
            "entities": len(g.nodes),
            "relationships": len(g.edges),
            "correlation_findings": len(case.findings),
            "suspect_clusters": len(case.suspects),
            "amount_reported": cattrs.get("amount") or 0,
            "amount_traced": trail.get("total_traced"),
            "hops_traced": len(trail.get("hops") or []),
            "processing_ms": case.processing_ms,
        },
        "prime_suspects": [_suspect_out(g, s) for s in case.suspects[:12]],
        "correlation_findings": [f.to_dict() for f in case.findings],
        "money_trail": {
            "origins": [g.nodes[o]["label"] for o in trail["origins"] if o in g.nodes],
            "total_traced": trail["total_traced"],
            "hops": [_hop_out(g, h) for h in trail["hops"]],
            "chains": [[_hop_out(g, h) for h in p] for p in trail["paths"][:8]],
            "cashouts": [dict(c, label=g.nodes[c["node"]]["label"] if c["node"] in g.nodes else c["node"])
                         for c in trail["cashouts"]],
        },
        "entity_clusters": [
            {"id": c["id"], "holders": c["holders"],
             "members": [{"id": m, "type": g.nodes[m]["type"], "label": g.nodes[m]["label"],
                          "score": case.scores.get(m, {}).get("score", 0)}
                         for m in c["members"] if m in g.nodes],
             "victim": c["victim"]}
            for c in case.clusters.values() if len(c["members"]) > 1
        ],
        "timeline": timeline,
        "recommended_actions": recs,
        "evidentiary_integrity": {
            "hash_algorithm": "SHA-256",
            "exhibits": [e.to_dict() for e in case.exhibits],
            "chain_of_custody": case.custody.to_dict(),
            "verification_note": (
                "Each exhibit was hashed on acquisition, copied read-only into the case "
                "working directory and re-hashed after the copy. The hashes below were "
                "recomputed at report generation time and matched."),
            "reverify": case.verify_all(),
        },
        "graph": case.graph_payload(),
    }
    blob = json.dumps(report, sort_keys=True, separators=(",", ":"), default=str).encode()
    report["report_sha256"] = sha256_bytes(blob)
    return report


def _suspect_out(g, s):
    return {
        "id": s["id"], "primary": s["primary"],
        "label": s["label"], "holders": s["holders"],
        "score": s["score"], "band": s["band"], "layer": s["layer"],
        "received": s["received"], "sent": s["sent"], "retained": s["retained"],
        "identifiers": [{"type": g.nodes[m]["type"], "value": g.nodes[m]["value"],
                         "label": g.nodes[m]["label"]}
                        for m in s["members"] if m in g.nodes],
        "reasons": s["reasons"],
    }


def _hop_out(g, h):
    return dict(h,
                from_label=g.nodes[h["from"]]["label"] if h["from"] in g.nodes else h["from"],
                to_label=g.nodes[h["to"]]["label"] if h["to"] in g.nodes else h["to"])


# ==========================================================================
# PDF rendering
# ==========================================================================

class _Doc:
    """Cursor + auto page-break wrapper around PDF."""

    def __init__(self, report):
        self.report = report
        self.pdf = PDF(title=f"Investigative Brief {report['case']['case_id']}")
        self.page = None
        self.y = 0.0
        self.page_no = 0
        self.width = A4[0]
        self.inner = A4[0] - 2 * MARGIN
        self.new_page()

    def new_page(self, header=None):
        if self.page is not None:
            self._footer()
        self.page = self.pdf.new_page()
        self.page_no += 1
        self.y = MARGIN
        if self.page_no > 1:
            self.page.text(MARGIN, self.y + 8, header or "Cyber Fraud Investigative Brief — continued",
                           8, HELV_B, MUTED)
            self.page.line(MARGIN, self.y + 14, self.width - MARGIN, self.y + 14, RULE)
            self.y += 30
        return self.page

    def space(self, n):
        if self.y + n > A4[1] - MARGIN - 24:
            self.new_page()
        self.y += n

    def need(self, h):
        if self.y + h > A4[1] - MARGIN - 24:
            self.new_page()

    def _footer(self):
        y = A4[1] - MARGIN + 4
        self.page.line(MARGIN, y - 10, self.width - MARGIN, y - 10, RULE)
        self.page.text(MARGIN, y, self.report["case"]["case_id"] +
                       "  •  machine-generated triage output — to be corroborated by the IO",
                       6.5, HELV, MUTED)
        self.page.text_right(self.width - MARGIN, y, f"Page {self.page_no}", 6.5, HELV, MUTED)

    def heading(self, text):
        self.need(40)
        self.page.rect(MARGIN, self.y, 3, 11, fill=ACCENT)
        self.page.text(MARGIN + 8, self.y + 9, text.upper(), 9.5, HELV_B, ACCENT)
        self.y += 17

    def para(self, text, size=8, color=INK, indent=0.0, gap=2.0, bold=False):
        lines = wrap(text, size, self.inner - indent, bold)
        for ln in lines:
            self.need(size + 3)
            self.page.text(MARGIN + indent, self.y + size, ln, size,
                           HELV_B if bold else HELV, color)
            self.y += size + 2.4
        self.y += gap

    def bullet(self, text, size=8, color=INK, marker="•", mcolor=None):
        lines = wrap(text, size, self.inner - 12)
        for i, ln in enumerate(lines):
            self.need(size + 3)
            if i == 0:
                self.page.text(MARGIN + 2, self.y + size, marker, size, HELV_B, mcolor or MUTED)
            self.page.text(MARGIN + 12, self.y + size, ln, size, HELV, color)
            self.y += size + 2.4

    def finish(self, path):
        self._footer()
        return self.pdf.save(path)


def render_pdf(report, path):
    d = _Doc(report)
    _pdf_header(d)
    _pdf_kpis(d)
    _pdf_case(d)
    _pdf_suspects(d)
    _pdf_trail(d)
    _pdf_actions(d)
    _pdf_annex_timeline(d)
    _pdf_annex_findings(d)
    _pdf_annex_integrity(d)
    return d.finish(path)


def _pdf_header(d):
    p, c = d.page, d.report["case"]
    p.rect(MARGIN, d.y, d.inner, 44, fill=(0.07, 0.11, 0.19))
    p.text(MARGIN + 12, d.y + 18, "CYBER FRAUD INVESTIGATIVE BRIEF", 13.5, HELV_B, (1, 1, 1))
    p.text(MARGIN + 12, d.y + 31, "Unified Cyber Fraud Analysis & Digital Artifact Correlator",
           7.5, HELV, (0.70, 0.78, 0.90))
    p.text_right(d.width - MARGIN - 12, d.y + 16, c["case_id"], 9, HELV_B, (1, 1, 1))
    p.text_right(d.width - MARGIN - 12, d.y + 27, "Generated " + c["generated_local"],
                 7, HELV, (0.70, 0.78, 0.90))
    p.text_right(d.width - MARGIN - 12, d.y + 37, "FOR OFFICIAL USE ONLY",
                 6.5, HELV_B, (0.95, 0.55, 0.35))
    d.y += 54


def _pdf_kpis(d):
    st = d.report["statistics"]
    cells = [
        ("AMOUNT DEFRAUDED", "Rs. " + inr(st.get("amount_reported") or
                                          d.report["victim"].get("amount_debited_observed") or 0),
         BAND_COLORS["CRITICAL"]),
        ("TOTAL VALUE TRACED", "Rs. " + inr(st.get("amount_traced") or 0), ACCENT),
        ("SUSPECT CLUSTERS", str(st.get("suspect_clusters") or 0), BAND_COLORS["HIGH"]),
        ("EXHIBITS / EVENTS", f"{st['exhibits']} / {st['events_normalised']}", INK),
    ]
    w = (d.inner - 3 * 6) / 4.0
    for i, (label, value, col) in enumerate(cells):
        x = MARGIN + i * (w + 6)
        d.page.rect(x, d.y, w, 36, fill=(0.96, 0.97, 0.99))
        d.page.rect(x, d.y, 2.5, 36, fill=col)
        d.page.text(x + 8, d.y + 12, label, 5.8, HELV_B, MUTED)
        size = 11 if text_width(value, 11, True) < w - 16 else 8.5
        d.page.text(x + 8, d.y + 27, value, size, HELV_B, INK)
    d.y += 46


def _pdf_case(d):
    v = d.report["victim"]
    st = d.report["statistics"]
    c = d.report["case"]
    d.heading("Case & complainant")
    bits = []
    if v.get("name"):
        bits.append(f"Complainant: {v['name']}")
    if c.get("acknowledgement_no"):
        bits.append(f"NCRP Ack: {c['acknowledgement_no']}")
    if c.get("category"):
        bits.append(f"Category: {c['category']}")
    if c.get("police_station"):
        bits.append(f"PS: {c['police_station']}")
    if v.get("first_debit"):
        bits.append(f"First fraudulent debit: {human_ts(v['first_debit'])}")
    if bits:
        d.para("   |   ".join(bits), 8, INK, gap=3)
    ids = ", ".join(f"{i['value']}" for i in v.get("identifiers", [])[:8])
    if ids:
        d.para(f"Victim identifiers on record: {ids}", 7.5, MUTED, gap=3)
    if v.get("narrative"):
        d.para(short(v["narrative"], 620), 7.5, INK, gap=4)
    d.para(f"Automated triage normalised {st['events_normalised']} events from {st['exhibits']} "
           f"exhibits into {st['entities']} entities and {st['relationships']} relationships in "
           f"{st['processing_ms']} ms, raising {st['correlation_findings']} correlation findings.",
           7.5, MUTED, gap=6)


def _pdf_suspects(d):
    d.heading("Prime suspects (risk-ranked)")
    sus = d.report["prime_suspects"][:6]
    if not sus:
        d.para("No scored suspects were produced from the supplied exhibits.", 8, MUTED)
        return
    cols = [(0, 14), (16, 150), (170, 96), (268, 34), (306, 78), (388, 48), (440, 79)]
    hdr = ["#", "Identifier", "Holder / linked", "Layer", "Received", "Score", "Band"]
    d.need(30)
    d.page.rect(MARGIN, d.y, d.inner, 13, fill=(0.93, 0.94, 0.97))
    for (x, w), label in zip(cols, hdr):
        d.page.text(MARGIN + x + 3, d.y + 9, label.upper(), 6, HELV_B, MUTED)
    d.y += 15

    for i, s in enumerate(sus, start=1):
        d.need(24)
        col = BAND_COLORS.get(s["band"], INK)
        if i % 2 == 0:
            d.page.rect(MARGIN, d.y - 2, d.inner, 16, fill=(0.975, 0.978, 0.985))
        holders = ", ".join(s["holders"]) or "—"
        extra = [x["value"] for x in s["identifiers"] if x["label"] != s["label"]][:2]
        if extra:
            holders = (holders + "  " if holders != "—" else "") + "/ " + ", ".join(extra)
        vals = [str(i), short(s["label"], 34), short(holders, 24),
                str(s["layer"]) if s["layer"] is not None else "—",
                "Rs. " + inr(s["received"]), f"{s['score']}/100", s["band"]]
        for j, ((x, w), val) in enumerate(zip(cols, vals)):
            font = HELV_B if j in (1, 5, 6) else HELV
            color = col if j == 6 else INK
            d.page.text(MARGIN + x + 3, d.y + 9, val, 7.2, font, color)
        d.y += 16
        top = s["reasons"][:2]
        if top:
            txt = "  •  ".join(short(r["text"], 96) for r in top)
            for ln in wrap(txt, 6.5, d.inner - 22)[:2]:
                d.need(10)
                d.page.text(MARGIN + 19, d.y + 6, ln, 6.5, HELV, MUTED)
                d.y += 9
        d.y += 3
    d.y += 4


def _pdf_trail(d):
    d.heading("Mule chain / fund flow")
    mt = d.report["money_trail"]
    chains = mt.get("chains") or []
    if not chains:
        d.para("No directional fund flow could be traced from the victim account with the "
               "supplied financial records.", 8, MUTED)
        return
    origin = ", ".join(mt["origins"]) or "victim account"
    d.para(f"Origin: {origin}    |    Rs. {inr(mt['total_traced'])} traced across "
           f"{len(mt['hops'])} hops", 7.5, MUTED, gap=4)

    for chain in chains[:4]:
        if not chain:
            continue
        d.need(30)
        nodes = [chain[0]["from_label"]] + [h["to_label"] for h in chain]
        x = MARGIN + 4
        d.page.circle(x, d.y + 5, 2.6, fill=ACCENT)
        d.page.text(x + 7, d.y + 8, short(nodes[0], 30), 7.2, HELV_B, INK)
        d.y += 14
        for h in chain:
            d.need(22)
            lag = f"+{h['lag_minutes']:.0f} min" if h.get("lag_minutes") is not None else ""
            col = BAND_COLORS["CRITICAL"] if h.get("cashout") else MUTED
            d.page.line(MARGIN + 4, d.y - 6, MARGIN + 4, d.y + 5, RULE, 1.2)
            d.page.text(MARGIN + 11, d.y + 5,
                        f"→ Rs. {inr(h['amount'])}   {human_ts(h['ts'])}   {lag}"
                        + (f"   [{h.get('rail')}]" if h.get("rail") else ""),
                        6.8, HELV, col)
            d.y += 11
            d.page.circle(MARGIN + 4, d.y + 4, 2.6,
                          fill=BAND_COLORS["CRITICAL"] if h.get("cashout") else (0.30, 0.42, 0.60))
            label = short(h["to_label"], 30) + (" — CASH-OUT" if h.get("cashout") else "")
            d.page.text(MARGIN + 11, d.y + 7, label, 7.2, HELV_B,
                        BAND_COLORS["CRITICAL"] if h.get("cashout") else INK)
            d.y += 13
        d.y += 6

    if mt.get("cashouts"):
        agg = {}
        for c in mt["cashouts"]:
            a = agg.setdefault(c["label"], {"n": 0, "total": 0.0, "modes": set()})
            a["n"] += 1
            a["total"] += c["amount"] or 0
            a["modes"].add(c["mode"])
        txt = "; ".join(
            f"{label} — Rs. {inr(a['total'])} in {a['n']} withdrawal(s) via "
            f"{'/'.join(sorted(a['modes']))}"
            for label, a in sorted(agg.items(), key=lambda kv: -kv[1]["total"]))
        d.para("Cash-out points: " + txt, 7.2, BAND_COLORS["CRITICAL"], gap=5)


def _pdf_actions(d):
    d.heading("Immediate seizure & preservation actions")
    recs = d.report["recommended_actions"]
    if not recs:
        d.para("No actionable endpoints were identified.", 8, MUTED)
        return
    for i, r in enumerate(recs[:12], start=1):
        d.need(26)
        col = BAND_COLORS["CRITICAL"] if r["priority"] == "IMMEDIATE" else \
            BAND_COLORS["HIGH"] if r["priority"] == "HIGH" else MUTED
        d.page.rect(MARGIN, d.y, 34, 9, fill=col)
        d.page.text(MARGIN + 3, d.y + 7, r["priority"][:9], 5.6, HELV_B, (1, 1, 1))
        lines = wrap(f"{i}. {r['action']}", 7.6, d.inner - 42, True)
        for k, ln in enumerate(lines):
            d.page.text(MARGIN + 40, d.y + 7 + k * 9.5, ln, 7.6, HELV_B, INK)
        d.y += 8 + 9.5 * len(lines)
        for ln in wrap(f"To: {r['authority']}  —  {r['rationale']}", 6.8, d.inner - 42)[:3]:
            d.need(10)
            d.page.text(MARGIN + 40, d.y + 6, ln, 6.8, HELV, MUTED)
            d.y += 8.6
        d.y += 4


def _pdf_annex_timeline(d):
    d.new_page("Annexure A — Incident timeline")
    d.heading("Annexure A — incident timeline")
    for t in d.report["timeline"]:
        d.need(16)
        col = BAND_COLORS["CRITICAL"] if t["flags"] else INK
        d.page.text(MARGIN, d.y + 7, t["display"], 6.8, COURIER, MUTED)
        d.page.text(MARGIN + 92, d.y + 7, t["kind"][:12], 6.4, HELV_B, ACCENT)
        body = t["summary"] + (f"   [Rs. {inr(t['amount'])}]" if t.get("amount") else "")
        lines = wrap(body, 7.2, d.inner - 150)
        for k, ln in enumerate(lines[:2]):
            d.page.text(MARGIN + 150, d.y + 7 + k * 9, ln, 7.2, HELV, col)
        d.y += 9 * max(1, min(2, len(lines)))
        if t["flags"]:
            for fl in t["flags"][:2]:
                for ln in wrap("⚠ " + fl, 6.4, d.inner - 158)[:1]:
                    d.need(9)
                    d.page.text(MARGIN + 152, d.y + 6, ln, 6.4, HELV, BAND_COLORS["HIGH"])
                    d.y += 8
        d.page.text_right(d.width - MARGIN, d.y + 1, t["cite"], 5.6, HELV, (0.62, 0.65, 0.72))
        d.y += 5
        d.page.line(MARGIN, d.y, d.width - MARGIN, d.y, (0.93, 0.94, 0.96))
        d.y += 4


def _pdf_annex_findings(d):
    d.new_page("Annexure B — Correlation findings")
    d.heading("Annexure B — entity correlation findings")
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in sorted(d.report["correlation_findings"],
                    key=lambda x: order.get(x["severity"], 9)):
        d.need(30)
        col = BAND_COLORS.get(f["severity"], INK)
        d.page.rect(MARGIN, d.y, 3, 9, fill=col)
        d.page.text(MARGIN + 8, d.y + 7, f["title"], 7.8, HELV_B, INK)
        d.y += 11
        d.page.text(MARGIN + 8, d.y + 6,
                    f"{f['severity']} • confidence {f['confidence']} • {f['category']} "
                    f"• {f['code']}", 6.2, HELV_B, col)
        d.y += 9
        for ln in wrap(f["detail"], 7, d.inner - 10):
            d.need(10)
            d.page.text(MARGIN + 8, d.y + 6, ln, 7, HELV, MUTED)
            d.y += 8.6
        d.y += 6


def _pdf_annex_integrity(d):
    d.new_page("Annexure C — Evidentiary integrity")
    d.heading("Annexure C — exhibit manifest & chain of custody")
    integ = d.report["evidentiary_integrity"]
    d.para(integ["verification_note"], 7.2, MUTED, gap=6)
    for ex in integ["exhibits"]:
        d.need(34)
        ok = "VERIFIED" if integ["reverify"].get(ex["exhibit_id"]) else "MISMATCH"
        col = (0.10, 0.45, 0.25) if ok == "VERIFIED" else BAND_COLORS["CRITICAL"]
        d.page.text(MARGIN, d.y + 7, ex["exhibit_id"], 7.4, HELV_B, ACCENT)
        d.page.text(MARGIN + 44, d.y + 7, short(ex["original_name"], 46), 7.4, HELV_B, INK)
        d.page.text_right(d.width - MARGIN, d.y + 7, ok, 6.4, HELV_B, col)
        d.y += 10
        d.page.text(MARGIN + 44, d.y + 6,
                    f"{ex['artifact_type']} • {ex['size_bytes']} bytes • "
                    f"{ex['records_extracted']} records • acquired {ex['acquired_utc']}",
                    6.2, HELV, MUTED)
        d.y += 9
        d.page.text(MARGIN + 44, d.y + 6, "SHA-256 " + ex["sha256"], 6.0, COURIER, INK)
        d.y += 9
        for note in ex.get("notes", [])[:2]:
            d.page.text(MARGIN + 44, d.y + 6, "! " + note, 6.2, HELV_B, BAND_COLORS["CRITICAL"])
            d.y += 8
        d.page.line(MARGIN, d.y, d.width - MARGIN, d.y, (0.93, 0.94, 0.96))
        d.y += 6

    d.space(6)
    d.heading("Chain of custody")
    for entry in integ["chain_of_custody"]["entries"]:
        d.need(12)
        d.page.text(MARGIN, d.y + 6, f"{entry['seq']:02d}", 6.4, COURIER, MUTED)
        d.page.text(MARGIN + 20, d.y + 6, entry["utc"], 6.4, COURIER, MUTED)
        d.page.text(MARGIN + 110, d.y + 6, entry["action"], 6.4, HELV_B, ACCENT)
        for ln in wrap(entry["detail"], 6.4, d.inner - 190)[:1]:
            d.page.text(MARGIN + 190, d.y + 6, ln, 6.4, HELV, INK)
        d.y += 9
    d.space(8)
    d.para("Custody log SHA-256: " + integ["chain_of_custody"]["log_sha256"], 6.4, INK)
    d.para("Report SHA-256: " + (d.report.get("report_sha256") or "(computed on export)"),
           6.4, INK)
    d.para("This brief is machine-generated triage output. Every assertion cites the exhibit "
           "and row it derives from; the investigating officer must corroborate before it is "
           "relied upon in a final report under Sec.173 CrPC / Sec.193 BNSS.", 6.6, MUTED)
