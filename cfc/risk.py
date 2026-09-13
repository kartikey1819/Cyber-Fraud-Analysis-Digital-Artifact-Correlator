"""Triage and risk scoring.

Every point added to an entity carries a human-readable reason and the event
ids that justify it, so the dashboard and the brief can always answer the
question a defence counsel will ask: *why is this account marked a mule?*

Scores are additive-with-saturation and capped at 100.  No black-box model is
used: the heuristics below are the ones an experienced cyber-cell IO applies by
hand, encoded so they run in seconds over bulk logs.
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict

from . import model as M
from .correlate import FINANCIAL_TYPES, layer_of

# Types that can head a suspect entry.  A handset or an APK is evidence to be
# seized, not a person to be arrested -- those surface as findings and as
# seizure recommendations instead.
ACTOR_TYPES = (M.ACCOUNT, M.UPI, M.PHONE, M.EMAIL, M.PERSON)
from .util import human_ts, inr, minutes_between, parse_ts

BANDS = [(75, "CRITICAL"), (55, "HIGH"), (35, "MEDIUM"), (0, "LOW")]

# heuristic weights (documented in FORENSICS.md)
W = {
    "PASS_THROUGH": 18,
    "LAYER_30": 22,
    "LAYER_60": 15,
    "LAYER_180": 8,
    "FAN_OUT": 12,
    "CASH_OUT": 16,
    "CRYPTO_OUT": 18,
    "STRUCTURING": 12,
    "NIGHT_OPS": 8,
    "VELOCITY": 10,
    "IN_TRAIL": 8,
    "PRE_TXN_CONTACT": 20,
    "LURE_SENDER": 14,
    "SPOOFED_HEADER": 16,
    "MALWARE_HOST": 14,
    "ROUND_SUM": 5,
}


def band(score):
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "LOW"


class Reason:
    __slots__ = ("code", "points", "text", "evidence")

    def __init__(self, code, points, text, evidence=None):
        self.code = code
        self.points = points
        self.text = text
        self.evidence = evidence or []

    def to_dict(self):
        return {"code": self.code, "points": self.points, "text": self.text,
                "evidence": self.evidence}


def score(g, events, findings, trail, clusters, node_to_cluster):
    """Score every entity.  Returns (scores_by_node, suspects, victim_context)."""
    by_id = {e.id: e for e in events}
    reasons = defaultdict(list)

    ctx = _victim_context(g, events)
    layers = layer_of(trail)

    _score_from_findings(g, findings, reasons)
    _score_financial(g, events, trail, layers, reasons)
    _score_telecom(g, events, ctx, reasons)
    _score_content(g, events, reasons)

    scores = {}
    for nid, rs in reasons.items():
        node = g.nodes.get(nid)
        if node is None:
            continue
        total = sum(r.points for r in rs)
        # saturating cap keeps one noisy rule from pinning everything at 100
        value = int(round(100 * (1 - pow(2.718281828, -total / 55.0))))
        value = min(100, max(0, value))
        if node["victim"]:
            value = min(value, 20)
        elif node.get("probable_victim"):
            value = min(value, 25)
        scores[nid] = {
            "node": nid,
            "score": value,
            "raw": total,
            "band": band(value),
            "layer": layers.get(nid),
            "reasons": [r.to_dict() for r in sorted(rs, key=lambda r: -r.points)],
        }
    for nid, node in g.nodes.items():
        scores.setdefault(nid, {"node": nid, "score": 0, "raw": 0, "band": "LOW",
                                "layer": layers.get(nid), "reasons": []})

    suspects = _rank_suspects(g, scores, clusters, node_to_cluster, trail)
    return scores, suspects, ctx


# --------------------------------------------------------------------------

def _victim_context(g, events):
    """Anchor facts: who the victim is and when the money started moving."""
    victim_fin = [n["id"] for n in g.nodes.values()
                  if n["victim"] and n["type"] in FINANCIAL_TYPES]
    victim_phone = [n["id"] for n in g.nodes.values()
                    if n["victim"] and n["type"] == M.PHONE]
    complaint = next((e for e in events if e.kind == M.COMPLAINT), None)

    # A victim's statement also contains ordinary spending.  Only debits inside
    # the reported incident window, and material relative to the reported loss,
    # count as the fraud -- otherwise a grocery payment becomes "the first
    # fraudulent debit".
    window_start = None
    floor = 0.0
    if complaint is not None:
        if complaint.ts:
            window_start = complaint.ts - dt.timedelta(hours=6)
        if complaint.amount:
            floor = complaint.amount * 0.02

    first_debit, debit_events = None, []
    for ev in events:
        if ev.kind != M.TXN or ev.direction != "DR" or not ev.amount:
            continue
        if window_start and ev.ts and ev.ts < window_start:
            continue
        if floor and ev.amount < floor:
            continue
        touches = any(f"{e['type']}|{e['value']}" in victim_fin for e in ev.entities)
        if touches:
            debit_events.append(ev)
            if ev.ts and (first_debit is None or ev.ts < first_debit):
                first_debit = ev.ts
    # The same debit may be recorded in both banks' statements; count it once.
    seen_debits, unique_debits = set(), []
    for e in debit_events:
        key = (round(e.amount, 2), e.ts.strftime("%Y%m%d%H%M") if e.ts else e.id)
        if key in seen_debits:
            continue
        seen_debits.add(key)
        unique_debits.append(e)
    debit_events = unique_debits
    total_out = sum(e.amount for e in debit_events if e.amount)
    return {
        "victim_financial": victim_fin,
        "victim_phone": victim_phone,
        "complaint": complaint.to_dict() if complaint else None,
        "first_debit": first_debit,
        "fraud_debits": [e.id for e in debit_events],
        "amount_defrauded": round(total_out, 2) if total_out else (
            complaint.amount if complaint else 0.0),
    }


# A finding that the engine itself rates as uncertain must not push an entity
# into the CRITICAL band on its own.
CONFIDENCE_WEIGHT = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3}


def _score_from_findings(g, findings, reasons):
    for f in findings:
        if f.score <= 0:
            continue
        targets = [e for e in f.entities if e in g.nodes][:8]
        for nid in targets:
            node = g.nodes[nid]
            pts = f.score * CONFIDENCE_WEIGHT.get(f.confidence, 1.0)
            # infrastructure nodes carry the finding but score lower than actors
            if node["type"] in (M.CELL, M.DOMAIN, M.IP):
                pts = max(2.0, pts / 2)
            reasons[nid].append(Reason(f.code, round(pts, 1), f.title, f.evidence))


def _score_financial(g, events, trail, layers, reasons):
    txns = [e for e in events if e.kind == M.TXN and e.amount
            and not e.attrs.get("corroborated")]
    by_node_out = defaultdict(list)
    by_node_in = defaultdict(list)
    for ev in txns:
        flow = ev.attrs.get("flow") or {}
        flow_node = flow.get("node")
        # a cash withdrawal has no counterparty node but is still an outflow
        if flow_node:
            (by_node_out if flow.get("direction") == "DR" else by_node_in)[flow_node].append(ev)
        for ln in ev.links:
            if ln["rel"] != "FUNDS":
                continue
            if ln["src"] != flow_node:
                by_node_out[ln["src"]].append(ev)
            if ln["dst"] != flow_node:
                by_node_in[ln["dst"]].append(ev)

    cashout_nodes = defaultdict(list)
    for c in trail["cashouts"]:
        cashout_nodes[c["node"]].append(c)

    for nid, node in g.nodes.items():
        if node["type"] not in FINANCIAL_TYPES or node["victim"]:
            continue
        outs = by_node_out.get(nid, [])
        ins = by_node_in.get(nid, [])
        in_amt, out_amt = node["in_amount"], node["out_amount"]

        if nid in layers and layers[nid] > 0:
            reasons[nid].append(Reason(
                "IN_TRAIL", W["IN_TRAIL"],
                f"Sits at layer {layers[nid]} of the traced fund flow from the victim",
                [h["event"] for h in trail["hops"] if h["to"] == nid][:4]))

        # 1. pass-through / low retention
        if in_amt > 0 and out_amt > 0:
            ratio = out_amt / in_amt
            if ratio >= 0.75:
                retained = max(0.0, in_amt - out_amt)
                reasons[nid].append(Reason(
                    "PASS_THROUGH", W["PASS_THROUGH"],
                    f"Pass-through account: ₹{inr(in_amt)} in, ₹{inr(out_amt)} out "
                    f"({ratio * 100:.0f}% forwarded, only ₹{inr(retained)} retained)",
                    [e.id for e in outs[:4]]))

        # 2. layering latency -- how fast money left after it arrived
        lag = _min_forward_lag(ins, outs)
        if lag is not None:
            if lag <= 30:
                reasons[nid].append(Reason(
                    "LAYER_30", W["LAYER_30"],
                    f"Immediate multi-hop routing: funds moved onward {lag:.0f} minutes "
                    "after credit", [e.id for e in outs[:3]]))
            elif lag <= 60:
                reasons[nid].append(Reason(
                    "LAYER_60", W["LAYER_60"],
                    f"Rapid layering: onward transfer {lag:.0f} minutes after credit",
                    [e.id for e in outs[:3]]))
            elif lag <= 180:
                reasons[nid].append(Reason(
                    "LAYER_180", W["LAYER_180"],
                    f"Same-session layering: onward transfer {lag / 60:.1f} hours after credit",
                    [e.id for e in outs[:3]]))

        # 3. fan-out to multiple downstream endpoints
        dsts = {ln["dst"] for e in outs for ln in e.links
                if ln["rel"] == "FUNDS" and ln["src"] == nid}
        if len(dsts) >= 3:
            reasons[nid].append(Reason(
                "FAN_OUT", W["FAN_OUT"],
                f"Splits funds onward to {len(dsts)} distinct beneficiaries "
                "— classic layering fan-out", [e.id for e in outs[:4]]))

        # 4. cash-out / crypto exit
        for c in cashout_nodes.get(nid, []):
            code = "CRYPTO_OUT" if c["mode"].startswith("CRYPTO") else "CASH_OUT"
            reasons[nid].append(Reason(
                code, W[code],
                f"Terminal {c['mode']} exit of ₹{inr(c['amount'])} on {human_ts(c['ts'])}"
                + (f" — '{c['narration']}'" if c.get("narration") else ""),
                [c["event"]]))

        # 5. structuring just under reporting/limit thresholds
        amounts = [e.amount for e in outs if e.amount]
        near = [a for a in amounts if 40000 <= a < 50000 or 90000 <= a < 100000
                or 190000 <= a < 200000]
        if len(near) >= 3:
            reasons[nid].append(Reason(
                "STRUCTURING", W["STRUCTURING"],
                f"{len(near)} outward transfers sit just below a round reporting threshold "
                f"(e.g. ₹{inr(near[0])}) — indicative of deliberate structuring",
                [e.id for e in outs[:4]]))
        repeats = defaultdict(int)
        for a in amounts:
            repeats[round(a, 2)] += 1
        if any(c >= 3 for c in repeats.values()):
            top = max(repeats.items(), key=lambda kv: kv[1])
            reasons[nid].append(Reason(
                "ROUND_SUM", W["ROUND_SUM"],
                f"Repeated identical transfer amount ₹{inr(top[0])} x{top[1]}",
                [e.id for e in outs[:3]]))

        # 6. nocturnal operation
        stamped = [e for e in (outs + ins) if e.ts]
        night = [e for e in stamped if 0 <= e.ts.hour < 5]
        if len(stamped) >= 3 and len(night) / len(stamped) >= 0.4:
            reasons[nid].append(Reason(
                "NIGHT_OPS", W["NIGHT_OPS"],
                f"{len(night)} of {len(stamped)} transactions executed between 00:00 and 05:00",
                [e.id for e in night[:3]]))

        # 7. burst velocity
        burst = _max_burst(stamped, window_min=60)
        if burst >= 4:
            reasons[nid].append(Reason(
                "VELOCITY", W["VELOCITY"],
                f"{burst} transactions inside a single 60-minute window",
                [e.id for e in stamped[:4]]))


def _min_forward_lag(ins, outs):
    """Smallest gap between a credit and the next debit (minutes)."""
    best = None
    ins_ts = sorted(e.ts for e in ins if e.ts)
    outs_ts = sorted(e.ts for e in outs if e.ts)
    for i in ins_ts:
        for o in outs_ts:
            if o >= i:
                gap = (o - i).total_seconds() / 60.0
                if best is None or gap < best:
                    best = gap
                break
    return best


def _max_burst(events, window_min=60):
    stamps = sorted(e.ts for e in events if e.ts)
    best, j = 0, 0
    for i, t in enumerate(stamps):
        while (t - stamps[j]).total_seconds() / 60.0 > window_min:
            j += 1
        best = max(best, i - j + 1)
    return best


def _score_telecom(g, events, ctx, reasons):
    first_debit = ctx["first_debit"]
    victim_phones = {nid.split("|", 1)[1] for nid in ctx["victim_phone"]}
    if not first_debit or not victim_phones:
        return
    window_start = first_debit - dt.timedelta(minutes=180)
    for ev in events:
        if ev.kind not in (M.CALL, M.SMS) or not ev.ts:
            continue
        if not (window_start <= ev.ts <= first_debit):
            continue
        parties = [e for e in ev.entities if e["type"] == M.PHONE]
        values = {p["value"] for p in parties}
        if not (values & victim_phones):
            continue
        for p in parties:
            if p["value"] in victim_phones:
                continue
            nid = f"{M.PHONE}|{p['value']}"
            if nid not in g.nodes:
                continue
            mins = minutes_between(ev.ts, first_debit)
            verb = "SMS" if ev.kind == M.SMS else "call"
            reasons[nid].append(Reason(
                "PRE_TXN_CONTACT", W["PRE_TXN_CONTACT"],
                f"Contacted the victim by {verb} at {human_ts(ev.ts)} — "
                f"{mins:.0f} minutes before the first fraudulent debit",
                [ev.id]))


def _score_content(g, events, reasons):
    for ev in events:
        lure = ev.attrs.get("lure_score") or 0
        if lure >= 40:
            for ent in ev.entities:
                if ent["type"] in (M.PHONE, M.EMAIL, M.PERSON) and \
                        ent.get("role") in ("a_party", "sender", "sms_peer", "chat_sender"):
                    nid = f"{ent['type']}|{ent['value']}"
                    if nid in g.nodes:
                        hits = ", ".join(ev.attrs.get("lure_hits", [])[:4])
                        reasons[nid].append(Reason(
                            "LURE_SENDER", W["LURE_SENDER"],
                            f"Sent social-engineering content (lure score {lure}"
                            + (f"; phrases: {hits}" if hits else "") + ")",
                            [ev.id]))
        if ev.kind == M.EMAIL_MSG:
            spoof = [f for f in ev.flags if "spoof" in f.lower() or "authentication failed" in f.lower()
                     or "mismatch" in f.lower()]
            if spoof:
                for ent in ev.entities:
                    if ent["type"] == M.EMAIL and ent.get("role") == "sender":
                        nid = f"{M.EMAIL}|{ent['value']}"
                        if nid in g.nodes:
                            reasons[nid].append(Reason(
                                "SPOOFED_HEADER", W["SPOOFED_HEADER"],
                                "Forged sender headers: " + "; ".join(spoof[:2]), [ev.id]))
        if ev.kind == M.APP and (ev.attrs.get("apk_risk") or 0) >= 55:
            for ent in ev.entities:
                if ent["type"] == M.APK:
                    nid = f"{M.APK}|{ent['value']}"
                    if nid in g.nodes:
                        reasons[nid].append(Reason(
                            "MALWARE_HOST", W["MALWARE_HOST"],
                            "Malicious-capability package: " +
                            "; ".join(ev.attrs.get("apk_reasons", [])[:2]), [ev.id]))


# --------------------------------------------------------------------------

def _rank_suspects(g, scores, clusters, node_to_cluster, trail):
    """Roll node scores up to actor clusters and rank them."""
    bucket = defaultdict(list)
    for nid, s in scores.items():
        if s["score"] <= 0:
            continue
        node = g.nodes[nid]
        if node["victim"] or node.get("probable_victim"):
            continue
        cid = node_to_cluster.get(nid, nid)
        bucket[cid].append(nid)

    suspects = []
    for cid, members in bucket.items():
        cluster = clusters.get(cid)
        member_ids = cluster["members"] if cluster else members
        member_ids = [m for m in member_ids if m in g.nodes and not g.nodes[m]["victim"]]
        if not member_ids:
            continue
        member_ids = [m for m in member_ids if not g.nodes[m].get("probable_victim")]
        actor_ids = [m for m in member_ids if g.nodes[m]["type"] in ACTOR_TYPES]
        if not actor_ids:
            continue
        top = max(actor_ids, key=lambda m: scores.get(m, {}).get("score", 0))
        best = max(scores.get(m, {}).get("score", 0) for m in actor_ids)
        if best <= 0:
            continue
        # An actor's money is usually visible on two rails (bank account and the
        # VPA mapped to it).  Summing both would double the turnover, so the
        # account rail wins where it exists.
        accounts = [m for m in member_ids if g.nodes[m]["type"] == M.ACCOUNT]
        money_nodes = accounts or [m for m in member_ids
                                   if g.nodes[m]["type"] in FINANCIAL_TYPES]
        received = sum(g.nodes[m]["in_amount"] for m in money_nodes)
        sent = sum(g.nodes[m]["out_amount"] for m in money_nodes)
        holders = sorted({g.nodes[m]["meta"].get("holder") for m in member_ids} - {None})
        layer = min([scores[m]["layer"] for m in member_ids
                     if scores.get(m, {}).get("layer") is not None] or [None],
                    default=None)
        reasons = []
        seen_codes = set()
        for m in sorted(member_ids, key=lambda m: -scores.get(m, {}).get("score", 0)):
            for r in scores.get(m, {}).get("reasons", []):
                if r["code"] in seen_codes:
                    continue
                seen_codes.add(r["code"])
                reasons.append(r)
        suspects.append({
            "id": cid,
            "primary": top,
            "label": g.nodes[top]["label"],
            "holders": holders,
            "members": sorted(member_ids, key=lambda m: -scores.get(m, {}).get("score", 0)),
            "score": best,
            "band": band(best),
            "layer": layer,
            "received": round(received, 2),
            "sent": round(sent, 2),
            "retained": round(received - sent, 2),
            "reasons": reasons[:10],
            "types": sorted({g.nodes[m]["type"] for m in member_ids}),
        })
    suspects.sort(key=lambda s: (-s["score"], -(s["received"] or 0)))
    return suspects
