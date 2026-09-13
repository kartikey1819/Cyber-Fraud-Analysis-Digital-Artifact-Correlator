"""Entity correlation engine: graph construction, identity resolution,
cross-artifact link detection and money-trail tracing.

Design note on false links
--------------------------
Identity *merging* is only performed across bindings that are one-to-one in the
source data (account<->VPA, account<->registered mobile, IMEI<->MAC on the same
extraction).  Weak signals -- a shared holder name, a masked account whose last
digits match -- are deliberately NOT merged; they are raised as separate
LOW-confidence findings for the IO to confirm.  This keeps the graph free of
the fabricated links that make a correlation report inadmissible.
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict

from . import model as M
from .model import Finding
from .util import human_ts, inr, is_private_ip, iso, minutes_between, subnet24

# relations that bind two identifiers to the same real-world actor
IDENTITY_RELS = {"LINKED_VPA", "REGISTERED_ON", "DEVICE_INTERFACE"}
FINANCIAL_TYPES = {M.ACCOUNT, M.UPI}


class Graph:
    def __init__(self):
        self.nodes = {}
        self.edges = {}

    # -- construction ------------------------------------------------------
    def node(self, node_id, etype=None, value=None):
        n = self.nodes.get(node_id)
        if n is None:
            n = {
                "id": node_id, "type": etype, "value": value,
                "roles": set(), "meta": {}, "events": [], "exhibits": set(),
                "first_seen": None, "last_seen": None,
                "in_amount": 0.0, "out_amount": 0.0,
                "in_count": 0, "out_count": 0,
                "victim": False, "reported": False, "probable_victim": False,
            }
            self.nodes[node_id] = n
        return n

    def observe(self, node_id, etype, value, role, meta, event):
        n = self.node(node_id, etype, value)
        if role:
            n["roles"].add(role)
        for k, v in (meta or {}).items():
            if v in (None, ""):
                continue
            if k == "victim":
                n["victim"] = True
            elif k == "reported":
                n["reported"] = True
            elif k not in n["meta"]:
                n["meta"][k] = v
        n["events"].append(event.id)
        if event.exhibit:
            n["exhibits"].add(event.exhibit)
        if event.ts:
            if n["first_seen"] is None or event.ts < n["first_seen"]:
                n["first_seen"] = event.ts
            if n["last_seen"] is None or event.ts > n["last_seen"]:
                n["last_seen"] = event.ts

    def edge(self, src, dst, rel, directed=True):
        key = (src, dst, rel) if directed else tuple(sorted((src, dst)) + [rel])
        e = self.edges.get(key)
        if e is None:
            e = {"key": "|".join(key), "src": src, "dst": dst, "rel": rel,
                 "directed": directed, "count": 0, "amount": 0.0, "corroborated": 0,
                 "events": [], "first": None, "last": None}
            self.edges[key] = e
        return e

    # -- queries -----------------------------------------------------------
    def neighbors(self, node_id, rels=None, direction="both"):
        out = set()
        for e in self.edges.values():
            if rels and e["rel"] not in rels:
                continue
            if e["src"] == node_id and direction in ("both", "out"):
                out.add(e["dst"])
            elif e["dst"] == node_id and (direction in ("both", "in") or not e["directed"]):
                out.add(e["src"])
        return out

    def by_type(self, etype):
        return [n for n in self.nodes.values() if n["type"] == etype]

    def fund_edges(self):
        return [e for e in self.edges.values() if e["rel"] == "FUNDS"]


def _txn_keys(ev):
    """Dedup keys for a financial event.

    The same transfer appears in BOTH banks' statements (a debit row in the
    remitter's and a credit row in the beneficiary's).  Counting it twice would
    double every mule's turnover, so events are matched on
    (source, destination, amount, minute) with a +/-1 minute tolerance for
    clock skew between the two institutions.
    """
    if ev.kind != M.TXN or not ev.amount:
        return [], []
    amt = round(abs(ev.amount), 2)
    pairs = [(ln["src"], ln["dst"]) for ln in ev.links if ln["rel"] == "FUNDS"]
    if not pairs:
        flow = ev.attrs.get("flow")
        if not flow or not flow.get("node"):
            return [], []
        pairs = [(flow["node"], "CASH" if flow["direction"] == "DR" else "SELF")]
    lookup, insert = [], []
    for src, dst in pairs:
        if ev.ts is None:
            key = (src, dst, amt, "")
            lookup.append(key)
            insert.append(key)
            continue
        insert.append((src, dst, amt, ev.ts.strftime("%Y%m%d%H%M")))
        for delta in (-1, 0, 1):
            t = ev.ts + dt.timedelta(minutes=delta)
            lookup.append((src, dst, amt, t.strftime("%Y%m%d%H%M")))
    return lookup, insert


def build_graph(events):
    """Fold the normalised event stream into an entity graph."""
    g = Graph()
    seen_txn = set()
    for ev in events:
        for ent in ev.entities:
            node_id = f"{ent['type']}|{ent['value']}"
            g.observe(node_id, ent["type"], ent["value"], ent.get("role"),
                      ent.get("meta"), ev)

        lookup, insert = _txn_keys(ev)
        duplicate = bool(lookup) and any(k in seen_txn for k in lookup)
        for k in insert:
            seen_txn.add(k)
        if duplicate:
            ev.attrs["corroborated"] = True
            ev.flag("Same transaction independently recorded in another exhibit "
                    "— corroborated, counted once")

        flow = ev.attrs.get("flow") or {}
        flow_node = flow.get("node")
        if not duplicate and flow_node in g.nodes and flow.get("amount"):
            n = g.nodes[flow_node]
            amt = abs(flow["amount"])
            if flow.get("direction") == "DR":
                n["out_amount"] += amt
                n["out_count"] += 1
            else:
                n["in_amount"] += amt
                n["in_count"] += 1

        for ln in ev.links:
            if ln["src"] not in g.nodes or ln["dst"] not in g.nodes:
                continue
            e = g.edge(ln["src"], ln["dst"], ln["rel"], ln.get("directed", True))
            e["count"] += 1
            amt = abs(ln.get("amount") or 0)
            if duplicate:
                e["corroborated"] += 1
            elif amt:
                e["amount"] += amt
            if len(e["events"]) < 200:
                e["events"].append(ev.id)
            if ev.ts:
                if e["first"] is None or ev.ts < e["first"]:
                    e["first"] = ev.ts
                if e["last"] is None or ev.ts > e["last"]:
                    e["last"] = ev.ts
            if ln["rel"] == "FUNDS" and amt and not duplicate:
                if ln["src"] != flow_node:
                    g.nodes[ln["src"]]["out_amount"] += amt
                    g.nodes[ln["src"]]["out_count"] += 1
                if ln["dst"] != flow_node:
                    g.nodes[ln["dst"]]["in_amount"] += amt
                    g.nodes[ln["dst"]]["in_count"] += 1
    for n in g.nodes.values():
        n["label"] = _label(n)
    return g


def _label(n):
    v = n["value"]
    t = n["type"]
    holder = n["meta"].get("holder")
    if t == M.ACCOUNT:
        disp = n["meta"].get("display") or v
        tail = str(v)[-4:] if not str(v).startswith("MASKED") else str(v)[-4:]
        base = f"A/c …{tail}"
        return f"{base} ({holder})" if holder else base
    if t == M.UPI:
        return v
    if t == M.IMEI:
        return f"IMEI …{str(v)[-6:]}"
    if t == M.IMSI:
        return f"IMSI …{str(v)[-6:]}"
    if t == M.PERSON:
        return str(v)
    if t == M.APK:
        return n["meta"].get("label") or str(v)
    return str(v)


# ==========================================================================
# identity clustering (union-find over one-to-one bindings)
# ==========================================================================

class _DSU:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def identity_clusters(g: Graph):
    """Group node ids into actor clusters using only high-confidence bindings."""
    dsu = _DSU()
    for nid in g.nodes:
        dsu.find(nid)
    for e in g.edges.values():
        if e["rel"] in IDENTITY_RELS:
            dsu.union(e["src"], e["dst"])
    clusters = defaultdict(list)
    for nid in g.nodes:
        clusters[dsu.find(nid)].append(nid)

    out = {}
    for root, members in clusters.items():
        fin = [m for m in members if g.nodes[m]["type"] in FINANCIAL_TYPES]
        if not fin and len(members) < 2:
            continue
        cid = "CL-" + root.replace("|", "-")[:28]
        holders = {g.nodes[m]["meta"].get("holder") for m in members}
        holders.discard(None)
        out[cid] = {
            "id": cid, "members": sorted(members), "root": root,
            "holders": sorted(holders),
            "victim": any(g.nodes[m]["victim"] for m in members),
            "financial": sorted(fin),
        }
    node_to_cluster = {}
    for cid, c in out.items():
        for m in c["members"]:
            node_to_cluster[m] = cid
    return out, node_to_cluster


# ==========================================================================
# correlation findings
# ==========================================================================

def _ev_ids(g, nodes, limit=8):
    ids = []
    for n in nodes:
        for e in g.nodes[n]["events"]:
            if e not in ids:
                ids.append(e)
            if len(ids) >= limit:
                return ids
    return ids


def correlate(g: Graph, events, node_to_cluster=None):
    """Run every cross-artifact correlation rule.  Returns list[Finding]."""
    by_id = {e.id: e for e in events}
    n2c = node_to_cluster or {}
    findings = []
    findings += _shared_handset(g)
    findings += _sim_velocity(g, by_id)
    findings += _handset_hopping(g)
    findings += _shared_ip(g, n2c)
    findings += _shared_subnet(g, n2c)
    findings += _shared_mac_device(g)
    findings += _recurring_beneficiary(g)
    findings += _apk_crossref(g, events)
    findings += _domain_pivot(g)
    findings += _name_collision(g, n2c)
    findings += _masked_candidates(g)
    findings += _phone_across_rails(g)
    findings += _additional_victims(g)
    seen, unique = set(), []
    for f in findings:
        if f.code in seen:
            continue
        seen.add(f.code)
        unique.append(f)
    return unique


def _shared_handset(g):
    out = []
    for imei in g.by_type(M.IMEI):
        phones = sorted(n for n in g.neighbors(imei["id"], {"USES_HANDSET"})
                        if g.nodes[n]["type"] == M.PHONE)
        if len(phones) < 2:
            continue
        nums = [g.nodes[p]["value"] for p in phones]
        out.append(Finding(
            code=f"SHARED-HANDSET-{imei['value'][-6:]}",
            title=f"{len(nums)} MSISDNs share handset IMEI …{imei['value'][-6:]}",
            detail=("The same physical handset (IMEI body " + imei["value"] + ") was used with "
                    f"{len(nums)} different subscriber numbers: " + ", ".join(nums) +
                    ". A single handset cycling multiple SIMs is the standard operating "
                    "pattern of a mule-SIM operator."),
            severity="HIGH" if len(nums) >= 3 else "MEDIUM",
            confidence="HIGH",
            category="DEVICE",
            entities=[imei["id"]] + phones,
            evidence=_ev_ids(g, [imei["id"]]),
            score=18 if len(nums) >= 3 else 12,
        ))
    return out


def _sim_velocity(g, by_id):
    out = []
    for imei in g.by_type(M.IMEI):
        sims = sorted(n for n in g.neighbors(imei["id"], {"SIM_IN_HANDSET"})
                      if g.nodes[n]["type"] == M.IMSI)
        phones = sorted(n for n in g.neighbors(imei["id"], {"USES_HANDSET"})
                        if g.nodes[n]["type"] == M.PHONE)
        distinct = len(set(sims)) or len(set(phones))
        if distinct < 3:
            continue
        stamps = []
        for n in sims + phones:
            for eid_ in g.nodes[n]["events"]:
                ev = by_id.get(eid_)
                if ev and ev.ts:
                    stamps.append(ev.ts)
        span_days = None
        if len(stamps) >= 2:
            span_days = (max(stamps) - min(stamps)).total_seconds() / 86400.0
        if span_days is not None and span_days > 30:
            continue
        window = f" within {span_days:.1f} days" if span_days is not None else ""
        out.append(Finding(
            code=f"SIM-VELOCITY-{imei['value'][-6:]}",
            title=f"High-velocity SIM switching on IMEI …{imei['value'][-6:]}",
            detail=(f"{distinct} distinct SIMs were observed in handset {imei['value']}"
                    f"{window}. Rapid SIM rotation on one handset is a recognised "
                    "indicator of a SIM-farm / mule-SIM handler rather than ordinary use."),
            severity="CRITICAL" if distinct >= 4 else "HIGH",
            confidence="HIGH",
            category="DEVICE",
            entities=[imei["id"]] + sims + phones,
            evidence=_ev_ids(g, [imei["id"]]),
            score=22 if distinct >= 4 else 16,
        ))
    return out


def _handset_hopping(g):
    out = []
    for ph in g.by_type(M.PHONE):
        imeis = sorted(n for n in g.neighbors(ph["id"], {"USES_HANDSET"})
                       if g.nodes[n]["type"] == M.IMEI)
        if len(imeis) < 2:
            continue
        out.append(Finding(
            code=f"HANDSET-HOP-{ph['value']}",
            title=f"MSISDN {ph['value']} moved across {len(imeis)} handsets",
            detail=("The subscriber number was observed in " + str(len(imeis)) +
                    " different handsets (" +
                    ", ".join(g.nodes[i]["value"] for i in imeis) +
                    "), consistent with a SIM being passed between operators."),
            severity="MEDIUM",
            confidence="HIGH",
            category="DEVICE",
            entities=[ph["id"]] + imeis,
            evidence=_ev_ids(g, [ph["id"]]),
            score=10,
        ))
    return out


def _actor_of(g, node_id):
    """Nearest 'meaningful' owner of an infrastructure node."""
    owners = []
    for e in g.edges.values():
        if e["dst"] == node_id and e["rel"] in ("USED_IP", "TXN_FROM_IP", "SENT_FROM_IP",
                                                "USED_DEVICE", "CONNECTED_TO"):
            owners.append(e["src"])
    return owners


def _distinct_actors(users, n2c):
    """Collapse identifiers that already resolve to one actor cluster."""
    return {n2c.get(u, u) for u in users}


def _shared_ip(g, n2c):
    out = []
    for ip in g.by_type(M.IP):
        if is_private_ip(ip["value"]):
            continue
        users = sorted({o for o in _actor_of(g, ip["id"])
                        if g.nodes[o]["type"] in (M.PHONE, M.ACCOUNT, M.UPI, M.EMAIL)})
        if len(users) < 2 or len(_distinct_actors(users, n2c)) < 2:
            continue
        if all(g.nodes[u]["victim"] for u in users):
            continue  # the victim's own handset and net-banking session
        labels = [g.nodes[u]["label"] for u in users]
        out.append(Finding(
            code=f"SHARED-IP-{ip['value']}",
            title=f"{len(users)} endpoints operated from the same public IP {ip['value']}",
            detail=("Public IP " + ip["value"] + " was used by: " + ", ".join(labels) +
                    ". Co-location of otherwise unrelated accounts on a single public IP "
                    "indicates a common operator console. Confirm with the ISP that the "
                    "address is not a shared CGNAT pool before relying on it."),
            severity="HIGH",
            confidence="MEDIUM",
            category="NETWORK",
            entities=[ip["id"]] + users,
            evidence=_ev_ids(g, [ip["id"]]),
            score=15,
        ))
    return out


def _shared_subnet(g, n2c):
    buckets = defaultdict(set)
    ip_of = defaultdict(set)
    for ip in g.by_type(M.IP):
        if is_private_ip(ip["value"]):
            continue
        sub = subnet24(ip["value"])
        if not sub:
            continue
        for o in _actor_of(g, ip["id"]):
            if g.nodes[o]["type"] in (M.PHONE, M.ACCOUNT, M.UPI, M.EMAIL):
                buckets[sub].add(o)
                ip_of[sub].add(ip["id"])
    out = []
    for sub, users in buckets.items():
        if len(users) < 2 or len(ip_of[sub]) < 2:
            continue
        if len(_distinct_actors(users, n2c)) < 2 or all(g.nodes[u]["victim"] for u in users):
            continue
        users = sorted(users)
        out.append(Finding(
            code=f"SHARED-SUBNET-{sub}",
            title=f"{len(users)} endpoints active in the same /24 subnet {sub}",
            detail=("Distinct endpoints (" + ", ".join(g.nodes[u]["label"] for u in users) +
                    ") connected from " + str(len(ip_of[sub])) + " addresses inside " + sub +
                    ". Adjacent addressing points to a single physical location or a single "
                    "leased block — a strong lead for a raid location, subject to ISP "
                    "confirmation of the allocation."),
            severity="MEDIUM",
            confidence="MEDIUM",
            category="NETWORK",
            entities=users + sorted(ip_of[sub]),
            evidence=_ev_ids(g, sorted(ip_of[sub])),
            score=12,
        ))
    return out


def _shared_mac_device(g):
    out = []
    for mac in g.by_type(M.MAC) + g.by_type(M.DEVICE):
        peers = sorted(g.neighbors(mac["id"], {"DEVICE_INTERFACE", "USED_DEVICE"}))
        actors = [p for p in peers if g.nodes[p]["type"] in (M.PHONE, M.UPI, M.ACCOUNT)]
        # A handset's own IMEIs share its MAC by definition; that is only
        # interesting when the same MAC turns up in a second extraction.
        imeis = [p for p in peers if g.nodes[p]["type"] == M.IMEI]
        if len({ex for p in imeis for ex in g.nodes[p]["exhibits"]}) > 1:
            actors += imeis
        if len(actors) < 2:
            continue
        out.append(Finding(
            code=f"SHARED-HW-{mac['type']}-{mac['value'][-8:]}",
            title=f"Hardware identifier {mac['value']} shared by {len(actors)} entities",
            detail=("The same " + ("MAC address" if mac["type"] == M.MAC else "device identifier") +
                    " appears against " + ", ".join(g.nodes[a]["label"] for a in actors) +
                    ". Hardware identifiers do not roam between genuinely separate users."),
            severity="HIGH",
            confidence="HIGH",
            category="DEVICE",
            entities=[mac["id"]] + actors,
            evidence=_ev_ids(g, [mac["id"]]),
            score=16,
        ))
    return out


def _recurring_beneficiary(g):
    out = []
    for n in g.nodes.values():
        if n["type"] not in FINANCIAL_TYPES:
            continue
        senders = sorted({e["src"] for e in g.fund_edges() if e["dst"] == n["id"]})
        if len(senders) < 3:
            continue
        total = n["in_amount"]
        out.append(Finding(
            code=f"FAN-IN-{n['id']}",
            title=f"{n['label']} collects funds from {len(senders)} distinct sources",
            detail=(f"₹{inr(total)} was received from {len(senders)} separate remitters "
                    f"({', '.join(g.nodes[s]['label'] for s in senders[:6])}"
                    f"{' …' if len(senders) > 6 else ''}). A recurring beneficiary fanning in "
                    "from unrelated remitters is the defining signature of a collection mule."),
            severity="HIGH" if len(senders) >= 4 else "MEDIUM",
            confidence="HIGH",
            category="FINANCIAL",
            entities=[n["id"]] + senders,
            evidence=_ev_ids(g, [n["id"]]),
            score=18 if len(senders) >= 4 else 12,
        ))
    return out


def _apk_crossref(g, events):
    out = []
    hash_map = defaultdict(set)
    for apk in g.by_type(M.APK):
        h = apk["meta"].get("sha256")
        if h:
            hash_map[h].add(apk["id"])
    for h, ids in hash_map.items():
        if len(ids) < 2:
            continue
        out.append(Finding(
            code=f"APK-HASH-{h[:12]}",
            title=f"Identical APK (SHA-256 {h[:16]}…) present under {len(ids)} names",
            detail=("The same binary was recovered under different package/file names: " +
                    ", ".join(sorted(g.nodes[i]["value"] for i in ids)) +
                    ". Hash identity is conclusive proof that the same payload was distributed."),
            severity="HIGH", confidence="HIGH", category="MALWARE",
            entities=sorted(ids), evidence=_ev_ids(g, sorted(ids)), score=15,
        ))
    for apk in g.by_type(M.APK):
        devices = sorted(n for n in g.neighbors(apk["id"], {"INSTALLED", "DELIVERED"}))
        risk = apk["meta"].get("risk") or 0
        if risk >= 55:
            out.append(Finding(
                code=f"MALICIOUS-APK-{apk['value'][:28]}",
                title=f"High-risk Android package '{apk['value']}' (risk {risk}/100)",
                detail=("Static triage of the package permissions and install source scored "
                        f"{risk}/100. Present on/delivered to: " +
                        (", ".join(g.nodes[d]["label"] for d in devices) or "unknown device") +
                        ". Seize the handset and preserve the APK for full reverse engineering."),
                severity="CRITICAL" if risk >= 75 else "HIGH",
                confidence="HIGH", category="MALWARE",
                entities=[apk["id"]] + devices,
                evidence=_ev_ids(g, [apk["id"]]), score=20 if risk >= 75 else 14,
            ))
    return out


def _domain_pivot(g):
    out = []
    for dom in g.by_type(M.DOMAIN):
        peers = sorted({e["src"] for e in g.edges.values()
                        if e["dst"] == dom["id"] and e["rel"] in
                        ("CONNECTED_TO", "SENT_LINK", "LINKS_TO", "CONTACTS")})
        peers = [p for p in peers if g.nodes[p]["type"] in (M.PHONE, M.EMAIL, M.IMEI, M.APK, M.IP)]
        if len(peers) < 2:
            continue
        out.append(Finding(
            code=f"DOMAIN-PIVOT-{dom['value'][:30]}",
            title=f"Domain {dom['value']} links {len(peers)} separate entities",
            detail=("The host was referenced or contacted by: " +
                    ", ".join(g.nodes[p]["label"] for p in peers) +
                    ". A common infrastructure endpoint ties the delivery, victim and "
                    "operator sides of the case together."),
            severity="MEDIUM", confidence="MEDIUM", category="NETWORK",
            entities=[dom["id"]] + peers, evidence=_ev_ids(g, [dom["id"]]), score=10,
        ))
    return out


def _name_collision(g, n2c):
    out = []
    for per in g.by_type(M.PERSON):
        held = sorted(n for n in g.neighbors(per["id"], {"HOLDS"})
                      if g.nodes[n]["type"] in FINANCIAL_TYPES)
        if len(held) < 2:
            continue
        # If the identifiers are already bound to one actor (account <-> its own
        # VPA), the shared name tells us nothing new -- do not raise noise.
        if len(_distinct_actors(held, n2c)) < 2:
            continue
        out.append(Finding(
            code=f"NAME-REUSE-{per['value'][:28]}",
            title=f"Holder name '{per['value']}' appears on {len(held)} financial identifiers",
            detail=("The same account-holder name is attached to " +
                    ", ".join(g.nodes[h]["label"] for h in held) +
                    ". NOT treated as a confirmed identity match — names are not unique. "
                    "Verify against PAN/Aadhaar seeding or the bank KYC record before merging "
                    "these into a single suspect."),
            severity="LOW", confidence="LOW", category="IDENTITY",
            entities=[per["id"]] + held, evidence=_ev_ids(g, [per["id"]]), score=4,
        ))
    return out


def _masked_candidates(g):
    """Masked account numbers are never auto-merged; suggest candidates only."""
    out = []
    full = [n for n in g.by_type(M.ACCOUNT) if not str(n["value"]).startswith("MASKED")]
    masked = [n for n in g.by_type(M.ACCOUNT) if str(n["value"]).startswith("MASKED")]
    for m in masked:
        tail = str(m["value"]).split("-", 1)[1]
        hits = [f for f in full if str(f["value"]).endswith(tail[-4:])]
        if not hits:
            continue
        out.append(Finding(
            code=f"MASKED-MATCH-{m['value']}",
            title=f"Masked account {m['value']} may correspond to {len(hits)} known account(s)",
            detail=("Trailing digits match " +
                    ", ".join(g.nodes[h["id"]]["label"] for h in hits) +
                    ". Retained as a SEPARATE node — last-4 collisions are common. "
                    "Issue a Sec.91 CrPC notice to the bank to resolve the full number."),
            severity="LOW", confidence="LOW", category="IDENTITY",
            entities=[m["id"]] + [h["id"] for h in hits],
            evidence=_ev_ids(g, [m["id"]]), score=3,
        ))
    return out


def _phone_across_rails(g):
    """A phone number that is both a telecom subject and a financial identifier."""
    out = []
    for ph in g.by_type(M.PHONE):
        fin = sorted(n for n in g.neighbors(ph["id"], {"REGISTERED_ON"})
                     if g.nodes[n]["type"] in FINANCIAL_TYPES)
        telecom = {"a_party", "b_party", "subscriber", "device_msisdn"} & ph["roles"]
        if fin and telecom:
            out.append(Finding(
                code=f"RAIL-BRIDGE-{ph['value']}",
                title=f"MSISDN {ph['value']} bridges telecom and financial evidence",
                detail=("The number appears in call/data records AND is the registered mobile "
                        "on " + ", ".join(g.nodes[f]["label"] for f in fin) +
                        ". This is the anchor identifier for a Sec.91 notice covering both "
                        "the telco and the bank."),
                severity="MEDIUM", confidence="HIGH", category="IDENTITY",
                entities=[ph["id"]] + fin, evidence=_ev_ids(g, [ph["id"]]), score=8,
            ))
    return out


def _additional_victims(g):
    """Identify remitters who are almost certainly OTHER victims, not mules.

    A fan-in node is fed by many remitters.  Scoring those remitters as
    suspects merely because they touched a mule account is the single most
    damaging false positive this tool could produce -- it would put a victim on
    a seizure list.  A remitter that only ever pays INTO a collector, shows no
    credits of its own and never cashes out is flagged and excluded from the
    suspect ranking.
    """
    collectors = set()
    for n in g.nodes.values():
        if n["type"] not in FINANCIAL_TYPES:
            continue
        senders = {e["src"] for e in g.fund_edges() if e["dst"] == n["id"]}
        if len(senders) >= 3:
            collectors.add(n["id"])
    if not collectors:
        return []

    out = []
    for n in g.nodes.values():
        if n["type"] not in FINANCIAL_TYPES or n["victim"]:
            continue
        dests = {e["dst"] for e in g.fund_edges() if e["src"] == n["id"]}
        if not dests or not dests <= collectors:
            continue
        if n["in_count"] or n["in_amount"]:
            continue
        n["probable_victim"] = True
        holder = n["meta"].get("holder")
        out.append(Finding(
            code=f"ADDL-VICTIM-{n['id']}",
            title=f"{n['label']} is probably an additional victim, not a suspect",
            detail=("This endpoint only ever remits INTO "
                    + ", ".join(g.nodes[d]["label"] for d in sorted(dests)) +
                    ", shows no incoming credits of its own and performs no cash-out. "
                    "Treat as a further complainant"
                    + (f" ({holder})" if holder else "") +
                    " and obtain a statement — it is excluded from the suspect ranking."),
            severity="INFO", confidence="MEDIUM", category="VICTIMOLOGY",
            entities=[n["id"]] + sorted(dests), evidence=_ev_ids(g, [n["id"]]), score=0,
        ))
    return out


# ==========================================================================
# money trail
# ==========================================================================

def trace_money(g: Graph, events, clusters, node_to_cluster, max_depth=6):
    """Trace fund flow outward from victim financial nodes.

    Returns dict with layered hops, full paths and identified cash-out points.
    Edges are only followed forward in time (a later hop cannot precede an
    earlier one), which is what makes the chain an evidentiary narrative rather
    than a topological guess.
    """
    by_id = {e.id: e for e in events}
    fund_events = [e for e in events if e.kind == M.TXN and e.amount
                   and not e.attrs.get("corroborated")]

    # per-edge transaction list, chronologically ordered
    edge_txns = defaultdict(list)
    for ev in fund_events:
        for ln in ev.links:
            if ln["rel"] != "FUNDS":
                continue
            edge_txns[(ln["src"], ln["dst"])].append(ev)
    for k in edge_txns:
        edge_txns[k].sort(key=lambda e: e.ts or dt.datetime.max)

    origins = sorted(n["id"] for n in g.nodes.values()
                     if n["victim"] and n["type"] in FINANCIAL_TYPES)
    if not origins:
        # fall back to the biggest net loser
        losers = [(n["out_amount"] - n["in_amount"], n["id"]) for n in g.nodes.values()
                  if n["type"] in FINANCIAL_TYPES and n["out_amount"] > 0]
        if losers:
            origins = [max(losers)[1]]

    out_map = defaultdict(list)
    for (s, d), txns in edge_txns.items():
        out_map[s].append((d, txns))

    paths, hop_records = [], []
    seen_states = set()

    def walk(node, after_ts, depth, path, amount_in):
        if depth >= max_depth:
            paths.append(list(path))
            return
        nexts = out_map.get(node, [])
        advanced = False
        for dst, txns in nexts:
            for tx in txns:
                if tx.ts and after_ts and tx.ts < after_ts:
                    continue
                state = (node, dst, tx.id)
                if state in seen_states:
                    continue
                seen_states.add(state)
                lag = minutes_between(after_ts, tx.ts) if after_ts and tx.ts else None
                hop = {
                    "from": node, "to": dst, "amount": tx.amount,
                    "ts": iso(tx.ts), "lag_minutes": round(lag, 1) if lag is not None else None,
                    "event": tx.id, "depth": depth + 1,
                    "rail": tx.attrs.get("rail"), "reference": tx.attrs.get("reference"),
                    "narration": tx.attrs.get("narration"),
                    "cashout": bool(tx.attrs.get("cashout") or tx.attrs.get("crypto")),
                }
                hop_records.append(hop)
                advanced = True
                if dst in [p["to"] for p in path]:
                    paths.append(list(path) + [hop])
                    continue
                walk(dst, tx.ts, depth + 1, path + [hop], tx.amount)
        if not advanced and path:
            paths.append(list(path))

    for origin in origins:
        walk(origin, None, 0, [], None)

    # cash-out endpoints
    cashouts = []
    for ev in fund_events:
        if ev.attrs.get("cashout") or ev.attrs.get("crypto"):
            for ent in ev.entities:
                if ent["type"] in FINANCIAL_TYPES:
                    cashouts.append({
                        "node": f"{ent['type']}|{ent['value']}",
                        "amount": ev.amount, "ts": iso(ev.ts),
                        "mode": "CRYPTO/P2P" if ev.attrs.get("crypto") else "ATM/CASH",
                        "narration": ev.attrs.get("narration"), "event": ev.id,
                    })
                    break
    # terminal nodes: receive money but send none onward
    terminals = []
    for n in g.nodes.values():
        if n["type"] in FINANCIAL_TYPES and n["in_amount"] > 0 and n["out_amount"] == 0:
            terminals.append(n["id"])

    cash_by_node = defaultdict(float)
    for c in cashouts:
        cash_by_node[c["node"]] += c["amount"] or 0
    for h in hop_records:
        if h["to"] in cash_by_node:
            h["dest_cashout"] = round(cash_by_node[h["to"]], 2)

    # dedupe & rank paths by total value then length
    uniq = {}
    for p in paths:
        if not p:
            continue
        key = tuple((h["from"], h["to"], h["event"]) for h in p)
        uniq[key] = p
    ranked = sorted(uniq.values(),
                    key=lambda p: (-sum(h["amount"] or 0 for h in p), -len(p)))[:25]

    return {
        "origins": origins,
        "hops": sorted(hop_records, key=lambda h: (h["ts"] or "", h["depth"])),
        "paths": ranked,
        "cashouts": cashouts,
        "terminal_nodes": terminals,
        "total_traced": round(sum(h["amount"] or 0 for h in hop_records), 2),
    }


def layer_of(trail):
    """Map node -> shortest hop depth from the victim (layer number)."""
    layers = {}
    for h in trail["hops"]:
        d = h["depth"]
        if h["to"] not in layers or d < layers[h["to"]]:
            layers[h["to"]] = d
    for o in trail["origins"]:
        layers[o] = 0
    return layers
