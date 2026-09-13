"""Case orchestration: acquire -> parse -> correlate -> score -> report."""

from __future__ import annotations

import json
import os
import time
import traceback

from . import correlate, parsers, report as report_mod, risk
from .evidence import CustodyLog, acquire, acquire_bytes, new_case_id
from .util import iso

SUPPORTED_EXT = {".csv", ".tsv", ".txt", ".xlsx", ".xlsm", ".eml", ".json"}


class Case:
    def __init__(self, case_id=None, officer="UNSPECIFIED", workdir="cases"):
        self.case_id = case_id or new_case_id()
        self.officer = officer
        self.root = os.path.join(workdir, self.case_id)
        self.evidence_dir = os.path.join(self.root, "exhibits")
        self.custody = CustodyLog(self.case_id, officer)
        self.exhibits = []
        self.events = []
        self.graph = None
        self.findings = []
        self.clusters = {}
        self.node_to_cluster = {}
        self.trail = {}
        self.scores = {}
        self.suspects = []
        self.context = {}
        self.processing_ms = 0
        self.errors = []
        self._report = None
        self._analysis = None
        os.makedirs(self.evidence_dir, exist_ok=True)
        self.custody.record("CASE_OPEN", f"Case {self.case_id} opened by {officer}")

    # -- ingestion ---------------------------------------------------------
    def add_path(self, path):
        idx = len(self.exhibits) + 1
        ex = acquire(path, self.evidence_dir, self.custody, idx)
        self.exhibits.append(ex)
        return ex

    def add_bytes(self, filename, data):
        idx = len(self.exhibits) + 1
        ex = acquire_bytes(data, filename, self.evidence_dir, self.custody, idx)
        self.exhibits.append(ex)
        return ex

    def add_directory(self, directory):
        found = []
        for name in sorted(os.listdir(directory)):
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            if os.path.splitext(name)[1].lower() not in SUPPORTED_EXT:
                continue
            found.append(self.add_path(full))
        if not found:
            raise ValueError(f"No supported artifacts found in {directory}")
        return found

    # -- pipeline ----------------------------------------------------------
    def analyze(self):
        t0 = time.time()
        self._report = None
        self._analysis = None
        self.events = []
        for ex in self.exhibits:
            if not ex.verify():
                ex.parse_status = "INTEGRITY_FAIL"
                ex.notes.append("SHA-256 mismatch at parse time — exhibit NOT processed")
                self.custody.record("INTEGRITY_FAIL", ex.original_name, exhibit=ex.exhibit_id)
                continue
            try:
                atype, events = parsers.parse(ex.stored_path, ex.exhibit_id, ex.original_name)
                ex.artifact_type = atype
                ex.records = len(events)
                ex.parse_status = "PARSED" if events else (
                    "UNSUPPORTED" if atype == "UNKNOWN" else "EMPTY")
                if atype == "UNKNOWN":
                    ex.notes.append("Artifact type could not be determined from content signature")
                self.events.extend(events)
                self.custody.record(
                    "PARSE", f"{ex.original_name}: detected {atype}, {len(events)} events extracted",
                    exhibit=ex.exhibit_id, artifact_type=atype, records=len(events))
            except Exception as exc:  # a bad exhibit must not kill the case
                ex.parse_status = "ERROR"
                ex.notes.append(f"Parser error: {exc}")
                self.errors.append({"exhibit": ex.exhibit_id, "error": str(exc),
                                    "trace": traceback.format_exc(limit=3)})
                self.custody.record("PARSE_ERROR", f"{ex.original_name}: {exc}",
                                    exhibit=ex.exhibit_id)

        self.events.sort(key=lambda e: (e.ts is None, e.ts))
        self.graph = correlate.build_graph(self.events)
        self.custody.record("CORRELATE",
                            f"Entity graph built: {len(self.graph.nodes)} nodes, "
                            f"{len(self.graph.edges)} relationships")
        self.clusters, self.node_to_cluster = correlate.identity_clusters(self.graph)
        self.findings = correlate.correlate(self.graph, self.events,
                                           self.node_to_cluster)
        self.trail = correlate.trace_money(self.graph, self.events, self.clusters,
                                           self.node_to_cluster)
        self.scores, self.suspects, self.context = risk.score(
            self.graph, self.events, self.findings, self.trail,
            self.clusters, self.node_to_cluster)
        self.processing_ms = int((time.time() - t0) * 1000)
        self.custody.record(
            "SCORE", f"{len(self.findings)} findings, {len(self.suspects)} suspect clusters, "
                     f"analysis completed in {self.processing_ms} ms")
        return self

    # -- outputs -----------------------------------------------------------
    def verify_all(self):
        return {ex.exhibit_id: ex.verify() for ex in self.exhibits}

    def graph_payload(self, max_nodes=600):
        g = self.graph
        nodes = []
        for nid, n in g.nodes.items():
            s = self.scores.get(nid, {})
            nodes.append({
                "id": nid, "type": n["type"], "value": n["value"], "label": n["label"],
                "score": s.get("score", 0), "band": s.get("band", "LOW"),
                "layer": s.get("layer"), "victim": n["victim"],
                "cluster": self.node_to_cluster.get(nid),
                "roles": sorted(n["roles"]), "meta": n["meta"],
                "in_amount": round(n["in_amount"], 2), "out_amount": round(n["out_amount"], 2),
                "events": len(n["events"]), "exhibits": sorted(n["exhibits"]),
                "first_seen": iso(n["first_seen"]), "last_seen": iso(n["last_seen"]),
                "reasons": s.get("reasons", []),
            })
        if len(nodes) > max_nodes:
            nodes.sort(key=lambda n: (-int(n["victim"]), -n["score"], -n["events"]))
            keep = {n["id"] for n in nodes[:max_nodes]}
            nodes = nodes[:max_nodes]
        else:
            keep = set(g.nodes)
        edges = [{
            "id": e["key"], "src": e["src"], "dst": e["dst"], "rel": e["rel"],
            "directed": e["directed"], "count": e["count"],
            "amount": round(e["amount"], 2) if e["amount"] else 0,
            "first": iso(e["first"]), "last": iso(e["last"]),
            "events": e["events"][:12],
        } for e in g.edges.values() if e["src"] in keep and e["dst"] in keep]
        return {"nodes": nodes, "edges": edges,
                "truncated": len(g.nodes) - len(nodes)}

    def report(self, rebuild=False):
        """The investigative brief for this case.

        A case is immutable once analysed, so the brief is built once and
        reused. That also gives the brief a stable `report_sha256` -- rebuilding
        it per request produced a new generation timestamp, and therefore a
        different digest, every time the same document was downloaded.
        """
        if self._report is None or rebuild:
            self._report = report_mod.build_report(self)
        return self._report

    def analysis_payload(self, rebuild=False):
        """Everything the dashboard needs, assembled once and cached.

        On a small shared instance this is the difference between a one-second
        load and half a minute: the graph payload, the per-entity scoring
        rationale and the event stream are all re-serialised otherwise.
        """
        if self._analysis is None or rebuild:
            payload = dict(self.report(rebuild=rebuild))
            payload["events"] = [{
                "id": e.id, "kind": e.kind, "ts": iso(e.ts), "summary": e.summary,
                "exhibit": e.exhibit, "source": e.source, "row": e.row,
                "amount": e.amount, "direction": e.direction, "flags": e.flags,
                "cite": e.cite(), "attrs": _compact_attrs(e.attrs),
            } for e in self.events]
            payload["scores"] = self.scores
            self._analysis = json.dumps(payload, default=str)
        return self._analysis

    def export(self, out_dir=None):
        out_dir = out_dir or os.path.join(self.root, "output")
        os.makedirs(out_dir, exist_ok=True)
        rep = self.report()
        json_path = os.path.join(out_dir, f"{self.case_id}_brief.json")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=2, default=str)
        pdf_path = os.path.join(out_dir, f"{self.case_id}_brief.pdf")
        report_mod.render_pdf(rep, pdf_path)
        events_path = os.path.join(out_dir, f"{self.case_id}_events.json")
        with open(events_path, "w", encoding="utf-8") as fh:
            json.dump([e.to_dict() for e in self.events], fh, indent=2, default=str)
        self.custody.record("EXPORT", f"Brief exported (JSON + PDF) to {out_dir}")
        return {"json": json_path, "pdf": pdf_path, "events": events_path, "report": rep}

    def summary(self):
        return {
            "case_id": self.case_id,
            "officer": self.officer,
            "exhibits": [e.to_dict() for e in self.exhibits],
            "events": len(self.events),
            "entities": len(self.graph.nodes) if self.graph else 0,
            "relationships": len(self.graph.edges) if self.graph else 0,
            "findings": len(self.findings),
            "suspects": len(self.suspects),
            "processing_ms": self.processing_ms,
            "errors": self.errors,
        }


def _compact_attrs(attrs):
    """Trim bulky fields out of the per-event payload sent to the browser."""
    out = {}
    for k, v in (attrs or {}).items():
        if k == "flow":
            continue
        if isinstance(v, str) and len(v) > 600:
            v = v[:600] + "…"
        if isinstance(v, list) and len(v) > 40:
            v = v[:40] + ["…"]
        out[k] = v
    return out


def run(paths, officer="UNSPECIFIED", workdir="cases", case_id=None):
    """Convenience one-shot: build a case from files/directories and analyse it."""
    case = Case(case_id=case_id, officer=officer, workdir=workdir)
    for p in paths:
        if os.path.isdir(p):
            case.add_directory(p)
        else:
            case.add_path(p)
    return case.analyze()
