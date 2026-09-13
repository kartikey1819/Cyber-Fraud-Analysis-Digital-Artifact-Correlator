"""Headless analysis runner.

    python cli.py sample_data
    python cli.py sample_data --officer "SI A. Deshmukh" --out out/
    python cli.py c:\\evidence\\case41 --json-only
"""

from __future__ import annotations

import argparse
import os
import sys

from cfc.case import Case
from cfc.util import inr

try:  # Indian rupee sign and arrows must survive a cp1252 console
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BOLD, DIM, RED, YEL, GRN, CYA, RST = (
    "\033[1m", "\033[2m", "\033[31m", "\033[33m", "\033[32m", "\033[36m", "\033[0m")
if os.name == "nt" and not os.environ.get("WT_SESSION"):
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        BOLD = DIM = RED = YEL = GRN = CYA = RST = ""

BAND_COLOR = {"CRITICAL": RED, "HIGH": YEL, "MEDIUM": CYA, "LOW": DIM}


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="cli.py",
        description="Unified Cyber Fraud Analysis & Digital Artifact Correlator")
    ap.add_argument("inputs", nargs="+",
                    help="evidence files and/or directories to ingest")
    ap.add_argument("--officer", default="UNSPECIFIED", help="investigating officer")
    ap.add_argument("--case-id", default=None, help="override the generated case id")
    ap.add_argument("--workdir", default="cases", help="case working directory")
    ap.add_argument("--out", default=None, help="export directory for the brief")
    ap.add_argument("--json-only", action="store_true", help="skip PDF rendering")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    case = Case(case_id=args.case_id, officer=args.officer, workdir=args.workdir)
    for path in args.inputs:
        if not os.path.exists(path):
            ap.error(f"no such path: {path}")
        if os.path.isdir(path):
            case.add_directory(path)
        else:
            case.add_path(path)

    case.analyze()
    if not args.quiet:
        _print_console(case)

    if args.json_only:
        import json
        out_dir = args.out or os.path.join(case.root, "output")
        os.makedirs(out_dir, exist_ok=True)
        p = os.path.join(out_dir, f"{case.case_id}_brief.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(case.report(), fh, indent=2, default=str)
        print(f"\n{GRN}JSON brief{RST} {p}")
        return 0

    paths = case.export(args.out)
    print(f"\n{GRN}JSON brief{RST}  {paths['json']}")
    print(f"{GRN}PDF brief {RST}  {paths['pdf']}")
    print(f"{DIM}Events    {RST}  {paths['events']}")
    return 0


def _print_console(case):
    rule = DIM + "-" * 78 + RST
    print(f"\n{BOLD}CASE {case.case_id}{RST}   officer: {case.officer}")
    print(rule)
    print(f"{BOLD}EXHIBITS{RST}")
    for ex in case.exhibits:
        ok = f"{GRN}OK{RST}" if ex.verify() else f"{RED}HASH MISMATCH{RST}"
        print(f"  {ex.exhibit_id}  {ex.original_name[:42]:<42} "
              f"{ex.artifact_type:<10} {ex.records:>5} rec  {ok}")
        print(f"        {DIM}sha256 {ex.sha256}{RST}")
        for note in ex.notes:
            print(f"        {YEL}! {note}{RST}")

    print(rule)
    s = case.summary()
    print(f"{BOLD}NORMALISED{RST}  {s['events']} events  |  {s['entities']} entities  |  "
          f"{s['relationships']} relationships  |  {s['processing_ms']} ms")

    print(rule)
    print(f"{BOLD}CORRELATION FINDINGS{RST}")
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in sorted(case.findings, key=lambda x: order.get(x.severity, 9)):
        col = BAND_COLOR.get(f.severity, "")
        print(f"  {col}[{f.severity:<8}]{RST} {f.title}")
        print(f"            {DIM}confidence {f.confidence} | {f.category} | {f.code}{RST}")

    print(rule)
    print(f"{BOLD}PRIME SUSPECTS{RST}")
    for i, sus in enumerate(case.suspects[:8], start=1):
        col = BAND_COLOR.get(sus["band"], "")
        holders = ", ".join(sus["holders"]) or "-"
        layer = sus["layer"] if sus["layer"] is not None else "-"
        print(f"  {i}. {col}{sus['score']:>3}/100 {sus['band']:<8}{RST} "
              f"{sus['label'][:34]:<34} L{layer}  in Rs.{inr(sus['received']):>12}")
        if holders != "-":
            print(f"       {DIM}holder: {holders}{RST}")
        for r in sus["reasons"][:3]:
            print(f"       {DIM}- {r['text'][:96]}{RST}")

    print(rule)
    print(f"{BOLD}MONEY TRAIL{RST}  Rs.{inr(case.trail['total_traced'])} across "
          f"{len(case.trail['hops'])} hops")
    for chain in case.trail["paths"][:3]:
        if not chain:
            continue
        g = case.graph
        parts = [g.nodes[chain[0]["from"]]["label"]]
        for h in chain:
            lag = f" (+{h['lag_minutes']:.0f}m)" if h.get("lag_minutes") is not None else ""
            parts.append(f"-[Rs.{inr(h['amount'])}{lag}]-> " +
                         g.nodes[h["to"]]["label"] +
                         (f" {RED}CASH-OUT{RST}" if h.get("cashout") else ""))
        print("  " + " ".join(parts))

    if case.errors:
        print(rule)
        print(f"{RED}PARSE ERRORS{RST}")
        for e in case.errors:
            print(f"  {e['exhibit']}: {e['error']}")


if __name__ == "__main__":
    sys.exit(main())
