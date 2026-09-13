# Unified Cyber Fraud Analysis & Digital Artifact Correlator

An automated digital-forensic triage pipeline for financial cyber fraud. It ingests the
fragmented artifacts an investigating officer actually receives — CDRs, IPDRs, bank and UPI
settlement sheets, phishing emails, Android device dumps, chat exports — normalises them,
correlates the entities **across** them, scores every endpoint, and produces a court-ready
investigative brief with SHA-256 exhibit integrity.

**Zero third-party dependencies.** Pure Python 3.8+ standard library and vanilla JavaScript.
No `pip install`, no CDN, no network access. It runs on a locked-down police workstation and
on an air-gapped machine, which is the environment this problem is actually set in.

---

## Quick start

```bash
python tools/make_sample_xlsx.py     # build the .xlsx exhibit (one-off)

python run.py                        # dashboard at http://127.0.0.1:8713
python cli.py sample_data --officer "SI A. Deshmukh" --out out/
python -m unittest discover -s tests -v
```

In the dashboard, click **Load demo case**, or drag your own evidence files onto the window.

---

## What it does

| Requirement | Implementation |
|---|---|
| Multi-source ingestion & normalisation | CSV / TSV / pipe / **XLSX** (own OOXML reader), `.eml`, Android `.json`/`.txt` dumps, WhatsApp chat exports, NCRP complaint JSON. Type detected by **content signature**, not filename. ~200 column aliases absorb per-TSP/per-bank schema drift. |
| Entity correlation engine | 13 rules linking shared IMEI/IMSI, SIM rotation, handset hopping, shared public IP and /24 subnet, shared MAC/device id, recurring beneficiaries, identical APK hashes, domain pivots, telecom↔financial bridges. |
| Mule account & network graph | Directed entity graph with time-ordered fund tracing from victim → layer-1 collector → layer-2 mules → ATM/crypto cash-out. Interactive canvas renderer with a dedicated **layered flow view**. |
| Triage & risk scoring | 17 explainable heuristics (pass-through ratio, layering latency, fan-in/fan-out, structuring, nocturnal bursts, cash-out, pre-transaction victim contact, spoofed headers, malicious APK). Every point carries a reason and the event ids that justify it. |
| Investigative brief | One-page field PDF + structured JSON: prime suspects, fund chain, timeline, seizure recommendations, exhibit manifest, chain of custody. Written by a hand-rolled PDF engine so nothing needs installing. |
| Evidentiary integrity | Hash-on-acquisition → read-only copy → re-hash → re-verify before every parse and at report time. Append-only custody log, itself hashed. A tampered exhibit is refused, not silently processed. |

---

## Architecture

```
 evidence files
      │
      ▼
 ┌──────────────┐   SHA-256 on acquisition, read-only copy, re-hash, custody log
 │  evidence.py │──────────────────────────────────────────────────────────────┐
 └──────┬───────┘                                                              │
        ▼                                                                      │
 ┌──────────────┐   content-signature detection + ~200 column aliases          │
 │  parsers.py  │   tabular.py (CSV/XLSX)   textmine.py (lure + indicators)    │
 └──────┬───────┘                                                              │
        ▼                                                                      │
   Event stream  ── one normalised fact per source row, provenance attached    │
        │                                                                      │
        ▼                                                                      │
 ┌──────────────┐   graph build · cross-statement de-duplication               │
 │ correlate.py │   identity clustering · 13 correlation rules · fund tracing   │
 └──────┬───────┘                                                              │
        ▼                                                                      │
 ┌──────────────┐   17 explainable heuristics, confidence-weighted             │
 │   risk.py    │   → score 0-100 + band + reasons + citations                 │
 └──────┬───────┘                                                              │
        ▼                                                                      ▼
 ┌──────────────┐                                              ┌────────────────────┐
 │  report.py   │──► JSON brief + one-page PDF (pdfwriter.py)  │ exhibit manifest & │
 └──────┬───────┘                                              │ chain of custody   │
        ▼                                                      └────────────────────┘
 server.py ──► web/ dashboard (loopback only, canvas graph, no CDN)
```

## Layout

```
cfc/            engine      util, evidence, tabular, textmine, model, parsers,
                            correlate, risk, report, pdfwriter, case, server
web/            dashboard   index.html, style.css, app.js, graph.js
sample_data/    mock case   12 exhibits spanning 8 artifact types
tools/          generators  make_sample_xlsx.py
tests/          39 tests    unit + end-to-end + integrity enforcement
cli.py          headless runner        run.py   dashboard launcher
PROPOSAL.md     technical proposal     FORENSICS.md   heuristics & evidentiary notes
```

---

## The demo case

`sample_data/` contains a complete, internally consistent APK-phishing → mule-network
scenario across **12 exhibits and 8 artifact types**, with a planted ground truth the tests
assert against:

> A phishing email (SPF/DKIM/DMARC fail, Return-Path mismatch) delivers `SBI-Rewards.apk`.
> The victim installs it; the package holds `READ_SMS + RECEIVE_SMS + ACCESSIBILITY` and
> intercepts OTPs. A caller contacts the victim 27 minutes before the first debit.
> ₹4,85,000 leaves in three IMPS debits to a layer-1 collector, which is also fed by three
> other victims, and is split within 7 minutes across four layer-2 mules that cash out at
> ATMs in Jharkhand and through a crypto P2P desk. The same handset (IMEI) carries four SIMs;
> the identical APK binary is recovered from the suspect's phone under a different package name.

The engine recovers all of it from the raw files with no scenario-specific code.

**What it deliberately does *not* do:** the three other remitters feeding the collector are
flagged as *probable additional victims* and excluded from the suspect ranking; the victim's
own grocery payment is excluded from the fraud total; accounts sharing only a holder *name*
are never merged. Those are the false positives that would put a victim on a seizure list.

---

## Deploying a public demo (Render)

The repository carries a `render.yaml` blueprint, so the whole service is defined in code:

1. Render dashboard → **New → Blueprint** → connect this repository → **Apply**.
2. Render reads `render.yaml`, builds, and publishes at
   `https://cyber-fraud-correlator.onrender.com` (the exact host is shown in the dashboard).

The blueprint sets `CFC_PUBLIC_DEMO=1`, which puts a standing warning banner on the dashboard,
and caps uploads at 16 MB. On the free plan the instance sleeps after ~15 minutes idle, so the
first request after a sleep takes roughly a minute to wake; the demo case is rebuilt in a
background thread as soon as it does, so the link still lands on a populated graph.

**Understand what the deployment changes.** This tool is designed to run on loopback on the
officer's own workstation, which is why it has no dependencies and never sends data anywhere.
A hosted instance is the opposite posture:

- anything ingested is reachable by **anyone with the link** — there is no authentication;
- storage is **ephemeral**, so cases vanish on restart or redeploy;
- exhibits are written to a shared host you do not control.

It is appropriate for a screening demo with the synthetic sample data, and **not** for real
case material. For casework, clone and run `python run.py` locally.

Any host that injects `PORT` works the same way (Railway, Fly.io, Heroku) — `run.py` binds
`0.0.0.0` and skips the browser launch when `PORT` is present.

---

## Design decisions worth knowing

- **De-duplication across institutions.** The same transfer appears as a debit in the
  remitter's statement and a credit in the beneficiary's. Matching on
  (source, destination, amount, minute ±1) counts it once and marks it *corroborated* —
  without this, every mule's turnover doubles.
- **Serving-subscriber inference.** CDR exports disagree about what the A-party column means
  on an incoming record. The subject of a SIM is inferred from the MSISDN most frequently
  observed with each (IMEI, IMSI) pair, so handsets are attached to the right person.
- **IMEI normalisation to 14 digits.** The 15th digit is a Luhn check and the 16th is a
  software version; both change while the handset does not.
- **Conservative identity merging.** Only one-to-one bindings merge (account↔VPA,
  account↔registered mobile, IMEI↔MAC in one extraction). Shared names and masked-account
  last-4 matches are raised as separate LOW-confidence findings for the IO to confirm.
- **Confidence-weighted scoring.** A MEDIUM-confidence finding contributes 60 % of its
  weight, LOW 30 %, so an uncertain signal cannot push an entity to CRITICAL alone.

---

## Performance & footprint

The 12-exhibit demo case — acquisition hashing, parsing, graph construction, correlation,
tracing, scoring and report assembly — completes in **under one second** on a standard
laptop. Memory is proportional to the event count. The graph payload sent to the browser is
capped at 600 nodes (highest-risk first) so the dashboard stays responsive on bulk data.

## Limitations

Output is **machine-generated triage**, stated as such on every page of the brief. Every
assertion cites the exhibit and row it derives from and must be corroborated by the IO before
it is relied upon under Sec.173 CrPC / Sec.193 BNSS. Shared-IP findings need ISP confirmation
that the address is not a CGNAT pool. Timestamps are normalised to IST. APK triage is static
permission/installer analysis, not behavioural reverse engineering.
