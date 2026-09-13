# Technical Proposal

## AI-Powered Unified Cyber Fraud Analysis & Digital Artifact Correlator

**Prototype:** working end-to-end system — ingestion engine, correlation engine, network graph
visualiser, risk triage, and PDF/JSON brief generation. Pure Python 3 standard library and
vanilla JavaScript; **no third-party packages, no network access, no CDN**.

---

## 1. Problem framing

During the golden hour an investigating officer holds a pile of mutually unintelligible files:
a telco's CDR in one column order, an IPDR in another, three banks' statements in three
formats, a PSP settlement sheet, a phishing `.eml`, an Android dump, a chat export. The
intelligence that matters — *the same handset carries four SIMs*, *this collector is fed by
four unrelated victims*, *the money left 7 minutes after it arrived* — exists only in the
**joins between those files**, which is precisely what manual triage cannot do at speed.

Our system automates the join. The constraint we designed to is the deployment environment:
a standard police workstation, often without administrative rights or internet access.
That ruled out any dependency stack, so the entire toolkit — XLSX reader, PDF writer, HTTP
server, graph layout engine — is implemented against the standard library.

---

## 2. Architecture

```
 ┌────────────────────────────────────────────────────────────────────────────┐
 │ ACQUISITION            evidence.py                                          │
 │ SHA-256 on arrival → read-only working copy → re-hash → compare             │
 │ append-only chain-of-custody log (itself SHA-256 sealed)                    │
 └───────────────────────────────┬────────────────────────────────────────────┘
                                 ▼
 ┌────────────────────────────────────────────────────────────────────────────┐
 │ INGESTION & NORMALISATION     parsers.py · tabular.py · textmine.py         │
 │ content-signature type detection  │  ~200 column aliases  │  8 artifact     │
 │ CSV/TSV/pipe/XLSX · .eml · Android JSON/text · chat · NCRP complaint        │
 │                    ▼                                                        │
 │            canonical Event stream — one fact per source row,                │
 │            carrying (exhibit id, file, row) provenance                      │
 └───────────────────────────────┬────────────────────────────────────────────┘
                                 ▼
 ┌────────────────────────────────────────────────────────────────────────────┐
 │ CORRELATION                   correlate.py                                  │
 │ entity graph build → cross-institution transaction de-duplication →         │
 │ identity clustering (union-find over 1:1 bindings) →                        │
 │ 13 correlation rules → time-ordered fund-trail tracing                      │
 └───────────────────────────────┬────────────────────────────────────────────┘
                                 ▼
 ┌────────────────────────────────────────────────────────────────────────────┐
 │ TRIAGE                        risk.py                                       │
 │ 17 explainable heuristics, confidence-weighted, saturating to 0-100         │
 │ every point → a reason string + the event ids that justify it               │
 └───────────────┬────────────────────────────────┬───────────────────────────┘
                 ▼                                ▼
 ┌───────────────────────────────┐   ┌────────────────────────────────────────┐
 │ BRIEF   report.py/pdfwriter.py│   │ DASHBOARD  server.py + web/            │
 │ one-page field PDF + JSON     │   │ loopback HTTP, canvas force graph,     │
 │ + timeline + seizure actions  │   │ layered flow view, evidence drill-down │
 │ + exhibit manifest & custody  │   │                                        │
 └───────────────────────────────┘   └────────────────────────────────────────┘
```

---

## 3. Data ingestion pipeline

**Type detection is by content signature, not filename.** Each candidate file is scored
against signature column sets; an artifact is classified CDR / IPDR / BANK / UPI, or routed by
structure for `.eml`, Android dumps, chat exports and complaint records. The officer drops in
whatever the telco or bank sent, unrenamed.

**Schema flexibility** is handled by a ~200-entry alias dictionary mapping normalised column
keys to canonical fields, so `A-PARTY`, `caller`, `calling_msisdn` and `MSISDN` all resolve to
the same field. Banner rows above the real header, mixed delimiters, BOMs and Latin-1
encodings are absorbed by the reader. `.xlsx` is parsed directly from its OOXML zip
(`zipfile` + `ElementTree`) — no `pandas`, no `openpyxl`.

**Normalisation is deliberately conservative.** MSISDNs are reduced to the bare 10-digit
subscriber number while short codes and alphanumeric sender IDs are preserved distinctly.
IMEIs are normalised to the **14-digit TAC+serial body**, because the 15th digit is a Luhn
check and the 16th an IMEISV software version — both vary while the handset does not; a failed
Luhn check is itself raised as a possible-reflash indicator. VPAs are separated from email
addresses by host structure. Masked account numbers (`XXXXXX7890`) are **never** merged into
full account numbers.

**Unstructured text** (chat, SMS, email bodies, transaction narrations) passes through a
context-gated indicator extractor — an account number is harvested only when an account
keyword sits beside it — plus a weighted social-engineering lexicon that scores lure content
and flags phishing-shaped URLs and OTP-stealer permission combinations.

Every extracted fact becomes an `Event` carrying its exhibit id, file name and row number, so
any assertion the system later makes can be traced to a line in an original exhibit.

---

## 4. Graph modelling approach

The entity graph is typed: nodes are PHONE, IMEI, IMSI, ACCOUNT, UPI, IP, MAC, EMAIL, DOMAIN,
APK, DEVICE, PERSON, CELL; edges are typed relations (`FUNDS`, `CALL`, `USES_HANDSET`,
`SIM_IN_HANDSET`, `USED_IP`, `LINKED_VPA`, `REGISTERED_ON`, `INSTALLED`, …), each carrying
count, value, first/last timestamp and its supporting event ids.

**Identity resolution** runs union-find over *one-to-one bindings only* — account↔VPA,
account↔registered mobile, IMEI↔MAC within a single extraction — producing actor clusters that
let a suspect be addressed as one person across rails. Weak signals are excluded from merging
by design and surfaced instead as separate LOW-confidence findings: a shared holder *name*, or
a masked account whose last digits match a known one. This is the central anti-false-link
decision in the system.

**Cross-institution de-duplication.** One transfer is recorded twice — as a debit in the
remitter's statement and a credit in the beneficiary's. Events are matched on
(source, destination, amount, minute ± 1 for clock skew); the duplicate is counted once and
marked *corroborated*, which raises confidence rather than inflating turnover. Without this,
every mule's throughput doubles and every pass-through ratio is wrong.

**Correlation rules (13)** include: shared handset across MSISDNs; high-velocity SIM rotation;
handset hopping; shared public IP; shared /24 subnet; shared MAC or device identifier;
recurring beneficiary fan-in; identical APK SHA-256 under different package names; malicious
permission profiles; domain pivots joining delivery, victim and operator; telecom↔financial
bridge identifiers; name-collision and masked-account candidates (both LOW confidence); and
probable-additional-victim detection.

**Fund-trail tracing** walks `FUNDS` edges outward from the victim's financial nodes, following
each edge **only forward in time**, so the chain is an evidentiary narrative rather than a
topological guess. Each hop records amount, timestamp and the latency since the credit that
funded it; terminal nodes are classified as ATM/cash or crypto/P2P cash-out points. Nodes are
assigned a layer number, which drives both the brief and the dashboard's layered flow view.

---

## 5. Triage & risk scoring

Seventeen heuristics, each encoding something an experienced cyber-cell IO does by hand:
pass-through ratio and retained balance; layering latency bands (≤30 / ≤60 / ≤180 min);
fan-out to multiple beneficiaries; recurring-beneficiary fan-in; structuring just below round
reporting thresholds; repeated identical amounts; nocturnal operation; burst velocity;
terminal cash-out and crypto exit; position in the traced chain; **contact with the victim
shortly before the first fraudulent debit**; social-engineering lure authorship; forged email
headers; and malicious-APK hosting.

Contributions are **weighted by the confidence of the finding** (HIGH 1.0, MEDIUM 0.6, LOW 0.3)
and combined on a saturating curve capped at 100, so no single noisy rule can pin an entity at
CRITICAL. Scores roll up to actor clusters; handsets and packages are reported as **seizure
targets**, not suspects. Victims and probable additional victims are capped and excluded from
the ranking.

Nothing is a black box: every score decomposes into reason strings with the event ids behind
them, surfaced in the dashboard and the brief. That is what a defence counsel will test.

---

## 6. Evidentiary integrity

1. Each exhibit is SHA-256 hashed on arrival, copied into a read-only case directory, re-hashed
   after the copy, and the two compared.
2. Every stage appends to a chain-of-custody log recording action, UTC time, officer, exhibit
   and digest. The log is itself SHA-256 sealed so tampering with it is visible.
3. Hashes are **re-verified before every parse and again at report generation**. An exhibit
   whose digest has changed is marked `INTEGRITY_FAIL` and is *not processed* — enforced by
   test, not merely documented.
4. The brief carries the full manifest (SHA-256, MD5 for legacy case-management indexing, size,
   acquisition time, record count, verification status) and the custody log; the report JSON
   carries its own digest.

---

## 7. Output for field units

A one-page PDF brief: amount defrauded and value traced, complainant details, risk-ranked
prime suspects with the two strongest reasons each, the mule chain with per-hop timing and
cash-out points, and prioritised seizure actions naming the authority to approach —
lien-marking requests to bank nodal officers, VPA freezes via NPCI, Sec.91 CrPC notices to
TSPs and ISPs, ATM CCTV and switch-log requisitions, CFSL referral of the APK, CERT-In takedown
requests, I4C escalation. Annexures carry the timeline, the correlation findings and the
exhibit manifest. The same content is exported as JSON for case-management ingestion.

---

## 8. Validation

39 automated tests: identifier normalisation, timestamp and amount parsing across formats,
context-gated extraction, APK and URL triage, tabular readers including XLSX, content-signature
detection for all 12 sample exhibits, CDR serving-subscriber attribution, email spoofing
detection, and a full end-to-end run asserting the planted ground truth — correct fraud total,
correct first-debit identification, single-counted cross-statement transactions, correct
identity clusters, full mule chain to cash-out, victims excluded from the suspect ranking, and
a tampered exhibit rejected. Full triage of the 12-exhibit case completes in **under one
second**.
