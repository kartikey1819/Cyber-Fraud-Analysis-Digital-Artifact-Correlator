# Forensic notes: heuristics, weights and evidentiary handling

Reference for the choices encoded in `cfc/risk.py` and `cfc/correlate.py`, kept separate so an
IO or a reviewing officer can audit the reasoning without reading Python.

## 1. Why links are *not* made

The damaging failure mode of a correlation tool is not a missed link — it is an asserted link
that is wrong. Three rules follow from that:

| Weak signal | Handling |
|---|---|
| Two accounts share a holder **name** | Never merged. Raised as `NAME-REUSE-*`, severity LOW, confidence LOW, with an instruction to verify against PAN/Aadhaar seeding or bank KYC. |
| A masked account (`XXXXXX7890`) matches a known account's last digits | Never merged. Kept as a separate node, raised as `MASKED-MATCH-*` with an instruction to issue a Sec.91 CrPC notice to resolve the full number. |
| An account number appears in free text | Harvested only when an account keyword sits beside it. A bare 12-digit number in a chat is not an account. |

Identity **merging** happens only across bindings that are one-to-one in the source data:
account ↔ its own VPA, account ↔ registered mobile, IMEI ↔ MAC within a single extraction.

## 2. Identifier normalisation

- **MSISDN** → bare 10-digit subscriber number; `91`/`0` trunk prefixes stripped. Short codes
  (`1930`) and alphanumeric sender IDs (`VM-HDFCBK`) are preserved verbatim so they cannot
  collide with subscriber numbers.
- **IMEI** → first **14 digits** (TAC + serial). The 15th is a Luhn check digit, the 16th an
  IMEISV software version; both change while the handset does not, so correlating on the full
  string would split one handset into several. A 15-digit IMEI failing its Luhn check is
  flagged as a possible reflashed or spoofed handset.
- **VPA vs email** — a VPA handle's host contains no dot; `ramesh@gmail.com` is an email,
  `sanjay.y@okaxis` is a VPA.
- **Timestamps** normalised to IST (UTC+05:30) from ISO-8601, epoch seconds/milliseconds,
  RFC-2822 and the common Indian telecom/bank layouts.

## 3. Serving-subscriber attribution in CDRs

CDR exports disagree about the A-party column on an **incoming** record: some place the subject
subscriber there, others the caller. Attaching the row's IMEI/IMSI/cell to the wrong party
links a handset to the wrong person.

The subject of each SIM is therefore **inferred**: for every (IMEI, IMSI) pair, the MSISDN that
occurs most often alongside it is the serving subscriber, because the subject of a CDR appears
on every row of it. Device identifiers attach to that number; the direction column is only a
fallback.

## 4. Cross-institution transaction de-duplication

One transfer appears twice — a debit row in the remitter's statement, a credit row in the
beneficiary's. Events are matched on **(source, destination, amount, minute ± 1)**; the ±1
minute tolerance absorbs clock skew between institutions. The duplicate is counted once and
marked *corroborated* — independent recording in two exhibits raises confidence, and is noted
as such, rather than doubling every mule's turnover.

## 5. Risk heuristics and weights

| Code | Weight | Signal |
|---|---|---|
| `LAYER_30` | 22 | Funds moved onward ≤30 min after credit — immediate multi-hop routing |
| `PRE_TXN_CONTACT` | 20 | Called/messaged the victim within 180 min before the first fraudulent debit |
| `PASS_THROUGH` | 18 | ≥75 % of credits forwarded; little or nothing retained |
| `CRYPTO_OUT` | 18 | Terminal exit through a crypto/P2P desk |
| `CASH_OUT` | 16 | Terminal ATM/cash withdrawal — last point before the money leaves the system |
| `SPOOFED_HEADER` | 16 | Return-Path/From mismatch, SPF/DKIM/DMARC failure, brand display-name mismatch |
| `LAYER_60` | 15 | Onward transfer ≤60 min after credit |
| `LURE_SENDER` | 14 | Authored social-engineering content (weighted lexicon, saturating score) |
| `MALWARE_HOST` | 14 | Package with OTP-interception capability |
| `FAN_OUT` | 12 | Splits onward to ≥3 distinct beneficiaries |
| `STRUCTURING` | 12 | ≥3 transfers just below a round reporting threshold |
| `VELOCITY` | 10 | ≥4 transactions inside one 60-minute window |
| `LAYER_180` | 8 | Same-session layering |
| `NIGHT_OPS` | 8 | ≥40 % of activity between 00:00 and 05:00 |
| `IN_TRAIL` | 8 | Sits on the traced chain from the victim |
| `ROUND_SUM` | 5 | Repeated identical transfer amounts |

Correlation findings contribute their own score, **multiplied by confidence** (HIGH 1.0,
MEDIUM 0.6, LOW 0.3) and halved for infrastructure nodes (IP, domain, cell). Totals are
combined on a saturating curve — `100 · (1 − e^(−total/55))` — capped at 100.

**Bands:** CRITICAL ≥ 75 · HIGH ≥ 55 · MEDIUM ≥ 35 · LOW below.

## 6. Who is excluded from the suspect ranking

- **The complainant**, on every identifier, capped at 20.
- **Probable additional victims** — endpoints that only ever remit *into* a fan-in collector,
  show no credits of their own and never cash out. Flagged `ADDL-VICTIM-*` with an instruction
  to obtain a statement, and capped at 25. Scoring them as suspects would put a victim on a
  seizure list; this is the single most damaging false positive the tool could produce.
- **Handsets, SIMs and packages** — reported as seizure and preservation targets, not suspects.

Ordinary spending in the victim's statement is excluded from the fraud total: only debits
inside the reported incident window and material relative to the reported loss are counted.

## 7. Findings requiring external confirmation

- **Shared public IP / /24 subnet** (confidence MEDIUM) — confirm with the ISP that the address
  is not a shared CGNAT pool before relying on co-location.
- **Name reuse, masked-account candidates** (confidence LOW) — confirm against bank KYC.
- **APK triage** is static permission and installer analysis, not behavioural reverse
  engineering; the brief recommends CFSL referral for full analysis.

## 8. Chain of custody

Hash on arrival → read-only copy → re-hash → compare → append to custody log. Digests are
re-verified before every parse and again at report generation; an exhibit whose digest has
changed is marked `INTEGRITY_FAIL` and **is not processed**. The custody log is itself
SHA-256 sealed, and the exported report carries its own digest.

Output is machine-generated triage. Every assertion cites the exhibit and row it derives from
and must be corroborated by the investigating officer before it is relied upon in a report
under Sec.173 CrPC / Sec.193 BNSS.
