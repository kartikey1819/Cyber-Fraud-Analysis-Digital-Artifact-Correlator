"""Multi-source ingestion: artifact-type detection + per-type normalising parsers.

Supported artifacts
    CDR      telecom call detail records      (.csv/.xlsx/.txt)
    IPDR     IP detail records                (.csv/.xlsx/.txt)
    BANK     bank statements / settlement     (.csv/.xlsx)
    UPI      UPI / PSP settlement sheets      (.csv/.xlsx)
    EMAIL    RFC-822 message                  (.eml)
    ANDROID  device / app dump                (.json/.txt)
    CHAT     WhatsApp-style chat export       (.txt)
    COMPLAINT NCRP-style complaint record     (.json)

Type detection is by *content signature*, not by filename, so the officer can
drop in whatever the telco/bank sent without renaming anything.
"""

from __future__ import annotations

import email
import email.policy
import json
import os
import re

from . import model as M
from .evidence import sha256_bytes
from .tabular import has_any, header_keys, pick, read_table
from .textmine import (apk_risk, extract_indicators, lure_score, url_risk)
from .util import (digits, iso, luhn_ok, norm_account, norm_email, norm_imei,
                   norm_imsi, norm_ip, norm_key, norm_mac, norm_msisdn,
                   norm_sha256, norm_upi, parse_amount, parse_ts, short)

# --------------------------------------------------------------------------
# column alias dictionary -- the schema-flexibility layer
# --------------------------------------------------------------------------

A = {
    # --- CDR ---
    "a_party": ["aparty", "apartyno", "apartynumber", "callingnumber", "caller",
                "callingparty", "anumber", "calling", "callingmsisdn", "msisdn",
                "subscriberno", "subscribernumber", "originatingnumber", "servingmsisdn",
                "fromnumber", "sourcenumber", "callerno", "mobileno", "mobilenumber"],
    "b_party": ["bparty", "bpartyno", "bpartynumber", "callednumber", "called",
                "calledparty", "bnumber", "dialednumber", "destinationnumber",
                "terminatingnumber", "otherparty", "tonumber", "targetnumber",
                "calledmsisdn", "receiverno"],
    "call_type": ["calltype", "type", "callcategory", "direction", "eventtype",
                  "servicetype", "ctype", "inout", "incomingoutgoing", "callindicator",
                  "smstype", "usagetype"],
    "start": ["datetime", "calldate", "calldatetime", "starttime", "startdatetime",
              "date", "timestamp", "calltime", "dateandtime", "eventtime",
              "datetimeofcall", "calldateandtime", "txndate", "sessionstarttime",
              "starttimestamp", "datetimestamp", "activitydate", "txntimestamp",
              "transactiontimestamp", "settlementdate", "postingdate", "valuedate",
              "transactiondate", "transactiondatetime", "trandate", "transdate",
              "bookingdate", "txndatetime", "datetimeoftransaction", "logdate"],
    "end": ["endtime", "enddatetime", "sessionendtime", "endtimestamp", "lastseen"],
    "duration": ["duration", "durationsecs", "durationinsec", "dursec", "callduration",
                 "durationseconds", "dur", "durationinseconds", "talktime", "durationsec"],
    "imei": ["imei", "imeinumber", "handsetimei", "equipmentid", "imeino", "deviceimei"],
    "imsi": ["imsi", "imsinumber", "simimsi", "imsino", "simid"],
    "cell": ["cellid", "cgi", "firstcgi", "lastcgi", "cellglobalid", "siteid",
             "towerid", "firstcellid", "firstcellglobalid", "lac", "cellidb"],
    "site": ["siteaddress", "towerlocation", "celllocation", "btsaddress", "towaddress",
             "firstcellsite", "location", "celltowerlocation", "address",
             "cellsiteaddress", "towerlocationaddress"],
    "roaming": ["roaming", "roamingflag", "roamingcircle", "circle", "lsa"],
    "sms_text": ["smstext", "messagetext", "content", "body", "message", "smsbody"],

    # --- IPDR ---
    "private_ip": ["privateip", "privateipaddress", "sourceip", "srcip", "lanip",
                   "useripaddress", "subscriberip", "assignedip", "privateipv4"],
    "public_ip": ["publicip", "natip", "translatedip", "publicipaddress",
                  "translatedsourceip", "natipaddress", "publicipv4", "wanip"],
    "dest_ip": ["destinationip", "destip", "dstip", "serverip", "remoteip",
                "destinationipaddress", "targetip"],
    "dest_port": ["destinationport", "destport", "dstport", "serverport", "remoteport"],
    "src_port": ["sourceport", "srcport", "privateport", "translatedport", "natport",
                 "translatedsourceport", "publicport"],
    "bytes_up": ["dataup", "uplinkvolume", "uploadbytes", "bytesup", "ulvolume", "uplink"],
    "bytes_down": ["datadown", "downlinkvolume", "downloadbytes", "bytesdown",
                   "dlvolume", "downlink"],
    "bytes": ["totalvolume", "bytes", "volume", "datavolume", "totalbytes", "datausage"],
    "apn": ["apn", "accesspointname", "accesspoint"],
    "host": ["url", "domain", "host", "website", "fqdn", "destinationhost", "sni",
             "visitedurl", "websiteurl"],

    # --- BANK ---
    "account": ["accountno", "accountnumber", "acno", "acctno", "account", "acc",
                "sourceaccount", "debitaccount", "payeraccount", "custaccountno",
                "accountid", "acnumber", "accno", "customeraccount"],
    "narration": ["narration", "description", "particulars", "remarks", "details",
                  "txndescription", "narrative", "transactionremarks", "transactiondetails",
                  "descriptionofthetransaction", "purpose"],
    "debit": ["debit", "withdrawal", "withdrawalamt", "dr", "debitamount",
              "withdrawalamount", "withdrawaldr", "debitinr", "amountdebited"],
    "credit": ["credit", "deposit", "depositamt", "cr", "creditamount",
               "depositamount", "depositcr", "creditinr", "amountcredited"],
    "amount": ["amount", "txnamount", "transactionamount", "amt", "value",
               "amountinr", "transactionvalue", "amountrs", "settlementamount"],
    "txn_type": ["txntype", "drcr", "crdr", "transactiontype", "indicator",
                 "debitcredit", "type", "trntype", "dramountcramount"],
    "balance": ["balance", "closingbalance", "availablebalance", "runningbalance",
                "bal", "balanceafter", "closingbal"],
    "ref": ["refno", "referenceno", "utr", "rrn", "transactionid", "txnid",
            "chequeno", "utrno", "transactionref", "referencenumber", "txnrefno",
            "bankreferenceno", "reference"],
    "cp_account": ["beneficiaryaccount", "beneficiaryac", "beneficiaryaccountno",
                   "payeeaccount", "counterpartyaccount", "toaccount", "creditaccount",
                   "destinationaccount", "remitteraccount", "otherpartyaccount",
                   "beneficiaryacno"],
    "cp_name": ["beneficiaryname", "payeename", "counterparty", "toname",
                "remittername", "sendername", "beneficiary", "counterpartyname",
                "otherpartyname", "payeer"],
    "cp_ifsc": ["beneficiaryifsc", "ifsc", "payeeifsc", "toifsc", "ifsccode",
                "beneficiaryifsccode"],
    "bank": ["bank", "bankname", "bankbranch", "branch"],
    "holder": ["accountholder", "customername", "accountname", "holdername",
               "accountholdername", "custname"],
    "channel": ["channel", "mode", "paymentmode", "txnmode", "transactionmode"],
    "ip_addr": ["ipaddress", "loginip", "deviceip", "txnip", "originip", "ip"],
    "device_id": ["deviceid", "device", "handset", "deviceidentifier", "terminalid"],
    "mobile": ["mobile", "mobileno", "registeredmobile", "phone", "contactno",
               "registeredmobileno", "linkedmobile"],

    # --- UPI ---
    "payer_vpa": ["payervpa", "payerupi", "payeraddress", "fromvpa", "remittervpa",
                  "debitvpa", "senderupi", "payervirtualaddress", "payervirtualpaymentaddress",
                  "payervirtualid", "fromupi", "sendervpa"],
    "payee_vpa": ["payeevpa", "payeeupi", "payeeaddress", "tovpa", "beneficiaryvpa",
                  "creditvpa", "receiverupi", "payeevirtualaddress",
                  "payeevirtualpaymentaddress", "toupi", "beneficiaryupi"],
    "payer_account": ["payeraccountno", "payeraccount", "remitteraccountno",
                      "debitaccountno", "senderaccount"],
    "payee_account": ["payeeaccountno", "payeeaccount", "beneficiaryaccountno",
                      "creditaccountno", "receiveraccount"],
    "payer_mobile": ["payermobile", "payermobileno", "remittermobile", "sendermobile"],
    "payee_mobile": ["payeemobile", "payeemobileno", "beneficiarymobile", "receivermobile"],
    "payer_bank": ["payerbank", "remitterbank", "payerpsp", "senderbank"],
    "payee_bank": ["payeebank", "beneficiarybank", "payeepsp", "receiverbank"],
    "payer_name": ["payername", "remittername", "sendername"],
    "payee_name": ["payeename", "beneficiaryname", "receivername"],
    "status": ["status", "txnstatus", "transactionstatus", "responsecode", "result"],
    "app": ["app", "appname", "psp", "pspapp", "payerapp", "application"],
}


def _aliases(*fields):
    out = []
    for f in fields:
        out.extend(A[f])
    return out


def _get(row, km, field):
    return pick(row, km, *A[field])


# --------------------------------------------------------------------------
# artifact type detection
# --------------------------------------------------------------------------

CHAT_LINE = re.compile(
    r"^\[?(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4})[,\s]+(\d{1,2}:\d{2}(?::\d{2})?\s*(?:[AaPp][Mm])?)\]?\s*[-–]?\s*([^:]{1,60}):\s?(.*)$"
)


def detect_type(path: str):
    """Return (artifact_type, hint_dict).  Content first, extension second."""
    ext = os.path.splitext(path)[1].lower()

    if ext == ".eml":
        return "EMAIL", {}

    if ext == ".json":
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                data = json.load(fh)
        except Exception:
            return "UNKNOWN", {}
        keys = {str(k).lower() for k in (data if isinstance(data, dict) else {})}
        if keys & {"complaint", "victim", "complainant", "acknowledgement_no", "ncrp_ack"}:
            return "COMPLAINT", {"data": data}
        if keys & {"device", "installed_packages", "packages", "apps", "device_info",
                   "sim", "sims", "telephony", "network"}:
            return "ANDROID", {"data": data}
        return "ANDROID", {"data": data}

    if ext in (".csv", ".xlsx", ".xlsm", ".tsv", ".txt"):
        if ext == ".txt":
            with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                head = [next(fh, "") for _ in range(60)]
            chat_hits = sum(1 for ln in head if CHAT_LINE.match(ln.strip()))
            if chat_hits >= 3:
                return "CHAT", {}
            joined = "".join(head).lower()
            if any(tok in joined for tok in ("dumpsys", "logcat", "package [", "build.fingerprint",
                                             "android_id", "getprop", "adb shell")):
                return "ANDROID_LOG", {}
        try:
            header, rows = read_table(path)
        except Exception:
            return "UNKNOWN", {}
        if not header:
            return "UNKNOWN", {}
        km = header_keys(header)
        scores = {
            "UPI": 3 * has_any(km, *_aliases("payer_vpa")) + 3 * has_any(km, *_aliases("payee_vpa")),
            "CDR": 3 * has_any(km, *_aliases("a_party")) + 3 * has_any(km, *_aliases("b_party"))
                   + has_any(km, *_aliases("duration")) + has_any(km, *_aliases("call_type"))
                   + has_any(km, *_aliases("cell")),
            "IPDR": 2 * has_any(km, *_aliases("private_ip")) + 2 * has_any(km, *_aliases("public_ip"))
                    + 2 * has_any(km, *_aliases("dest_ip")) + has_any(km, *_aliases("dest_port"))
                    + has_any(km, *_aliases("bytes", "bytes_up", "bytes_down")),
            "BANK": 2 * has_any(km, *_aliases("narration")) + 2 * has_any(km, *_aliases("debit", "credit"))
                    + has_any(km, *_aliases("balance")) + has_any(km, *_aliases("account"))
                    + has_any(km, *_aliases("cp_account", "cp_name")),
        }
        # CDR must not swallow an IPDR that also carries an MSISDN column
        if scores["IPDR"] >= 4:
            scores["CDR"] = max(0, scores["CDR"] - 3)
        best = max(scores, key=scores.get)
        if scores[best] >= 4:
            return best, {"header": header, "rows": rows}
        if scores[best] >= 2:
            return best, {"header": header, "rows": rows, "low_confidence": True}
        return "UNKNOWN", {"header": header, "rows": rows}

    return "UNKNOWN", {}


# --------------------------------------------------------------------------
# parsers -- each returns list[Event]
# --------------------------------------------------------------------------

def parse(path: str, exhibit_id: str, source_name: str, artifact_type=None, hint=None):
    """Parse one exhibit into normalised events."""
    if artifact_type is None:
        artifact_type, hint = detect_type(path)
    hint = hint or {}
    fn = {
        "CDR": parse_cdr,
        "IPDR": parse_ipdr,
        "BANK": parse_bank,
        "UPI": parse_upi,
        "EMAIL": parse_eml,
        "ANDROID": parse_android_json,
        "ANDROID_LOG": parse_android_log,
        "CHAT": parse_chat,
        "COMPLAINT": parse_complaint,
    }.get(artifact_type)
    if fn is None:
        return artifact_type, []
    return artifact_type, fn(path, exhibit_id, source_name, hint)


def _table(path, hint):
    if "rows" in hint:
        return hint["header"], hint["rows"]
    return read_table(path)


_DIR_IN = re.compile(r"(?:^|[^a-z])(incoming|inbound|terminating|in|mtc|mt|smt|rcvd|received)(?:[^a-z]|$)")
_DIR_OUT = re.compile(r"(?:^|[^a-z])(outgoing|outbound|originating|out|moc|mo|smo|sent|dialled|dialed)(?:[^a-z]|$)")


def _call_direction(raw: str):
    """Direction of the event relative to the subscriber whose CDR this is.

    Handles the many spellings telcos use: IN / INCOMING / MTC / SMS-IN / MT /
    A2P-IN, and their outgoing counterparts.
    """
    r = (raw or "").strip().lower()
    if not r:
        return None
    if _DIR_IN.search(r):
        return "IN"
    if _DIR_OUT.search(r):
        return "OUT"
    return None


def _is_sms(raw: str):
    r = (raw or "").lower()
    return "sms" in r or r in ("s", "smt", "smo") or "message" in r


# ---- CDR -----------------------------------------------------------------

def _serving_subscribers(rows, km):
    """Work out which MSISDN each SIM actually belongs to.

    CDR exports disagree about what the A-party column means on an INCOMING
    record -- some put the subject subscriber there, others the caller.  Rather
    than trust the column order, we take the MSISDN that occurs most often
    alongside a given (IMEI, IMSI) pair: the SIM identifies the subscriber, and
    the subject of a CDR appears on every row of it.  Device identifiers are
    then attached to that number, which is what stops handsets being linked to
    the wrong person.
    """
    from collections import Counter, defaultdict
    tally = defaultdict(Counter)
    for row in rows:
        key = (norm_imei(_get(row, km, "imei")), norm_imsi(_get(row, km, "imsi")))
        if key == (None, None):
            continue
        for field in ("a_party", "b_party"):
            num = norm_msisdn(_get(row, km, field))
            if num and num.isdigit() and len(num) == 10:
                tally[key][num] += 1
    return {k: c.most_common(1)[0][0] for k, c in tally.items() if c}


def parse_cdr(path, exhibit, source, hint):
    header, rows = _table(path, hint)
    km = header_keys(header)
    serving = _serving_subscribers(rows, km)
    events = []
    for i, row in enumerate(rows, start=2):
        a = norm_msisdn(_get(row, km, "a_party"))
        b = norm_msisdn(_get(row, km, "b_party"))
        if not a and not b:
            continue
        ctype_raw = _get(row, km, "call_type")
        ts = parse_ts(_get(row, km, "start"))
        dur = _get(row, km, "duration")
        try:
            dur = int(float(digits(dur) or 0))
        except (TypeError, ValueError):
            dur = 0
        imei_raw = _get(row, km, "imei")
        imsi_raw = _get(row, km, "imsi")
        cell = _get(row, km, "cell")
        site = _get(row, km, "site")
        kind = M.SMS if _is_sms(ctype_raw) else M.CALL
        direction = _call_direction(ctype_raw)

        verb = "SMS" if kind == M.SMS else "Call"
        arrow = "→"
        if direction == "IN":
            summary = f"{verb} {b or '?'} {arrow} {a or '?'}"
        else:
            summary = f"{verb} {a or '?'} {arrow} {b or '?'}"
        if kind == M.CALL and dur:
            summary += f" ({dur}s)"

        ev = M.Event(kind, ts, summary, exhibit, source, i)
        ev.attrs = {"duration_sec": dur, "raw_type": ctype_raw, "direction": direction,
                    "cell_id": cell or None, "cell_site": site or None,
                    "roaming": _get(row, km, "roaming") or None}
        na = ev.ent(M.PHONE, a, role="a_party") if a else None
        nb = ev.ent(M.PHONE, b, role="b_party") if b else None

        imei = norm_imei(imei_raw)
        ni = None
        if imei:
            ni = ev.ent(M.IMEI, imei, role="handset", display=str(imei_raw).strip())
            if len(digits(imei_raw)) == 15 and not luhn_ok(imei_raw):
                ev.flag("IMEI fails Luhn check digit — possibly spoofed/reflashed handset")
        imsi = norm_imsi(imsi_raw)
        nm = ev.ent(M.IMSI, imsi, role="sim") if imsi else None
        nc = ev.ent(M.CELL, cell, role="cell", site=site) if cell else None

        if na and nb:
            src, dst = (nb, na) if direction == "IN" else (na, nb)
            ev.link(src, dst, "SMS" if kind == M.SMS else "CALL")
        # The IMEI/IMSI/cell on a CDR row belong to the SERVING subscriber.
        # Prefer the inferred subject of the SIM; fall back to the direction
        # column.  Attaching them to the wrong party is a classic false-link
        # generator.
        subject = serving.get((imei, imsi))
        if subject == a and na:
            owner = na
        elif subject == b and nb:
            owner = nb
        else:
            owner = (nb or na) if direction == "IN" else (na or nb)
        if owner and ni:
            ev.link(owner, ni, "USES_HANDSET")
        if ni and nm:
            ev.link(ni, nm, "SIM_IN_HANDSET")
        if owner and nm:
            ev.link(owner, nm, "USES_SIM")
        if owner and nc:
            ev.link(owner, nc, "SEEN_AT_CELL")

        text = _get(row, km, "sms_text")
        if text:
            ev.attrs["text"] = text
            score, hits = lure_score(text)
            if score >= 35:
                ev.attrs["lure_score"] = score
                ev.attrs["lure_hits"] = hits[:6]
                ev.flag(f"Social-engineering language in SMS (lure score {score})")
            ind = extract_indicators(text)
            for u in ind["urls"]:
                host = re.sub(r"^https?://", "", u).split("/")[0]
                nd = ev.ent(M.DOMAIN, host.lower(), role="linked_domain", url=u)
                if owner and nd:
                    ev.link(owner, nd, "SENT_LINK")
                if url_risk(u):
                    ev.flag(f"Suspicious URL in SMS: {short(u, 70)}")
        events.append(ev)
    return events


# ---- IPDR ----------------------------------------------------------------

def parse_ipdr(path, exhibit, source, hint):
    header, rows = _table(path, hint)
    km = header_keys(header)
    events = []
    for i, row in enumerate(rows, start=2):
        msisdn = norm_msisdn(_get(row, km, "a_party"))
        priv = norm_ip(_get(row, km, "private_ip"))
        pub = norm_ip(_get(row, km, "public_ip"))
        dst = norm_ip(_get(row, km, "dest_ip"))
        ts = parse_ts(_get(row, km, "start"))
        end = parse_ts(_get(row, km, "end"))
        host = _get(row, km, "host")
        if not any([msisdn, priv, pub, dst, host]):
            continue

        up = parse_amount(_get(row, km, "bytes_up")) or 0
        down = parse_amount(_get(row, km, "bytes_down")) or 0
        total = parse_amount(_get(row, km, "bytes")) or (up + down)

        label = host or dst or pub or "data session"
        summary = f"Data session {msisdn or priv or '?'} → {label}"
        ev = M.Event(M.SESSION, ts, summary, exhibit, source, i)
        ev.attrs = {"private_ip": priv, "public_ip": pub, "dest_ip": dst,
                    "dest_port": _get(row, km, "dest_port") or None,
                    "src_port": _get(row, km, "src_port") or None,
                    "apn": _get(row, km, "apn") or None,
                    "bytes": total or None, "end": iso(end), "host": host or None}

        nsub = ev.ent(M.PHONE, msisdn, role="subscriber") if msisdn else None
        npub = ev.ent(M.IP, pub, role="public_ip") if pub else None
        npriv = ev.ent(M.IP, priv, role="private_ip") if priv else None
        ndst = ev.ent(M.IP, dst, role="dest_ip") if dst else None
        imei = norm_imei(_get(row, km, "imei"))
        ni = ev.ent(M.IMEI, imei, role="handset") if imei else None
        imsi = norm_imsi(_get(row, km, "imsi"))
        nm = ev.ent(M.IMSI, imsi, role="sim") if imsi else None

        nd = None
        if host:
            hostname = re.sub(r"^https?://", "", host).split("/")[0].lower()
            nd = ev.ent(M.DOMAIN, hostname, role="destination")
            risks = url_risk(host)
            if risks:
                ev.flag("Suspicious destination: " + "; ".join(risks))

        for node in (npub, npriv):
            if nsub and node:
                ev.link(nsub, node, "USED_IP")
        if nsub and ni:
            ev.link(nsub, ni, "USES_HANDSET")
        if ni and nm:
            ev.link(ni, nm, "SIM_IN_HANDSET")
        if nsub and nd:
            ev.link(nsub, nd, "CONNECTED_TO")
        if npub and ndst:
            ev.link(npub, ndst, "CONNECTED_TO")
        events.append(ev)
    return events


# ---- BANK ----------------------------------------------------------------

CASHOUT_TOKENS = ("atm", "cash wdl", "cash withdrawal", "cwdr", "nwd", "cash-wdl",
                  "atw", "cashpoint", "wdl", "cash dep")
CRYPTO_TOKENS = ("binance", "wazirx", "coindcx", "crypto", "usdt", "bitcoin", "p2p")


def parse_bank(path, exhibit, source, hint):
    header, rows = _table(path, hint)
    km = header_keys(header)
    events = []
    file_account, _ = norm_account(_find_statement_account(rows, km))
    for i, row in enumerate(rows, start=2):
        acct_raw = _get(row, km, "account") or ""
        acct, masked = norm_account(acct_raw)
        acct = acct or file_account
        ts = parse_ts(_get(row, km, "start"))
        narration = _get(row, km, "narration")
        debit = parse_amount(_get(row, km, "debit"))
        credit = parse_amount(_get(row, km, "credit"))
        amount = parse_amount(_get(row, km, "amount"))
        ttype = (_get(row, km, "txn_type") or "").strip().upper()

        if debit and credit and debit == credit:
            credit = None
        if debit:
            direction, value = "DR", abs(debit)
        elif credit:
            direction, value = "CR", abs(credit)
        elif amount is not None:
            if ttype.startswith("D") or ttype in ("DR", "DEBIT", "W"):
                direction, value = "DR", abs(amount)
            elif ttype.startswith("C") or ttype in ("CR", "CREDIT", "D"):
                direction, value = "CR", abs(amount)
            else:
                direction, value = ("DR", abs(amount)) if amount < 0 else ("CR", abs(amount))
        else:
            continue
        if not value:
            continue

        cp_acct_raw = _get(row, km, "cp_account")
        cp_acct, cp_masked = norm_account(cp_acct_raw)
        cp_name = _get(row, km, "cp_name")
        ref = _get(row, km, "ref")
        chan = _get(row, km, "channel")
        bal = parse_amount(_get(row, km, "balance"))
        low_nar = (narration or "").lower()

        # counterparty VPA can hide inside the narration (UPI/xxxx@ybl/...)
        cp_vpa = None
        for token in re.split(r"[\s/|,;]+", narration or ""):
            v = norm_upi(token)
            if v:
                cp_vpa = v
                break
        if not cp_vpa:
            for ind in extract_indicators(narration or "")["vpas"]:
                cp_vpa = ind
                break

        who = cp_name or cp_vpa or (cp_acct_raw or "counterparty")
        summary = (f"₹ debit from A/c {acct or '?'} → {short(who, 34)}" if direction == "DR"
                   else f"₹ credit to A/c {acct or '?'} ← {short(who, 34)}")
        ev = M.Event(M.TXN, ts, summary, exhibit, source, i)
        ev.amount = value
        ev.direction = direction
        ev.attrs = {"narration": narration or None, "reference": ref or None,
                    "channel": chan or None, "balance": bal, "rail": "BANK",
                    "counterparty_name": cp_name or None,
                    "counterparty_ifsc": _get(row, km, "cp_ifsc") or None,
                    "bank": _get(row, km, "bank") or None}

        holder = _get(row, km, "holder")
        nacct = ev.ent(M.ACCOUNT, acct, role="subject_account", masked=masked,
                       holder=holder, bank=_get(row, km, "bank"),
                       display=acct_raw or acct) if acct else None
        ncp = ev.ent(M.ACCOUNT, cp_acct, role="counterparty_account", masked=cp_masked,
                     holder=cp_name, ifsc=_get(row, km, "cp_ifsc"),
                     display=cp_acct_raw or cp_acct) if cp_acct else None
        nvpa = ev.ent(M.UPI, cp_vpa, role="counterparty_vpa", holder=cp_name) if cp_vpa else None
        nper = ev.ent(M.PERSON, cp_name.strip().title(), role="counterparty") if cp_name else None
        nholder = ev.ent(M.PERSON, holder.strip().title(), role="account_holder") if holder else None
        nip = ev.ent(M.IP, norm_ip(_get(row, km, "ip_addr")), role="txn_ip")
        mob = norm_msisdn(_get(row, km, "mobile"))
        nmob = ev.ent(M.PHONE, mob, role="registered_mobile") if mob else None

        if nacct:
            ev.attrs["flow"] = {"node": nacct, "direction": direction, "amount": value}

        counter = ncp or nvpa
        if nacct and counter:
            if direction == "DR":
                ev.link(nacct, counter, "FUNDS", amount=value)
            else:
                ev.link(counter, nacct, "FUNDS", amount=value)
        if ncp and nvpa:
            ev.link(ncp, nvpa, "LINKED_VPA", directed=False)
        if nper and (ncp or nvpa):
            ev.link(nper, ncp or nvpa, "HOLDS", directed=False)
        if nholder and nacct:
            ev.link(nholder, nacct, "HOLDS", directed=False)
        if nacct and nip:
            ev.link(nacct, nip, "TXN_FROM_IP")
        if nacct and nmob:
            ev.link(nmob, nacct, "REGISTERED_ON", directed=False)

        if any(t in low_nar for t in CASHOUT_TOKENS) or (chan or "").lower() in ("atm", "cash"):
            ev.attrs["cashout"] = True
            ev.flag("Cash-out channel (ATM/cash withdrawal)")
        if any(t in low_nar for t in CRYPTO_TOKENS):
            ev.attrs["crypto"] = True
            ev.flag("Crypto / P2P exchange counterparty")
        events.append(ev)
    return events


def _find_statement_account(rows, km):
    """Statements often carry the account number once, in a banner row."""
    col = None
    for alias in A["account"]:
        if alias in km:
            col = km[alias]
            break
    if col:
        for r in rows[:5]:
            if str(r.get(col, "")).strip():
                return r[col]
    for r in rows[:8]:
        for v in r.values():
            m = re.search(r"(?:a/?c|account)\s*(?:no\.?|number)?\s*[:\-]?\s*(\d{9,18})",
                          str(v), re.I)
            if m:
                return m.group(1)
    return ""


# ---- UPI -----------------------------------------------------------------

def parse_upi(path, exhibit, source, hint):
    header, rows = _table(path, hint)
    km = header_keys(header)
    events = []
    for i, row in enumerate(rows, start=2):
        payer = norm_upi(_get(row, km, "payer_vpa"))
        payee = norm_upi(_get(row, km, "payee_vpa"))
        if not payer and not payee:
            continue
        value = parse_amount(_get(row, km, "amount"))
        ts = parse_ts(_get(row, km, "start"))
        status = (_get(row, km, "status") or "").upper()
        ref = _get(row, km, "ref")

        summary = f"UPI {payer or '?'} → {payee or '?'}"
        ev = M.Event(M.TXN, ts, summary, exhibit, source, i)
        ev.amount = abs(value) if value else None
        ev.direction = "DR"
        ev.attrs = {"rail": "UPI", "status": status or None, "reference": ref or None,
                    "app": _get(row, km, "app") or None,
                    "payer_bank": _get(row, km, "payer_bank") or None,
                    "payee_bank": _get(row, km, "payee_bank") or None,
                    "narration": _get(row, km, "narration") or None}

        npayer = ev.ent(M.UPI, payer, role="payer_vpa",
                        holder=_get(row, km, "payer_name"),
                        bank=_get(row, km, "payer_bank")) if payer else None
        npayee = ev.ent(M.UPI, payee, role="payee_vpa",
                        holder=_get(row, km, "payee_name"),
                        bank=_get(row, km, "payee_bank")) if payee else None

        pa, pa_masked = norm_account(_get(row, km, "payer_account"))
        ea, ea_masked = norm_account(_get(row, km, "payee_account"))
        npa = ev.ent(M.ACCOUNT, pa, role="payer_account", masked=pa_masked,
                     holder=_get(row, km, "payer_name"),
                     bank=_get(row, km, "payer_bank")) if pa else None
        nea = ev.ent(M.ACCOUNT, ea, role="payee_account", masked=ea_masked,
                     holder=_get(row, km, "payee_name"),
                     bank=_get(row, km, "payee_bank")) if ea else None

        pm = norm_msisdn(_get(row, km, "payer_mobile"))
        em = norm_msisdn(_get(row, km, "payee_mobile"))
        npm = ev.ent(M.PHONE, pm, role="payer_mobile") if pm else None
        nem = ev.ent(M.PHONE, em, role="payee_mobile") if em else None
        nip = ev.ent(M.IP, norm_ip(_get(row, km, "ip_addr")), role="txn_ip")
        dev = _get(row, km, "device_id")
        ndev = ev.ent(M.DEVICE, dev, role="device") if dev else None

        for name_field, node in (("payer_name", npayer), ("payee_name", npayee)):
            nm = _get(row, km, name_field)
            if nm and node:
                nper = ev.ent(M.PERSON, nm.strip().title(), role=name_field)
                ev.link(nper, node, "HOLDS", directed=False)

        if npayer and npayee and status in ("", "SUCCESS", "S", "COMPLETED", "OK", "00"):
            ev.link(npayer, npayee, "FUNDS", amount=ev.amount)
        if npa and npayer:
            ev.link(npa, npayer, "LINKED_VPA", directed=False)
        if nea and npayee:
            ev.link(nea, npayee, "LINKED_VPA", directed=False)
        if npm and npayer:
            ev.link(npm, npayer, "REGISTERED_ON", directed=False)
        if nem and npayee:
            ev.link(nem, npayee, "REGISTERED_ON", directed=False)
        if npayer and nip:
            ev.link(npayer, nip, "TXN_FROM_IP")
        if npayer and ndev:
            ev.link(npayer, ndev, "USED_DEVICE")
        if status and status not in ("SUCCESS", "S", "COMPLETED", "OK", "00"):
            ev.flag(f"UPI transaction status = {status}")
        events.append(ev)
    return events


# ---- EMAIL (.eml) --------------------------------------------------------

AUTH_FAIL = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(fail|softfail|none|permerror|temperror|neutral)\b", re.I)


def parse_eml(path, exhibit, source, hint):
    with open(path, "rb") as fh:
        msg = email.message_from_binary_file(fh, policy=email.policy.default)

    frm = norm_email(_addr(msg.get("From")))
    ret = norm_email(_addr(msg.get("Return-Path")))
    reply = norm_email(_addr(msg.get("Reply-To")))
    to = [norm_email(a) for a in re.split(r"[,;]", msg.get("To", "") or "")]
    to = [t for t in to if t]
    ts = parse_ts(msg.get("Date"))
    subject = str(msg.get("Subject", "") or "")

    ev = M.Event(M.EMAIL_MSG, ts, f"Email: {short(subject, 48)}", exhibit, source, 1)
    body = _body_text(msg)
    ev.attrs = {"subject": subject, "from": frm, "return_path": ret, "reply_to": reply,
                "to": to, "message_id": msg.get("Message-ID"),
                "display_name": _display_name(msg.get("From")),
                "body_excerpt": short(body.replace("\n", " "), 400)}

    nfrom = ev.ent(M.EMAIL, frm, role="sender") if frm else None
    for t in to:
        nt = ev.ent(M.EMAIL, t, role="recipient")
        if nfrom and nt:
            ev.link(nfrom, nt, "EMAILED")
    if ret and ret != frm:
        nret = ev.ent(M.EMAIL, ret, role="return_path")
        ev.flag(f"Envelope mismatch: Return-Path <{ret}> != From <{frm}> — header spoofing indicator")
        if nfrom and nret:
            ev.link(nret, nfrom, "SPOOFS", directed=False)
    if reply and frm and reply != frm:
        ev.ent(M.EMAIL, reply, role="reply_to")
        ev.flag(f"Reply-To <{reply}> diverted away from From <{frm}>")

    # authentication results
    auth = " ".join(str(v) for v in msg.get_all("Authentication-Results", []) or [])
    auth += " " + " ".join(str(v) for v in msg.get_all("Received-SPF", []) or [])
    fails = {m.group(1).upper(): m.group(2).lower() for m in AUTH_FAIL.finditer(auth)}
    if fails:
        ev.attrs["auth_failures"] = fails
        ev.flag("Sender authentication failed: " +
                ", ".join(f"{k}={v}" for k, v in sorted(fails.items())))

    # display-name vs domain impersonation
    disp = (ev.attrs.get("display_name") or "").lower()
    if frm and disp:
        dom = frm.split("@")[1]
        for brand in ("sbi", "hdfc", "icici", "axis", "kotak", "paytm", "npci", "rbi"):
            if brand in disp and brand not in dom:
                ev.flag(f"Display name claims '{brand.upper()}' but domain is '{dom}'")
                break

    # Received chain -> originating IPs
    hops = msg.get_all("Received", []) or []
    ips = []
    for h in hops:
        for m in re.finditer(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?", str(h)):
            ip = norm_ip(m.group(1))
            if ip and ip not in ips:
                ips.append(ip)
    xoip = norm_ip(msg.get("X-Originating-IP", "").strip("[] "))
    if xoip and xoip not in ips:
        ips.insert(0, xoip)
    ev.attrs["received_hops"] = len(hops)
    ev.attrs["originating_ips"] = ips
    for ip in ips:
        nip = ev.ent(M.IP, ip, role="originating_ip")
        if nfrom and nip:
            ev.link(nfrom, nip, "SENT_FROM_IP")

    if frm:
        ndom = ev.ent(M.DOMAIN, frm.split("@")[1], role="sender_domain")
        if nfrom and ndom:
            ev.link(nfrom, ndom, "ON_DOMAIN", directed=False)

    # body intelligence
    score, hits = lure_score(subject + "\n" + body)
    if score:
        ev.attrs["lure_score"] = score
        ev.attrs["lure_hits"] = hits[:8]
    if score >= 40:
        ev.flag(f"Phishing / social-engineering language (lure score {score})")

    ind = extract_indicators(subject + "\n" + body)
    for u in ind["urls"]:
        host = re.sub(r"^https?://", "", u).split("/")[0].lower()
        nd = ev.ent(M.DOMAIN, host, role="payload_host", url=u)
        if nfrom and nd:
            ev.link(nfrom, nd, "LINKS_TO")
        risks = url_risk(u)
        if risks:
            ev.flag(f"Malicious-shaped URL {short(u, 60)}: " + "; ".join(risks))
    for ph in ind["phones"]:
        np_ = ev.ent(M.PHONE, ph, role="contact_in_body")
        if nfrom and np_:
            ev.link(nfrom, np_, "MENTIONS")
    for v in ind["vpas"]:
        nv = ev.ent(M.UPI, v, role="vpa_in_body")
        if nfrom and nv:
            ev.link(nfrom, nv, "MENTIONS")

    events = [ev]

    # attachments
    for part in msg.walk():
        fname = part.get_filename()
        if not fname:
            continue
        payload = part.get_payload(decode=True) or b""
        digest = sha256_bytes(payload)
        aev = M.Event(M.APP, ts, f"Email attachment: {fname}", exhibit, source, 1)
        aev.attrs = {"filename": fname, "sha256": digest, "size": len(payload),
                     "content_type": part.get_content_type(), "from": frm}
        na = aev.ent(M.APK, fname.lower(), role="attachment", sha256=digest) \
            if fname.lower().endswith(".apk") else None
        if na:
            aev.flag("APK delivered as email attachment — probable malware dropper")
            if frm:
                sender = aev.ent(M.EMAIL, frm, role="sender")
                aev.link(sender, na, "DELIVERED")
        events.append(aev)
    return events


def _addr(value):
    if not value:
        return ""
    m = re.search(r"<([^>]+)>", str(value))
    return (m.group(1) if m else str(value)).strip()


def _display_name(value):
    if not value:
        return ""
    s = str(value)
    m = re.match(r'\s*"?([^"<]+)"?\s*<', s)
    return (m.group(1).strip() if m else "")


def _body_text(msg):
    chunks = []
    for part in msg.walk():
        if part.get_content_maintype() != "text":
            continue
        if part.get_filename():
            continue
        try:
            text = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            text = payload.decode("utf-8", errors="replace")
        if part.get_content_subtype() == "html":
            text = re.sub(r"<a[^>]+href=\"([^\"]+)\"[^>]*>", r" \1 ", text, flags=re.I)
            text = re.sub(r"<[^>]+>", " ", text)
        chunks.append(text)
    return "\n".join(chunks)


# ---- Android dump (JSON) -------------------------------------------------

def _find(data, *names):
    """Case-insensitive nested lookup for the first matching key."""
    if not isinstance(data, dict):
        return None
    low = {str(k).lower(): v for k, v in data.items()}
    for n in names:
        if n in low:
            return low[n]
    for v in data.values():
        if isinstance(v, dict):
            got = _find(v, *names)
            if got is not None:
                return got
    return None


def parse_android_json(path, exhibit, source, hint):
    data = hint.get("data")
    if data is None:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            data = json.load(fh)
    events = []
    dev = _find(data, "device", "device_info", "deviceinfo") or data
    extracted = parse_ts(_find(data, "extraction_time", "extracted_at", "dump_time",
                               "acquisition_time", "timestamp"))

    model = _find(dev, "model", "device_model") or ""
    maker = _find(dev, "manufacturer", "make", "brand") or ""
    label = (f"{maker} {model}").strip() or "device"

    ev = M.Event(M.DEVICE_OBS, extracted, f"Device extraction: {label}", exhibit, source, 1)
    ev.attrs = {"model": model, "manufacturer": maker,
                "android_version": _find(dev, "android_version", "os_version", "release"),
                "serial": _find(dev, "serial", "serial_no", "serialnumber"),
                "android_id": _find(dev, "android_id", "androidid"),
                "owner": _find(data, "owner", "seized_from", "custodian", "subject")}

    anchor = None
    imei_vals = _find(dev, "imei", "imeis", "imei_list") or []
    if isinstance(imei_vals, (str, int)):
        imei_vals = [imei_vals]
    imei_nodes = []
    for raw in imei_vals:
        n = norm_imei(raw)
        if n:
            node = ev.ent(M.IMEI, n, role="device_imei", display=str(raw))
            imei_nodes.append(node)
            anchor = anchor or node
            if len(digits(raw)) == 15 and not luhn_ok(raw):
                ev.flag(f"IMEI {raw} fails Luhn check — possible reflashed handset")

    wifi_mac = norm_mac(_find(dev, "wifi_mac", "wlan_mac", "mac_address", "mac"))
    bt_mac = norm_mac(_find(dev, "bluetooth_mac", "bt_mac"))
    for mac, role in ((wifi_mac, "wifi_mac"), (bt_mac, "bluetooth_mac")):
        nm = ev.ent(M.MAC, mac, role=role) if mac else None
        anchor = anchor or nm
        for n in imei_nodes:
            if nm:
                ev.link(n, nm, "DEVICE_INTERFACE", directed=False)

    aid = _find(dev, "android_id", "androidid")
    nid = ev.ent(M.DEVICE, str(aid), role="android_id") if aid else None
    for n in imei_nodes:
        if nid:
            ev.link(n, nid, "DEVICE_INTERFACE", directed=False)
    events.append(ev)

    # SIMs
    sims = _find(data, "sim", "sims", "sim_cards", "telephony") or []
    if isinstance(sims, dict):
        sims = [sims]
    for idx, sim in enumerate(sims, start=1):
        if not isinstance(sim, dict):
            continue
        msisdn = norm_msisdn(_find(sim, "msisdn", "number", "phone", "phone_number", "line_number"))
        imsi = norm_imsi(_find(sim, "imsi"))
        iccid = _find(sim, "iccid")
        first_seen = parse_ts(_find(sim, "first_seen", "inserted", "activated_on", "insert_time"))
        sev = M.Event(M.DEVICE_OBS, first_seen or extracted,
                      f"SIM in slot {_find(sim, 'slot') or idx}: {msisdn or imsi or iccid or '?'}",
                      exhibit, source, 1)
        sev.attrs = {"operator": _find(sim, "operator", "carrier", "spn"),
                     "iccid": iccid, "slot": _find(sim, "slot") or idx,
                     "removed": _find(sim, "removed", "removed_on")}
        np_ = sev.ent(M.PHONE, msisdn, role="device_msisdn") if msisdn else None
        nims = sev.ent(M.IMSI, imsi, role="device_imsi") if imsi else None
        for n in imei_nodes:
            if np_:
                sev.link(np_, n, "USES_HANDSET")
            if nims:
                sev.link(n, nims, "SIM_IN_HANDSET")
        if np_ and nims:
            sev.link(np_, nims, "USES_SIM")
        events.append(sev)

    # installed packages
    pkgs = _find(data, "installed_packages", "packages", "apps", "applications") or []
    for pkg in pkgs:
        if not isinstance(pkg, dict):
            pkg = {"package": str(pkg)}
        name = _find(pkg, "package", "package_name", "pkg", "name") or ""
        if not name:
            continue
        perms = _find(pkg, "permissions", "perms", "granted_permissions") or []
        if isinstance(perms, str):
            perms = [p.strip() for p in re.split(r"[,\s]+", perms) if p.strip()]
        installer = _find(pkg, "installer", "installer_package", "install_source") or ""
        apk_hash = norm_sha256(_find(pkg, "sha256", "apk_sha256", "hash", "digest"))
        installed = parse_ts(_find(pkg, "install_time", "installed_on", "first_install_time",
                                   "installed", "install_date"))
        score, reasons = apk_risk(name, perms, installer, _find(pkg, "flags") or [])

        pev = M.Event(M.APP, installed or extracted, f"App installed: {name}",
                      exhibit, source, 1)
        pev.attrs = {"package": name, "label": _find(pkg, "label", "app_name", "title"),
                     "version": _find(pkg, "version", "version_name"),
                     "installer": installer or None, "sha256": apk_hash,
                     "permissions": perms, "apk_risk": score, "apk_reasons": reasons,
                     "path": _find(pkg, "path", "apk_path")}
        napk = pev.ent(M.APK, name.lower(), role="package", sha256=apk_hash,
                       label=_find(pkg, "label", "app_name"), risk=score)
        for n in imei_nodes:
            if napk:
                pev.link(n, napk, "INSTALLED")
        if nid and napk:
            pev.link(nid, napk, "INSTALLED")
        if score >= 55:
            pev.flag(f"High-risk package (score {score}): " + "; ".join(reasons[:3]))
        for host in (_find(pkg, "c2", "c2_domain", "network_endpoints", "endpoints",
                           "contacted_hosts") or []):
            h = re.sub(r"^https?://", "", str(host)).split("/")[0].lower()
            nd = pev.ent(M.DOMAIN, h, role="c2_endpoint")
            if napk and nd:
                pev.link(napk, nd, "CONTACTS")
                pev.flag(f"Package {name} contacts external endpoint {h}")
        events.append(pev)

    # SMS store
    for sms in (_find(data, "sms", "messages", "sms_messages") or []):
        if not isinstance(sms, dict):
            continue
        body = _find(sms, "body", "text", "message") or ""
        addr = _find(sms, "address", "from", "sender", "number") or ""
        ts = parse_ts(_find(sms, "date", "timestamp", "time", "received"))
        score, hits = lure_score(body)
        sev = M.Event(M.SMS, ts, f"Device SMS from {addr}: {short(body, 40)}",
                      exhibit, source, 1)
        sev.attrs = {"address": addr, "text": body, "lure_score": score,
                     "lure_hits": hits[:6], "folder": _find(sms, "type", "folder")}
        folder = str(_find(sms, "type", "folder") or "").lower()
        outbound = folder in ("sent", "outbox", "2", "outgoing")
        peer = norm_msisdn(addr)
        # On a SENT message the stored address is the RECIPIENT -- attributing
        # the lure text to them would score a victim as the sender.
        nsend = sev.ent(M.PHONE, peer,
                        role="sms_recipient" if outbound else "sms_peer") if peer else None
        if outbound and score >= 40:
            sev.flag(f"Lure message SENT from this device to {addr}")
        ind = extract_indicators(body)
        for u in ind["urls"]:
            h = re.sub(r"^https?://", "", u).split("/")[0].lower()
            nd = sev.ent(M.DOMAIN, h, role="sms_link", url=u)
            if nsend and nd:
                sev.link(nsend, nd, "SENT_LINK")
            if url_risk(u):
                sev.flag(f"Malicious-shaped link in SMS: {short(u, 60)}")
        for v in ind["vpas"]:
            sev.ent(M.UPI, v, role="vpa_in_sms")
        if score >= 40:
            sev.flag(f"OTP/KYC lure language in device SMS (score {score})")
        events.append(sev)

    # browser / download history
    for item in (_find(data, "browser_history", "downloads", "history") or []):
        if not isinstance(item, dict):
            continue
        url = _find(item, "url", "link", "uri") or ""
        ts = parse_ts(_find(item, "time", "timestamp", "date", "visited"))
        dev_ev = M.Event(M.SESSION, ts, f"Browser: {short(url, 52)}", exhibit, source, 1)
        host = re.sub(r"^https?://", "", url).split("/")[0].lower()
        dev_ev.attrs = {"url": url, "title": _find(item, "title")}
        nd = dev_ev.ent(M.DOMAIN, host, role="visited") if host else None
        for n in imei_nodes:
            if nd:
                dev_ev.link(n, nd, "CONNECTED_TO")
        risks = url_risk(url)
        if risks:
            dev_ev.flag("Suspicious browsing: " + "; ".join(risks))
        events.append(dev_ev)

    return events


def parse_android_log(path, exhibit, source, hint):
    """Tolerant scraper for textual device dumps (dumpsys / getprop / logcat)."""
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        text = fh.read()
    ev = M.Event(M.DEVICE_OBS, None, f"Android text dump: {os.path.basename(path)}",
                 exhibit, source, 1)
    ind = extract_indicators(text)
    imeis = []
    for m in re.finditer(r"(?:imei|device\s*id)\D{0,12}(\d{14,16})", text, re.I):
        n = norm_imei(m.group(1))
        if n and n not in imeis:
            imeis.append(n)
    nodes = [ev.ent(M.IMEI, n, role="device_imei") for n in imeis]
    for m in re.finditer(r"(?:hwaddr|mac|wlan0)\D{0,12}([0-9a-f]{2}(?::[0-9a-f]{2}){5})", text, re.I):
        nm = ev.ent(M.MAC, norm_mac(m.group(1)), role="wifi_mac")
        for n in nodes:
            if nm:
                ev.link(n, nm, "DEVICE_INTERFACE", directed=False)
    ev.attrs = {"indicators": {k: v for k, v in ind.items() if v}}
    events = [ev]
    for pkg in ind["packages"][:200]:
        pev = M.Event(M.APP, None, f"Package present: {pkg}", exhibit, source, 1)
        napk = pev.ent(M.APK, pkg, role="package")
        for n in nodes:
            if napk:
                pev.link(n, napk, "INSTALLED")
        events.append(pev)
    return events


# ---- Chat export ---------------------------------------------------------

def parse_chat(path, exhibit, source, hint):
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        lines = fh.read().splitlines()
    events, buffer = [], None

    def flush(buf):
        if buf is None:
            return
        ts, sender, text, lineno = buf
        ev = M.Event(M.CHAT, ts, f"{sender}: {short(text, 52)}", exhibit, source, lineno)
        score, hits = lure_score(text)
        ev.attrs = {"sender": sender, "text": text, "lure_score": score, "lure_hits": hits[:6]}
        sp = norm_msisdn(sender)
        nsend = ev.ent(M.PHONE, sp, role="chat_sender") if sp else \
            ev.ent(M.PERSON, sender.strip().title(), role="chat_sender")
        ind = extract_indicators(text)
        for ph in ind["phones"]:
            n = ev.ent(M.PHONE, ph, role="phone_in_chat")
            if nsend and n:
                ev.link(nsend, n, "MENTIONS")
        for v in ind["vpas"]:
            n = ev.ent(M.UPI, v, role="vpa_in_chat")
            if nsend and n:
                ev.link(nsend, n, "MENTIONS")
            ev.flag(f"UPI handle exchanged in chat: {v}")
        for acc in ind["accounts"]:
            n = ev.ent(M.ACCOUNT, acc, role="account_in_chat")
            if nsend and n:
                ev.link(nsend, n, "MENTIONS")
            ev.flag(f"Bank account number exchanged in chat: {acc}")
        for u in ind["urls"]:
            host = re.sub(r"^https?://", "", u).split("/")[0].lower()
            n = ev.ent(M.DOMAIN, host, role="url_in_chat", url=u)
            if nsend and n:
                ev.link(nsend, n, "SENT_LINK")
            if url_risk(u):
                ev.flag(f"Suspicious link shared: {short(u, 60)}")
        for em in ind["emails"]:
            ev.ent(M.EMAIL, em, role="email_in_chat")
        if score >= 40:
            ev.flag(f"Mule-recruitment / lure language (score {score})")
        if ind["amounts"]:
            ev.attrs["amounts_mentioned"] = ind["amounts"][:10]
        events.append(ev)

    for i, line in enumerate(lines, start=1):
        m = CHAT_LINE.match(line.strip())
        if m:
            flush(buffer)
            date_s, time_s, sender, text = m.groups()
            buffer = (parse_ts(f"{date_s} {time_s}"), sender.strip(), text.strip(), i)
        elif buffer is not None and line.strip():
            ts, sender, text, lineno = buffer
            buffer = (ts, sender, text + " " + line.strip(), lineno)
    flush(buffer)
    return events


# ---- Complaint (NCRP-style JSON) ----------------------------------------

def parse_complaint(path, exhibit, source, hint):
    data = hint.get("data")
    if data is None:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            data = json.load(fh)
    victim = _find(data, "victim", "complainant") or {}
    ts = parse_ts(_find(data, "incident_time", "incident_datetime", "reported_at",
                        "complaint_time", "date_of_incident"))
    amount = parse_amount(_find(data, "amount", "fraud_amount", "amount_lost",
                                "disputed_amount", "loss_amount"))
    name = _find(victim, "name", "complainant_name") or "Complainant"

    ev = M.Event(M.COMPLAINT, ts, f"Complaint lodged by {name}", exhibit, source, 1)
    ev.amount = amount
    ev.attrs = {
        "acknowledgement_no": _find(data, "acknowledgement_no", "ack_no", "ncrp_ack",
                                    "complaint_id", "case_no"),
        "category": _find(data, "category", "fraud_type", "modus", "sub_category"),
        "narrative": _find(data, "narrative", "description", "summary", "statement"),
        "police_station": _find(data, "police_station", "ps", "station"),
        "io": _find(data, "io", "investigating_officer", "officer"),
        "district": _find(data, "district", "city"),
        "reported_at": iso(parse_ts(_find(data, "reported_at", "report_time"))),
        "victim_name": name,
        "amount": amount,
    }
    nper = ev.ent(M.PERSON, str(name).strip().title(), role="victim", victim=True)
    ph = norm_msisdn(_find(victim, "phone", "mobile", "msisdn", "contact"))
    nph = ev.ent(M.PHONE, ph, role="victim_phone", victim=True) if ph else None
    acct, masked = norm_account(_find(victim, "account", "account_no", "bank_account"))
    nac = ev.ent(M.ACCOUNT, acct, role="victim_account", victim=True, masked=masked,
                 holder=name, bank=_find(victim, "bank", "bank_name")) if acct else None
    vpa = norm_upi(_find(victim, "upi", "vpa", "upi_id"))
    nvp = ev.ent(M.UPI, vpa, role="victim_vpa", victim=True, holder=name) if vpa else None
    em = norm_email(_find(victim, "email", "email_id"))
    nem = ev.ent(M.EMAIL, em, role="victim_email", victim=True) if em else None
    for node in (nph, nac, nvp, nem):
        if node:
            ev.link(nper, node, "HOLDS", directed=False)
    if nac and nvp:
        ev.link(nac, nvp, "LINKED_VPA", directed=False)

    # suspect identifiers named in the complaint
    for s in (_find(data, "suspects", "suspect_details", "reported_suspects") or []):
        if isinstance(s, str):
            s = {"value": s}
        for key, etype, norm in (("phone", M.PHONE, norm_msisdn), ("mobile", M.PHONE, norm_msisdn),
                                 ("upi", M.UPI, norm_upi), ("vpa", M.UPI, norm_upi),
                                 ("account", M.ACCOUNT, lambda v: norm_account(v)[0]),
                                 ("email", M.EMAIL, norm_email)):
            raw = _find(s, key)
            if raw:
                val = norm(raw)
                if val:
                    ev.ent(etype, val, role="reported_suspect", reported=True)
    ev.flag(f"Complaint value ₹{amount:,.2f}" if amount else "Complaint registered")
    return [ev]
