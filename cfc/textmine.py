"""Unstructured-text intelligence: indicator extraction and a lure classifier.

Used on chat exports, SMS bodies, email bodies and transaction narrations.
Extraction is context-gated (an account number is only harvested when an
account keyword sits next to it) because blind regex harvesting over free text
is the main generator of false entity links.
"""

from __future__ import annotations

import math
import re

from .util import norm_account, norm_email, norm_ip, norm_msisdn, norm_upi, norm_sha256

# --------------------------------------------------------------------------
# indicator patterns
# --------------------------------------------------------------------------

RE_PHONE = re.compile(r"(?<!\d)(?:\+?91[\s\-]?)?([6-9]\d{9})(?!\d)")
RE_VPA = re.compile(r"\b([a-z0-9._\-]{2,64}@[a-z][a-z0-9]{1,24})\b", re.I)
RE_EMAIL = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", re.I)
RE_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"')]+", re.I)
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_IMEI = re.compile(r"(?<!\d)(\d{15})(?!\d)")
RE_SHA = re.compile(r"\b[0-9a-f]{64}\b", re.I)
RE_AMOUNT = re.compile(r"(?:rs\.?|inr|₹)\s*([\d,]+(?:\.\d{1,2})?)", re.I)
RE_ACCOUNT_CTX = re.compile(
    r"(?:a/?c(?:count)?(?:\s*(?:no\.?|number|#))?|acct|ac)\s*[:\-#]?\s*([0-9Xx*]{6,20})", re.I)
RE_APK = re.compile(r"\b([\w\-]+\.apk)\b", re.I)
RE_PKG = re.compile(r"\b((?:com|in|org|net)\.[a-z0-9_]+(?:\.[a-z0-9_]+){0,4})\b", re.I)

# Domains that are VPA handles, not email hosts.  Anything matching RE_VPA
# whose host has no dot is treated as a VPA; this list only boosts confidence.
KNOWN_PSP = {
    "okaxis", "okhdfcbank", "oksbi", "okicici", "ybl", "paytm", "upi", "apl",
    "axl", "ibl", "airtel", "freecharge", "jupiteraxis", "fam", "abfspay",
    "sbi", "hdfcbank", "icici", "kotak", "yesbank", "idfcbank", "barodampay",
}

# --------------------------------------------------------------------------
# social-engineering lure lexicon (weighted)
# --------------------------------------------------------------------------

LURE_LEXICON = {
    # credential / OTP harvesting
    "otp": 3, "one time password": 3, "cvv": 4, "pin number": 3, "upi pin": 4,
    "net banking password": 4, "atm pin": 4, "card number": 3,
    # urgency + account threat
    "kyc": 3, "re-kyc": 3, "account will be blocked": 4, "will be suspended": 3,
    "account blocked": 3, "immediately": 1, "within 24 hours": 2, "urgent": 2,
    "last warning": 3, "final notice": 2, "expire": 1, "deactivate": 2,
    # payload delivery
    ".apk": 4, "install the app": 3, "install this": 2, "download the app": 3,
    "anydesk": 5, "teamviewer": 4, "quick support": 3, "screen share": 3,
    "enable accessibility": 4,
    # reward / refund bait
    "lottery": 3, "you have won": 3, "cashback": 2, "refund": 2, "reward point": 3,
    "credit card reward": 3, "prize": 2, "gift": 1,
    # authority impersonation
    "cyber cell": 3, "customs": 3, "parcel": 2, "fedex": 2, "narcotics": 4,
    "digital arrest": 5, "cbi": 3, "police verification": 3, "court notice": 3,
    # work-from-home / task fraud
    "work from home": 2, "task based": 2, "telegram group": 3, "prepaid task": 3,
    "investment plan": 2, "guaranteed return": 3, "trading account": 2,
    # mule recruitment
    "commission": 2, "use your account": 4, "rent your account": 5,
    "your bank account for": 3, "passbook and atm card": 4, "give me your account": 4,
}

SUSPICIOUS_TLD = {".xyz", ".top", ".click", ".buzz", ".cfd", ".rest", ".shop",
                  ".online", ".site", ".icu", ".link", ".live", ".fit"}

BRAND_TOKENS = ["sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe",
                "gpay", "npci", "rbi", "irctc", "epfo", "incometax"]

# Genuine registrable domains for the brands above.  Without this allowlist a
# legitimate bank URL (onlinesbi.sbi) is flagged as impersonating itself.
LEGIT_SUFFIXES = {
    "sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbi.bank.in",
    "hdfcbank.com", "hdfclife.com", "icicibank.com", "icicidirect.com",
    "axisbank.com", "axisbank.co.in", "kotak.com", "kotak811.com",
    "paytm.com", "paytmbank.com", "phonepe.com", "pay.google.com",
    "npci.org.in", "rbi.org.in", "irctc.co.in", "epfindia.gov.in",
    "incometax.gov.in", "bankofbaroda.in", "pnbindia.in", "unionbankofindia.co.in",
}


def _legit_host(host: str) -> bool:
    host = (host or "").lower().strip(".")
    if host.endswith((".gov.in", ".nic.in", ".rbi.org.in")):
        return True
    return any(host == s or host.endswith("." + s) for s in LEGIT_SUFFIXES)


def extract_indicators(text: str) -> dict:
    """Harvest structured identifiers out of free text."""
    text = text or ""
    low = text.lower()
    out = {"phones": set(), "vpas": set(), "emails": set(), "urls": set(),
           "ips": set(), "imeis": set(), "accounts": set(), "hashes": set(),
           "apks": set(), "packages": set(), "amounts": []}

    emails = {m.group(0).lower() for m in RE_EMAIL.finditer(text)}
    for e in emails:
        n = norm_email(e)
        if n:
            out["emails"].add(n)

    for m in RE_VPA.finditer(text):
        cand = m.group(1).lower()
        if cand in emails:
            continue
        n = norm_upi(cand)
        if n:
            out["vpas"].add(n)

    for m in RE_PHONE.finditer(text):
        n = norm_msisdn(m.group(1))
        if n:
            out["phones"].add(n)

    for m in RE_URL.finditer(text):
        out["urls"].add(m.group(0).rstrip(".,);"))

    for m in RE_IP.finditer(text):
        n = norm_ip(m.group(0))
        if n:
            out["ips"].add(n)

    for m in RE_IMEI.finditer(text):
        out["imeis"].add(m.group(1))

    for m in RE_SHA.finditer(text):
        n = norm_sha256(m.group(0))
        if n:
            out["hashes"].add(n)

    for m in RE_ACCOUNT_CTX.finditer(text):
        key, masked = norm_account(m.group(1))
        if key:
            out["accounts"].add(key)

    for m in RE_APK.finditer(text):
        out["apks"].add(m.group(1).lower())

    for m in RE_PKG.finditer(text):
        out["packages"].add(m.group(1).lower())

    for m in RE_AMOUNT.finditer(low):
        try:
            out["amounts"].append(float(m.group(1).replace(",", "")))
        except ValueError:
            pass

    return {k: (sorted(v) if isinstance(v, set) else v) for k, v in out.items()}


def lure_score(text: str):
    """Score free text for social-engineering content.

    Returns (0-100 score, list of matched phrases).  A saturating curve is used
    so that one repeated phrase cannot dominate the score.
    """
    low = (text or "").lower()
    hits, raw = [], 0
    for phrase, weight in LURE_LEXICON.items():
        if phrase in low:
            hits.append(phrase)
            raw += weight
    if not raw:
        return 0, []
    score = int(round(100 * (1 - math.exp(-raw / 12.0))))
    return min(score, 100), sorted(hits, key=lambda p: -LURE_LEXICON[p])


def url_risk(url: str):
    """Flag phishing-shaped URLs: brand token on a non-brand domain, odd TLD,
    raw IP host, or a direct .apk payload."""
    u = (url or "").lower()
    reasons = []
    host = re.sub(r"^https?://", "", u).split("/")[0].split(":")[0]
    if RE_IP.fullmatch(host or ""):
        reasons.append("host is a raw IP address")
    for tld in SUSPICIOUS_TLD:
        if host.endswith(tld):
            reasons.append(f"high-abuse TLD {tld}")
            break
    if not _legit_host(host):
        for brand in BRAND_TOKENS:
            if brand in host:
                reasons.append(f"impersonates brand '{brand.upper()}' on unrelated domain")
                break
    if u.endswith(".apk"):
        reasons.append("serves a direct Android package (.apk) payload")
    if host.count("-") >= 2:
        reasons.append("hyphen-stuffed hostname")
    return reasons


# --------------------------------------------------------------------------
# Android permission triage
# --------------------------------------------------------------------------

DANGEROUS_PERMS = {
    "android.permission.READ_SMS": 5,
    "android.permission.RECEIVE_SMS": 5,
    "android.permission.SEND_SMS": 4,
    "android.permission.READ_CALL_LOG": 3,
    "android.permission.ANSWER_PHONE_CALLS": 3,
    "android.permission.CALL_PHONE": 2,
    "android.permission.READ_CONTACTS": 2,
    "android.permission.SYSTEM_ALERT_WINDOW": 4,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 5,
    "android.permission.REQUEST_INSTALL_PACKAGES": 3,
    "android.permission.RECEIVE_BOOT_COMPLETED": 2,
    "android.permission.FOREGROUND_SERVICE": 1,
    "android.permission.READ_PHONE_STATE": 2,
    "android.permission.QUERY_ALL_PACKAGES": 2,
}

# Combination that is effectively diagnostic of a banking/OTP stealer.
STEALER_COMBO = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
}


def apk_risk(package: str, permissions, installer: str = "", flags=None):
    """Score an installed package.  Returns (score 0-100, reasons)."""
    perms = {str(p).strip() for p in (permissions or [])}
    perms = {p if p.startswith("android.permission.") else "android.permission." + p
             for p in perms if p}
    reasons, raw = [], 0
    for p in sorted(perms):
        w = DANGEROUS_PERMS.get(p)
        if w:
            raw += w
    if STEALER_COMBO.issubset(perms):
        raw += 12
        reasons.append("holds READ_SMS + RECEIVE_SMS + ACCESSIBILITY — OTP interception capable")
    if perms & {"android.permission.SYSTEM_ALERT_WINDOW"} and \
            perms & {"android.permission.BIND_ACCESSIBILITY_SERVICE"}:
        reasons.append("overlay + accessibility — credential screen-overlay capable")
        raw += 5
    inst = (installer or "").lower()
    if inst and inst not in ("com.android.vending", "com.google.android.packageinstaller",
                             "play store", "google play"):
        reasons.append(f"sideloaded (installer='{installer}', not Play Store)")
        raw += 8
    elif not inst:
        reasons.append("installer package unknown — probable sideload")
        raw += 5
    for f in (flags or []):
        fl = str(f).lower()
        if "debug" in fl or "test" in fl:
            reasons.append(f"build flag '{f}'")
            raw += 2
    pkg = (package or "").lower()
    for brand in BRAND_TOKENS:
        if brand in pkg:
            reasons.append(f"package name impersonates '{brand.upper()}'")
            raw += 6
            break
    dangerous = sorted(p for p in perms if p in DANGEROUS_PERMS)
    if dangerous:
        short = ", ".join(p.rsplit(".", 1)[-1] for p in dangerous[:6])
        reasons.append(f"dangerous permissions: {short}")
    score = int(round(100 * (1 - math.exp(-raw / 22.0))))
    return min(score, 100), reasons
