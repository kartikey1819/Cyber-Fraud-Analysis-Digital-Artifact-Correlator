"""Shared helpers: identifier normalisation, timestamp parsing, small utilities.

Every identifier that enters the correlation engine passes through a normaliser
here.  Normalisation is deliberately conservative: we would rather miss a weak
link than assert a false one (see FORENSICS.md -> "avoidance of false links").
"""

from __future__ import annotations

import datetime as dt
import re

IST = dt.timezone(dt.timedelta(hours=5, minutes=30))

# --------------------------------------------------------------------------
# timestamps
# --------------------------------------------------------------------------

_TS_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
    "%d-%m-%Y %H:%M:%S",
    "%d-%m-%Y %H:%M",
    "%d-%m-%Y",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%d/%m/%Y",
    "%d-%b-%Y %H:%M:%S",
    "%d-%b-%Y %H:%M",
    "%d-%b-%Y",
    "%d %b %Y %H:%M:%S",
    "%d %B %Y %H:%M:%S",
    "%b %d %Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y%m%d%H%M%S",
]


def parse_ts(value):
    """Best-effort timestamp parser -> naive datetime in IST, or None.

    Accepts ISO-8601 (with or without offset), the common Indian telecom /
    bank export layouts, and epoch seconds/milliseconds.
    """
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return _to_ist(value)
    if isinstance(value, (int, float)):
        return _from_epoch(float(value))

    s = str(value).strip()
    if not s or s.lower() in {"na", "n/a", "-", "null", "none", ""}:
        return None

    # epoch?
    if re.fullmatch(r"\d{10}", s):
        return _from_epoch(float(s))
    if re.fullmatch(r"\d{13}", s):
        return _from_epoch(float(s) / 1000.0)

    iso_candidate = s.replace("T", " ") if "T" in s and " " not in s else s
    try:
        return _to_ist(dt.datetime.fromisoformat(s.replace("Z", "+00:00")))
    except ValueError:
        pass

    for fmt in _TS_FORMATS:
        try:
            return dt.datetime.strptime(iso_candidate, fmt)
        except ValueError:
            continue

    # RFC-2822 (email Date: headers)
    try:
        from email.utils import parsedate_to_datetime

        return _to_ist(parsedate_to_datetime(s))
    except Exception:
        return None


def _from_epoch(sec: float):
    return dt.datetime.fromtimestamp(sec, IST).replace(tzinfo=None)


def _to_ist(d: dt.datetime):
    if d.tzinfo is None:
        return d
    return d.astimezone(IST).replace(tzinfo=None)


def iso(d):
    if d is None:
        return None
    if isinstance(d, str):
        return d
    return d.strftime("%Y-%m-%dT%H:%M:%S")


def human_ts(d):
    if d is None:
        return "unknown"
    if isinstance(d, str):
        d = parse_ts(d)
        if d is None:
            return "unknown"
    return d.strftime("%d-%b-%Y %H:%M:%S")


def minutes_between(a, b):
    if a is None or b is None:
        return None
    if isinstance(a, str):
        a = parse_ts(a)
    if isinstance(b, str):
        b = parse_ts(b)
    if a is None or b is None:
        return None
    return abs((b - a).total_seconds()) / 60.0


# --------------------------------------------------------------------------
# identifier normalisation
# --------------------------------------------------------------------------

def digits(value) -> str:
    return re.sub(r"\D", "", str(value or ""))


def norm_key(header) -> str:
    """Collapse a column header to a comparison key: 'A-Party No.' -> 'apartyno'."""
    return re.sub(r"[^a-z0-9]", "", str(header or "").lower())


def norm_msisdn(value):
    """Indian MSISDN -> bare 10-digit subscriber number.

    Longer strings are trimmed of the 91/0 trunk prefix.  Short codes and
    service numbers (<10 digits) are preserved verbatim so that e.g. bank
    sender IDs do not collide with subscriber numbers.
    """
    raw = str(value or "").strip()
    if not raw:
        return None
    if re.fullmatch(r"[A-Za-z]{2}-?[A-Za-z]{5,8}", raw):  # 'VM-SBIINB' style sender id
        return raw.upper()
    d = digits(raw)
    if not d:
        return None
    if len(d) > 10:
        if d.startswith("91") and len(d) >= 12:
            d = d[-10:]
        elif d.startswith("0"):
            d = d.lstrip("0")[-10:] if len(d.lstrip("0")) >= 10 else d.lstrip("0")
        else:
            d = d[-10:]
    return d or None


def norm_imei(value):
    """IMEI/IMEISV -> 14-digit TAC+serial body.

    The 15th digit is a Luhn check digit and the 16th (IMEISV) is a software
    version; both change while the *handset* stays the same, so correlation is
    done on the 14-digit body.  Display keeps the original.
    """
    d = digits(value)
    if len(d) < 14:
        return None
    return d[:14]


def luhn_ok(imei: str) -> bool:
    d = digits(imei)
    if len(d) != 15:
        return False
    total, parity = 0, len(d) % 2
    for i, ch in enumerate(d):
        n = int(ch)
        if i % 2 != parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def norm_imsi(value):
    d = digits(value)
    return d if 14 <= len(d) <= 15 else (d or None)


MASK_CHARS = set("xX*#")


def norm_account(value):
    """Return (key, is_masked) for a bank account number.

    Masked accounts ('XXXXXX7890') are NEVER merged with full account numbers
    here -- doing so is the classic source of false links.  They are kept as
    their own node and the risk engine raises a separate low-confidence
    'candidate identity' finding instead.
    """
    raw = str(value or "").strip()
    if not raw:
        return None, False
    masked = any(c in MASK_CHARS for c in raw)
    if masked:
        tail = digits(raw)
        if len(tail) < 4:
            return None, True
        return "MASKED-" + tail[-6:], True
    d = digits(raw)
    if len(d) < 6:
        return None, False
    return d, False


VPA_RE = re.compile(r"^[a-z0-9._\-]{2,64}@[a-z][a-z0-9]{1,24}$", re.I)


def norm_upi(value):
    raw = str(value or "").strip().lower()
    if not raw or "@" not in raw:
        return None
    if not VPA_RE.match(raw):
        return None
    # A VPA handle never contains a dot (that would be an email domain).
    if "." in raw.split("@", 1)[1]:
        return None
    return raw


EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$", re.I)


def norm_email(value):
    raw = str(value or "").strip().lower().strip("<>")
    return raw if EMAIL_RE.match(raw) else None


IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def norm_ip(value):
    raw = str(value or "").strip()
    if not IPV4_RE.match(raw):
        return None
    parts = raw.split(".")
    if any(int(p) > 255 for p in parts):
        return None
    return ".".join(str(int(p)) for p in parts)


def subnet24(ip):
    ip = norm_ip(ip)
    if not ip:
        return None
    return ".".join(ip.split(".")[:3]) + ".0/24"


def is_private_ip(ip):
    ip = norm_ip(ip)
    if not ip:
        return False
    a, b = (int(x) for x in ip.split(".")[:2])
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127


MAC_RE = re.compile(r"^[0-9a-f]{12}$")


def norm_mac(value):
    raw = re.sub(r"[^0-9a-fA-F]", "", str(value or "")).lower()
    if not MAC_RE.match(raw):
        return None
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2))


def norm_sha256(value):
    raw = str(value or "").strip().lower()
    return raw if re.fullmatch(r"[0-9a-f]{64}", raw) else None


AMOUNT_RE = re.compile(r"-?\d[\d,]*\.?\d*")


def parse_amount(value):
    """'Rs. 4,85,000.00 Dr' -> 485000.0 ; returns None when not a number."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    if not s or s in {"-", "--", "NA", "N/A"}:
        return None
    neg = s.upper().endswith("DR") or s.startswith("-") or ("(" in s and ")" in s)
    m = AMOUNT_RE.search(s.replace("₹", " "))
    if not m:
        return None
    try:
        val = float(m.group(0).replace(",", ""))
    except ValueError:
        return None
    val = abs(val)
    return -val if neg and val else val


def inr(amount):
    """Format in the Indian grouping convention: 485000 -> '4,85,000'."""
    if amount is None:
        return "-"
    neg = amount < 0
    whole = f"{abs(amount):.2f}"
    ip, fp = whole.split(".")
    if len(ip) > 3:
        head, tail = ip[:-3], ip[-3:]
        head = re.sub(r"(\d)(?=(\d\d)+$)", r"\1,", head)
        ip = head + "," + tail
    out = f"{ip}.{fp}" if fp != "00" else ip
    return ("-" if neg else "") + out


def eid(etype: str, value: str) -> str:
    """Stable entity id used as the graph node key."""
    return f"{etype}|{value}"


def short(text, width=60):
    text = str(text or "")
    return text if len(text) <= width else text[: width - 1] + "…"
