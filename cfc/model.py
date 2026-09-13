"""Canonical event / entity model that every parser normalises into.

One `Event` == one observed fact from one exhibit row.  Events never lose their
provenance: exhibit id, file name and row number ride along so that anything the
engine later asserts can be traced back to a line in an original exhibit.
"""

from __future__ import annotations

import itertools

from .util import eid, iso

# entity types ------------------------------------------------------------
PHONE = "PHONE"
IMEI = "IMEI"
IMSI = "IMSI"
ACCOUNT = "ACCOUNT"
UPI = "UPI"
IP = "IP"
MAC = "MAC"
EMAIL = "EMAIL"
DOMAIN = "DOMAIN"
APK = "APK"
DEVICE = "DEVICE"
PERSON = "PERSON"
CELL = "CELL"

ENTITY_LABELS = {
    PHONE: "Phone / MSISDN",
    IMEI: "Handset (IMEI)",
    IMSI: "SIM (IMSI)",
    ACCOUNT: "Bank account",
    UPI: "UPI handle (VPA)",
    IP: "IP address",
    MAC: "MAC address",
    EMAIL: "Email address",
    DOMAIN: "Domain / URL host",
    APK: "Android package",
    DEVICE: "Device identifier",
    PERSON: "Person / account holder",
    CELL: "Cell site",
}

# event kinds -------------------------------------------------------------
CALL = "CALL"
SMS = "SMS"
SESSION = "DATA_SESSION"
TXN = "TXN"
EMAIL_MSG = "EMAIL"
CHAT = "CHAT"
APP = "APP_INSTALL"
DEVICE_OBS = "DEVICE"
COMPLAINT = "COMPLAINT"

_counter = itertools.count(1)


class Event:
    __slots__ = ("id", "kind", "ts", "summary", "exhibit", "source", "row",
                 "amount", "direction", "entities", "links", "attrs", "flags")

    def __init__(self, kind, ts, summary, exhibit="", source="", row=0):
        self.id = f"E{next(_counter):06d}"
        self.kind = kind
        self.ts = ts
        self.summary = summary
        self.exhibit = exhibit
        self.source = source
        self.row = row
        self.amount = None
        self.direction = None
        self.entities = []   # [{type, value, role, meta{}}]
        self.links = []      # [{src, dst, rel, directed, amount, meta{}}]
        self.attrs = {}
        self.flags = []

    # -- construction helpers ---------------------------------------------
    def ent(self, etype, value, role=None, **meta):
        """Attach an entity observation; returns its node id (or None)."""
        if not value:
            return None
        node = eid(etype, value)
        self.entities.append({"type": etype, "value": value, "role": role,
                              "meta": {k: v for k, v in meta.items() if v not in (None, "")}})
        return node

    def link(self, src, dst, rel, directed=True, amount=None, **meta):
        if not src or not dst or src == dst:
            return
        self.links.append({"src": src, "dst": dst, "rel": rel, "directed": directed,
                           "amount": amount, "meta": meta})

    def flag(self, text):
        if text and text not in self.flags:
            self.flags.append(text)

    # -- serialisation -----------------------------------------------------
    def to_dict(self):
        return {
            "id": self.id,
            "kind": self.kind,
            "ts": iso(self.ts),
            "summary": self.summary,
            "exhibit": self.exhibit,
            "source": self.source,
            "row": self.row,
            "amount": self.amount,
            "direction": self.direction,
            "entities": self.entities,
            "attrs": self.attrs,
            "flags": self.flags,
        }

    def cite(self):
        """Court-style citation for this fact."""
        loc = f" row {self.row}" if self.row else ""
        return f"{self.exhibit} ({self.source}){loc}"


class Finding:
    """A correlation or anomaly assertion made by the engine."""

    __slots__ = ("id", "code", "title", "detail", "severity", "confidence",
                 "entities", "evidence", "score", "category")

    def __init__(self, code, title, detail, severity="MEDIUM", confidence="HIGH",
                 entities=None, evidence=None, score=0, category="CORRELATION"):
        self.id = code
        self.code = code
        self.title = title
        self.detail = detail
        self.severity = severity
        self.confidence = confidence
        self.entities = entities or []
        self.evidence = evidence or []
        self.score = score
        self.category = category

    def to_dict(self):
        return {
            "code": self.code, "title": self.title, "detail": self.detail,
            "severity": self.severity, "confidence": self.confidence,
            "category": self.category, "entities": self.entities,
            "evidence": self.evidence, "score": self.score,
        }
