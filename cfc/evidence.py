"""Evidentiary integrity: SHA-256 acquisition hashing and chain-of-custody log.

Nothing in the pipeline touches an original exhibit.  Files are hashed on
arrival, copied into a read-only case working directory, re-hashed after the
copy, and every subsequent stage appends to an append-only custody log.  The
final brief carries the manifest so a court can re-verify the exhibits.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import stat
import uuid

CHUNK = 1024 * 1024


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5_file(path: str) -> str:
    """Secondary digest.  MD5 is not relied on for integrity; it is emitted
    only because several legacy police case-management systems still index on
    it."""
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


class CustodyLog:
    """Append-only chain-of-custody record for one case."""

    def __init__(self, case_id: str, officer: str = "UNSPECIFIED"):
        self.case_id = case_id
        self.officer = officer
        self.entries = []

    def record(self, action: str, detail: str, **extra):
        entry = {
            "seq": len(self.entries) + 1,
            "utc": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "action": action,
            "detail": detail,
            "officer": self.officer,
        }
        entry.update(extra)
        self.entries.append(entry)
        return entry

    def seal(self) -> str:
        """Hash of the custody log itself, so tampering with the log is visible."""
        blob = json.dumps(self.entries, sort_keys=True, separators=(",", ":")).encode()
        return sha256_bytes(blob)

    def to_dict(self):
        return {"case_id": self.case_id, "entries": self.entries, "log_sha256": self.seal()}


class Exhibit:
    """One ingested artifact plus its integrity metadata."""

    __slots__ = ("exhibit_id", "original_name", "stored_path", "size",
                 "sha256", "md5", "acquired_utc", "artifact_type", "parse_status",
                 "records", "notes")

    def __init__(self, exhibit_id, original_name, stored_path, size, sha256, md5, acquired_utc):
        self.exhibit_id = exhibit_id
        self.original_name = original_name
        self.stored_path = stored_path
        self.size = size
        self.sha256 = sha256
        self.md5 = md5
        self.acquired_utc = acquired_utc
        self.artifact_type = "UNKNOWN"
        self.parse_status = "PENDING"
        self.records = 0
        self.notes = []

    def verify(self) -> bool:
        """Re-hash the working copy and compare with the acquisition hash."""
        try:
            return sha256_file(self.stored_path) == self.sha256
        except OSError:
            return False

    def to_dict(self):
        return {
            "exhibit_id": self.exhibit_id,
            "original_name": self.original_name,
            "artifact_type": self.artifact_type,
            "size_bytes": self.size,
            "sha256": self.sha256,
            "md5": self.md5,
            "acquired_utc": self.acquired_utc,
            "parse_status": self.parse_status,
            "records_extracted": self.records,
            "notes": self.notes,
        }


def acquire(src_path: str, dest_dir: str, custody: CustodyLog, index: int) -> Exhibit:
    """Hash-then-copy-then-verify an exhibit into the case working directory."""
    os.makedirs(dest_dir, exist_ok=True)
    name = os.path.basename(src_path)
    exhibit_id = f"EX-{index:03d}"
    pre_hash = sha256_file(src_path)
    dest = os.path.join(dest_dir, f"{exhibit_id}_{name}")
    shutil.copy2(src_path, dest)
    post_hash = sha256_file(dest)

    ex = Exhibit(
        exhibit_id=exhibit_id,
        original_name=name,
        stored_path=dest,
        size=os.path.getsize(dest),
        sha256=post_hash,
        md5=md5_file(dest),
        acquired_utc=dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    if pre_hash != post_hash:
        ex.notes.append("INTEGRITY FAILURE: hash changed during acquisition copy")
        custody.record("ACQUIRE_FAILED", f"{name}: {pre_hash} -> {post_hash}", exhibit=exhibit_id)
    else:
        custody.record(
            "ACQUIRE",
            f"{name} acquired and verified (SHA-256 {post_hash[:16]}...)",
            exhibit=exhibit_id, sha256=post_hash, source=os.path.abspath(src_path),
        )
    _make_readonly(dest)
    return ex


def acquire_bytes(data: bytes, filename: str, dest_dir: str, custody: CustodyLog, index: int) -> Exhibit:
    """Same as acquire() but for an uploaded byte stream."""
    os.makedirs(dest_dir, exist_ok=True)
    exhibit_id = f"EX-{index:03d}"
    digest = sha256_bytes(data)
    dest = os.path.join(dest_dir, f"{exhibit_id}_{os.path.basename(filename)}")
    with open(dest, "wb") as fh:
        fh.write(data)
    post = sha256_file(dest)
    ex = Exhibit(
        exhibit_id=exhibit_id,
        original_name=os.path.basename(filename),
        stored_path=dest,
        size=len(data),
        sha256=post,
        md5=md5_file(dest),
        acquired_utc=dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    if digest != post:
        ex.notes.append("INTEGRITY FAILURE: hash changed while writing working copy")
    custody.record("ACQUIRE_UPLOAD", f"{filename} received via dashboard upload",
                   exhibit=exhibit_id, sha256=post)
    _make_readonly(dest)
    return ex


def _make_readonly(path):
    try:
        os.chmod(path, stat.S_IREAD)
    except OSError:
        pass


def new_case_id() -> str:
    return "CASE-" + dt.datetime.now().strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:6].upper()
