"""Local dashboard server (standard library only).

Binds to 127.0.0.1 by default: the case data never leaves the workstation,
which is what makes the tool usable on an air-gapped police machine.
"""

from __future__ import annotations

import json
import mimetypes
import os
import posixpath
import re
import threading
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .case import SUPPORTED_EXT, Case
from .util import iso

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WEB_DIR = os.path.join(ROOT, "web")
SAMPLE_DIR = os.path.join(ROOT, "sample_data")

# Upload ceiling. Lower on a shared public host, where a large upload is more
# likely to exhaust the instance than to be genuine evidence.
MAX_UPLOAD = int(os.environ.get("CFC_MAX_UPLOAD_MB", "96")) * 1024 * 1024

# Public-demo mode: the dashboard shows a standing warning that the instance is
# internet-facing and must not receive real case material. Set by render.yaml.
PUBLIC_DEMO = os.environ.get("CFC_PUBLIC_DEMO", "").strip().lower() in ("1", "true", "yes")

_cases = {}
_lock = threading.Lock()

# The demonstration case is built in the background at start-up so the
# dashboard has something on screen the moment the link is opened.  Requests
# that arrive mid-build wait on this event rather than starting a second one.
_prewarm_started = threading.Event()
_prewarm_done = threading.Event()


# --------------------------------------------------------------------------
# multipart/form-data (the stdlib `cgi` module is gone in 3.13)
# --------------------------------------------------------------------------

def parse_multipart(body: bytes, boundary: bytes):
    """Yield (field_name, filename, data) for each part."""
    sep = b"--" + boundary
    out = []
    for chunk in body.split(sep):
        if not chunk or chunk in (b"--", b"--\r\n", b"\r\n"):
            continue
        chunk = chunk.lstrip(b"\r\n")
        head, _, data = chunk.partition(b"\r\n\r\n")
        if not _:
            continue
        data = data[:-2] if data.endswith(b"\r\n") else data
        headers = head.decode("latin-1", "replace")
        disp = re.search(r'Content-Disposition:[^\r\n]*', headers, re.I)
        if not disp:
            continue
        name = re.search(r'name="([^"]*)"', disp.group(0))
        fname = re.search(r'filename="([^"]*)"', disp.group(0))
        out.append((name.group(1) if name else "",
                    fname.group(1) if fname else None, data))
    return out


# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "CyberFraudCorrelator/1.0"
    protocol_version = "HTTP/1.1"

    # -- plumbing ---------------------------------------------------------
    def log_message(self, fmt, *args):
        if os.environ.get("CFC_VERBOSE"):
            super().log_message(fmt, *args)

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload, code=200):
        self._send(code, json.dumps(payload, default=str), "application/json")

    def _error(self, code, message):
        self._json({"error": message}, code)

    # -- routing ----------------------------------------------------------
    def do_GET(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            if path in ("/", "/index.html"):
                return self._static("index.html")
            if path.startswith("/static/"):
                return self._static(path[len("/static/"):])
            if path == "/api/config":
                return self._json({
                    "public_demo": PUBLIC_DEMO,
                    "max_upload_mb": MAX_UPLOAD // (1024 * 1024),
                    "version": "1.0.0",
                })
            if path == "/api/cases":
                _await_prewarm()
                with _lock:
                    return self._json({"cases": [
                        {"case_id": c.case_id, "officer": c.officer,
                         "exhibits": len(c.exhibits), "events": len(c.events),
                         "suspects": len(c.suspects)}
                        for c in _cases.values()]})
            m = re.fullmatch(r"/api/case/([A-Za-z0-9\-]+)/analysis", path)
            if m:
                return self._analysis(m.group(1))
            m = re.fullmatch(r"/api/case/([A-Za-z0-9\-]+)/report\.json", path)
            if m:
                case = self._case(m.group(1))
                if case is None:
                    return
                return self._send(
                    200, json.dumps(case.report(), indent=2, default=str),
                    "application/json",
                    {"Content-Disposition":
                     f'attachment; filename="{case.case_id}_brief.json"'})
            m = re.fullmatch(r"/api/case/([A-Za-z0-9\-]+)/report\.pdf", path)
            if m:
                return self._pdf(m.group(1))
            m = re.fullmatch(r"/api/case/([A-Za-z0-9\-]+)/event/(E\d+)", path)
            if m:
                return self._event(m.group(1), m.group(2))
            return self._error(404, "not found")
        except Exception as exc:
            traceback.print_exc()
            return self._error(500, str(exc))

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            if path == "/api/case/sample":
                return self._new_sample()
            if path == "/api/case/upload":
                return self._new_upload()
            return self._error(404, "not found")
        except Exception as exc:
            traceback.print_exc()
            return self._error(500, str(exc))

    # -- handlers ---------------------------------------------------------
    def _static(self, rel):
        rel = posixpath.normpath(rel).lstrip("./\\")
        full = os.path.join(WEB_DIR, rel.replace("/", os.sep))
        if not os.path.abspath(full).startswith(os.path.abspath(WEB_DIR)) \
                or not os.path.isfile(full):
            return self._error(404, "not found")
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        with open(full, "rb") as fh:
            return self._send(200, fh.read(), ctype)

    def _case(self, case_id):
        with _lock:
            case = _cases.get(case_id)
        if case is None:
            self._error(404, f"unknown case {case_id}")
            return None
        return case

    def _register(self, case):
        with _lock:
            _cases[case.case_id] = case
        return case

    def _new_sample(self):
        officer = self._officer()
        if not os.path.isdir(SAMPLE_DIR):
            return self._error(500, "sample_data directory is missing")
        case = Case(officer=officer)
        case.add_directory(SAMPLE_DIR)
        case.analyze()
        self._register(case)
        return self._json({"case_id": case.case_id, "summary": case.summary()})

    def _new_upload(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return self._error(400, "empty upload")
        if length > MAX_UPLOAD:
            return self._error(413, "upload too large")
        ctype = self.headers.get("Content-Type", "")
        m = re.search(r"boundary=(.+)$", ctype)
        if not m:
            return self._error(400, "expected multipart/form-data")
        boundary = m.group(1).strip('"').encode("latin-1")
        body = self._read_exact(length)
        parts = parse_multipart(body, boundary)

        officer = "UNSPECIFIED"
        files = []
        for name, filename, data in parts:
            if filename:
                if os.path.splitext(filename)[1].lower() not in SUPPORTED_EXT:
                    continue
                files.append((filename, data))
            elif name == "officer" and data.strip():
                officer = data.decode("utf-8", "replace").strip()
        if not files:
            return self._error(400,
                               "no supported artifacts in upload (accepted: "
                               + ", ".join(sorted(SUPPORTED_EXT)) + ")")
        case = Case(officer=officer)
        for filename, data in files:
            case.add_bytes(filename, data)
        case.analyze()
        self._register(case)
        return self._json({"case_id": case.case_id, "summary": case.summary()})

    def _read_exact(self, length):
        buf = bytearray()
        while len(buf) < length:
            chunk = self.rfile.read(min(65536, length - len(buf)))
            if not chunk:
                break
            buf += chunk
        return bytes(buf)

    def _officer(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return "UNSPECIFIED"
        raw = self._read_exact(length)
        try:
            return (json.loads(raw).get("officer") or "UNSPECIFIED").strip()
        except Exception:
            return "UNSPECIFIED"

    def _analysis(self, case_id):
        case = self._case(case_id)
        if case is None:
            return
        report = case.report()
        report["events"] = [{
            "id": e.id, "kind": e.kind, "ts": iso(e.ts), "summary": e.summary,
            "exhibit": e.exhibit, "source": e.source, "row": e.row,
            "amount": e.amount, "direction": e.direction, "flags": e.flags,
            "cite": e.cite(), "attrs": _compact(e.attrs),
        } for e in case.events]
        report["scores"] = case.scores
        return self._json(report)

    def _event(self, case_id, event_id):
        case = self._case(case_id)
        if case is None:
            return
        ev = next((e for e in case.events if e.id == event_id), None)
        if ev is None:
            return self._error(404, "unknown event")
        payload = ev.to_dict()
        payload["cite"] = ev.cite()
        return self._json(payload)

    def _pdf(self, case_id):
        case = self._case(case_id)
        if case is None:
            return
        from .report import render_pdf
        out_dir = os.path.join(case.root, "output")
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f"{case.case_id}_brief.pdf")
        render_pdf(case.report(), path)
        with open(path, "rb") as fh:
            data = fh.read()
        return self._send(200, data, "application/pdf",
                          {"Content-Disposition":
                           f'inline; filename="{case.case_id}_brief.pdf"'})


def _await_prewarm(timeout=25.0):
    """Block briefly if the demo case is still being built at start-up."""
    if _prewarm_started.is_set() and not _prewarm_done.is_set():
        _prewarm_done.wait(timeout)


def prewarm_sample():
    """Ingest and analyse the demonstration case ahead of the first request."""
    _prewarm_started.set()

    def build():
        try:
            if not os.path.isdir(SAMPLE_DIR):
                return
            case = Case(officer="UNSPECIFIED")
            case.add_directory(SAMPLE_DIR)
            case.analyze()
            with _lock:
                _cases[case.case_id] = case
            print(f"  Demo case  : {case.case_id} ready "
                  f"({len(case.exhibits)} exhibits, {len(case.events)} events, "
                  f"{case.processing_ms} ms)", flush=True)
        except Exception as exc:
            print(f"  Demo case  : unavailable ({exc})", flush=True)
        finally:
            _prewarm_done.set()

    threading.Thread(target=build, daemon=True).start()


def _compact(attrs):
    """Trim bulky fields out of the per-event payload sent to the browser."""
    out = {}
    for k, v in (attrs or {}).items():
        if k in ("flow",):
            continue
        if isinstance(v, str) and len(v) > 600:
            v = v[:600] + "…"
        if isinstance(v, list) and len(v) > 40:
            v = v[:40] + ["…"]
        out[k] = v
    return out


def serve(host="127.0.0.1", port=8713, open_browser=True, demo=True):
    httpd = ThreadingHTTPServer((host, port), Handler)
    if demo:
        prewarm_sample()
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{shown}:{port}/"
    print("=" * 70)
    print("  Unified Cyber Fraud Analysis & Digital Artifact Correlator")
    print("=" * 70)
    print(f"  Dashboard : {url}")
    if host in ("0.0.0.0", "::"):
        print(f"  Binding   : {host}:{port} - reachable from the network")
        print("  Evidence  : NOT loopback-only in this mode. Do not send real")
        print("              case material to a shared or internet-facing host.")
    else:
        print("  Evidence  : loopback only - nothing is uploaded off this machine")
    if PUBLIC_DEMO:
        print("  Mode      : PUBLIC DEMO (banner shown, uploads capped at "
              f"{MAX_UPLOAD // (1024 * 1024)} MB)")
    print("  Demo case : pre-loading (use --no-demo to start empty)" if demo
          else "  Demo case : disabled")
    print("  Stop      : Ctrl+C")
    print("=" * 70, flush=True)
    if open_browser:
        try:
            import webbrowser
            threading.Timer(0.6, lambda: webbrowser.open(url)).start()
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        httpd.server_close()
