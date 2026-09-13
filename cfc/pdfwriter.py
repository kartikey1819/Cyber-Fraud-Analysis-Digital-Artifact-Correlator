"""Minimal PDF writer (pure standard library).

Exists so the toolkit produces a court-ready PDF on an offline police
workstation with no wheels to install.  Supports the three base-14 fonts we
need, colour fills, rules, boxes and word-wrapped text.
"""

from __future__ import annotations

import zlib

A4 = (595.28, 841.89)

HELV = "F1"
HELV_B = "F2"
COURIER = "F3"

# Unicode we use in the UI but that WinAnsiEncoding cannot render.
_TRANSLIT = {
    "₹": "Rs.", "→": "->", "←": "<-", "—": "-", "–": "-",
    "…": "...", "‘": "'", "’": "'", "“": '"', "”": '"',
    "•": "-", " ": " ", "✓": "v", "●": "*", "▸": ">",
}


def _sanitize(text):
    s = str(text if text is not None else "")
    for k, v in _TRANSLIT.items():
        s = s.replace(k, v)
    return "".join(ch if ord(ch) < 256 else "?" for ch in s)


def _esc(text):
    return _sanitize(text).replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


# approximate Helvetica advance widths (em fractions) -- good enough for wrap
_NARROW = set("iljI.,:;|!'`()[]{}/\\ ")
_THIN = set("fjrt")
_WIDE = set("mMW@")


def text_width(text, size, bold=False):
    total = 0.0
    for ch in _sanitize(text):
        if ch == " ":
            w = 0.278
        elif ch in _NARROW:
            w = 0.28
        elif ch in _THIN:
            w = 0.34
        elif ch in _WIDE:
            w = 0.86
        elif ch.isdigit():
            w = 0.556
        elif ch.isupper():
            w = 0.70
        else:
            w = 0.54
        total += w
    if bold:
        total *= 1.06
    return total * size


def wrap(text, size, max_width, bold=False):
    """Greedy word wrap honouring explicit newlines."""
    lines = []
    for para in str(text or "").split("\n"):
        words, cur = para.split(), ""
        for w in words:
            trial = (cur + " " + w).strip()
            if text_width(trial, size, bold) <= max_width or not cur:
                cur = trial
            else:
                lines.append(cur)
                cur = w
        lines.append(cur)
    return lines or [""]


class Page:
    def __init__(self, width, height):
        self.width = width
        self.height = height
        self.ops = []

    # coordinates are top-left origin; converted on emit
    def _y(self, y):
        return self.height - y

    def text(self, x, y, s, size=9, font=HELV, color=(0, 0, 0)):
        r, g, b = color
        self.ops.append(
            f"BT /{font} {size:.2f} Tf {r:.3f} {g:.3f} {b:.3f} rg "
            f"1 0 0 1 {x:.2f} {self._y(y):.2f} Tm ({_esc(s)}) Tj ET")

    def text_right(self, x_right, y, s, size=9, font=HELV, color=(0, 0, 0)):
        w = text_width(s, size, font == HELV_B)
        self.text(x_right - w, y, s, size, font, color)

    def rect(self, x, y, w, h, fill=None, stroke=None, lw=0.6):
        if fill:
            r, g, b = fill
            self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg "
                            f"{x:.2f} {self._y(y + h):.2f} {w:.2f} {h:.2f} re f")
        if stroke:
            r, g, b = stroke
            self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} RG {lw:.2f} w "
                            f"{x:.2f} {self._y(y + h):.2f} {w:.2f} {h:.2f} re S")

    def line(self, x1, y1, x2, y2, color=(0.8, 0.8, 0.85), lw=0.6):
        r, g, b = color
        self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} RG {lw:.2f} w "
                        f"{x1:.2f} {self._y(y1):.2f} m {x2:.2f} {self._y(y2):.2f} l S")

    def circle(self, cx, cy, r, fill=(0, 0, 0)):
        k = 0.5523 * r
        y = self._y(cy)
        red, g, b = fill
        self.ops.append(
            f"{red:.3f} {g:.3f} {b:.3f} rg "
            f"{cx + r:.2f} {y:.2f} m "
            f"{cx + r:.2f} {y + k:.2f} {cx + k:.2f} {y + r:.2f} {cx:.2f} {y + r:.2f} c "
            f"{cx - k:.2f} {y + r:.2f} {cx - r:.2f} {y + k:.2f} {cx - r:.2f} {y:.2f} c "
            f"{cx - r:.2f} {y - k:.2f} {cx - k:.2f} {y - r:.2f} {cx:.2f} {y - r:.2f} c "
            f"{cx + k:.2f} {y - r:.2f} {cx + r:.2f} {y - k:.2f} {cx + r:.2f} {y:.2f} c f")

    def stream(self):
        return "\n".join(self.ops).encode("latin-1", errors="replace")


class PDF:
    def __init__(self, size=A4, title="Report", author="Cyber Fraud Correlator"):
        self.size = size
        self.pages = []
        self.title = title
        self.author = author

    def new_page(self):
        p = Page(*self.size)
        self.pages.append(p)
        return p

    def save(self, path):
        data = self.build()
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def build(self) -> bytes:
        if not self.pages:
            self.new_page()
        objects = []           # 1-indexed list of byte strings

        def add(obj: bytes) -> int:
            objects.append(obj)
            return len(objects)

        font_ids = {}
        for key, base in ((HELV, "Helvetica"), (HELV_B, "Helvetica-Bold"),
                          (COURIER, "Courier")):
            font_ids[key] = add(
                b"<< /Type /Font /Subtype /Type1 /BaseFont /" + base.encode() +
                b" /Encoding /WinAnsiEncoding >>")

        pages_id = len(objects) + 1 + 2 * len(self.pages)  # reserve
        page_ids, content_ids = [], []
        for page in self.pages:
            raw = page.stream()
            comp = zlib.compress(raw)
            cid = add(b"<< /Length " + str(len(comp)).encode() +
                      b" /Filter /FlateDecode >>\nstream\n" + comp + b"\nendstream")
            content_ids.append(cid)
            res = (b"<< /Font << " + b" ".join(
                b"/" + k.encode() + b" " + str(v).encode() + b" 0 R"
                for k, v in font_ids.items()) + b" >> >>")
            pid = add(b"<< /Type /Page /Parent " + str(pages_id).encode() +
                      b" 0 R /MediaBox [0 0 " +
                      f"{self.size[0]:.2f} {self.size[1]:.2f}".encode() +
                      b"] /Resources " + res + b" /Contents " + str(cid).encode() + b" 0 R >>")
            page_ids.append(pid)

        real_pages_id = add(
            b"<< /Type /Pages /Count " + str(len(page_ids)).encode() + b" /Kids [" +
            b" ".join(str(p).encode() + b" 0 R" for p in page_ids) + b"] >>")
        # patch parent references if the reservation guess was wrong
        if real_pages_id != pages_id:
            for i, pid in enumerate(page_ids):
                objects[pid - 1] = objects[pid - 1].replace(
                    b"/Parent " + str(pages_id).encode() + b" 0 R",
                    b"/Parent " + str(real_pages_id).encode() + b" 0 R")

        info_id = add(b"<< /Title (" + _esc(self.title).encode("latin-1", "replace") +
                      b") /Author (" + _esc(self.author).encode("latin-1", "replace") +
                      b") /Producer (CyberFraudCorrelator) >>")
        catalog_id = add(b"<< /Type /Catalog /Pages " + str(real_pages_id).encode() + b" 0 R >>")

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for i, obj in enumerate(objects, start=1):
            offsets.append(len(out))
            out += str(i).encode() + b" 0 obj\n" + obj + b"\nendobj\n"
        xref_at = len(out)
        n = len(objects) + 1
        out += b"xref\n0 " + str(n).encode() + b"\n0000000000 65535 f \n"
        for off in offsets[1:]:
            out += f"{off:010d} 00000 n \n".encode()
        out += (b"trailer\n<< /Size " + str(n).encode() +
                b" /Root " + str(catalog_id).encode() + b" 0 R" +
                b" /Info " + str(info_id).encode() + b" 0 R >>\nstartxref\n" +
                str(xref_at).encode() + b"\n%%EOF\n")
        return bytes(out)
