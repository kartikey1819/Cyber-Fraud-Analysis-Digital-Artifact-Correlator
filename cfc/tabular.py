"""Schema-flexible tabular reader (CSV / TSV / pipe / XLSX) built on the
standard library only -- no pandas, no openpyxl.

Telecom and bank exports are never consistent: different delimiters, a few
junk banner rows above the real header, BOMs, Latin-1 encodings, merged
columns.  `read_table` deals with all of that and hands the parsers a clean
list of dicts plus the detected header.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import os
import re
import xml.etree.ElementTree as ET
import zipfile

from .util import norm_key

MAX_PREVIEW = 40


# --------------------------------------------------------------------------
# text delimited files
# --------------------------------------------------------------------------

def _decode(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def _sniff_delimiter(sample: str) -> str:
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except csv.Error:
        counts = {d: sample.count(d) for d in ",;\t|"}
        best = max(counts, key=counts.get)
        return best if counts[best] else ","


def _header_row_index(rows) -> int:
    """Skip banner / disclaimer lines that precede the real header.

    The header is the first row with >=2 non-empty cells where most cells look
    like labels (alphabetic, short) rather than data.
    """
    best_idx, best_score = 0, -1.0
    for i, row in enumerate(rows[:MAX_PREVIEW]):
        cells = [c.strip() for c in row if str(c).strip()]
        if len(cells) < 2:
            continue
        labelish = sum(1 for c in cells if re.search(r"[A-Za-z]", c) and len(c) <= 40
                       and not re.fullmatch(r"[\d/,.\-: ]+", c))
        score = labelish / len(cells) * min(len(cells), 12)
        if score > best_score:
            best_idx, best_score = i, score
        if score >= 10:
            break
    return best_idx


def _read_delimited(path: str):
    with open(path, "rb") as fh:
        text = _decode(fh.read())
    if not text.strip():
        return [], []
    delim = _sniff_delimiter(text[:8192])
    rows = list(csv.reader(io.StringIO(text), delimiter=delim))
    rows = [r for r in rows if any(str(c).strip() for c in r)]
    if not rows:
        return [], []
    hi = _header_row_index(rows)
    header = [str(c).strip() for c in rows[hi]]
    # de-duplicate blank / repeated header labels
    seen, clean = {}, []
    for i, h in enumerate(header):
        h = h or f"col{i + 1}"
        if h in seen:
            seen[h] += 1
            h = f"{h}_{seen[h]}"
        else:
            seen[h] = 0
        clean.append(h)
    out = []
    for r in rows[hi + 1:]:
        if len(r) < len(clean):
            r = list(r) + [""] * (len(clean) - len(r))
        out.append({clean[i]: str(r[i]).strip() for i in range(len(clean))})
    return clean, out


# --------------------------------------------------------------------------
# xlsx (OOXML) -- a zip of XML, readable with zipfile + ElementTree
# --------------------------------------------------------------------------

NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
EXCEL_EPOCH = dt.datetime(1899, 12, 30)


def _col_index(ref: str) -> int:
    letters = re.match(r"[A-Z]+", ref or "A").group(0)
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _shared_strings(zf) -> list:
    try:
        root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
    except KeyError:
        return []
    out = []
    for si in root.findall(f"{NS}si"):
        out.append("".join(t.text or "" for t in si.iter(f"{NS}t")))
    return out


def _read_xlsx(path: str):
    with zipfile.ZipFile(path) as zf:
        strings = _shared_strings(zf)
        sheets = sorted(n for n in zf.namelist()
                        if n.startswith("xl/worksheets/sheet") and n.endswith(".xml"))
        if not sheets:
            return [], []
        root = ET.fromstring(zf.read(sheets[0]))
        grid = []
        for row in root.iter(f"{NS}row"):
            cells = {}
            for c in row.findall(f"{NS}c"):
                idx = _col_index(c.get("r", ""))
                ctype = c.get("t", "n")
                v = c.find(f"{NS}v")
                if ctype == "s" and v is not None:
                    try:
                        val = strings[int(v.text)]
                    except (ValueError, IndexError):
                        val = ""
                elif ctype == "inlineStr":
                    node = c.find(f"{NS}is")
                    val = "".join(t.text or "" for t in node.iter(f"{NS}t")) if node is not None else ""
                elif v is not None:
                    val = v.text or ""
                else:
                    val = ""
                cells[idx] = val.strip()
            if cells:
                width = max(cells) + 1
                grid.append([cells.get(i, "") for i in range(width)])
        if not grid:
            return [], []
    width = max(len(r) for r in grid)
    grid = [r + [""] * (width - len(r)) for r in grid]
    hi = _header_row_index(grid)
    header = [str(c).strip() or f"col{i + 1}" for i, c in enumerate(grid[hi])]
    out = []
    for r in grid[hi + 1:]:
        if not any(str(c).strip() for c in r):
            continue
        row = {header[i]: str(r[i]).strip() for i in range(len(header))}
        _coerce_excel_dates(row)
        out.append(row)
    return header, out


def _coerce_excel_dates(row):
    """Excel stores dates as serial numbers.  Convert only where the column
    name says it is a date -- never guess on an arbitrary numeric column."""
    for k, v in list(row.items()):
        key = norm_key(k)
        if not any(tok in key for tok in ("date", "time", "stamp", "dt")):
            continue
        try:
            serial = float(v)
        except (TypeError, ValueError):
            continue
        if 20000 < serial < 80000:
            row[k] = (EXCEL_EPOCH + dt.timedelta(days=serial)).strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------

def read_table(path: str):
    """Return (header_list, list_of_row_dicts) for any supported tabular file."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".xlsx", ".xlsm"):
        return _read_xlsx(path)
    return _read_delimited(path)


def header_keys(header):
    """Map normalised key -> original column name."""
    return {norm_key(h): h for h in header}


def pick(row, keymap, *aliases):
    """Fetch the first present alias from a row.  `aliases` are normalised keys."""
    for alias in aliases:
        col = keymap.get(alias)
        if col is not None:
            val = row.get(col, "")
            if str(val).strip():
                return str(val).strip()
    return ""


def has_any(keymap, *aliases) -> bool:
    return any(a in keymap for a in aliases)
