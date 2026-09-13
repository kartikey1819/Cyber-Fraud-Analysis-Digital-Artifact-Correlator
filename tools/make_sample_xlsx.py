"""Generate the Axis Bank mule statement as a real .xlsx (OOXML) file.

Kept as a generator rather than a checked-in binary so the sample dataset stays
diff-able and auditable.  Uses zipfile + string templates only.

    python tools/make_sample_xlsx.py
"""

import os
import zipfile
from xml.sax.saxutils import escape

HEADER = ["ACCT NO", "CUSTOMER NAME", "VALUE DATE", "PARTICULARS", "UTR",
          "DR", "CR", "BALANCE", "COUNTERPARTY NAME", "COUNTERPARTY ACCOUNT",
          "IFSC", "CHANNEL", "LOGIN IP", "REGISTERED MOBILE"]

ACC = "918020045566778"
CUST = "SANJAY YADAV"

ROWS = [
    ["2026-09-08 09:55:12", "UPI-IN/226951090012/ANITA SHARMA/anita.sharma7@ybl",
     "226951090012", "", 60000.00, 68420.00, "ANITA SHARMA", "4410022003311",
     "YESB0000441", "UPI", "103.86.12.71"],
    ["2026-09-08 10:12:40", "UPI-IN/226951090188/M K PATEL/mkpatel.1972@okicici",
     "226951090188", "", 45000.00, 113420.00, "M K PATEL", "004401502299813",
     "ICIC0000044", "UPI", "103.86.12.71"],
    ["2026-09-08 10:32:11", "IMPS-IN/226951112040/RAMESH KUMAR/HDFC",
     "226951112040", "", 195000.00, 308420.00, "RAMESH KUMAR", "50100234567890",
     "HDFC0001842", "IMPS", "103.86.12.71"],
    ["2026-09-08 10:36:47", "IMPS-IN/226951112188/RAMESH KUMAR/HDFC",
     "226951112188", "", 195000.00, 503420.00, "RAMESH KUMAR", "50100234567890",
     "HDFC0001842", "IMPS", "103.86.12.71"],
    ["2026-09-08 10:41:05", "IMPS-IN/226951112377/RAMESH KUMAR/HDFC",
     "226951112377", "", 95000.00, 598420.00, "RAMESH KUMAR", "50100234567890",
     "HDFC0001842", "IMPS", "103.86.12.71"],
    ["2026-09-08 10:48:33", "IMPS-OUT/226951113904/POOJA DEVI/SBIN",
     "226951113904", 195000.00, "", 403420.00, "POOJA DEVI", "20345678901234",
     "SBIN0003421", "IMPS", "103.86.12.71"],
    ["2026-09-08 10:53:07", "IMPS-OUT/226951114188/RAKESH VERMA/ICIC",
     "226951114188", 190000.00, "", 213420.00, "RAKESH VERMA", "004301500222789",
     "ICIC0004301", "IMPS", "103.86.12.71"],
    ["2026-09-08 10:58:41", "IMPS-OUT/226951114620/KARAN TRADERS/KKBK",
     "226951114620", 95000.00, "", 118420.00, "KARAN TRADERS", "751234567890",
     "KKBK0007512", "IMPS", "103.86.12.71"],
    ["2026-09-08 11:04:55", "IMPS-OUT/226951114901/KARAN TRADERS/KKBK",
     "226951114901", 110000.00, "", 8420.00, "KARAN TRADERS", "751234567890",
     "KKBK0007512", "IMPS", "103.86.12.71"],
    ["2026-09-08 11:15:03", "UPI-IN/226951090402/D SOLANKI/d.solanki88@oksbi",
     "226951090402", "", 38000.00, 46420.00, "D SOLANKI", "20399887711234",
     "SBIN0020399", "UPI", "103.86.12.71"],
    ["2026-09-08 11:18:22", "IMPS-OUT/226951115233/MEENA DEVI/BKID",
     "226951115233", 38000.00, "", 8420.00, "MEENA DEVI", "441010110002233",
     "BKID0004410", "IMPS", "103.86.12.71"],
]

MOBILE = "9812345670"

CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
</Types>"""

RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

WORKBOOK = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Statement" sheetId="1" r:id="rId1"/></sheets>
</workbook>"""

WB_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
</Relationships>"""


def col_name(idx):
    name = ""
    idx += 1
    while idx:
        idx, rem = divmod(idx - 1, 26)
        name = chr(65 + rem) + name
    return name


def build():
    grid = [HEADER]
    for r in ROWS:
        date, part, utr, dr, cr, bal, cpn, cpa, ifsc, chan, ip = r
        grid.append([ACC, CUST, date, part, utr, dr, cr, bal, cpn, cpa, ifsc,
                     chan, ip, MOBILE])

    strings, index = [], {}

    def sid(val):
        if val not in index:
            index[val] = len(strings)
            strings.append(val)
        return index[val]

    rows_xml = []
    for r_i, row in enumerate(grid, start=1):
        cells = []
        for c_i, val in enumerate(row):
            ref = f"{col_name(c_i)}{r_i}"
            if isinstance(val, (int, float)) and val != "":
                cells.append(f'<c r="{ref}"><v>{val}</v></c>')
            else:
                text = "" if val is None else str(val)
                if text == "":
                    continue
                cells.append(f'<c r="{ref}" t="s"><v>{sid(text)}</v></c>')
        rows_xml.append(f'<row r="{r_i}">' + "".join(cells) + "</row>")

    sheet = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
             "<sheetData>" + "".join(rows_xml) + "</sheetData></worksheet>")

    shared = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              f'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
              f'count="{len(strings)}" uniqueCount="{len(strings)}">' +
              "".join(f"<si><t>{escape(s)}</t></si>" for s in strings) + "</sst>")

    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "sample_data", "bank_statement_axis_mule.xlsx")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", CONTENT_TYPES)
        zf.writestr("_rels/.rels", RELS)
        zf.writestr("xl/workbook.xml", WORKBOOK)
        zf.writestr("xl/_rels/workbook.xml.rels", WB_RELS)
        zf.writestr("xl/sharedStrings.xml", shared)
        zf.writestr("xl/worksheets/sheet1.xml", sheet)
    print("wrote", out)
    return out


if __name__ == "__main__":
    build()
