"""End-to-end and unit tests.

    python -m unittest discover -s tests -v
    python tests/test_pipeline.py
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cfc import correlate, parsers  # noqa: E402
from cfc.case import Case  # noqa: E402
from cfc.evidence import sha256_file  # noqa: E402
from cfc.pdfwriter import PDF, wrap  # noqa: E402
from cfc.report import render_pdf  # noqa: E402
from cfc.tabular import read_table  # noqa: E402
from cfc.textmine import apk_risk, extract_indicators, lure_score, url_risk  # noqa: E402
from cfc.util import (inr, norm_account, norm_imei, norm_ip, norm_mac,  # noqa: E402
                      norm_msisdn, norm_upi, parse_amount, parse_ts, subnet24)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "sample_data")


class TestNormalisation(unittest.TestCase):
    def test_msisdn(self):
        for raw in ("9876543210", "+91 98765 43210", "919876543210", "09876543210",
                    "91-9876543210"):
            self.assertEqual(norm_msisdn(raw), "9876543210", raw)
        self.assertEqual(norm_msisdn("1930"), "1930")           # short code preserved
        self.assertEqual(norm_msisdn("VM-HDFCBK"), "VM-HDFCBK")  # sender id preserved
        self.assertIsNone(norm_msisdn(""))

    def test_imei_normalises_to_14_digit_body(self):
        # 15th digit is a Luhn check, 16th is software version: same handset
        self.assertEqual(norm_imei("351756051523987"), "35175605152398")
        self.assertEqual(norm_imei("3517560515239812"), "35175605152398")
        self.assertIsNone(norm_imei("12345"))

    def test_masked_accounts_are_not_merged(self):
        full, masked = norm_account("50100234567890")
        self.assertEqual((full, masked), ("50100234567890", False))
        m, is_masked = norm_account("XXXXXX7890")
        self.assertTrue(is_masked)
        self.assertNotEqual(m, full)

    def test_vpa_vs_email(self):
        self.assertEqual(norm_upi("Sanjay.Y@okaxis"), "sanjay.y@okaxis")
        self.assertIsNone(norm_upi("ramesh@gmail.com"))   # dotted host = email

    def test_ip_mac_subnet(self):
        self.assertEqual(norm_ip("103.86.012.044"), "103.86.12.44")
        self.assertIsNone(norm_ip("999.1.1.1"))
        self.assertEqual(subnet24("103.86.12.71"), "103.86.12.0/24")
        self.assertEqual(norm_mac("02-1A-2B-3C-4D-5E"), "02:1a:2b:3c:4d:5e")

    def test_timestamps(self):
        want = "2026-09-08 10:32:11"
        for raw in ("2026-09-08 10:32:11", "08/09/2026 10:32:11", "08-09-2026 10:32:11",
                    "08-Sep-2026 10:32:11", "2026-09-08T10:32:11"):
            self.assertEqual(str(parse_ts(raw)), want, raw)
        self.assertIsNone(parse_ts("not a date"))

    def test_amounts(self):
        self.assertEqual(parse_amount("Rs. 4,85,000.00"), 485000.0)
        self.assertEqual(parse_amount("1,250 DR"), -1250.0)
        self.assertIsNone(parse_amount("-"))
        self.assertEqual(inr(485000), "4,85,000")


class TestTextIntelligence(unittest.TestCase):
    def test_indicator_extraction_is_context_gated(self):
        text = ("Call 9123456789 or pay to sanjay.y@okaxis, a/c no 751234567890, "
                "link http://sbi-rewardz.xyz/x.apk, mail a@b.com, 351756051523987")
        ind = extract_indicators(text)
        self.assertIn("9123456789", ind["phones"])
        self.assertIn("sanjay.y@okaxis", ind["vpas"])
        self.assertIn("751234567890", ind["accounts"])
        self.assertIn("a@b.com", ind["emails"])
        self.assertIn("351756051523987", ind["imeis"])
        self.assertNotIn("a@b.com", ind["vpas"])   # email must not become a VPA

    def test_bare_numbers_are_not_harvested_as_accounts(self):
        # no account keyword nearby -> not an account
        self.assertEqual(extract_indicators("reference 751234567890 quoted")["accounts"], [])

    def test_lure_and_url_scoring(self):
        score, hits = lure_score("Your KYC is pending, account will be blocked. "
                                 "Install this .apk and enable accessibility. Share OTP.")
        self.assertGreater(score, 60)
        self.assertTrue(hits)
        self.assertEqual(lure_score("Meeting at 5pm")[0], 0)
        reasons = url_risk("http://sbi-rewardz.xyz/download/SBI-Rewards.apk")
        self.assertTrue(any("apk" in r.lower() for r in reasons))
        self.assertTrue(any("sbi" in r.lower() for r in reasons))
        self.assertEqual(url_risk("https://www.onlinesbi.sbi/"), [])

    def test_apk_triage(self):
        score, reasons = apk_risk("com.sbi.rewards", [
            "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW"], installer="com.android.chrome")
        self.assertGreaterEqual(score, 75)
        self.assertTrue(any("OTP" in r for r in reasons))
        benign, _ = apk_risk("com.whatsapp", ["android.permission.CAMERA"],
                             installer="com.android.vending")
        self.assertLess(benign, 35)


class TestTabular(unittest.TestCase):
    def test_reads_csv_with_banner_rows(self):
        header, rows = read_table(os.path.join(SAMPLES, "cdr_victim_9876543210.csv"))
        self.assertIn("A-PARTY", header)
        self.assertEqual(len(rows), 14)

    def test_reads_pipe_delimited_txt(self):
        header, rows = read_table(os.path.join(SAMPLES, "cdr_imei_dump_359871042256641.txt"))
        self.assertIn("caller", header)
        self.assertEqual(len(rows), 14)

    def test_reads_xlsx_without_openpyxl(self):
        path = os.path.join(SAMPLES, "bank_statement_axis_mule.xlsx")
        if not os.path.exists(path):
            self.skipTest("run tools/make_sample_xlsx.py first")
        header, rows = read_table(path)
        self.assertIn("ACCT NO", header)
        self.assertEqual(len(rows), 11)


class TestDetection(unittest.TestCase):
    EXPECTED = {
        "cdr_victim_9876543210.csv": "CDR",
        "cdr_imei_dump_359871042256641.txt": "CDR",
        "ipdr_sessions.csv": "IPDR",
        "bank_statement_hdfc_victim.csv": "BANK",
        "bank_layer2_consolidated.csv": "BANK",
        "bank_statement_axis_mule.xlsx": "BANK",
        "upi_settlement_psp.csv": "UPI",
        "phishing_email_sbi_rewards.eml": "EMAIL",
        "android_dump_victim_handset.json": "ANDROID",
        "android_dump_suspect_handset.json": "ANDROID",
        "whatsapp_chat_export.txt": "CHAT",
        "complaint.json": "COMPLAINT",
    }

    def test_content_signature_detection(self):
        for name, want in self.EXPECTED.items():
            path = os.path.join(SAMPLES, name)
            if not os.path.exists(path):
                continue
            got, _ = parsers.detect_type(path)
            self.assertEqual(got, want, f"{name}: detected {got}, expected {want}")


class TestCorrelationRules(unittest.TestCase):
    def test_cdr_ownership_follows_the_serving_subscriber(self):
        """On an INCOMING record the IMEI belongs to the B-party, not the caller."""
        _, events = parsers.parse(os.path.join(SAMPLES, "cdr_victim_9876543210.csv"),
                                  "EX-T", "cdr.csv")
        g = correlate.build_graph(events)
        imei = [n for n in g.by_type("IMEI")][0]
        phones = {g.nodes[p]["value"]
                  for p in g.neighbors(imei["id"], {"USES_HANDSET"})
                  if g.nodes[p]["type"] == "PHONE"}
        self.assertEqual(phones, {"9876543210"})

    def test_email_header_spoofing_detected(self):
        _, events = parsers.parse(os.path.join(SAMPLES, "phishing_email_sbi_rewards.eml"),
                                  "EX-T", "mail.eml")
        flags = " ".join(f for e in events for f in e.flags).lower()
        self.assertIn("envelope mismatch", flags)
        self.assertIn("authentication failed", flags)
        self.assertIn("spf", flags)


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cfc-test-")
        cls.case = Case(officer="TEST", workdir=cls.tmp)
        cls.case.add_directory(SAMPLES)
        cls.case.analyze()
        cls.report = cls.case.report()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_every_exhibit_parsed_and_verified(self):
        self.assertGreaterEqual(len(self.case.exhibits), 10)
        for ex in self.case.exhibits:
            self.assertEqual(ex.parse_status, "PARSED", ex.original_name)
            self.assertTrue(ex.verify(), ex.original_name)
            self.assertNotEqual(ex.artifact_type, "UNKNOWN", ex.original_name)
        self.assertEqual(self.case.errors, [])

    def test_hashes_are_recorded_and_reverified(self):
        integ = self.report["evidentiary_integrity"]
        self.assertTrue(all(integ["reverify"].values()))
        for ex in integ["exhibits"]:
            self.assertRegex(ex["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(integ["chain_of_custody"]["log_sha256"], r"^[0-9a-f]{64}$")

    def test_victim_identified_from_complaint(self):
        v = self.report["victim"]
        self.assertEqual(v["name"], "Ramesh Kumar")
        self.assertEqual(v["amount_reported"], 485000.0)
        # the three fraudulent IMPS debits, not the unrelated grocery payment
        self.assertEqual(v["amount_debited_observed"], 485000.0)
        self.assertTrue(v["first_debit"].startswith("2026-09-08T10:32"))

    def test_cross_statement_transactions_counted_once(self):
        """The same transfer appears in both banks' statements."""
        axis = self.case.graph.nodes["ACCOUNT|918020045566778"]
        self.assertEqual(round(axis["in_amount"]), 628000)
        self.assertEqual(round(axis["out_amount"]), 628000)

    def test_shared_handset_and_sim_velocity(self):
        codes = {f.code for f in self.case.findings}
        self.assertIn("SHARED-HANDSET-225664", codes)
        self.assertIn("SIM-VELOCITY-225664", codes)
        sim = next(f for f in self.case.findings if f.code == "SIM-VELOCITY-225664")
        self.assertEqual(sim.severity, "CRITICAL")

    def test_identity_cluster_merges_account_vpa_and_mobile(self):
        cid = self.case.node_to_cluster["ACCOUNT|918020045566778"]
        members = set(self.case.clusters[cid]["members"])
        self.assertIn("UPI|sanjay.y@okaxis", members)
        self.assertIn("PHONE|9812345670", members)

    def test_names_alone_never_merge_identities(self):
        """Two accounts sharing only a holder name stay separate nodes."""
        a = self.case.node_to_cluster.get("ACCOUNT|918020045566778")
        b = self.case.node_to_cluster.get("ACCOUNT|20345678901234")
        self.assertNotEqual(a, b)

    def test_apk_hash_cross_reference(self):
        codes = {f.code for f in self.case.findings}
        self.assertTrue(any(c.startswith("APK-HASH-") for c in codes))
        self.assertTrue(any(c.startswith("MALICIOUS-APK-com.sbi.rewards") for c in codes))

    def test_mule_chain_reaches_the_cash_out(self):
        trail = self.case.trail
        self.assertIn("ACCOUNT|50100234567890", trail["origins"])
        reached = {h["to"] for h in trail["hops"]}
        for mule in ("ACCOUNT|918020045566778", "ACCOUNT|20345678901234",
                     "ACCOUNT|004301500222789", "ACCOUNT|751234567890"):
            self.assertIn(mule, reached, mule)
        modes = {c["mode"] for c in trail["cashouts"]}
        self.assertIn("ATM/CASH", modes)
        self.assertIn("CRYPTO/P2P", modes)

    def test_layer_assignment(self):
        layers = correlate.layer_of(self.case.trail)
        self.assertEqual(layers["ACCOUNT|918020045566778"], 1)
        self.assertEqual(layers["ACCOUNT|20345678901234"], 2)

    def test_prime_suspects_are_the_mules(self):
        labels = {s["primary"] for s in self.case.suspects[:6]}
        self.assertIn("ACCOUNT|918020045566778", labels)
        self.assertIn("ACCOUNT|751234567890", labels)
        for s in self.case.suspects[:5]:
            self.assertGreaterEqual(s["score"], 55)
            self.assertTrue(s["reasons"], "every score must be explainable")

    def test_victim_is_never_ranked_as_a_suspect(self):
        primaries = {s["primary"] for s in self.case.suspects}
        self.assertNotIn("ACCOUNT|50100234567890", primaries)
        self.assertNotIn("PHONE|9876543210", primaries)

    def test_other_complainants_excluded_from_suspects(self):
        """Remitters who only ever pay into a collector are further victims."""
        primaries = {s["primary"] for s in self.case.suspects}
        for other in ("ACCOUNT|4410022003311", "ACCOUNT|004401502299813",
                      "ACCOUNT|20399887711234"):
            self.assertNotIn(other, primaries, other)
        self.assertTrue(any(f.code.startswith("ADDL-VICTIM-") for f in self.case.findings))

    def test_recommendations_cover_the_golden_hour(self):
        recs = self.report["recommended_actions"]
        immediate = [r for r in recs if r["priority"] == "IMMEDIATE"]
        self.assertTrue(immediate)
        text = " ".join(r["action"] for r in recs)
        self.assertIn("918020045566778", text)
        self.assertIn("Freeze VPA", text)
        self.assertIn("Sec.91", text)

    def test_every_timeline_entry_cites_its_exhibit(self):
        for entry in self.report["timeline"]:
            self.assertRegex(entry["cite"], r"^EX-\d{3} \(")

    def test_report_is_json_serialisable_and_hashed(self):
        blob = json.dumps(self.report, default=str)
        self.assertGreater(len(blob), 5000)
        self.assertRegex(self.report["report_sha256"], r"^[0-9a-f]{64}$")

    def test_pdf_renders(self):
        path = os.path.join(self.tmp, "brief.pdf")
        render_pdf(self.report, path)
        with open(path, "rb") as fh:
            data = fh.read()
        self.assertTrue(data.startswith(b"%PDF-1.4"))
        self.assertTrue(data.rstrip().endswith(b"%%EOF"))
        self.assertGreaterEqual(data.count(b"/Type /Page "), 4)
        self.assertGreater(len(data), 8000)

    def test_performance_budget(self):
        """Triage must finish inside the golden hour, not compete with it."""
        self.assertLess(self.case.processing_ms, 15000)


class TestIntegrityEnforcement(unittest.TestCase):
    def test_tampered_exhibit_is_rejected(self):
        tmp = tempfile.mkdtemp(prefix="cfc-tamper-")
        try:
            src = os.path.join(tmp, "cdr.csv")
            shutil.copy2(os.path.join(SAMPLES, "cdr_victim_9876543210.csv"), src)
            case = Case(officer="TEST", workdir=tmp)
            ex = case.add_path(src)
            original = ex.sha256

            os.chmod(ex.stored_path, 0o600)
            with open(ex.stored_path, "a", encoding="utf-8") as fh:
                fh.write("9999999999,8888888888,OUTGOING,08/09/2026 23:59:59,10,"
                         "351756051523987,404451122334455,X,Y,N\n")

            self.assertNotEqual(sha256_file(ex.stored_path), original)
            self.assertFalse(ex.verify())
            case.analyze()
            self.assertEqual(ex.parse_status, "INTEGRITY_FAIL")
            self.assertEqual(len(case.events), 0)
            self.assertTrue(any(e["action"] == "INTEGRITY_FAIL"
                                for e in case.custody.entries))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestPdfWriter(unittest.TestCase):
    def test_wrap_respects_width(self):
        lines = wrap("the quick brown fox jumps over the lazy dog " * 6, 8, 200)
        self.assertGreater(len(lines), 4)

    def test_minimal_document(self):
        pdf = PDF()
        page = pdf.new_page()
        page.text(40, 40, "Rupee ₹ and arrow → transliterate safely")
        page.rect(40, 60, 100, 20, fill=(1, 0, 0))
        data = pdf.build()
        self.assertTrue(data.startswith(b"%PDF"))
        self.assertIn(b"startxref", data)


class TestRobustness(unittest.TestCase):
    def test_unknown_and_empty_files_do_not_crash_the_case(self):
        tmp = tempfile.mkdtemp(prefix="cfc-junk-")
        try:
            with open(os.path.join(tmp, "empty.csv"), "w") as fh:
                fh.write("")
            with open(os.path.join(tmp, "junk.txt"), "w") as fh:
                fh.write("nothing structured here at all\n" * 5)
            with open(os.path.join(tmp, "broken.json"), "w") as fh:
                fh.write("{not valid json")
            shutil.copy2(os.path.join(SAMPLES, "complaint.json"), tmp)
            case = Case(officer="TEST", workdir=os.path.join(tmp, "work"))
            case.add_directory(tmp)
            case.analyze()
            self.assertEqual(case.errors, [])
            self.assertGreaterEqual(len(case.events), 1)
            report = case.report()
            self.assertIn("prime_suspects", report)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
