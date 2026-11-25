"""Testes unitários para PdfSecurityAnalyzer e LinkSecurityAnalyzer."""

import unittest

from olho_de_sauron.analyzers.link_scanner import LinkSecurityAnalyzer
from olho_de_sauron.analyzers.pdf_scanner import PdfSecurityAnalyzer


class TestPdfAndLinkScanners(unittest.TestCase):
    def setUp(self) -> None:
        self.pdf_analyzer = PdfSecurityAnalyzer()
        self.link_analyzer = LinkSecurityAnalyzer()

    def test_clean_pdf_returns_seguro(self) -> None:
        pdf_bytes = (
            b"%PDF-1.7\n"
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Count 1 /Kids [3 0 R] >> endobj\n"
            b"3 0 obj << /Type /Page /Parent 2 0 R >> endobj\n"
            b"%%EOF\n"
        )
        res = self.pdf_analyzer.analyze_bytes(pdf_bytes, filename="limpo.pdf")
        self.assertTrue(res["valid_pdf_header"])
        self.assertEqual(res["pdf_version"], "1.7")
        self.assertEqual(res["verdict"], "SEGURO")
        self.assertEqual(res["findings"], [])

    def test_malicious_pdf_detects_js_auto_launch_embed_and_audits_urls(self) -> None:
        pdf_bytes = (
            b"%PDF-1.6\n"
            b"1 0 obj << /Title (Fatura) /OpenAction 2 0 R >> endobj\n"
            b"2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj\n"
            b"3 0 obj << /S /Launch /F (cmd.exe) >> endobj\n"
            b"4 0 obj << /Type /Filespec /EF << /F 5 0 R >> /EmbeddedFile 1 >> endobj\n"
            b"5 0 obj << /A << /S /URI /URI (http://nubank-seguro.atualiza.xyz/boleto.exe) >> >> endobj\n"
            b"%%EOF\n"
        )
        res = self.pdf_analyzer.analyze_bytes(pdf_bytes, filename="fatura.pdf")
        rules = [f["rule_id"] for f in res["findings"]]
        self.assertEqual(res["verdict"], "PERIGOSO")
        self.assertIn("PDF-JS-001", rules)
        self.assertIn("PDF-AUTO-002", rules)
        self.assertIn("PDF-LAUNCH-003", rules)
        self.assertIn("PDF-EMBED-004", rules)
        self.assertIn("PDF-URI-006", rules)
        self.assertEqual(len(res["extracted_urls"]), 1)
        self.assertEqual(res["extracted_urls"][0]["verdict"], "PERIGOSO")

    def test_pdf_hex_obfuscation_and_invalid_header(self) -> None:
        obfuscated = b"%PDF-1.4\n1 0 obj << /J#61vaScript (x) >> endobj\n%%EOF\n"
        res_obf = self.pdf_analyzer.analyze_bytes(obfuscated, filename="obf.pdf")
        rules = [f["rule_id"] for f in res_obf["findings"]]
        self.assertIn("PDF-OBFUSC-007", rules)
        self.assertIn("PDF-JS-001", rules)

        not_pdf = self.pdf_analyzer.analyze_bytes(b"MZ_NOT_A_PDF", filename="fake.pdf")
        self.assertFalse(not_pdf["valid_pdf_header"])
        self.assertIn("PDF-HEADER-008", [f["rule_id"] for f in not_pdf["findings"]])

    def test_link_analyzer_safe_vs_phishing_patterns(self) -> None:
        safe = self.link_analyzer.analyze_url("https://docs.python.org/3/library/")
        self.assertEqual(safe["verdict"], "SEGURO")
        self.assertEqual(safe["risk_score"], 0)

        phish = self.link_analyzer.analyze_url("http://nubank-seguro.atualiza.xyz/login.exe")
        phish_rules = [f["rule_id"] for f in phish["findings"]]
        self.assertEqual(phish["verdict"], "PERIGOSO")
        self.assertIn("URL-BRAND-008", phish_rules)
        self.assertIn("URL-EXT-011", phish_rules)
        self.assertIn("URL-TLS-002", phish_rules)
        self.assertIn("URL-TLD-007", phish_rules)

        at_url = self.link_analyzer.analyze_url("https://banco.com@evil.click/auth")
        self.assertIn("URL-AT-004", [f["rule_id"] for f in at_url["findings"]])

        puny_url = self.link_analyzer.analyze_url("https://xn--pypal-4ve.com/login")
        self.assertIn("URL-PUNYCODE-005", [f["rule_id"] for f in puny_url["findings"]])

        js_url = self.link_analyzer.analyze_url("javascript:alert(1)")
        self.assertIn("URL-SCHEME-001", [f["rule_id"] for f in js_url["findings"]])

    def test_link_live_check_blocks_ssrf_to_loopback(self) -> None:
        res = self.link_analyzer.analyze_url("http://127.0.0.1:8000/admin", check_live=True)
        self.assertIsNotNone(res["live_check"])
        self.assertTrue(res["live_check"]["blocked_ssrf"])
        self.assertFalse(res["live_check"]["checked"])


if __name__ == "__main__":
    unittest.main()
