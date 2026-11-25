"""Testes unitários para todos os formatadores de relatório."""

import json
import unittest

from olho_de_sauron.models import Finding, Pillar, ScanResult, Severity, Verdict
from olho_de_sauron.reporters import (
    render_html,
    render_json,
    render_markdown,
    render_sarif,
    render_terminal,
)


def _sample_result(snippet: str = "query = f'SELECT * FROM x'") -> ScanResult:
    finding = Finding(
        rule_id="SAURON-SQLI-001",
        title="Possível SQL Injection via query dinâmica",
        severity=Severity.CRITICAL,
        pillar=Pillar.INJECTION,
        file_path="lab/app_vulneravel.py",
        line=34,
        column=5,
        snippet=snippet,
        description="Consulta dinâmica.",
        remediation="Use prepared statements.",
        owasp="A03:2021 - Injection",
        mitre_attack="T1190 - Exploit Public-Facing Application",
        cwe="CWE-89",
        cid_impact=["Confidencialidade", "Integridade"],
        scanner="python-ast",
    )
    return ScanResult(
        target="lab/app_vulneravel.py",
        started_at="2026-11-24T17:00:00+00:00",
        duration_seconds=0.05,
        files_scanned=1,
        files_skipped=0,
        findings=[finding],
        score=75,
        grade="C",
        verdict=Verdict.BLOQUEADO,
        counts_by_severity={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        counts_by_pillar={p.value: (1 if p == Pillar.INJECTION else 0) for p in Pillar},
    )


class TestReporters(unittest.TestCase):
    def test_json_reporter_valid_payload(self) -> None:
        raw = render_json(_sample_result())
        data = json.loads(raw)
        self.assertEqual(data["verdict"], "BLOQUEADO")
        self.assertEqual(data["total_findings"], 1)
        self.assertEqual(data["findings"][0]["rule_id"], "SAURON-SQLI-001")

    def test_markdown_reporter_contains_sections(self) -> None:
        md = render_markdown(_sample_result())
        self.assertIn("# Olho de Sauron", md)
        self.assertIn("SAURON-SQLI-001", md)
        self.assertIn("6 Pilares DevSecOps", md)

    def test_sarif_reporter_schema_v210(self) -> None:
        sarif = json.loads(render_sarif(_sample_result()))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("sarif-2.1.0.json", sarif["$schema"])
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "SAURON-SQLI-001")
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(
            run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            34,
        )

    def test_html_reporter_escapes_xss_payloads(self) -> None:
        xss_snippet = '<script>alert("xss")</script>'
        html_out = render_html(_sample_result(snippet=xss_snippet))
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertNotIn(xss_snippet, html_out)
        self.assertIn("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;", html_out)

    def test_terminal_reporter_fallback_works(self) -> None:
        out = render_terminal(_sample_result(), use_rich=False)
        self.assertIn("BLOQUEADO", out)
        self.assertIn("SAURON-SQLI-001", out)


if __name__ == "__main__":
    unittest.main()
