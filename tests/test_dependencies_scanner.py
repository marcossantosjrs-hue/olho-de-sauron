"""Testes unitários para o scanner de dependências e supply chain."""

import unittest
from pathlib import Path

from olho_de_sauron.scanners.dependencies import DependencyScanner


class TestDependencyScanner(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = DependencyScanner()

    def test_requirements_unpinned_vulnerable_and_http(self) -> None:
        req = (
            "--extra-index-url http://insecure.example.com/simple\n"
            "requests\n"
            "pycrypto==2.6.1\n"
            "flask==2.0.1\n"
            "click==8.1.7\n"
        )
        findings = self.scanner.scan_file(Path("requirements.txt"), "requirements.txt", req)
        rules = [f.rule_id for f in findings]
        self.assertIn("SAURON-DEP-003", rules)
        self.assertIn("SAURON-DEP-001", rules)
        self.assertEqual(rules.count("SAURON-DEP-002"), 2)

    def test_package_json_detection(self) -> None:
        pkg = (
            '{\n'
            '  "name": "demo",\n'
            '  "dependencies": {\n'
            '    "lodash": "4.17.15",\n'
            '    "express": "latest",\n'
            '    "evil": "http://registry.insecure.local/evil.tgz"\n'
            '  }\n'
            '}\n'
        )
        findings = self.scanner.scan_file(Path("package.json"), "package.json", pkg)
        rules = [f.rule_id for f in findings]
        self.assertIn("SAURON-DEP-002", rules)
        self.assertIn("SAURON-DEP-001", rules)
        self.assertIn("SAURON-DEP-003", rules)

    def test_secure_requirements_has_zero_findings(self) -> None:
        req = "click==8.1.7\nPyYAML==6.0.3\nrequests==2.32.3\n"
        self.assertEqual(
            self.scanner.scan_file(Path("requirements.txt"), "requirements.txt", req),
            [],
        )


if __name__ == "__main__":
    unittest.main()
