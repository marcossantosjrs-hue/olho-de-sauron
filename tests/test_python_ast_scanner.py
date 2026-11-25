"""Testes unitários para o motor SAST via AST Python."""

import unittest
from pathlib import Path

from olho_de_sauron.scanners.python_ast import PythonAstScanner

ROOT_DIR = Path(__file__).resolve().parent.parent


class TestPythonAstScanner(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = PythonAstScanner()

    def _scan(self, code: str, filename: str = "sample.py") -> list[str]:
        findings = self.scanner.scan_file(Path(filename), filename, code)
        return [f.rule_id for f in findings]

    def test_detects_sqli_direct_and_variable(self) -> None:
        code = (
            "def q(conn, user):\n"
            "    sql = f'SELECT * FROM users WHERE name = {user}'\n"
            "    conn.execute(sql)\n"
            "    conn.execute('SELECT * FROM users WHERE id = ' + user)\n"
        )
        rules = self._scan(code)
        self.assertEqual(rules.count("SAURON-SQLI-001"), 2)

    def test_detects_lab_vulnerable_and_passes_lab_safe(self) -> None:
        vuln_path = ROOT_DIR / "lab" / "app_vulneravel.py"
        safe_path = ROOT_DIR / "lab" / "app_seguro.py"

        vuln_findings = self.scanner.scan_file(
            vuln_path, "lab/app_vulneravel.py", vuln_path.read_text(encoding="utf-8")
        )
        safe_findings = self.scanner.scan_file(
            safe_path, "lab/app_seguro.py", safe_path.read_text(encoding="utf-8")
        )

        self.assertTrue(any(f.rule_id == "SAURON-SQLI-001" for f in vuln_findings))
        self.assertEqual(safe_findings, [])

    def test_detects_command_injection_eval_deserialization(self) -> None:
        code = (
            "import os, subprocess, pickle, yaml\n"
            "os.system('ls')\n"
            "subprocess.run('id', shell=True)\n"
            "eval('1+1')\n"
            "pickle.loads(b'abc')\n"
            "yaml.load('a: 1')\n"
            "yaml.load('a: 1', Loader=yaml.SafeLoader)\n"
        )
        rules = self._scan(code)
        self.assertEqual(rules.count("SAURON-INJ-002"), 2)
        self.assertIn("SAURON-INJ-003", rules)
        self.assertEqual(rules.count("SAURON-DESER-004"), 2)

    def test_detects_weak_crypto_tls_debug_bind_except_and_logging(self) -> None:
        code = (
            "import hashlib, logging, ssl, requests, socket\n"
            "DEBUG = True\n"
            "hashlib.md5(b'abc')\n"
            "hashlib.md5(b'abc', usedforsecurity=False)\n"
            "requests.get('https://example.com', verify=False)\n"
            "ssl._create_unverified_context()\n"
            "app.run(debug=True, host='0.0.0.0')\n"
            "s = socket.socket()\n"
            "s.bind(('0.0.0.0', 8080))\n"
            "password = 'x'\n"
            "logging.info('User pass=%s', password)\n"
            "try:\n"
            "    pass\n"
            "except Exception:\n"
            "    pass\n"
        )
        rules = self._scan(code)
        self.assertEqual(rules.count("SAURON-CRYPTO-005"), 1)
        self.assertEqual(rules.count("SAURON-CFG-006"), 2)
        self.assertEqual(rules.count("SAURON-CFG-007"), 2)
        self.assertEqual(rules.count("SAURON-NET-010"), 2)
        self.assertIn("SAURON-LOG-009", rules)
        self.assertIn("SAURON-ERR-008", rules)

    def test_inline_suppression_ignores_rule(self) -> None:
        code = (
            "import os\n"
            "os.system('echo ok')  # sauron: ignore[SAURON-INJ-002]\n"
            "eval('1+1')  # sauron: ignore\n"
        )
        self.assertEqual(self._scan(code), [])

    def test_syntax_error_returns_empty(self) -> None:
        self.assertEqual(self._scan("def broken(:\n  pass"), [])


if __name__ == "__main__":
    unittest.main()
