"""Testes unitários para o scanner de segredos e arquivos .env."""

import unittest
from pathlib import Path

from olho_de_sauron.scanners.secrets import SecretsScanner


class TestSecretsScanner(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = SecretsScanner()

    def test_detects_provider_keys_and_masks_snippet(self) -> None:
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        gh_tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        content = f'AWS_KEY = "{aws_key}"\nGITHUB = "{gh_tok}"\n'
        findings = self.scanner.scan_file(Path("config.py"), "config.py", content)

        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.rule_id == "SAURON-SEC-001" for f in findings))
        for f in findings:
            self.assertNotIn(aws_key, f.snippet)
            self.assertNotIn(gh_tok, f.snippet)
            self.assertIn("***REDACTED***", f.snippet)

    def test_detects_private_key_and_db_uri(self) -> None:
        pk_header = "-----BEGIN " + "RSA PRIVATE KEY-----"
        db_uri = "postgres://" + "admin:MyProdPass99@db.internal:5432/prod"
        content = f"{pk_header}\nDATABASE_URL = '{db_uri}'\n"
        findings = self.scanner.scan_file(Path("db.py"), "db.py", content)
        rules = [f.rule_id for f in findings]

        self.assertIn("SAURON-SEC-002", rules)
        self.assertIn("SAURON-SEC-003", rules)
        for f in findings:
            self.assertNotIn("MyProdPass99", f.snippet)

    def test_detects_hardcoded_secret_and_ignores_placeholders(self) -> None:
        real_secret = "x9K!mP2$vL8#qZ4@"
        content = (
            f'jwt_secret = "{real_secret}"\n'
            'api_key = "SUA_CHAVE_AQUI"\n'
            'secret_key = "changeme_placeholder"\n'
        )
        findings = self.scanner.scan_file(Path("settings.py"), "settings.py", content)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SAURON-SEC-004")
        self.assertNotIn(real_secret, findings[0].snippet)

    def test_real_env_flagged_while_env_example_is_safe(self) -> None:
        env_content = "API_KEY=RealSecretValue987654\n"
        example_content = "API_KEY=SUA_CHAVE_AQUI\n"

        env_findings = self.scanner.scan_file(Path(".env"), ".env", env_content)
        example_findings = self.scanner.scan_file(Path(".env.example"), ".env.example", example_content)

        env_rules = [f.rule_id for f in env_findings]
        self.assertIn("SAURON-SEC-005", env_rules)
        self.assertIn("SAURON-SEC-004", env_rules)
        self.assertEqual(example_findings, [])


if __name__ == "__main__":
    unittest.main()
