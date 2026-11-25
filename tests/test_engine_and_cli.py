"""Testes de integração end-to-end para ScanEngine e CLI `sauron`."""

import json
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from olho_de_sauron.cli import main

ROOT_DIR = Path(__file__).resolve().parent.parent


class TestEngineAndCli(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_scan_vulnerable_lab_blocks_with_exit_code_2(self) -> None:
        target = str(ROOT_DIR / "lab" / "app_vulneravel.py")
        res = self.runner.invoke(main, ["scan", target])
        self.assertEqual(res.exit_code, 2, msg=res.output)
        self.assertIn("BLOQUEADO", res.output)
        self.assertIn("SAURON-SQLI-001", res.output)

    def test_scan_safe_lab_approves_with_exit_code_0(self) -> None:
        target = str(ROOT_DIR / "lab" / "app_seguro.py")
        res = self.runner.invoke(main, ["scan", target])
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertIn("APROVADO", res.output)

    def test_self_scan_olho_de_sauron_is_clean(self) -> None:
        target = str(ROOT_DIR / "olho_de_sauron")
        res = self.runner.invoke(main, ["scan", target, "--fail-on", "high"])
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertIn("APROVADO", res.output)

    def test_scan_generates_all_artifact_formats(self) -> None:
        target = str(ROOT_DIR / "lab")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            html_file = tmp_path / "report.html"
            sarif_file = tmp_path / "report.sarif"
            json_file = tmp_path / "report.json"
            md_file = tmp_path / "report.md"

            res = self.runner.invoke(
                main,
                [
                    "scan",
                    target,
                    "--html",
                    str(html_file),
                    "--sarif",
                    str(sarif_file),
                    "--json-out",
                    str(json_file),
                    "--md-out",
                    str(md_file),
                    "--fail-on",
                    "none",
                ],
            )
            self.assertEqual(res.exit_code, 0, msg=res.output)
            self.assertTrue(html_file.is_file())
            self.assertTrue(sarif_file.is_file())
            self.assertTrue(json_file.is_file())
            self.assertTrue(md_file.is_file())

            sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
            self.assertEqual(sarif_data["version"], "2.1.0")
            json_data = json.loads(json_file.read_text(encoding="utf-8"))
            self.assertGreaterEqual(json_data["total_findings"], 1)

    def test_rules_version_and_init_ignore_commands(self) -> None:
        r_rules = self.runner.invoke(main, ["rules", "--severity", "critical"])
        self.assertEqual(r_rules.exit_code, 0, msg=r_rules.output)
        self.assertIn("SAURON-SQLI-001", r_rules.output)

        r_ver = self.runner.invoke(main, ["version"])
        self.assertEqual(r_ver.exit_code, 0, msg=r_ver.output)
        self.assertIn("Olho de Sauron", r_ver.output)

        with tempfile.TemporaryDirectory() as tmp:
            r_init = self.runner.invoke(main, ["init-ignore", tmp])
            self.assertEqual(r_init.exit_code, 0, msg=r_init.output)
            self.assertTrue((Path(tmp) / ".sauronignore").is_file())


if __name__ == "__main__":
    unittest.main()
