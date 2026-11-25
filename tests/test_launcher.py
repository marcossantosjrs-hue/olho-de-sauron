"""Testes unitários para o launcher standalone e resolução de assets frozen."""

import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from olho_de_sauron.launcher import find_available_port, run_launcher
from olho_de_sauron.web.app import _resolve_static_dir


class TestLauncherAndFrozenAssets(unittest.TestCase):
    def test_find_available_port_skips_occupied_port(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            occupied.bind(("127.0.0.1", 0))
            busy_port = int(occupied.getsockname()[1])
            chosen = find_available_port("127.0.0.1", preferred=busy_port, max_attempts=5)
            self.assertNotEqual(chosen, busy_port)
            self.assertGreater(chosen, 0)

    def test_resolve_static_dir_normal_and_frozen(self) -> None:
        normal_dir = _resolve_static_dir()
        self.assertTrue((normal_dir / "index.html").is_file())

        with tempfile.TemporaryDirectory() as tmp:
            fake_static = Path(tmp) / "olho_de_sauron" / "web" / "static"
            fake_static.mkdir(parents=True)
            (fake_static / "index.html").write_text("<html></html>", encoding="utf-8")

            with patch.object(sys, "frozen", True, create=True), patch.object(
                sys, "_MEIPASS", tmp, create=True
            ):
                resolved = _resolve_static_dir()
                self.assertEqual(resolved, fake_static)

    def test_run_launcher_delegates_cli_arguments(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            with self.assertRaises(SystemExit) as ctx:
                run_launcher(["version"])
            self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
