"""Testes unitários para o instalador standalone Olho de Sauron."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from installer.setup_wizard import install_application


class TestInstallerSetup(unittest.TestCase):
    def test_install_application_copies_payload_and_creates_uninstaller(self) -> None:
        with tempfile.TemporaryDirectory() as payload_tmp, tempfile.TemporaryDirectory() as dest_tmp:
            payload_dir = Path(payload_tmp)
            fake_exe = payload_dir / "OlhoDeSauron.exe"
            fake_ico = payload_dir / "sauron_eye.ico"
            fake_exe.write_bytes(b"MZ_FAKE_EXE")
            fake_ico.write_bytes(b"FAKE_ICO")

            dest_dir = Path(dest_tmp) / "Olho de Sauron"
            with patch("installer.setup_wizard._resolve_payload_dir", return_value=payload_dir):
                res = install_application(
                    dest_dir=dest_dir,
                    create_desktop=False,
                    create_start_menu=False,
                    register_uninstall=False,
                )

            self.assertTrue((dest_dir / "OlhoDeSauron.exe").is_file())
            self.assertTrue((dest_dir / "sauron_eye.ico").is_file())
            self.assertTrue((dest_dir / "Desinstalar.bat").is_file())
            self.assertEqual(Path(res["exe_path"]), dest_dir.resolve() / "OlhoDeSauron.exe")


if __name__ == "__main__":
    unittest.main()
