"""Testes unitários para o scanner de configurações e hardening."""

import unittest
from pathlib import Path

from olho_de_sauron.scanners.configs import ConfigHardeningScanner


class TestConfigHardeningScanner(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = ConfigHardeningScanner()

    def test_dockerfile_root_and_latest_detection(self) -> None:
        bad_dockerfile = "FROM python:latest\nWORKDIR /app\nCMD [\"python\", \"app.py\"]\n"
        findings = self.scanner.scan_file(Path("Dockerfile"), "Dockerfile", bad_dockerfile)
        rules = [f.rule_id for f in findings]
        self.assertIn("SAURON-INFRA-001", rules)
        self.assertIn("SAURON-INFRA-002", rules)

        good_dockerfile = "FROM python:3.12-slim\nRUN useradd -m app\nUSER app\nCMD [\"python\", \"app.py\"]\n"
        self.assertEqual(
            self.scanner.scan_file(Path("Dockerfile"), "Dockerfile", good_dockerfile),
            [],
        )

    def test_docker_compose_privileged_and_socket(self) -> None:
        compose = (
            "services:\n"
            "  app:\n"
            "    image: myimage:1.0\n"
            "    privileged: true\n"
            "    volumes:\n"
            "      - /var/run/docker.sock:/var/run/docker.sock\n"
        )
        findings = self.scanner.scan_file(Path("docker-compose.yml"), "docker-compose.yml", compose)
        self.assertEqual([f.rule_id for f in findings], ["SAURON-INFRA-003", "SAURON-INFRA-003"])

    def test_sshd_and_nginx_hardening(self) -> None:
        sshd = "PermitRootLogin yes\nPasswordAuthentication yes\n"
        ssh_rules = [f.rule_id for f in self.scanner.scan_file(Path("sshd_config"), "sshd_config", sshd)]
        self.assertEqual(ssh_rules, ["SAURON-INFRA-004", "SAURON-INFRA-004"])

        nginx = "server {\n  server_tokens on;\n  autoindex on;\n  ssl_protocols TLSv1 TLSv1.2;\n}\n"
        nginx_rules = [f.rule_id for f in self.scanner.scan_file(Path("nginx.conf"), "nginx.conf", nginx)]
        self.assertEqual(nginx_rules.count("SAURON-INFRA-005"), 3)

    def test_cors_wildcard_and_debug_config(self) -> None:
        py_cors = 'app.add_middleware(CORSMiddleware, allow_origins=["*"])\n'
        env_dbg = "DEBUG=true\n"
        self.assertEqual(
            [f.rule_id for f in self.scanner.scan_file(Path("api.py"), "api.py", py_cors)],
            ["SAURON-CFG-008"],
        )
        self.assertEqual(
            [f.rule_id for f in self.scanner.scan_file(Path(".env.example"), ".env.example", env_dbg)],
            ["SAURON-CFG-009"],
        )


if __name__ == "__main__":
    unittest.main()
