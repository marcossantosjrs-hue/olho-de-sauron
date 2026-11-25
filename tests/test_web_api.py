"""Testes de integração para as rotas e modelos da interface Web SOC FastAPI."""

import base64
import unittest
from pathlib import Path
from typing import Any, Callable

from fastapi import HTTPException
from fastapi.routing import APIRoute

from olho_de_sauron.web.app import (
    CodeScanRequest,
    LinkScanRequest,
    PdfScanRequest,
    create_app,
)

ROOT_DIR = Path(__file__).resolve().parent.parent


class TestWebSocApi(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.routes: dict[tuple[str, str], Callable[..., Any]] = {}
        for route in self.app.routes:
            if isinstance(route, APIRoute):
                for method in route.methods:
                    if method in {"GET", "POST"}:
                        self.routes[(method, route.path)] = route.endpoint

    def test_all_expected_routes_are_registered(self) -> None:
        expected = {
            ("GET", "/"),
            ("GET", "/favicon.ico"),
            ("GET", "/static/sauron_eye.png"),
            ("GET", "/api/health"),
            ("POST", "/api/scan/pdf"),
            ("POST", "/api/scan/links"),
            ("GET", "/api/monitor/processes"),
            ("GET", "/api/monitor/network"),
            ("POST", "/api/scan/code"),
        }
        self.assertTrue(expected.issubset(set(self.routes.keys())))

    def test_index_and_health(self) -> None:
        resp = self.routes[("GET", "/")]()
        self.assertEqual(resp.status_code, 200)
        html = resp.body.decode("utf-8")
        self.assertIn("Olho de Sauron", html)
        self.assertIn("Scanner de PDFs", html)
        self.assertIn("Analisador de Links", html)
        self.assertIn("Processos da Máquina", html)
        self.assertIn("Tráfego de Rede", html)
        self.assertIn("Código DevSecOps", html)

        fav_resp = self.routes[("GET", "/favicon.ico")]()
        self.assertEqual(fav_resp.media_type, "image/x-icon")
        png_resp = self.routes[("GET", "/static/sauron_eye.png")]()
        self.assertEqual(png_resp.media_type, "image/png")

        health = self.routes[("GET", "/api/health")]()
        self.assertEqual(health["status"], "ok")
        self.assertEqual(
            set(health["modules"]),
            {"pdf", "links", "processes", "network", "code"},
        )

    def test_scan_pdf_and_links_endpoints(self) -> None:
        pdf_raw = b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JS (x) >> endobj\n%%EOF\n"
        b64 = base64.b64encode(pdf_raw).decode("ascii")
        res_pdf = self.routes[("POST", "/api/scan/pdf")](
            PdfScanRequest(filename="teste.pdf", content_base64=b64)
        )
        self.assertEqual(res_pdf["verdict"], "PERIGOSO")

        with self.assertRaises(HTTPException) as ctx:
            self.routes[("POST", "/api/scan/pdf")](
                PdfScanRequest(filename="bad.pdf", content_base64="!!!invalido!!!")
            )
        self.assertEqual(ctx.exception.status_code, 400)

        res_links = self.routes[("POST", "/api/scan/links")](
            LinkScanRequest(
                urls=[
                    "https://www.github.com",
                    "http://nubank-seguro.atualiza.xyz/login.exe",
                ],
                check_live=False,
            )
        )
        self.assertEqual(res_links["total"], 2)
        self.assertEqual(res_links["counts"]["SEGURO"], 1)
        self.assertEqual(res_links["counts"]["PERIGOSO"], 1)

    def test_monitor_processes_network_and_code_endpoints(self) -> None:
        procs = self.routes[("GET", "/api/monitor/processes")]()
        self.assertGreaterEqual(procs["total_processes"], 1)

        net = self.routes[("GET", "/api/monitor/network")]()
        self.assertIn("summary", net)
        self.assertIn("traffic_history", net)

        res_c = self.routes[("POST", "/api/scan/code")](
            CodeScanRequest(target=str(ROOT_DIR / "lab" / "app_seguro.py"))
        )
        self.assertEqual(res_c["verdict"], "APROVADO")

        with self.assertRaises(HTTPException) as ctx:
            self.routes[("POST", "/api/scan/code")](
                CodeScanRequest(target=str(ROOT_DIR / "lab" / "nao_existe_12345.py"))
            )
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
