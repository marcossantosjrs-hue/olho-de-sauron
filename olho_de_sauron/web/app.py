"""Aplicação FastAPI do painel interativo Olho de Sauron SOC."""

from __future__ import annotations

import base64
import binascii
import platform
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

from olho_de_sauron import APP_NAME, __version__
from olho_de_sauron.analyzers.link_scanner import LinkSecurityAnalyzer
from olho_de_sauron.analyzers.network_monitor import NetworkMonitor
from olho_de_sauron.analyzers.pdf_scanner import MAX_PDF_BYTES, PdfSecurityAnalyzer
from olho_de_sauron.analyzers.process_monitor import ProcessMonitor
from olho_de_sauron.engine import ScanEngine


def _resolve_static_dir() -> Path:
    """Resolve o diretório de arquivos estáticos em execução normal ou empacotada (PyInstaller)."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass = Path(getattr(sys, "_MEIPASS"))
        candidate = meipass / "olho_de_sauron" / "web" / "static"
        if candidate.is_dir():
            return candidate
    return Path(__file__).resolve().parent / "static"


STATIC_DIR = _resolve_static_dir()


class PdfScanRequest(BaseModel):
    filename: str = Field(default="documento.pdf", max_length=260)
    content_base64: str = Field(..., min_length=1)


class LinkScanRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=30)
    check_live: bool = False


class CodeScanRequest(BaseModel):
    target: str = Field(default=".", max_length=500)


def create_app() -> FastAPI:
    """Cria e configura a instância FastAPI do Olho de Sauron."""
    api = FastAPI(
        title=f"{APP_NAME} SOC Web",
        version=__version__,
        description="Interface defensiva para análise de PDFs, Links, Processos, Tráfego de Rede e Código.",
    )

    pdf_analyzer = PdfSecurityAnalyzer()
    link_analyzer = LinkSecurityAnalyzer()
    process_monitor = ProcessMonitor()
    network_monitor = NetworkMonitor()
    code_engine = ScanEngine()

    @api.get("/", response_class=HTMLResponse)
    def serve_index() -> HTMLResponse:
        index_file = _resolve_static_dir() / "index.html"
        if not index_file.is_file():
            raise HTTPException(status_code=500, detail="Arquivo index.html da interface não encontrado.")
        return HTMLResponse(content=index_file.read_text(encoding="utf-8"))

    @api.get("/favicon.ico")
    def serve_favicon() -> FileResponse:
        ico_file = _resolve_static_dir() / "sauron_eye.ico"
        if not ico_file.is_file():
            raise HTTPException(status_code=404, detail="Ícone não encontrado.")
        return FileResponse(path=ico_file, media_type="image/x-icon")

    @api.get("/static/sauron_eye.png")
    def serve_logo_png() -> FileResponse:
        png_file = _resolve_static_dir() / "sauron_eye.png"
        if not png_file.is_file():
            raise HTTPException(status_code=404, detail="Imagem de logo não encontrada.")
        return FileResponse(path=png_file, media_type="image/png")

    @api.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "app": APP_NAME,
            "version": __version__,
            "platform": platform.system(),
            "modules": ["pdf", "links", "processes", "network", "code"],
        }

    @api.post("/api/scan/pdf")
    def scan_pdf(payload: PdfScanRequest) -> dict[str, Any]:
        raw_b64 = payload.content_base64.strip()
        if "," in raw_b64 and raw_b64.lower().startswith("data:"):
            raw_b64 = raw_b64.split(",", 1)[1]

        # Verificação prévia de tamanho aproximado antes de decodificar
        if len(raw_b64) > (MAX_PDF_BYTES * 4 // 3) + 1024:
            raise HTTPException(status_code=413, detail="Arquivo PDF excede o limite de 15 MB.")

        try:
            pdf_bytes = base64.b64decode(raw_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"Base64 inválido: {exc}") from exc

        try:
            return pdf_analyzer.analyze_bytes(pdf_bytes, filename=payload.filename)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @api.post("/api/scan/links")
    def scan_links(payload: LinkScanRequest) -> dict[str, Any]:
        cleaned = [u.strip() for u in payload.urls if u.strip()]
        if not cleaned:
            raise HTTPException(status_code=400, detail="Informe pelo menos uma URL válida.")
        return link_analyzer.analyze_batch(cleaned[:30], check_live=payload.check_live)

    @api.get("/api/monitor/processes")
    def monitor_processes() -> dict[str, Any]:
        return process_monitor.scan()

    @api.get("/api/monitor/network")
    def monitor_network() -> dict[str, Any]:
        return network_monitor.scan()

    @api.post("/api/scan/code")
    def scan_code(payload: CodeScanRequest) -> dict[str, Any]:
        target_str = payload.target.strip() or "."
        try:
            result = code_engine.scan(targets=target_str)
            return result.to_dict()
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return api


app = create_app()
