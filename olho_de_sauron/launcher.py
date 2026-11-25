"""Launcher standalone do executável Olho de Sauron (duplo clique ou CLI)."""

from __future__ import annotations

import multiprocessing
import socket
import sys
import threading
import webbrowser

from olho_de_sauron import APP_NAME, __version__
from olho_de_sauron.cli import _safe_echo, main


def find_available_port(
    host: str = "127.0.0.1",
    preferred: int = 8000,
    max_attempts: int = 20,
) -> int:
    """Retorna a primeira porta TCP livre a partir de `preferred`, ou porta efêmera."""
    for offset in range(max_attempts):
        candidate = preferred + offset
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((host, candidate))
                return candidate
            except OSError:
                continue

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def run_launcher(argv: list[str] | None = None) -> None:
    """Abre a interface Web SOC no duplo clique ou delega subcomandos à CLI."""
    multiprocessing.freeze_support()
    args = sys.argv[1:] if argv is None else list(argv)

    if args:
        main(args=args)
        return

    import uvicorn

    from olho_de_sauron.web.app import app

    host = "127.0.0.1"
    port = find_available_port(host=host, preferred=8000)
    url = f"http://{host}:{port}"

    banner = (
        "======================================================================\n"
        f"  {APP_NAME} v{__version__} — Central SOC Defensiva Local\n"
        "======================================================================\n"
        f"Painel Web disponível em : {url}\n"
        "Abrindo navegador automaticamente...\n"
        "Mantenha esta janela aberta enquanto usa o painel.\n"
        "Pressione Ctrl+C para encerrar.\n"
    )
    _safe_echo(banner)

    threading.Timer(1.2, webbrowser.open, args=(url,)).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    run_launcher()
