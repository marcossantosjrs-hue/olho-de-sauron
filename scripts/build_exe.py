"""Script para gerar ícones, compilar o executável portátil e o instalador Windows."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
APP_SPEC = ROOT_DIR / "olho_de_sauron.spec"
SETUP_SPEC = ROOT_DIR / "olho_de_sauron_setup.spec"
DIST_DIR = ROOT_DIR / "dist"


def compute_sha256(file_path: Path) -> str:
    """Calcula o hash SHA-256 de um arquivo em blocos."""
    digest = hashlib.sha256()
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_sha256(target: Path) -> None:
    sha_hex = compute_sha256(target)
    sha_file = target.with_name(f"{target.name}.sha256")
    sha_file.write_text(f"{sha_hex}  {target.name}\n", encoding="utf-8")
    size_mb = target.stat().st_size / (1024 * 1024)
    print(f"Gerado   : {target} ({size_mb:.2f} MB)")
    print(f"SHA-256  : {sha_hex}")


def _run_pyinstaller(spec_path: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--clean",
            "--noconfirm",
            str(spec_path),
        ],
        cwd=str(ROOT_DIR),
        check=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compila OlhoDeSauron.exe e OlhoDeSauron-Setup.exe")
    parser.add_argument(
        "--portable-only",
        action="store_true",
        help="Compila apenas o executável portátil sem o instalador.",
    )
    args = parser.parse_args(argv)

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print(
            "PyInstaller não está instalado neste ambiente.\n"
            "Instale com: pip install pyinstaller",
            file=sys.stderr,
        )
        return 1

    webp_src = ROOT_DIR / "sauron-eye.webp"
    ico_dest = ROOT_DIR / "olho_de_sauron" / "web" / "static" / "sauron_eye.ico"
    png_dest = ROOT_DIR / "olho_de_sauron" / "web" / "static" / "sauron_eye.png"
    if webp_src.is_file() and (not ico_dest.is_file() or not png_dest.is_file()):
        from scripts.prepare_icon import main as prepare_icon_main

        if prepare_icon_main() != 0:
            return 1

    print(f"1) Compilando aplicativo portátil: {APP_SPEC}")
    _run_pyinstaller(APP_SPEC)
    exe_path = DIST_DIR / "OlhoDeSauron.exe"
    if not exe_path.is_file():
        exe_path = DIST_DIR / "OlhoDeSauron"
    if not exe_path.is_file():
        print("Erro: OlhoDeSauron.exe não encontrado após build.", file=sys.stderr)
        return 1
    _write_sha256(exe_path)

    if not args.portable_only and exe_path.name.endswith(".exe"):
        print(f"\n2) Compilando instalador Windows: {SETUP_SPEC}")
        _run_pyinstaller(SETUP_SPEC)
        setup_path = DIST_DIR / "OlhoDeSauron-Setup.exe"
        if not setup_path.is_file():
            print("Erro: OlhoDeSauron-Setup.exe não encontrado após build.", file=sys.stderr)
            return 1
        _write_sha256(setup_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
