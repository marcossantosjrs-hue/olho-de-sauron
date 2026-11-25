"""Converte `sauron-eye.webp` em ícones `.ico` multi-resolução e `.png` para o app e instalador."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SOURCE_IMAGE = ROOT_DIR / "sauron-eye.webp"
STATIC_DIR = ROOT_DIR / "olho_de_sauron" / "web" / "static"
PNG_DEST = STATIC_DIR / "sauron_eye.png"
ICO_DEST = STATIC_DIR / "sauron_eye.ico"

ICO_SIZES = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]


def main() -> int:
    if not SOURCE_IMAGE.is_file():
        print(f"Erro: imagem de origem não encontrada em {SOURCE_IMAGE}", file=sys.stderr)
        return 1

    try:
        from PIL import Image
    except ImportError:
        print(
            "Pillow não está instalado. Instale com: pip install pillow",
            file=sys.stderr,
        )
        return 1

    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    with Image.open(SOURCE_IMAGE) as img:
        rgba = img.convert("RGBA")
        png_img = rgba.resize((256, 256), Image.Resampling.LANCZOS)
        png_img.save(PNG_DEST, format="PNG")
        rgba.save(ICO_DEST, format="ICO", sizes=ICO_SIZES)

    print(f"PNG gerado : {PNG_DEST} ({PNG_DEST.stat().st_size} bytes)")
    print(f"ICO gerado : {ICO_DEST} ({ICO_DEST.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
