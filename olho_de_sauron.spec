# -*- mode: python ; coding: utf-8 -*-
"""Especificação PyInstaller para gerar o executável standalone OlhoDeSauron."""

from pathlib import Path

block_cipher = None
ROOT = Path(SPECPATH)
STATIC_DIR = ROOT / "olho_de_sauron" / "web" / "static"
ICON_PATH = STATIC_DIR / "sauron_eye.ico"

datas = [
    (str(STATIC_DIR / "index.html"), "olho_de_sauron/web/static"),
]
for asset_name in ("sauron_eye.ico", "sauron_eye.png"):
    asset_file = STATIC_DIR / asset_name
    if asset_file.is_file():
        datas.append((str(asset_file), "olho_de_sauron/web/static"))

a = Analysis(
    [str(ROOT / "olho_de_sauron" / "launcher.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.loops.asyncio",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.http.httptools_impl",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
        "uvicorn.lifespan.off",
        "anyio._backends._asyncio",
        "olho_de_sauron.web.app",
        "olho_de_sauron.cli",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="OlhoDeSauron",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON_PATH) if ICON_PATH.is_file() else None,
)
