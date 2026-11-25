# -*- mode: python ; coding: utf-8 -*-
"""Especificação PyInstaller para o instalador gráfico OlhoDeSauron-Setup.exe."""

from pathlib import Path

block_cipher = None
ROOT = Path(SPECPATH)
STATIC_DIR = ROOT / "olho_de_sauron" / "web" / "static"
DIST_DIR = ROOT / "dist"
ICON_PATH = STATIC_DIR / "sauron_eye.ico"

datas = [
    (str(DIST_DIR / "OlhoDeSauron.exe"), "payload"),
]
for asset_name in ("sauron_eye.ico", "sauron_eye.png"):
    asset_file = STATIC_DIR / asset_name
    if asset_file.is_file():
        datas.append((str(asset_file), "payload"))

a = Analysis(
    [str(ROOT / "installer" / "setup_wizard.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=["tkinter", "tkinter.filedialog", "tkinter.messagebox", "tkinter.ttk"],
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
    name="OlhoDeSauron-Setup",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON_PATH) if ICON_PATH.is_file() else None,
)
