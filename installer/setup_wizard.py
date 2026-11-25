"""Instalador gráfico standalone do Olho de Sauron para Windows (sem exigir Python)."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

APP_DISPLAY_NAME = "Olho de Sauron"
APP_VERSION = "1.0.0"
PUBLISHER = "Marcos Antonio (Olho de Sauron SOC)"
EXE_FILENAME = "OlhoDeSauron.exe"
ICON_FILENAME = "sauron_eye.ico"
PNG_FILENAME = "sauron_eye.png"

ROOT_DIR = Path(__file__).resolve().parent.parent


def default_install_dir() -> Path:
    """Retorna o diretório padrão de instalação sem exigir privilégios administrativos."""
    local_app = os.environ.get("LOCALAPPDATA")
    if local_app:
        return Path(local_app) / "Programs" / APP_DISPLAY_NAME
    return Path.home() / "AppData" / "Local" / "Programs" / APP_DISPLAY_NAME


def _resolve_payload_dir() -> Path:
    """Localiza os arquivos do payload em execução empacotada ou desenvolvimento."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        candidate = Path(getattr(sys, "_MEIPASS")) / "payload"
        if candidate.is_dir():
            return candidate
    return ROOT_DIR / "dist"


def _find_payload_file(filename: str) -> Path:
    payload_dir = _resolve_payload_dir()
    candidate = payload_dir / filename
    if candidate.is_file():
        return candidate
    static_fallback = ROOT_DIR / "olho_de_sauron" / "web" / "static" / filename
    if static_fallback.is_file():
        return static_fallback
    raise FileNotFoundError(f"Arquivo de instalação não encontrado: {filename}")


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _create_windows_shortcut(
    lnk_path: Path,
    target_exe: Path,
    working_dir: Path,
    icon_path: Path | None,
    description: str,
) -> None:
    lnk_path.parent.mkdir(parents=True, exist_ok=True)
    icon_line = (
        f"$s.IconLocation = {_ps_quote(str(icon_path))}; "
        if icon_path and icon_path.is_file()
        else ""
    )
    ps_cmd = (
        "$ws = New-Object -ComObject WScript.Shell; "
        f"$s = $ws.CreateShortcut({_ps_quote(str(lnk_path))}); "
        f"$s.TargetPath = {_ps_quote(str(target_exe))}; "
        f"$s.WorkingDirectory = {_ps_quote(str(working_dir))}; "
        f"$s.Description = {_ps_quote(description)}; "
        f"{icon_line}"
        "$s.Save()"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
        check=True,
        capture_output=True,
    )


def _register_windows_uninstall(dest_dir: Path, exe_path: Path, icon_path: Path, uninstall_bat: Path) -> None:
    if platform.system().lower() != "windows":
        return
    import winreg

    reg_path = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\OlhoDeSauron"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, APP_DISPLAY_NAME)
        winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, APP_VERSION)
        winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, PUBLISHER)
        winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(dest_dir))
        winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, str(icon_path if icon_path.is_file() else exe_path))
        winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, f'"{uninstall_bat}"')
        winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)


def _write_uninstaller_bat(dest_dir: Path, desktop_lnk: Path | None, start_menu_dir: Path | None) -> Path:
    uninstall_bat = dest_dir / "Desinstalar.bat"
    lines = [
        "@echo off",
        "echo Removendo Olho de Sauron...",
        'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OlhoDeSauron" /f >nul 2>&1',
    ]
    if desktop_lnk is not None:
        lines.append(f'del /f /q "{desktop_lnk}" >nul 2>&1')
    if start_menu_dir is not None:
        lines.append(f'rmdir /s /q "{start_menu_dir}" >nul 2>&1')
    lines.extend(
        [
            f'start "" cmd /c "timeout /t 1 /nobreak >nul & rmdir /s /q \\"{dest_dir}\\""',
            "exit /b 0",
        ]
    )
    uninstall_bat.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
    return uninstall_bat


def install_application(
    dest_dir: Path,
    create_desktop: bool = True,
    create_start_menu: bool = True,
    register_uninstall: bool = True,
    progress_cb: Callable[[int, str], None] | None = None,
) -> dict[str, str]:
    """Instala o OlhoDeSauron.exe, ícones, atalhos e desinstalador no diretório alvo."""
    def _report(pct: int, msg: str) -> None:
        if progress_cb:
            progress_cb(pct, msg)

    _report(10, "Preparando pasta de instalação...")
    dest_dir = dest_dir.resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    src_exe = _find_payload_file(EXE_FILENAME)
    dest_exe = dest_dir / EXE_FILENAME
    _report(35, "Copiando OlhoDeSauron.exe...")
    shutil.copy2(src_exe, dest_exe)

    dest_ico = dest_dir / ICON_FILENAME
    try:
        src_ico = _find_payload_file(ICON_FILENAME)
        shutil.copy2(src_ico, dest_ico)
    except FileNotFoundError:
        pass

    desktop_lnk: Path | None = None
    start_menu_dir: Path | None = None
    is_windows = platform.system().lower() == "windows"

    if is_windows and create_desktop:
        _report(60, "Criando atalho na Área de Trabalho...")
        desktop_dir = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Desktop"
        desktop_lnk = desktop_dir / f"{APP_DISPLAY_NAME}.lnk"
        _create_windows_shortcut(
            lnk_path=desktop_lnk,
            target_exe=dest_exe,
            working_dir=dest_dir,
            icon_path=dest_ico,
            description="Central SOC Defensiva — PDFs, Links, Processos, Rede e Código",
        )

    if is_windows and create_start_menu:
        _report(78, "Registrando no Menu Iniciar...")
        appdata = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
        start_menu_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / APP_DISPLAY_NAME
        start_menu_lnk = start_menu_dir / f"{APP_DISPLAY_NAME}.lnk"
        _create_windows_shortcut(
            lnk_path=start_menu_lnk,
            target_exe=dest_exe,
            working_dir=dest_dir,
            icon_path=dest_ico,
            description="Central SOC Defensiva — PDFs, Links, Processos, Rede e Código",
        )

    _report(90, "Criando desinstalador e registrando aplicativo...")
    uninstall_bat = _write_uninstaller_bat(dest_dir, desktop_lnk, start_menu_dir)
    if is_windows and register_uninstall:
        _register_windows_uninstall(dest_dir, dest_exe, dest_ico, uninstall_bat)

    _report(100, "Instalação concluída com sucesso!")
    return {
        "install_dir": str(dest_dir),
        "exe_path": str(dest_exe),
        "icon_path": str(dest_ico) if dest_ico.is_file() else "",
        "uninstaller_path": str(uninstall_bat),
    }


def launch_installed_app(exe_path: Path) -> None:
    """Inicia o aplicativo instalado em processo independente."""
    subprocess.Popen([str(exe_path)], cwd=str(exe_path.parent))


def run_gui() -> int:
    """Exibe o assistente gráfico Tkinter em tema escuro SOC."""
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title(f"Instalador — {APP_DISPLAY_NAME} v{APP_VERSION}")
    root.geometry("560x480")
    root.resizable(False, False)
    root.configure(bg="#0b0e15")

    try:
        ico_path = _find_payload_file(ICON_FILENAME)
        root.iconbitmap(str(ico_path))
    except (FileNotFoundError, tk.TclError):
        pass

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("Amber.Horizontal.TProgressbar", troughcolor="#161d2b", background="#f59e0b")

    header = tk.Frame(root, bg="#111622", padx=20, pady=16)
    header.pack(fill="x")

    logo_ref = None
    try:
        png_path = _find_payload_file(PNG_FILENAME)
        raw_img = tk.PhotoImage(file=str(png_path))
        logo_ref = raw_img.subsample(4, 4)
        logo_lbl = tk.Label(header, image=logo_ref, bg="#111622")
        logo_lbl.image = logo_ref  # type: ignore[attr-defined]
        logo_lbl.pack(side="left", padx=(0, 14))
    except (FileNotFoundError, tk.TclError):
        pass

    title_box = tk.Frame(header, bg="#111622")
    title_box.pack(side="left", fill="both", expand=True)
    tk.Label(
        title_box,
        text=f"{APP_DISPLAY_NAME} v{APP_VERSION}",
        fg="#f59e0b",
        bg="#111622",
        font=("Segoe UI", 16, "bold"),
        anchor="w",
    ).pack(fill="x")
    tk.Label(
        title_box,
        text="Central SOC Defensiva — PDFs, Links, Processos, Rede e Código",
        fg="#9aa6be",
        bg="#111622",
        font=("Segoe UI", 9),
        anchor="w",
    ).pack(fill="x", pady=(2, 0))

    body = tk.Frame(root, bg="#0b0e15", padx=22, pady=18)
    body.pack(fill="both", expand=True)

    tk.Label(
        body,
        text="Este assistente instalará o Olho de Sauron localmente na sua máquina\n(sem necessidade de Python instalado ou permissões de administrador).",
        fg="#dbe3f0",
        bg="#0b0e15",
        font=("Segoe UI", 9),
        justify="left",
        anchor="w",
    ).pack(fill="x", pady=(0, 14))

    tk.Label(
        body,
        text="Pasta de instalação:",
        fg="#9aa6be",
        bg="#0b0e15",
        font=("Segoe UI", 9, "bold"),
        anchor="w",
    ).pack(fill="x")

    dir_row = tk.Frame(body, bg="#0b0e15")
    dir_row.pack(fill="x", pady=(4, 14))
    dest_var = tk.StringVar(value=str(default_install_dir()))
    tk.Entry(
        dir_row,
        textvariable=dest_var,
        bg="#151c2a",
        fg="#e6ebf5",
        insertbackground="#f59e0b",
        relief="flat",
        font=("Consolas", 9),
    ).pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))

    def _browse() -> None:
        chosen = filedialog.askdirectory(initialdir=dest_var.get())
        if chosen:
            dest_var.set(str(Path(chosen) / APP_DISPLAY_NAME))

    tk.Button(
        dir_row,
        text="Alterar...",
        command=_browse,
        bg="#1c2538",
        fg="#e6ebf5",
        relief="flat",
        padx=12,
        pady=5,
        cursor="hand2",
    ).pack(side="right")

    desktop_var = tk.BooleanVar(value=True)
    start_var = tk.BooleanVar(value=True)
    launch_var = tk.BooleanVar(value=True)

    for text, var in (
        ("Criar atalho na Área de Trabalho", desktop_var),
        ("Criar atalho no Menu Iniciar", start_var),
        ("Abrir o Olho de Sauron ao concluir", launch_var),
    ):
        tk.Checkbutton(
            body,
            text=text,
            variable=var,
            bg="#0b0e15",
            fg="#dbe3f0",
            selectcolor="#151c2a",
            activebackground="#0b0e15",
            activeforeground="#f59e0b",
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill="x", pady=2)

    status_var = tk.StringVar(value="Pronto para instalar.")
    tk.Label(
        body,
        textvariable=status_var,
        fg="#f59e0b",
        bg="#0b0e15",
        font=("Segoe UI", 9),
        anchor="w",
    ).pack(fill="x", pady=(16, 4))

    progress = ttk.Progressbar(
        body,
        style="Amber.Horizontal.TProgressbar",
        orient="horizontal",
        mode="determinate",
        maximum=100,
    )
    progress.pack(fill="x", pady=(0, 18))

    btn_row = tk.Frame(body, bg="#0b0e15")
    btn_row.pack(fill="x", side="bottom")

    installed_exe: list[Path] = []

    def _on_progress(pct: int, msg: str) -> None:
        progress["value"] = pct
        status_var.set(msg)
        root.update_idletasks()

    def _run_install() -> None:
        install_btn.config(state="disabled")
        try:
            res = install_application(
                dest_dir=Path(dest_var.get().strip()),
                create_desktop=desktop_var.get(),
                create_start_menu=start_var.get(),
                register_uninstall=True,
                progress_cb=_on_progress,
            )
            exe_p = Path(res["exe_path"])
            installed_exe.append(exe_p)
            if launch_var.get():
                launch_installed_app(exe_p)
                root.destroy()
            else:
                install_btn.config(text="Abrir Olho de Sauron", state="normal", command=_open_and_close)
        except Exception as exc:
            install_btn.config(state="normal")
            status_var.set("Erro na instalação.")
            messagebox.showerror("Erro na instalação", str(exc))

    def _open_and_close() -> None:
        if installed_exe:
            launch_installed_app(installed_exe[0])
        root.destroy()

    tk.Button(
        btn_row,
        text="Cancelar",
        command=root.destroy,
        bg="#1c2538",
        fg="#dbe3f0",
        relief="flat",
        padx=16,
        pady=8,
        cursor="hand2",
    ).pack(side="left")

    install_btn = tk.Button(
        btn_row,
        text="Instalar Agora",
        command=_run_install,
        bg="#f59e0b",
        fg="#0b0e15",
        font=("Segoe UI", 10, "bold"),
        relief="flat",
        padx=20,
        pady=8,
        cursor="hand2",
    )
    install_btn.pack(side="right")

    root.mainloop()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"Instalador {APP_DISPLAY_NAME}")
    parser.add_argument("--silent", action="store_true", help="Instala sem abrir interface gráfica.")
    parser.add_argument("--dir", dest="target_dir", default=None, help="Diretório de destino.")
    parser.add_argument("--no-shortcuts", action="store_true", help="Não cria atalhos no Windows.")
    parser.add_argument("--no-registry", action="store_true", help="Não registra no Painel de Controle.")
    args = parser.parse_args(argv)

    if args.silent:
        dest = Path(args.target_dir) if args.target_dir else default_install_dir()
        res = install_application(
            dest_dir=dest,
            create_desktop=not args.no_shortcuts,
            create_start_menu=not args.no_shortcuts,
            register_uninstall=not args.no_registry,
        )
        print(f"Instalado com sucesso em: {res['install_dir']}")
        return 0

    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
