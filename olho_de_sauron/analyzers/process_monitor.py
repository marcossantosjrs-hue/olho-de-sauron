"""Monitor defensivo de processos e Threat Hunting local (Windows, Linux e macOS)."""

from __future__ import annotations

import ctypes
import platform
import re
import subprocess
from ctypes import wintypes
from datetime import datetime, timezone
from typing import Any

try:
    import psutil  # type: ignore[import-not-found]

    _HAS_PSUTIL = True
except ImportError:
    psutil = None  # type: ignore[assignment]
    _HAS_PSUTIL = False

_LOLBINS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}

_SUSPICIOUS_CMD_FLAGS = (
    "-enc",
    "-encodedcommand",
    "frombase64string",
    "downloadstring",
    "downloadfile",
    "iex ",
    "invoke-expression",
    "-w hidden",
    "-windowstyle hidden",
    "urlcache",
    "http://",
    "https://",
)

_PROTECTED_WINDOWS_PROCS = {
    "svchost.exe": ("\\windows\\system32\\", "\\windows\\syswow64\\"),
    "lsass.exe": ("\\windows\\system32\\",),
    "csrss.exe": ("\\windows\\system32\\",),
    "services.exe": ("\\windows\\system32\\",),
    "smss.exe": ("\\windows\\system32\\",),
    "wininit.exe": ("\\windows\\system32\\",),
    "explorer.exe": ("\\windows\\",),
}

_MINER_AND_OFFENSIVE_TERMS = (
    "xmrig",
    "minerd",
    "cgminer",
    "ethminer",
    "stratum+tcp",
    "mimikatz",
    "meterpreter",
    "cobalt",
    "chisel",
    "ncat",
)

_SUSPICIOUS_DIR_MARKERS = (
    "\\temp\\",
    "\\tmp\\",
    "\\users\\public\\",
    "\\appdata\\local\\temp\\",
    "\\programdata\\",
    "/tmp/",
    "/dev/shm/",
)

_DOUBLE_EXT_RE = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|txt|zip)\.(?:exe|scr|bat|cmd|ps1|vbs|com)$",
    re.IGNORECASE,
)

_DOC_PARENT_PROCS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "acrord32.exe",
    "acrobat.exe",
}

_INTERPRETER_CHILDREN = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
}


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def _collect_windows_toolhelp() -> list[dict[str, Any]]:
    """Enumera processos no Windows via Win32 Toolhelp32 sem spawnar subprocessos lentos."""
    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    th32cs_snapprocess = 0x00000002
    proc_query_limited = 0x1000
    proc_vm_read = 0x0010

    snapshot = kernel32.CreateToolhelp32Snapshot(th32cs_snapprocess, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        return []

    processes: list[dict[str, Any]] = []
    entry = _PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)

    try:
        if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            while True:
                pid = int(entry.th32ProcessID)
                ppid = int(entry.th32ParentProcessID)
                name = entry.szExeFile
                exe_path = ""
                memory_mb = 0.0

                if pid > 0:
                    handle = kernel32.OpenProcess(proc_query_limited | proc_vm_read, False, pid)
                    if not handle:
                        handle = kernel32.OpenProcess(proc_query_limited, False, pid)
                    if handle:
                        try:
                            buf = ctypes.create_unicode_buffer(1024)
                            size = wintypes.DWORD(1024)
                            if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                                exe_path = buf.value

                            pmc = _PROCESS_MEMORY_COUNTERS()
                            pmc.cb = ctypes.sizeof(_PROCESS_MEMORY_COUNTERS)
                            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
                                memory_mb = round(pmc.WorkingSetSize / (1024 * 1024), 2)
                        finally:
                            kernel32.CloseHandle(handle)

                processes.append(
                    {
                        "pid": pid,
                        "ppid": ppid,
                        "name": name,
                        "exe": exe_path,
                        "cmdline": "",
                        "memory_mb": memory_mb,
                    }
                )
                if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snapshot)

    return processes


def _collect_posix_ps() -> list[dict[str, Any]]:
    try:
        proc = subprocess.run(
            ["ps", "-eo", "pid,ppid,rss,comm,args"],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []

    lines = proc.stdout.decode("utf-8", errors="replace").splitlines()
    results: list[dict[str, Any]] = []
    for line in lines[1:]:
        parts = line.strip().split(None, 4)
        if len(parts) < 4:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            rss_kb = int(parts[2])
        except ValueError:
            continue
        name = parts[3]
        cmdline = parts[4] if len(parts) > 4 else ""
        exe = cmdline.split(" ", 1)[0] if cmdline.startswith("/") else ""
        results.append(
            {
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "exe": exe,
                "cmdline": cmdline,
                "memory_mb": round(rss_kb / 1024, 2),
            }
        )
    return results


def _collect_with_psutil() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "memory_info"]):
        try:
            info = proc.info
            mem_info = info.get("memory_info")
            mem_mb = round(mem_info.rss / (1024 * 1024), 2) if mem_info else 0.0
            cmdline_list = info.get("cmdline") or []
            results.append(
                {
                    "pid": int(info.get("pid") or 0),
                    "ppid": int(info.get("ppid") or 0),
                    "name": info.get("name") or "",
                    "exe": info.get("exe") or "",
                    "cmdline": " ".join(cmdline_list),
                    "memory_mb": mem_mb,
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return results


class ProcessMonitor:
    """Inspeciona processos em execução na máquina aplicando heurísticas de Threat Hunting."""

    def collect_processes(self) -> tuple[list[dict[str, Any]], str]:
        if _HAS_PSUTIL:
            return _collect_with_psutil(), "psutil"
        if platform.system().lower() == "windows":
            return _collect_windows_toolhelp(), "win32-toolhelp32"
        return _collect_posix_ps(), "posix-ps"

    def evaluate_processes(
        self,
        processes: list[dict[str, Any]],
        collector: str = "manual",
    ) -> dict[str, Any]:
        """Aplica regras defensivas de detecção sobre uma lista de processos."""
        by_pid = {int(p.get("pid", 0)): p for p in processes}
        alerts: list[dict[str, Any]] = []
        enriched: list[dict[str, Any]] = []

        for proc in processes:
            pid = int(proc.get("pid", 0))
            ppid = int(proc.get("ppid", 0))
            name = str(proc.get("name") or "")
            exe = str(proc.get("exe") or "")
            cmdline = str(proc.get("cmdline") or "")
            mem_mb = float(proc.get("memory_mb") or 0.0)

            name_low = name.lower()
            exe_low = exe.lower()
            cmd_low = cmdline.lower()
            parent = by_pid.get(ppid)
            parent_name = str(parent.get("name") or "") if parent else ""
            parent_low = parent_name.lower()

            proc_alerts: list[dict[str, Any]] = []

            # 1. LOLBin com argumentos suspeitos
            if name_low in _LOLBINS and cmd_low:
                if any(flag in cmd_low for flag in _SUSPICIOUS_CMD_FLAGS):
                    proc_alerts.append(
                        {
                            "rule_id": "PROC-LOLBIN-001",
                            "severity": "CRITICAL",
                            "pid": pid,
                            "process_name": name,
                            "title": f"LOLBin com linha de comando suspeita ({name})",
                            "description": f"Argumentos potencialmente ofuscados ou de download remoto detectados: {cmdline[:160]}",
                            "mitre_attack": "T1059 - Command and Scripting Interpreter",
                            "remediation": "Valide se o comando foi disparado por script administrativo legítimo ou encerramento imediato.",
                        }
                    )

            # 2. Mascaramento de processo protegido do Windows
            if name_low in _PROTECTED_WINDOWS_PROCS and exe_low:
                allowed_dirs = _PROTECTED_WINDOWS_PROCS[name_low]
                if not any(allowed in exe_low for allowed in allowed_dirs):
                    proc_alerts.append(
                        {
                            "rule_id": "PROC-MASQ-003",
                            "severity": "CRITICAL",
                            "pid": pid,
                            "process_name": name,
                            "title": f"Possível mascaramento de processo do sistema ({name})",
                            "description": f"Executável '{name}' rodando fora da pasta esperada do Windows: {exe}",
                            "mitre_attack": "T1036.005 - Match Legitimate Name or Location",
                            "remediation": "Inspecione o binário e verifique assinatura digital antes de confiar no processo.",
                        }
                    )

            # 3. Mineradores ou ferramentas ofensivas conhecidas
            combined_proc_text = f"{name_low} {exe_low} {cmd_low}"
            matched_term = next((t for t in _MINER_AND_OFFENSIVE_TERMS if t in combined_proc_text), None)
            if matched_term:
                proc_alerts.append(
                    {
                        "rule_id": "PROC-MINER-004",
                        "severity": "CRITICAL",
                        "pid": pid,
                        "process_name": name,
                        "title": f"Assinatura de minerador ou ferramenta ofensiva ({matched_term})",
                        "description": f"Processo '{name}' (PID {pid}) corresponde ao indicador '{matched_term}'.",
                        "mitre_attack": "T1496 - Resource Hijacking",
                        "remediation": "Encerre o processo se não autorizado e investigue persistência na máquina.",
                    }
                )

            # 4. Executável rodando de diretório temporário/público
            if exe_low and any(marker in exe_low for marker in _SUSPICIOUS_DIR_MARKERS):
                proc_alerts.append(
                    {
                        "rule_id": "PROC-PATH-002",
                        "severity": "HIGH",
                        "pid": pid,
                        "process_name": name,
                        "title": f"Executável ativo em diretório temporário ou público ({name})",
                        "description": f"Executáveis em pastas temporárias são comuns em infecções iniciais: {exe}",
                        "mitre_attack": "T1204 - User Execution",
                        "remediation": "Verifique a origem do binário e se pertence a algum instalador legítimo em andamento.",
                    }
                )

            # 5. Dupla extensão
            if _DOUBLE_EXT_RE.search(name_low):
                proc_alerts.append(
                    {
                        "rule_id": "PROC-DOUBLEEXT-005",
                        "severity": "HIGH",
                        "pid": pid,
                        "process_name": name,
                        "title": f"Binário com dupla extensão enganosa ({name})",
                        "description": "Executáveis disfarçados como documentos/imagens usam dupla extensão para enganar usuários.",
                        "mitre_attack": "T1036.007 - Double File Extension",
                        "remediation": "Isole o arquivo e execute análise antimalware completa.",
                    }
                )

            # 6. Processo pai de documento/email gerando interpretador
            if parent_low in _DOC_PARENT_PROCS and name_low in _INTERPRETER_CHILDREN:
                proc_alerts.append(
                    {
                        "rule_id": "PROC-PARENT-006",
                        "severity": "HIGH",
                        "pid": pid,
                        "process_name": name,
                        "title": f"Interpretador '{name}' iniciado por '{parent_name}'",
                        "description": "Aplicativos de escritório ou leitores de PDF iniciando shells costumam indicar macro/payload malicioso.",
                        "mitre_attack": "T1566.001 - Spearphishing Attachment",
                        "remediation": "Feche o documento de origem e verifique se houve criação de tarefas agendadas.",
                    }
                )

            alerts.extend(proc_alerts)
            max_sev = "OK"
            if any(a["severity"] == "CRITICAL" for a in proc_alerts):
                max_sev = "CRITICAL"
            elif any(a["severity"] == "HIGH" for a in proc_alerts):
                max_sev = "HIGH"

            enriched.append(
                {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "parent_name": parent_name,
                    "exe": exe,
                    "cmdline": cmdline,
                    "memory_mb": mem_mb,
                    "suspicious": bool(proc_alerts),
                    "risk_level": max_sev,
                    "reasons": [a["title"] for a in proc_alerts],
                }
            )

        sev_rank = {"CRITICAL": 3, "HIGH": 2, "OK": 0}
        enriched.sort(key=lambda p: (-sev_rank.get(p["risk_level"], 0), -p["memory_mb"], p["pid"]))
        alerts.sort(key=lambda a: (-sev_rank.get(a["severity"], 0), a["pid"]))

        suspicious_count = sum(1 for p in enriched if p["suspicious"])
        critical_count = sum(1 for a in alerts if a["severity"] == "CRITICAL")
        total_mem = round(sum(p["memory_mb"] for p in enriched), 1)

        if critical_count > 0:
            verdict = "CRITICO"
        elif suspicious_count > 0:
            verdict = "ALERTA"
        else:
            verdict = "SEGURO"

        return {
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "platform": platform.system(),
            "collector": collector,
            "total_processes": len(enriched),
            "suspicious_count": suspicious_count,
            "critical_count": critical_count,
            "total_memory_mb": total_mem,
            "verdict": verdict,
            "alerts": alerts,
            "processes": enriched,
        }

    def scan(self) -> dict[str, Any]:
        """Coleta processos reais do sistema e executa análise defensiva."""
        processes, collector = self.collect_processes()
        return self.evaluate_processes(processes, collector=collector)
