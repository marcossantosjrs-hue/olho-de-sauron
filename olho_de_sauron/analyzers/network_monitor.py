"""Monitor defensivo de conexões e estatísticas de tráfego de rede em tempo real."""

from __future__ import annotations

import ipaddress
import logging
import platform
import re
import subprocess
import time
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any

from olho_de_sauron.analyzers.process_monitor import ProcessMonitor

_LOGGER = logging.getLogger(__name__)

try:
    import psutil  # type: ignore[import-not-found]

    _HAS_PSUTIL = True
except ImportError:
    psutil = None  # type: ignore[assignment]
    _HAS_PSUTIL = False

_STATE_NORMALIZATION = {
    "ESCUTANDO": "LISTEN",
    "LISTENING": "LISTEN",
    "LISTEN": "LISTEN",
    "ESTABELECIDA": "ESTABLISHED",
    "ESTABLISHED": "ESTABLISHED",
    "ESTAB": "ESTABLISHED",
    "ESPERA_TEMPO": "TIME_WAIT",
    "TIME_WAIT": "TIME_WAIT",
    "FECHAR_ESPERA": "CLOSE_WAIT",
    "CLOSE_WAIT": "CLOSE_WAIT",
    "SIN_ENVIADO": "SYN_SENT",
    "SYN_SENT": "SYN_SENT",
    "SIN_RECEBIDO": "SYN_RECEIVED",
    "SYN_RECV": "SYN_RECEIVED",
    "FECHADO": "CLOSED",
    "CLOSED": "CLOSED",
    "ULTIMO_ACK": "LAST_ACK",
    "LAST_ACK": "LAST_ACK",
    "FIN_ESPERA_1": "FIN_WAIT1",
    "FIN_ESPERA_2": "FIN_WAIT2",
}

_C2_SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 5555, 6666, 6667, 6697, 8888, 9001, 9050}
_MINER_PORTS = {3333, 14444, 14433, 45700}
_SENSITIVE_LISTEN_PORTS = {23, 445, 3306, 3389, 5432, 5985, 6379, 27017}
_CLEARTEXT_PORTS = {21, 23, 80}
_LOLBIN_NETWORK_PROCS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe",
    "rundll32.exe",
    "regsvr32.exe",
}


def _decode_os_bytes(data: bytes) -> str:
    """Decodifica saída de comandos de rede Windows (cp850/cp1252) ou POSIX sem falhar."""
    for encoding in ("cp850", "utf-8", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def split_host_port(endpoint: str) -> tuple[str, int | None]:
    """Separa IPv4/IPv6 e porta de strings como `127.0.0.1:8000`, `[::]:443` ou `*:*`."""
    raw = endpoint.strip()
    if not raw or raw in {"*:*", "*"}:
        return "*", None
    if raw.startswith("["):
        end_bracket = raw.find("]")
        if end_bracket != -1:
            ip_part = raw[1:end_bracket]
            rest = raw[end_bracket + 1 :]
            if rest.startswith(":") and rest[1:].isdigit():
                return ip_part, int(rest[1:])
            return ip_part, None
    if ":" in raw:
        ip_part, port_part = raw.rsplit(":", 1)
        if port_part.isdigit():
            return ip_part, int(port_part)
        return ip_part, None
    return raw, None


def is_public_ip(ip_str: str) -> bool:
    """Indica se o endereço IP é roteável na internet (não loopback/privado/reservado)."""
    cleaned = ip_str.strip("[]").split("%", 1)[0]
    if not cleaned or cleaned in {"*", "0.0.0.0", "::"}:
        return False
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def parse_windows_netstat_ano(output_text: str) -> list[dict[str, Any]]:
    """Faz parsing robusto da saída de `netstat -ano` em PT-BR ou EN."""
    connections: list[dict[str, Any]] = []
    for raw_line in output_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        proto = parts[0].upper()
        if proto not in {"TCP", "UDP"}:
            continue

        if proto == "TCP" and len(parts) >= 5:
            local_ip, local_port = split_host_port(parts[1])
            remote_ip, remote_port = split_host_port(parts[2])
            raw_state = parts[3].upper()
            state = _STATE_NORMALIZATION.get(raw_state, raw_state)
            pid = int(parts[4]) if parts[4].isdigit() else 0
        elif proto == "UDP" and len(parts) >= 4:
            local_ip, local_port = split_host_port(parts[1])
            remote_ip, remote_port = split_host_port(parts[2])
            state = "UDP"
            pid = int(parts[3]) if parts[3].isdigit() else 0
        else:
            continue

        connections.append(
            {
                "proto": proto,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": state,
                "pid": pid,
            }
        )
    return connections


def parse_windows_netstat_e(output_text: str) -> dict[str, int]:
    """Faz parsing de `netstat -e` em PT-BR ou EN para bytes/pacotes/erros."""
    stats = {
        "bytes_recv": 0,
        "bytes_sent": 0,
        "packets_recv": 0,
        "packets_sent": 0,
        "discards": 0,
        "errors": 0,
    }
    for raw_line in output_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        nums = re.findall(r"\b\d+\b", line)
        low = line.lower()
        if "bytes" in low and len(nums) >= 2:
            stats["bytes_recv"] = int(nums[0])
            stats["bytes_sent"] = int(nums[1])
        elif "unicast" in low and "nao" not in low and "não" not in low and "non-" not in low and len(nums) >= 2:
            stats["packets_recv"] = int(nums[0])
            stats["packets_sent"] = int(nums[1])
        elif ("descart" in low or "discard" in low) and len(nums) >= 2:
            stats["discards"] = int(nums[0]) + int(nums[1])
        elif ("erro" in low or "error" in low) and len(nums) >= 2:
            stats["errors"] = int(nums[0]) + int(nums[1])
    return stats


class NetworkMonitor:
    """Monitora conexões ativas, portas expostas e taxa de tráfego em tempo real."""

    def __init__(self) -> None:
        self._history: deque[dict[str, Any]] = deque(maxlen=20)
        self._last_sample: tuple[float, int, int] | None = None
        self._proc_monitor = ProcessMonitor()

    def collect_connections(self) -> tuple[list[dict[str, Any]], str]:
        if _HAS_PSUTIL:
            items: list[dict[str, Any]] = []
            try:
                for conn in psutil.net_connections(kind="inet"):
                    laddr = conn.laddr
                    raddr = conn.raddr
                    proto = "TCP" if conn.type == 1 else "UDP"
                    items.append(
                        {
                            "proto": proto,
                            "local_ip": laddr.ip if laddr else "*",
                            "local_port": laddr.port if laddr else None,
                            "remote_ip": raddr.ip if raddr else "*",
                            "remote_port": raddr.port if raddr else None,
                            "state": _STATE_NORMALIZATION.get(conn.status, conn.status or "UDP"),
                            "pid": int(conn.pid or 0),
                        }
                    )
                return items, "psutil"
            except (OSError, RuntimeError) as exc:
                _LOGGER.debug("Fallback de conexões após falha do psutil: %s", exc)

        if platform.system().lower() == "windows":
            proc = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0:
                return parse_windows_netstat_ano(_decode_os_bytes(proc.stdout)), "netstat-ano"
            return [], "netstat-ano"

        return self._collect_posix_connections(), "posix-ss"

    def _collect_posix_connections(self) -> list[dict[str, Any]]:
        try:
            proc = subprocess.run(["ss", "-tunap"], capture_output=True, timeout=5, check=False)
        except (FileNotFoundError, OSError, subprocess.SubprocessError) as exc:
            _LOGGER.debug("Comando ss indisponível para coleta POSIX: %s", exc)
            return []
        if proc.returncode != 0:
            return []
        conns: list[dict[str, Any]] = []
        for line in _decode_os_bytes(proc.stdout).splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0].upper()
            raw_state = parts[1].upper()
            state = _STATE_NORMALIZATION.get(raw_state, raw_state)
            local_ip, local_port = split_host_port(parts[4])
            remote_ip, remote_port = split_host_port(parts[5]) if len(parts) > 5 else ("*", None)
            pid_match = re.search(r"pid=(\d+)", line)
            pid = int(pid_match.group(1)) if pid_match else 0
            conns.append(
                {
                    "proto": "TCP" if "TCP" in proto else "UDP",
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": state,
                    "pid": pid,
                }
            )
        return conns

    def collect_traffic_stats(self) -> tuple[dict[str, int], list[dict[str, Any]]]:
        if _HAS_PSUTIL:
            try:
                per_nic = psutil.net_io_counters(pernic=True)
                interfaces: list[dict[str, Any]] = []
                totals = {
                    "bytes_recv": 0,
                    "bytes_sent": 0,
                    "packets_recv": 0,
                    "packets_sent": 0,
                    "discards": 0,
                    "errors": 0,
                }
                for nic_name, c in per_nic.items():
                    totals["bytes_recv"] += c.bytes_recv
                    totals["bytes_sent"] += c.bytes_sent
                    totals["packets_recv"] += c.packets_recv
                    totals["packets_sent"] += c.packets_sent
                    totals["discards"] += c.dropin + c.dropout
                    totals["errors"] += c.errin + c.errout
                    interfaces.append(
                        {
                            "name": nic_name,
                            "bytes_recv": c.bytes_recv,
                            "bytes_sent": c.bytes_sent,
                            "packets_recv": c.packets_recv,
                            "packets_sent": c.packets_sent,
                        }
                    )
                return totals, interfaces
            except (OSError, RuntimeError) as exc:
                _LOGGER.debug("Fallback de tráfego após falha do psutil: %s", exc)

        if platform.system().lower() == "windows":
            proc = subprocess.run(["netstat", "-e"], capture_output=True, timeout=5, check=False)
            if proc.returncode == 0:
                totals = parse_windows_netstat_e(_decode_os_bytes(proc.stdout))
                interfaces = [
                    {
                        "name": "Interface Principal (netstat -e)",
                        "bytes_recv": totals["bytes_recv"],
                        "bytes_sent": totals["bytes_sent"],
                        "packets_recv": totals["packets_recv"],
                        "packets_sent": totals["packets_sent"],
                    }
                ]
                return totals, interfaces

        return self._collect_posix_proc_net_dev()

    @staticmethod
    def _collect_posix_proc_net_dev() -> tuple[dict[str, int], list[dict[str, Any]]]:
        totals = {
            "bytes_recv": 0,
            "bytes_sent": 0,
            "packets_recv": 0,
            "packets_sent": 0,
            "discards": 0,
            "errors": 0,
        }
        interfaces: list[dict[str, Any]] = []
        try:
            with open("/proc/net/dev", "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()[2:]
        except OSError:
            return totals, interfaces

        for line in lines:
            if ":" not in line:
                continue
            nic, data_str = line.split(":", 1)
            cols = data_str.split()
            if len(cols) < 12:
                continue
            b_recv, p_recv, err_in, drop_in = int(cols[0]), int(cols[1]), int(cols[2]), int(cols[3])
            b_sent, p_sent, err_out, drop_out = int(cols[8]), int(cols[9]), int(cols[10]), int(cols[11])
            totals["bytes_recv"] += b_recv
            totals["bytes_sent"] += b_sent
            totals["packets_recv"] += p_recv
            totals["packets_sent"] += p_sent
            totals["errors"] += err_in + err_out
            totals["discards"] += drop_in + drop_out
            interfaces.append(
                {
                    "name": nic.strip(),
                    "bytes_recv": b_recv,
                    "bytes_sent": b_sent,
                    "packets_recv": p_recv,
                    "packets_sent": p_sent,
                }
            )
        return totals, interfaces

    def evaluate_connections(self, connections: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Avalia conexões quanto a portas C2, exposição sensível e comportamento anômalo."""
        alerts: list[dict[str, Any]] = []
        annotated: list[dict[str, Any]] = []
        pid_external_ips: dict[int, set[str]] = {}

        for conn in connections:
            pid = int(conn.get("pid") or 0)
            remote_ip = str(conn.get("remote_ip") or "*")
            if conn.get("state") == "ESTABLISHED" and is_public_ip(remote_ip) and pid > 0:
                pid_external_ips.setdefault(pid, set()).add(remote_ip)

        fanout_pids = {pid for pid, ips in pid_external_ips.items() if len(ips) >= 25}
        fanout_alerted: set[int] = set()

        for conn in connections:
            item = dict(conn)
            pid = int(item.get("pid") or 0)
            proc_name = str(item.get("process_name") or "")
            proc_low = proc_name.lower()
            state = str(item.get("state") or "")
            local_ip = str(item.get("local_ip") or "*")
            local_port = item.get("local_port")
            remote_ip = str(item.get("remote_ip") or "*")
            remote_port = item.get("remote_port")
            remote_public = is_public_ip(remote_ip)

            reasons: list[str] = []
            max_sev = "OK"

            def _add_alert(rule_id: str, sev: str, title: str, desc: str, mitre: str, rem: str) -> None:
                nonlocal max_sev
                reasons.append(title)
                rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "OK": 0}
                if rank[sev] > rank[max_sev]:
                    max_sev = sev
                alerts.append(
                    {
                        "rule_id": rule_id,
                        "severity": sev,
                        "pid": pid,
                        "process_name": proc_name or f"PID {pid}",
                        "endpoint": f"{remote_ip}:{remote_port}" if remote_port else f"{local_ip}:{local_port}",
                        "title": title,
                        "description": desc,
                        "mitre_attack": mitre,
                        "remediation": rem,
                    }
                )

            if state == "ESTABLISHED" and remote_port in _C2_SUSPICIOUS_PORTS:
                _add_alert(
                    "NET-C2PORT-001",
                    "CRITICAL",
                    f"Conexão ativa em porta associada a C2/backdoor (:{remote_port})",
                    f"Processo '{proc_name or pid}' conectado a {remote_ip}:{remote_port}.",
                    "T1571 - Non-Standard Port",
                    "Investigue imediatamente o processo proprietário e bloqueie o IP remoto no firewall.",
                )

            if state == "ESTABLISHED" and remote_port in _MINER_PORTS:
                _add_alert(
                    "NET-MINER-002",
                    "CRITICAL",
                    f"Conexão ativa em porta de pool de mineração (:{remote_port})",
                    f"Processo '{proc_name or pid}' conectado a {remote_ip}:{remote_port}.",
                    "T1496 - Resource Hijacking",
                    "Encerre o processo se não autorizado e verifique tarefas agendadas.",
                )

            if state == "LISTEN" and local_port in _SENSITIVE_LISTEN_PORTS and local_ip in {"0.0.0.0", "::", "*"}:
                _add_alert(
                    "NET-EXPOSED-003",
                    "HIGH",
                    f"Serviço sensível exposto em todas as interfaces (:{local_port})",
                    f"Porta {local_port} em escuta global ({local_ip}) pelo processo '{proc_name or pid}'.",
                    "T1190 - Exploit Public-Facing Application",
                    "Restrinja o bind para `127.0.0.1` ou bloqueie acesso externo via firewall.",
                )

            if state == "ESTABLISHED" and remote_public and proc_low in _LOLBIN_NETWORK_PROCS:
                _add_alert(
                    "NET-UNUSUAL-004",
                    "HIGH",
                    f"Interpretador do sistema ({proc_name}) conectado à internet",
                    f"Conexão externa para {remote_ip}:{remote_port} originada por '{proc_name}'.",
                    "T1071 - Application Layer Protocol",
                    "Confirme se a conexão pertence a script administrativo legítimo.",
                )

            if pid in fanout_pids and pid not in fanout_alerted:
                fanout_alerted.add(pid)
                _add_alert(
                    "NET-FANOUT-006",
                    "MEDIUM",
                    f"Alto fan-out de IPs externos no PID {pid} ({len(pid_external_ips[pid])} IPs)",
                    "Muitas conexões externas simultâneas podem indicar varredura ou P2P/C2.",
                    "T1046 - Network Service Discovery",
                    "Verifique se o processo é navegador/torrent esperado ou atividade anômala.",
                )

            if state == "ESTABLISHED" and remote_public and remote_port in _CLEARTEXT_PORTS:
                _add_alert(
                    "NET-INSECURE-005",
                    "LOW",
                    f"Conexão externa em protocolo sem criptografia (:{remote_port})",
                    f"Tráfego em texto claro para {remote_ip}:{remote_port}.",
                    "T1040 - Network Sniffing",
                    "Prefira protocolos cifrados (HTTPS/SFTP/SSH) sempre que possível.",
                )

            item["remote_is_public"] = remote_public
            item["suspicious"] = bool(reasons)
            item["risk_level"] = max_sev
            item["reasons"] = reasons
            annotated.append(item)

        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "OK": 0}
        annotated.sort(
            key=lambda c: (
                -sev_rank.get(c["risk_level"], 0),
                0 if c["state"] == "ESTABLISHED" else (1 if c["state"] == "LISTEN" else 2),
                c["local_port"] or 0,
            )
        )
        alerts.sort(key=lambda a: (-sev_rank.get(a["severity"], 0), a["pid"]))
        return annotated, alerts

    def scan(self, process_map: dict[int, dict[str, Any]] | None = None) -> dict[str, Any]:
        """Coleta conexões + estatísticas de tráfego e calcula taxas em KB/s."""
        if process_map is None:
            procs, _ = self._proc_monitor.collect_processes()
            process_map = {int(p.get("pid", 0)): p for p in procs}

        raw_conns, collector = self.collect_connections()
        for c in raw_conns:
            p = process_map.get(int(c.get("pid") or 0))
            c["process_name"] = p.get("name", "") if p else ""

        annotated_conns, alerts = self.evaluate_connections(raw_conns)
        totals, interfaces = self.collect_traffic_stats()

        now_mono = time.monotonic()
        rx_kbps = 0.0
        tx_kbps = 0.0
        if self._last_sample is not None:
            prev_t, prev_rx, prev_tx = self._last_sample
            dt = max(0.1, now_mono - prev_t)
            if totals["bytes_recv"] >= prev_rx and totals["bytes_sent"] >= prev_tx:
                rx_kbps = round(((totals["bytes_recv"] - prev_rx) / 1024.0) / dt, 2)
                tx_kbps = round(((totals["bytes_sent"] - prev_tx) / 1024.0) / dt, 2)

        self._last_sample = (now_mono, totals["bytes_recv"], totals["bytes_sent"])
        time_label = datetime.now().strftime("%H:%M:%S")
        self._history.append({"time": time_label, "rx_kbps": rx_kbps, "tx_kbps": tx_kbps})

        established_count = sum(1 for c in annotated_conns if c["state"] == "ESTABLISHED")
        listening_count = sum(1 for c in annotated_conns if c["state"] == "LISTEN")
        suspicious_count = sum(1 for c in annotated_conns if c["suspicious"])
        unique_remote_ips = len(
            {
                c["remote_ip"]
                for c in annotated_conns
                if c["remote_ip"] not in {"*", "0.0.0.0", "::", "127.0.0.1", "::1"}
            }
        )

        if any(a["severity"] == "CRITICAL" for a in alerts):
            verdict = "CRITICO"
        elif any(a["severity"] in {"HIGH", "MEDIUM"} for a in alerts):
            verdict = "ALERTA"
        else:
            verdict = "SEGURO"

        # Top portas remotas/locais para resumo visual
        port_counter = Counter(
            c["remote_port"]
            for c in annotated_conns
            if c["state"] == "ESTABLISHED" and c["remote_port"]
        )
        top_remote_ports = [
            {"port": port, "count": cnt} for port, cnt in port_counter.most_common(6)
        ]

        return {
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "platform": platform.system(),
            "collector": collector,
            "summary": {
                "total_connections": len(annotated_conns),
                "established_count": established_count,
                "listening_count": listening_count,
                "suspicious_count": suspicious_count,
                "unique_remote_ips": unique_remote_ips,
                "rx_kbps": rx_kbps,
                "tx_kbps": tx_kbps,
                "total_bytes_recv": totals["bytes_recv"],
                "total_bytes_sent": totals["bytes_sent"],
                "packets_recv": totals["packets_recv"],
                "packets_sent": totals["packets_sent"],
                "discards": totals["discards"],
                "errors": totals["errors"],
            },
            "top_remote_ports": top_remote_ports,
            "interfaces": interfaces,
            "traffic_history": list(self._history),
            "verdict": verdict,
            "alerts": alerts,
            "connections": annotated_conns,
        }
