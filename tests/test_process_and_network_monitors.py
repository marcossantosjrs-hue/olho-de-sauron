"""Testes unitários para ProcessMonitor e NetworkMonitor."""

import unittest

from olho_de_sauron.analyzers.network_monitor import (
    NetworkMonitor,
    parse_windows_netstat_ano,
    parse_windows_netstat_e,
)
from olho_de_sauron.analyzers.process_monitor import ProcessMonitor


class TestProcessAndNetworkMonitors(unittest.TestCase):
    def test_process_heuristics_detect_all_suspicious_patterns(self) -> None:
        monitor = ProcessMonitor()
        sample_procs = [
            {
                "pid": 100,
                "ppid": 4,
                "name": "winword.exe",
                "exe": r"C:\Program Files\Microsoft Office\winword.exe",
                "cmdline": "",
                "memory_mb": 120.0,
            },
            {
                "pid": 101,
                "ppid": 100,
                "name": "powershell.exe",
                "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "cmdline": "powershell.exe -NoP -w hidden -enc SQBFAFgA",
                "memory_mb": 45.0,
            },
            {
                "pid": 102,
                "ppid": 4,
                "name": "svchost.exe",
                "exe": r"C:\Users\Public\svchost.exe",
                "cmdline": r"C:\Users\Public\svchost.exe",
                "memory_mb": 12.0,
            },
            {
                "pid": 103,
                "ppid": 4,
                "name": "fatura.pdf.exe",
                "exe": r"C:\Users\User\AppData\Local\Temp\fatura.pdf.exe",
                "cmdline": "",
                "memory_mb": 8.0,
            },
            {
                "pid": 104,
                "ppid": 4,
                "name": "xmrig.exe",
                "exe": r"C:\ProgramData\xmrig.exe",
                "cmdline": "xmrig.exe -o stratum+tcp://pool.example:3333",
                "memory_mb": 250.0,
            },
            {
                "pid": 105,
                "ppid": 4,
                "name": "svchost.exe",
                "exe": r"C:\Windows\System32\svchost.exe",
                "cmdline": "",
                "memory_mb": 20.0,
            },
        ]

        res = monitor.evaluate_processes(sample_procs, collector="unit-test")
        rules = {a["rule_id"] for a in res["alerts"]}
        self.assertEqual(res["verdict"], "CRITICO")
        self.assertIn("PROC-LOLBIN-001", rules)
        self.assertIn("PROC-PARENT-006", rules)
        self.assertIn("PROC-MASQ-003", rules)
        self.assertIn("PROC-PATH-002", rules)
        self.assertIn("PROC-DOUBLEEXT-005", rules)
        self.assertIn("PROC-MINER-004", rules)

        legit = [p for p in res["processes"] if p["pid"] == 105][0]
        self.assertFalse(legit["suspicious"])

    def test_real_process_scan_succeeds(self) -> None:
        res = ProcessMonitor().scan()
        self.assertGreaterEqual(res["total_processes"], 1)
        self.assertIn(res["verdict"], {"SEGURO", "ALERTA", "CRITICO"})

    def test_netstat_ptbr_parsers(self) -> None:
        ano_sample = (
            "\nConexões ativas\n\n"
            "  Proto  Endereço local         Endereço externo       Estado           PID\n"
            "  TCP    0.0.0.0:445            0.0.0.0:0              ESCUTANDO        4\n"
            "  TCP    192.168.0.10:55120     8.8.8.8:443            ESTABELECIDA     2020\n"
            "  UDP    127.0.0.1:5353         *:*                                    1500\n"
        )
        conns = parse_windows_netstat_ano(ano_sample)
        self.assertEqual(len(conns), 3)
        self.assertEqual(conns[0]["state"], "LISTEN")
        self.assertEqual(conns[0]["local_port"], 445)
        self.assertEqual(conns[1]["state"], "ESTABLISHED")
        self.assertEqual(conns[1]["remote_ip"], "8.8.8.8")
        self.assertEqual(conns[2]["proto"], "UDP")

        e_sample = (
            "Estatísticas de interface\n\n"
            "                           Recebido         Enviado\n\n"
            "Bytes                     123456789         98765432\n"
            "Pacotes unicast               12000            11000\n"
            "Descartes                         1                2\n"
            "Erros                             0                3\n"
        )
        stats = parse_windows_netstat_e(e_sample)
        self.assertEqual(stats["bytes_recv"], 123456789)
        self.assertEqual(stats["bytes_sent"], 98765432)
        self.assertEqual(stats["discards"], 3)
        self.assertEqual(stats["errors"], 3)

    def test_network_heuristics_detect_c2_miner_exposed_and_lolbin(self) -> None:
        monitor = NetworkMonitor()
        sample_conns = [
            {
                "proto": "TCP",
                "local_ip": "192.168.1.5",
                "local_port": 51000,
                "remote_ip": "198.51.100.10",
                "remote_port": 4444,
                "state": "ESTABLISHED",
                "pid": 1001,
                "process_name": "evil.exe",
            },
            {
                "proto": "TCP",
                "local_ip": "192.168.1.5",
                "local_port": 51001,
                "remote_ip": "198.51.100.11",
                "remote_port": 3333,
                "state": "ESTABLISHED",
                "pid": 1002,
                "process_name": "miner.exe",
            },
            {
                "proto": "TCP",
                "local_ip": "0.0.0.0",
                "local_port": 3389,
                "remote_ip": "0.0.0.0",
                "remote_port": 0,
                "state": "LISTEN",
                "pid": 1003,
                "process_name": "svchost.exe",
            },
            {
                "proto": "TCP",
                "local_ip": "192.168.1.5",
                "local_port": 51002,
                "remote_ip": "93.184.216.34",
                "remote_port": 443,
                "state": "ESTABLISHED",
                "pid": 1004,
                "process_name": "powershell.exe",
            },
            {
                "proto": "TCP",
                "local_ip": "127.0.0.1",
                "local_port": 8000,
                "remote_ip": "0.0.0.0",
                "remote_port": 0,
                "state": "LISTEN",
                "pid": 1005,
                "process_name": "python.exe",
            },
        ]
        annotated, alerts = monitor.evaluate_connections(sample_conns)
        rules = {a["rule_id"] for a in alerts}
        self.assertIn("NET-C2PORT-001", rules)
        self.assertIn("NET-MINER-002", rules)
        self.assertIn("NET-EXPOSED-003", rules)
        self.assertIn("NET-UNUSUAL-004", rules)

        safe_conn = [c for c in annotated if c["pid"] == 1005][0]
        self.assertFalse(safe_conn["suspicious"])

    def test_real_network_scan_succeeds(self) -> None:
        res = NetworkMonitor().scan()
        self.assertIn("summary", res)
        self.assertIn("traffic_history", res)
        self.assertGreaterEqual(len(res["traffic_history"]), 1)


if __name__ == "__main__":
    unittest.main()
