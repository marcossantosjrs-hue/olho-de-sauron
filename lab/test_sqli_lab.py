"""
Testes automatizados defensivos de regressão de segurança (Laboratório Local).

Executa exclusivamente em bancos SQLite em memória (:memory:) para comprovar:
1. Que `lab/app_vulneravel.py` reproduz o bypass de autenticação por SQL Injection.
2. Que `lab/app_seguro.py` bloqueia payloads de SQL Injection e preserva o login legítimo.
"""

import sqlite3
import sys
import unittest
from contextlib import closing
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from lab import app_seguro, app_vulneravel


class TestSQLInjectionLab(unittest.TestCase):
    """Suite de testes defensivos do laboratório de SQL Injection."""

    def test_versao_vulneravel_aceita_bypass_sqli(self) -> None:
        with closing(sqlite3.connect(":memory:")) as conn:
            app_vulneravel.criar_banco_lab(conn)
            resultado = app_vulneravel.fazer_login(conn, "admin' --", "qualquer_coisa")
            self.assertEqual(resultado, "Acesso Permitido!")

    def test_versao_segura_permite_usuario_valido(self) -> None:
        with closing(sqlite3.connect(":memory:")) as conn:
            app_seguro.criar_banco_lab(conn)
            resultado = app_seguro.fazer_login(conn, "admin", "senha_lab_123")
            self.assertEqual(resultado, "Acesso Permitido!")

    def test_versao_segura_rejeita_senha_incorreta(self) -> None:
        with closing(sqlite3.connect(":memory:")) as conn:
            app_seguro.criar_banco_lab(conn)
            resultado = app_seguro.fazer_login(conn, "admin", "senha_errada")
            self.assertEqual(resultado, "Acesso Negado!")

    def test_versao_segura_bloqueia_payloads_sqli(self) -> None:
        payloads = [
            ("' OR '1'='1' --", "qualquer"),
            ("admin' --", "qualquer"),
            ("' OR 1=1 --", "qualquer"),
            ("admin", "' OR '1'='1"),
            ("admin'; DROP TABLE usuarios; --", "123"),
        ]
        with closing(sqlite3.connect(":memory:")) as conn:
            app_seguro.criar_banco_lab(conn)
            for usuario, senha in payloads:
                with self.subTest(usuario=usuario, senha=senha):
                    resultado = app_seguro.fazer_login(conn, usuario, senha)
                    self.assertEqual(resultado, "Acesso Negado!")

            total = conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
            self.assertEqual(total, 1)

    def test_versao_segura_rejeita_tipos_invalidos(self) -> None:
        with closing(sqlite3.connect(":memory:")) as conn:
            app_seguro.criar_banco_lab(conn)
            self.assertEqual(app_seguro.fazer_login(conn, None, "senha_lab_123"), "Acesso Negado!")  # type: ignore[arg-type]
            self.assertEqual(app_seguro.fazer_login(conn, "admin", 123456), "Acesso Negado!")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
