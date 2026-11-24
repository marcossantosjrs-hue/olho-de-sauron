"""
LABORATÓRIO EDUCACIONAL — EXEMPLO INTENCIONALMENTE VULNERÁVEL (SQL INJECTION)

AVISO: Este arquivo existe EXCLUSIVAMENTE para fins didáticos e testes em
laboratório local isolado. NUNCA utilize concatenação de strings em consultas
SQL em ambientes reais ou de produção.

Veja a versão mitigada em: lab/app_seguro.py
"""

import sqlite3
from contextlib import closing


def criar_banco_lab(conexao: sqlite3.Connection) -> None:
    """Cria uma tabela simples de usuários em memória para testes de laboratório."""
    conexao.execute(
        "CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conexao.execute(
        "INSERT INTO usuarios (username, password) VALUES ('admin', 'senha_lab_123')"
    )
    conexao.commit()


def fazer_login(conexao: sqlite3.Connection, usuario: str, senha: str) -> str:
    """
    VULNERÁVEL: monta a query SQL concatenando diretamente a entrada do usuário.
    (OWASP A03:2021 - Injection / MITRE ATT&CK T1190)
    """
    query = (
        f"SELECT * FROM usuarios WHERE username = '{usuario}' AND password = '{senha}'"
    )
    resultado = conexao.execute(query).fetchone()
    return "Acesso Permitido!" if resultado else "Acesso Negado!"


if __name__ == "__main__":
    with closing(sqlite3.connect(":memory:")) as conn:
        criar_banco_lab(conn)
        print("Teste 1 (credencial válida):", fazer_login(conn, "admin", "senha_lab_123"))
        print("Teste 2 (senha errada):", fazer_login(conn, "admin", "errada"))
        print(
            "Teste 3 (entrada maliciosa em lab):",
            fazer_login(conn, "admin' --", "qualquer_coisa"),
        )
