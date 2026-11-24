"""
Versão mitigada do laboratório de login em SQLite.

Correções aplicadas:
1. Consulta parametrizada (Prepared Statement) com placeholders `?`, impedindo SQL Injection.
2. Validação básica de tipo das entradas.
3. Uso seguro de hash de senha com salt (`hashlib.scrypt` + `hmac.compare_digest`),
   evitando armazenamento de senhas em texto puro.
"""

import hashlib
import hmac
import os
import sqlite3
from contextlib import closing


def gerar_hash_senha(senha: str) -> tuple[bytes, bytes]:
    """Gera salt aleatório e hash seguro da senha usando scrypt."""
    salt = os.urandom(16)
    hash_derivado = hashlib.scrypt(
        senha.encode("utf-8"), salt=salt, n=16384, r=8, p=1
    )
    return salt, hash_derivado


def verificar_senha(senha: str, salt: bytes, hash_esperado: bytes) -> bool:
    """Compara a senha informada com o hash salvo em tempo constante."""
    hash_informado = hashlib.scrypt(
        senha.encode("utf-8"), salt=salt, n=16384, r=8, p=1
    )
    return hmac.compare_digest(hash_informado, hash_esperado)


def criar_banco_lab(conexao: sqlite3.Connection) -> None:
    """Cria uma tabela de usuários em memória com senha protegida por hash + salt."""
    conexao.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_salt BLOB NOT NULL,
            password_hash BLOB NOT NULL
        )
        """
    )
    salt, password_hash = gerar_hash_senha("senha_lab_123")
    conexao.execute(
        "INSERT INTO usuarios (username, password_salt, password_hash) VALUES (?, ?, ?)",
        ("admin", salt, password_hash),
    )
    conexao.commit()


def fazer_login(conexao: sqlite3.Connection, usuario: str, senha: str) -> str:
    """Valida credenciais usando consulta parametrizada e verificação de hash."""
    if not isinstance(usuario, str) or not isinstance(senha, str):
        return "Acesso Negado!"

    registro = conexao.execute(
        "SELECT password_salt, password_hash FROM usuarios WHERE username = ? LIMIT 1",
        (usuario,),
    ).fetchone()

    if not registro:
        return "Acesso Negado!"

    salt, password_hash = registro
    if verificar_senha(senha, salt, password_hash):
        return "Acesso Permitido!"
    return "Acesso Negado!"


if __name__ == "__main__":
    with closing(sqlite3.connect(":memory:")) as conn:
        criar_banco_lab(conn)

        print("Teste 1 (credencial válida):", fazer_login(conn, "admin", "senha_lab_123"))
        print("Teste 2 (senha errada):", fazer_login(conn, "admin", "errada"))
        print(
            "Teste 3 (entrada maliciosa em lab):",
            fazer_login(conn, "admin' --", "qualquer_coisa"),
        )
