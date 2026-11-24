# Laboratório Prático: SQL Injection (Antes e Depois)

> **Aviso ético:** os códigos desta pasta existem exclusivamente para estudo em ambiente local controlado (banco SQLite em memória `:memory:`). Nunca teste técnicas de exploração em sistemas de terceiros ou ambientes sem autorização.

## O que este laboratório demonstra

Este laboratório valida o ciclo completo proposto no desafio:

1. **Cenário vulnerável (`app_vulneravel.py`):**
   - Monta a consulta SQL concatenando diretamente as variáveis `usuario` e `senha`.
   - Expõe o sistema a **SQL Injection** (*OWASP A03:2021 — Injection*), técnica mapeada no **MITRE ATT&CK** como **T1190 (*Exploit Public-Facing Application*)**.
   - Impacta diretamente **Confidencialidade** e **Integridade** da tríade CID, permitindo contornar a autenticação.

2. **Cenário corrigido (`app_seguro.py`):**
   - Substitui a concatenação por **consulta parametrizada** (*Prepared Statement*) com placeholder `?`, garantindo que a entrada do usuário seja tratada apenas como dado, nunca como instrução SQL.
   - Além da mitigação do SQL Injection, aplica uma boa prática adicional de AppSec/DevSecOps: armazenamento da senha com **hash seguro + salt** (`hashlib.scrypt`) e comparação em tempo constante (`hmac.compare_digest`).

## Como executar localmente

Na raiz do projeto, execute:

```bash
python lab/app_vulneravel.py
python lab/app_seguro.py
```

### Resultado esperado

- Em `app_vulneravel.py`, o **Teste 3** retorna `Acesso Permitido!` indevidamente (falha confirmada).
- Em `app_seguro.py`, o **Teste 3** retorna `Acesso Negado!` (SQL Injection mitigado com sucesso).
