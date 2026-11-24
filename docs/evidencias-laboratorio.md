# Evidências Práticas do Laboratório

Este documento registra as evidências de teste do agente **Olho de Sauron**, comprovando o funcionamento da análise de vulnerabilidades (antes e depois da correção), da validação automatizada, do comportamento de **coleta de contexto antes de comandos** e da comparação com um chat genérico.

> Todos os testes abaixo foram executados **exclusivamente em código próprio e banco SQLite local em memória (`:memory:`)**, sem qualquer alvo externo.

---

## 1. Evidência AppSec — Antes da correção (`lab/app_vulneravel.py`)

### Código analisado (trecho vulnerável)
```python
query = (
    f"SELECT 1 FROM usuarios "
    f"WHERE username = '{usuario}' AND password = '{senha}'"
)
resultado = conexao.execute(query).fetchone()
```

### Relatório padronizado produzido seguindo a skill `analise-vulnerabilidades`

- **Resumo do cenário:** Função de login local em Python/SQLite (`lab/app_vulneravel.py`) que autentica usuários montando uma consulta SQL por concatenação direta de strings.
- **Achado 1: SQL Injection no fluxo de autenticação**
  - **Impacto:** **Alto** — permite burlar a autenticação sem conhecer a senha e, dependendo da consulta/permissões, ler ou manipular registros do banco.
  - **Probabilidade:** **Alta** — qualquer usuário consegue enviar caracteres especiais no campo de login, sem exigir privilégios prévios.
  - **Severidade:** **Crítica** *(Alto × Alta)*.
  - **Tríade CID afetada:** Confidencialidade e Integridade.
  - **Referências:**
    - **OWASP Top 10 (A03:2021 — Injection):** ocorre quando dados não confiáveis são enviados a um interpretador como parte de um comando ou consulta.
    - **MITRE ATT&CK `T1190` (Exploit Public-Facing Application):** exploração de fraquezas em aplicações expostas para obter acesso inicial, frequentemente combinada com **`T1078` (Valid Accounts)** quando resulta em bypass de autenticação.
  - **Por que é um risco:** ao interpolar `usuario` diretamente na query, uma entrada como `admin' --` ou `' OR '1'='1' --` altera a lógica da consulta SQL e comenta o restante da verificação de senha, fazendo o banco autenticar o usuário sem senha válida.
- **Achado 2 (risco residual): Armazenamento/comparação de senha em texto puro**
  - **Impacto:** **Alto** — em caso de vazamento do banco de dados, todas as credenciais ficam imediatamente expostas.
  - **Probabilidade:** **Média** — depende de acesso ao banco ou backup, mas amplia severamente o dano de qualquer incidente.
  - **Severidade:** **Alta** *(Alto × Média)*.
  - **Referências:** **OWASP A02:2021 (Cryptographic Failures)** | **MITRE ATT&CK `T1552` (Unsecured Credentials)**.

---

## 2. Evidência AppSec — Correção e Revalidação (`lab/app_seguro.py` e `lab/test_sqli_lab.py`)

### Mudanças aplicadas
1. **Consulta parametrizada (`?`):** aplicada em [`lab/app_seguro.py`](../lab/app_seguro.py), separando a estrutura do SQL dos dados digitados.
2. **Eliminação do risco residual de senha em texto puro:** em [`lab/app_seguro.py`](../lab/app_seguro.py), a senha é protegida com `hashlib.scrypt` + salt aleatório e verificada em tempo constante com `hmac.compare_digest`.
3. **Validação automatizada de regressão:** criada em [`lab/test_sqli_lab.py`](../lab/test_sqli_lab.py) usando SQLite em memória (`:memory:`), executável com `python -m unittest discover -s lab -p "test_*.py" -v`.

### Comparativo Antes × Depois

| Critério | `lab/app_vulneravel.py` | `lab/app_seguro.py` |
|----------|-------------------------|---------------------|
| Entrada maliciosa (`admin' --` / `' OR '1'='1' --`) | **Acesso Permitido!** (Vulnerável) | **Acesso Negado!** (Mitigado) |
| Login legítimo válido (`admin` + senha correta) | Acesso Permitido! | Acesso Permitido! |
| Severidade SQL Injection | **Crítica** | **Mitigada** |
| Proteção da senha no banco | Texto puro (Risco Alto) | Hash `scrypt` + salt + `hmac.compare_digest` (Mitigado) |
| Suite automatizada (`lab/test_sqli_lab.py`) | Confirma reprodução da falha | Confirma bloqueio de 5 payloads + validação de tipos (`5 tests OK`) |

---

## 3. Evidência de Comportamento — Servidor Ubuntu de Laboratório (Agente Especializado vs. Chat Genérico)

### Prompt testado
> *"Tenho um servidor Ubuntu de laboratório exposto na internet. O que devo fazer para deixá-lo mais seguro?"*

| Aspecto | Chat genérico (sem skill/persona) | Agente Olho de Sauron (com `analise-vulnerabilidades`) |
|---------|-----------------------------------|--------------------------------------------------------|
| **Primeira reação** | Despeja imediatamente 10+ comandos (`ufw`, `apt`, `sshd_config`, `fail2ban`) sem saber o que roda no servidor. | **Não sugere comandos na primeira resposta.** Confirma que é um laboratório próprio e pergunta o contexto essencial (quais serviços/portas precisam ficar expostos, como é feito o acesso SSH e o que já está configurado). |
| **Risco operacional** | Pode até fazer um iniciante bloquear o próprio acesso SSH ao copiar comandos de firewall sem contexto. | Evita bloqueios acidentais e adapta o hardening à superfície real do servidor. |
| **Classificação de risco** | Lista solta de dicas sem priorização padronizada. | Entrega relatório padronizado com **Impacto, Probabilidade, Severidade**, Tríade CID e **MITRE ATT&CK** (`T1046`, `T1110`). |
| **Aprendizado** | Resposta pronta para copiar e colar. | Explica o *porquê* de cada controle e valida o entendimento com uma pergunta curta ao final. |

---

## 4. Checklist de Prints Recomendados para o Portfólio

Antes de publicar/entregar na DIO, salve seus prints reais do Google Antigravity na pasta [`docs/prints/`](prints/README.md) e referencie-os no `README.md`:

1. `docs/prints/01-analise-app-vulneravel.png` — Agente encontrando o SQL Injection no `lab/app_vulneravel.py`, citando MITRE ATT&CK (`T1190`) e classificando Impacto, Probabilidade e Severidade.
2. `docs/prints/02-revalidacao-app-corrigido.png` — Nova varredura no `lab/app_seguro.py` + saída dos testes `lab/test_sqli_lab.py`.
3. `docs/prints/03-cenario-ubuntu-contexto.png` — Conversa sobre o servidor Ubuntu de laboratório mostrando o agente perguntando o contexto **antes** de sugerir qualquer comando.
4. *(Opcional — diferencial)* `docs/prints/04-comparacao-chat-generico.png` — Mesma pergunta do servidor Ubuntu em um chat genérico sem skill, destacando a diferença de comportamento.
