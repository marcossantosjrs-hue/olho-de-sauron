# Skill: Testes de Segurança Defensivos (`testes-seguranca`)

Esta skill ensina o **DIO Agent (Olho de Sauron)** a conduzir **testes defensivos de validação** em código e ambientes próprios de laboratório, comprovando na prática que uma correção de segurança realmente mitigou a vulnerabilidade e criando proteção contra regressões no fluxo DevSecOps.

---

## 🎯 Objetivo

Ajudar estudantes e desenvolvedores a:
- Validar na prática se uma correção (como consultas parametrizadas no `app.py`) realmente bloqueia o ataque em laboratório.
- Escrever **testes automatizados de regressão de segurança** (ex.: testes unitários com banco em memória).
- Identificar **riscos residuais** após uma primeira correção (ex.: SQLi mitigado, mas senha ainda armazenada em texto puro).
- Aplicar verificações defensivas de **SAST** (análise estática) e checagem de configuração antes de ir para produção.

---

## ⚡ Quando o agente ativa esta skill

O agente aciona esta skill quando você:
- Corrige uma vulnerabilidade e pede para **revalidar** o código.
- Quer criar testes automatizados para garantir que uma falha (SQL Injection, validação de entrada, controle de acesso) não volte.
- Pergunta como testar a segurança do seu projeto de laboratório de forma ética e defensiva.

---

## 🔄 Fluxo seguido pelo agente

1. **Confirmação de escopo e autorização:** garante que o teste será feito exclusivamente em ambiente local ou laboratório próprio.
2. **Definição da hipótese defensiva:** estabelece claramente o que precisa ser bloqueado ou validado.
3. **Escolha do teste adequado:** teste unitário de regressão, análise estática (SAST) ou checagem defensiva de configuração.
4. **Análise de resultados e riscos residuais:** classifica o status (**Mitigado**, **Parcialmente mitigado** ou **Vulnerável**) e mostra como incorporar a verificação ao fluxo DevSecOps.

---

## 💬 Exemplos de uso

**1. Revalidar correção de SQL Injection**
> *"Troquei a query do meu `app.py` de laboratório por uma consulta parametrizada. Me ajuda a criar um teste automatizado local com SQLite em memória para provar que o SQL Injection foi mitigado?"*

**2. Revisão de riscos residuais**
> *"Já corrigi o SQL Injection do login no meu laboratório. Que outros testes de segurança devo fazer nessa função antes de considerar o login pronto?"*

---

## 📄 Arquivo da skill

As instruções lidas pelo agente estão em [`SKILL.md`](SKILL.md).
