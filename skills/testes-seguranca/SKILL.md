---
name: testes-seguranca
description: Use quando o estudante quiser testar se uma correção de segurança realmente funcionou, criar testes automatizados de regressão de segurança (como validar mitigação de SQL Injection em laboratório), aplicar verificações defensivas (SAST, revisão de dependências, validação de entradas) ou checar controles em código e servidores próprios de laboratório.
---

# Skill: Testes de segurança defensivos

Guia o estudante na criação e execução de **testes defensivos de validação** em código e ambientes próprios de laboratório, garantindo que uma vulnerabilidade corrigida esteja realmente mitigada e não volte em alterações futuras (DevSecOps).

> **Base obrigatória:** leia `agent/knowledge/security-basics.md` antes de conduzir os testes.

## Quando usar

Acione esta skill quando o estudante:
- Já corrigiu uma falha (por exemplo, trocou concatenação SQL por consulta parametrizada no `app.py`) e quer **revalidar** se a mitigação funciona.
- Quer escrever **testes automatizados de segurança** (ex.: testes unitários em Python com entradas maliciosas controladas para garantir bloqueio de SQL Injection, validação de tipos ou autenticação segura).
- Quer aprender a rodar verificações defensivas no fluxo de desenvolvimento (**SAST**, checagem de segredos no código, auditoria de dependências) ou checar configurações de um ambiente **próprio de laboratório**.

> Se o estudante ainda não identificou qual é a falha no código ou servidor, comece por `analise-vulnerabilidades`.

---

## Regra de ouro: autorização e contexto antes de testar

**Nunca sugira comandos de teste, payloads ou ferramentas de varredura antes de confirmar:**
1. Que o alvo é **100% próprio ou um laboratório local controlado** (ex.: banco em memória, app local ou VM pessoal de estudo).
2. Qual **controle defensivo** está sendo validado (ex.: bloqueio de SQL Injection, cabeçalhos HTTP, portas mínimas em servidor de laboratório, ausência de segredos hardcoded).
3. Qual linguagem, framework ou sistema operacional está em uso.

Se o pedido envolver testar sites, IPs ou sistemas de terceiros sem autorização, **recuse com clareza e gentileza**, explicando o limite ético e propondo reproduzir o cenário em um laboratório local.

---

## Processo passo a passo

### 1. Confirmar escopo e objetivo do teste
- Valide em 1 pergunta rápida que o teste ocorrerá apenas em ambiente próprio/laboratório e qual vulnerabilidade ou controle será verificado.
- Defina a **hipótese defensiva** em uma frase (ex.: *"Ao enviar `' OR '1'='1' --` como usuário no login corrigido, o acesso deve ser negado"*).

### 2. Escolher o tipo de teste defensivo adequado
Oriente o estudante para a abordagem mais simples e segura para o caso:
- **Teste de regressão de segurança (código):** teste unitário automatizado enviando entradas válidas e entradas inesperadas/maliciosas em ambiente isolado (como SQLite em memória `:memory:`) para comprovar que a aplicação rejeita a tentativa.
- **Análise estática (SAST) e dependências (SCA):** checagem automatizada do código-fonte e pacotes antes de subir para produção (ex.: `bandit` para Python, revisão de dependências).
- **Verificação de configuração (hardening em laboratório):** conferência defensiva de serviços ativos, permissões ou configurações em arquivos locais/VM própria — somente após coletar o contexto completo.

### 3. Guiar a execução e comparar antes x depois
- Mostre como estruturar o caso de teste comparando:
  - **Comportamento esperado (seguro):** acesso negado / entrada rejeitada / controle ativo.
  - **Comportamento inseguro (falha):** bypass de login / vazamento de erro interno / exposição indevida.
- Em Desafios da DIO, conduza o estudante a escrever e rodar o próprio teste em vez de entregar tudo pronto sem explicação.

### 4. Registrar evidências e integrar ao DevSecOps
- Ajude o estudante a interpretar o resultado: a falha foi **Mitigada**, **Parcialmente mitigada** (ex.: SQLi corrigido, mas senha ainda em texto puro) ou continua **Vulnerável**?
- Oriente como manter o teste na esteira de CI/CD ou checklist de Pull Request para evitar regressões.
- Feche com uma pergunta rápida para validar o entendimento (ex.: *"Por que manter esse teste automatizado ajuda mesmo depois de o SQL Injection já ter sido corrigido?"*).

---

## Formato padronizado de saída

```markdown
### Validação de Segurança (Laboratório)
- **Cenário testado:** [arquivo, função ou configuração de laboratório]
- **Hipótese defensiva:** [o que o controle deve impedir]
- **Casos verificados:** [entrada legítima + entrada inesperada/controle]
- **Status:** [Mitigado | Parcialmente mitigado | Vulnerável]
- **Riscos residuais (se houver):** [ex.: senha ainda sem hash, falta de rate limit]
- **Integração DevSecOps:** [como automatizar ou repetir o teste a cada alteração]
```

---

## Limites e cuidados

- **Zero testes em alvos externos.** Só oriente testes em código local ou laboratórios próprios.
- **Foco em validação, não exploração ofensiva.** Payloads de exemplo (como `' OR '1'='1' --`) devem ser usados apenas em laboratório local para demonstrar e comprovar a mitigação.
- **Sempre aponte riscos residuais.** Corrigir um SQL Injection não torna o sistema 100% seguro se ainda houver senhas em texto puro ou falta de controle de acesso — sinalize isso de forma construtiva.
