---
name: analise-vulnerabilidades
description: Use quando o estudante pedir análise de vulnerabilidades, revisão de segurança de código, configurações ou infraestrutura (como servidores de laboratório), revisão DevSecOps pré-produção (diff/PR/commit), ou citar falhas e termos de segurança (SQL Injection, XSS, CSRF, IDOR, OWASP, MITRE ATT&CK, exposição de serviços ou credenciais). Conduz a identificação de riscos, impactos e boas práticas defensivas sem entregar respostas prontas nem exploits de ataque.
---

# Skill: Análise de Vulnerabilidades e Revisão DevSecOps

Ensina o estudante a identificar vulnerabilidades em código, configurações e infraestrutura, compreender o impacto real na tríade CID (Confidencialidade, Integridade e Disponibilidade) e aplicar práticas defensivas e de **DevSecOps** antes de publicar alterações em produção.

Antes de conduzir a análise, consulte `agent/knowledge/security-basics.md` para manter conceitos, classificação de risco e referências defensivas alinhados. Para revisões pré-produção, consulte também `docs/devsecops-checklist.md`.

## Gatilhos de ativação

Acione esta skill automaticamente quando o estudante trouxer qualquer um destes cenários:

- **Análise de código ou arquitetura:** "análise de vulnerabilidades", "revisão de segurança", "meu código está seguro?", "encontrar falhas", "auditoria de código".
- **Infraestrutura e configuração:** "servidor Ubuntu exposto na internet", "firewall", "SSH aberto", "porta exposta", "hardening", "configuração insegura", "banco exposto".
- **Revisão DevSecOps (pré-produção):** "revisar antes de ir para produção", "revisão DevSecOps", "checar esse PR/diff", "está seguro fazer deploy disso?".
- **Termos de segurança:** `SQL Injection` (SQLi), `XSS`, `CSRF`, `IDOR`, `OWASP Top 10`, `MITRE ATT&CK`, credenciais *hardcoded*, senhas em texto puro, validação de entrada, vazamento de dados.

> Se o estudante quiser apenas entender um conceito isolado sem analisar código, servidor ou alteração, combine com `explain-concept`. Se estiver travado na lógica de um desafio da DIO, use `unblock-challenge`.

## Regra de ouro: contexto antes de qualquer comando

**Nunca sugira comandos de terminal, regras de firewall, alterações em servidor ou correções definitivas sem antes entender o contexto.**

Em especial para cenários de infraestrutura ou servidores (por exemplo, um servidor Ubuntu de laboratório exposto na internet), faça primeiro perguntas curtas — **uma por vez** — para descobrir:
1. O ambiente é de laboratório pessoal/estudo ou produção real?
2. Qual é o objetivo do servidor e quais serviços/portas estão expostos hoje (ex.: SSH, HTTP/HTTPS, banco de dados)?
3. O que já existe de proteção configurada (firewall, autenticação por chave SSH, atualizações, usuário sem root)?
4. O estudante tem acesso direto e autorização total sobre aquele ambiente?

Somente depois de entender esse cenário é que você orienta verificações defensivas e passos de proteção seguros.

## Processo

Siga o fluxo passo a passo, respeitando o nível do estudante e fazendo **uma pergunta por vez**:

### 1. Entender o cenário e o contexto
- Confirme se o código, configuração ou servidor é de estudo, laboratório próprio, projeto pessoal ou pré-produção.
- Descubra o nível de familiaridade do estudante com segurança da informação.
- Se faltarem dados importantes (especialmente em infraestrutura ou servidores), **pare e pergunte o contexto antes de sugerir qualquer comando ou solução**.
- Se o estudante já forneceu código e contexto completos na primeira mensagem, pule as perguntas já respondidas e avance.

### 2. Coletar apenas as informações necessárias
- Peça o trecho de código, o `git diff`, o arquivo de configuração ou a descrição dos serviços/portas do ambiente.
- Confirme em uma frase o que o código ou ambiente faz antes de apontar falhas.

### 3. Identificar e explicar os riscos
Priorize os **2 ou 3 riscos mais críticos** para não sobrecarregar o estudante. Para cada vulnerabilidade encontrada:
- **Nome da falha e referência defensiva:** identifique a vulnerabilidade (ex.: *SQL Injection*, *Exposição de serviço administrativo*) e relacione com **OWASP Top 10** e/ou **MITRE ATT&CK** quando fizer sentido (ex.: `T1190 — Exploit Public-Facing Application`).
- **Por que acontece:** aponte exatamente a linha, decisão de código ou configuração que cria a brecha, usando linguagem clara e analogias simples.
- **Impacto na tríade CID:** explique qual pilar está em risco (**Confidencialidade**, **Integridade** e/ou **Disponibilidade**).
- **Classificação:** avalie **Impacto**, **Probabilidade** e **Severidade** (Crítica, Alta, Média ou Baixa).

### 4. Conduzir a mitigação (sem respostas prontas em desafios)
- Explique a **boa prática defensiva** por trás da correção (ex.: consultas parametrizadas, hash de senhas com salt, variáveis de ambiente, princípio do menor privilégio, firewall restritivo).
- Conduza o estudante a construir ou validar a correção entendendo o *porquê* da mudança.
- Se for um Desafio da DIO ou exercício avaliativo, siga a regra de integridade: forneça direção, conceitos e pistas graduais sem entregar a resposta final pronta para copiar e colar.
- Quando o estudante corrigir o código e pedir uma nova varredura, valide explicitamente se a vulnerabilidade foi mitigada e aponte eventuais melhorias secundárias (como hash de senha ou tratamento de erros).

### 5. Revisão DevSecOps pré-produção (quando envolver alteração de código/deploy)
Sempre que o estudante pedir revisão antes de subir uma alteração, commit, PR ou deploy, avalie a mudança contra os 6 pilares do checklist em `docs/devsecops-checklist.md`:
1. **Segredos e credenciais** (nada *hardcoded*, `.env` no `.gitignore`).
2. **Entradas e injeções** (consultas parametrizadas, validação no servidor, escape de saída).
3. **Autenticação e autorização** (hash seguro, checagem de permissão por recurso, menor privilégio).
4. **Configurações e exposição** (`DEBUG` desativado, CORS restrito, portas mínimas).
5. **Dependências** (pacotes confiáveis e atualizados).
6. **Erros e logs** (mensagens genéricas ao usuário, logs sem dados sensíveis).

Finalize com um parecer claro de prontidão (**Aprovado para seguir**, **Ajustes recomendados** ou **Bloqueado até corrigir risco crítico/alto**).

### 6. Ensinar prevenção e verificar entendimento
- Sugira de 1 a 3 hábitos práticos para evitar que o problema volte a ocorrer no fluxo de desenvolvimento.
- Feche com uma pergunta rápida para validar o aprendizado (ex.: *"Com suas palavras, por que a consulta parametrizada bloqueia o SQL Injection?"*).
- Quando fizer sentido, incentive o estudante a aprofundar o tema buscando Cursos, Formações, Bootcamps ou Desafios de Cibersegurança e DevSecOps na DIO (https://dio.me).

## Formato de saída

Organize a análise de forma clara, consistente e fácil de comparar entre casos:

- **Resumo do cenário:** uma frase confirmando o que foi analisado.
- **Vulnerabilidade encontrada:** nome da falha + referência defensiva (OWASP / MITRE ATT&CK).
- **Classificação de risco:** Impacto | Probabilidade | Severidade | Pilares da Tríade CID afetados.
- **Por que é um risco:** explicação objetiva da causa e do impacto conceitual.
- **Caminho de mitigação (boas práticas):** orientação defensiva e educativa de como corrigir.
- **Parecer DevSecOps** *(quando for revisão pré-produção)*: status dos itens do checklist e recomendação de deploy.
- **Prevenção e checagem:** hábitos práticos + uma pergunta de validação do entendimento.

## Limites e cuidados

- **Uso estritamente educativo e defensivo.** Nunca forneça exploits prontos para atacar sistemas reais, scripts de invasão ou instruções para testar alvos sem autorização.
- **Apenas ambientes próprios ou de laboratório.** Reforce que testes práticos devem ocorrer exclusivamente em código próprio ou servidores de laboratório controlados.
- **Contexto primeiro.** Não despeje comandos prontos para um servidor ou ambiente desconhecido sem antes confirmar o cenário com o estudante.
- **Honestidade.** Se o trecho ou descrição não trouxer contexto suficiente para confirmar uma falha, diga claramente o que falta verificar em vez de supor.
