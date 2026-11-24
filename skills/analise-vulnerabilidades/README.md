# Skill: Análise de Vulnerabilidades e Revisão DevSecOps

Esta pasta contém a skill **`analise-vulnerabilidades`**, que especializa o **DIO Agent** (**Olho de Sauron**) em análise defensiva de vulnerabilidades, boas práticas de AppSec e revisão **DevSecOps** antes de levar alterações para produção.

## Objetivo

Ajudar estudantes e desenvolvedores a aprender segurança na prática, desenvolvendo autonomia para:

- Compreender conceitos fundamentais (**vulnerabilidade, ameaça, risco** e **tríade CID**);
- Identificar falhas em código, configurações e servidores de laboratório com referência a **OWASP Top 10** e **MITRE ATT&CK**;
- Classificar riscos por **Impacto**, **Probabilidade** e **Severidade**;
- Aplicar correções seguras e validar se a vulnerabilidade foi realmente mitigada;
- Incorporar uma revisão **DevSecOps** antes de subir alterações para produção.

## Como o agente usa esta skill

O estudante não precisa invocar o nome da skill manualmente. O agente lê o arquivo [`SKILL.md`](SKILL.md) automaticamente sempre que a conversa envolver análise de segurança, falhas em código, exposição de servidores ou revisão pré-produção, consultando também:

- [`agent/knowledge/security-basics.md`](../../agent/knowledge/security-basics.md) — base teórica e boas práticas defensivas;
- [`docs/devsecops-checklist.md`](../../docs/devsecops-checklist.md) — checklist de revisão pré-produção.

## Fluxo de atuação

1. **Entender o cenário e o contexto:** faz perguntas objetivas (uma por vez) antes de sugerir qualquer comando ou intervenção — especialmente em servidores e infraestrutura.
2. **Coletar informações essenciais:** pede apenas o código, diff ou detalhes necessários e confirma o entendimento.
3. **Identificar e explicar riscos:** aponta as falhas prioritárias, explica a causa em linguagem simples e classifica Impacto, Probabilidade, Severidade e pilares da tríade CID.
4. **Conduzir a mitigação:** ensina as boas práticas defensivas por trás da correção, sem entregar respostas prontas em desafios.
5. **Revisão DevSecOps pré-produção:** aplica os 6 pilares do checklist de segurança antes de merge/deploy.
6. **Ensinar prevenção e validar entendimento:** fecha com hábitos de prevenção e uma pergunta rápida de fixação.

## Exemplos de prompts para testar

**Análise de código (AppSec):**
```text
Analise este código de login do meu laboratório em Python como especialista em AppSec.
Quero entender se existe alguma vulnerabilidade, qual o impacto, a técnica no MITRE ATT&CK e como mitigar de forma segura.
```

**Cenário de infraestrutura (verificação de contexto antes de comandos):**
```text
Tenho um servidor Ubuntu de laboratório exposto na internet. O que devo fazer para deixá-lo seguro?
```

**Revisão DevSecOps pré-produção:**
```text
Faça uma revisão DevSecOps pré-produção neste trecho de código antes de eu subir para a branch principal.
```

## Princípios defensivos

- **Educação acima de respostas prontas:** conduz o raciocínio para que o estudante aprenda a prevenir novas falhas.
- **Ética e escopo controlado:** testes e exemplos aplicam-se somente a códigos próprios e servidores de laboratório autorizados.
- **Zero conteúdo ofensivo:** a skill não fornece exploits para atacar sistemas reais.
