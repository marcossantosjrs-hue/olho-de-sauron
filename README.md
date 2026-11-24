<div align="center">

# 👁️ Olho de Sauron
### Agente de Análise de Vulnerabilidades, AppSec & DevSecOps

[![DIO Challenge](https://img.shields.io/badge/DIO-Desafio%20de%20Projeto-7B2CBF?style=for-the-badge)](https://dio.me)
[![Padrão AGENTS.md](https://img.shields.io/badge/Padr%C3%A3o-AGENTS.md-0A66C2?style=for-the-badge)](AGENTS.md)
[![Foco Defensivo](https://img.shields.io/badge/AppSec-DevSecOps-2EA043?style=for-the-badge)](docs/devsecops-workflow.md)
[![Python Lab](https://img.shields.io/badge/Lab-Python%203.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](lab/README.md)

> Especialização do [DIO Agent](https://github.com/digitalinnovationone/dio-agent) voltada para **Análise de Vulnerabilidades, AppSec e Revisão DevSecOps**, construída para o Desafio de Projeto da [DIO](https://dio.me).

[Especialização](#-especialização-do-agente-e-por-quê) •
[Melhoria DevSecOps](#-melhoria-escolhida-revisão-devsecops-no-fluxo-de-desenvolvimento) •
[Arquivos](#-arquivos-criados-e-alterados) •
[Como Rodar](#-como-rodar-o-agente-no-harness) •
[Laboratório](#-laboratório-e-validação-prática) •
[Evidências](#-evidências-dos-testes-prints-e-relatório) •
[Estrutura](#️-estrutura-do-repositório)

</div>

---

## 🎯 Especialização do agente (e por quê)

O **Olho de Sauron** evolui o DIO Agent de um mentor genérico de estudos para um **mentor de segurança defensiva e DevSecOps**.

### Por que essa especialização?

Quem está aprendendo programação ou infraestrutura costuma focar primeiro em "fazer funcionar" — e só descobre problemas como *SQL Injection*, credenciais expostas no Git ou servidores mal configurados depois de um incidente.

Ao contrário de um chat genérico que despeja comandos ou código pronto sem entender o ambiente, este agente segue um roteiro estruturado que:

- **Pergunta o contexto antes de sugerir qualquer comando** (especialmente em servidores e infraestrutura);
- **Explica vulnerabilidade, ameaça, risco e tríade CID** em português claro, sem jargão desnecessário;
- **Mapeia riscos com frameworks de mercado** (**OWASP Top 10** e **MITRE ATT&CK**) e classifica **Impacto, Probabilidade e Severidade**;
- **Adota postura 100% defensiva e educativa**, conduzindo o estudante à correção em vez de entregar exploits ou respostas prontas de desafios;
- **Integra segurança ao fluxo de desenvolvimento (DevSecOps)** com um checklist de revisão pré-produção.

---

## 🧩 Melhoria escolhida: Revisão DevSecOps no fluxo de desenvolvimento

Entre as possibilidades de evolução do projeto, escolhi levar a análise de segurança para o fluxo de desenvolvimento (**DevSecOps / *Shift-Left Security***), avaliando cada alteração **antes** de chegar à produção.

### O que essa melhoria adiciona na prática

1. **Checklist e Fluxo *Shift-Left*:** guia de verificação pré-deploy em [`docs/devsecops-checklist.md`](docs/devsecops-checklist.md) e fluxo completo em [`docs/devsecops-workflow.md`](docs/devsecops-workflow.md), cobrindo 6 pilares:
   - Segredos e Credenciais
   - Entradas e Injeções
   - Autenticação e Controle de Acesso
   - Configurações e Exposição
   - Dependências
   - Tratamento de Erros e Logs
2. **Automação em Pull Requests e CI/CD:** template de PR com checklist de segurança em [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) e esteira no GitHub Actions em [`.github/workflows/devsecops-check.yml`](.github/workflows/devsecops-check.yml) (executando testes de regressão de segurança + análise estática SAST com Bandit).
3. **Parecer de Prontidão na Skill:** etapa dedicada em [`skills/analise-vulnerabilidades/SKILL.md`](skills/analise-vulnerabilidades/SKILL.md) para emitir um veredito claro (*Aprovado para seguir*, *Ajustes recomendados* ou *Bloqueado até corrigir risco crítico/alto*) sempre que o estudante enviar código, commit ou `git diff`.
4. **Skills Complementares:** [`skills/testes-seguranca/SKILL.md`](skills/testes-seguranca/SKILL.md) (validação defensiva e testes de regressão) e [`skills/trilha-ciberseguranca/SKILL.md`](skills/trilha-ciberseguranca/SKILL.md) (trilha de estudos em cibersegurança).
5. **Laboratório Comparativo Automatizado:** ambiente local em [`lab/`](lab/README.md) que, além de mitigar o SQL Injection com consulta parametrizada, aplica boas práticas de AppSec/DevSecOps (validação de tipos + hash de senha com `scrypt` e `salt`).

---

## 📂 Arquivos criados e alterados

| Arquivo | Ação | Papel no projeto |
| :--- | :---: | :--- |
| [`skills/analise-vulnerabilidades/SKILL.md`](skills/analise-vulnerabilidades/SKILL.md) | `Criado` | Roteiro principal da skill (`name` e `description`), com regra de contexto antes de comandos, classificação de risco, OWASP/MITRE ATT&CK e revisão DevSecOps. |
| [`skills/analise-vulnerabilidades/README.md`](skills/analise-vulnerabilidades/README.md) | `Criado` | Documentação voltada para pessoas explicando objetivo, gatilhos, fluxo e prompts de exemplo da skill. |
| [`skills/testes-seguranca/SKILL.md`](skills/testes-seguranca/SKILL.md) | `Criado` | Skill complementar focada em testes defensivos e validação de regressão de segurança em laboratório. |
| [`skills/testes-seguranca/README.md`](skills/testes-seguranca/README.md) | `Criado` | Documentação humana da skill de testes de segurança. |
| [`skills/trilha-ciberseguranca/SKILL.md`](skills/trilha-ciberseguranca/SKILL.md) | `Criado` | Skill complementar para montar trilhas estruturadas de estudo em cibersegurança (AppSec, Blue Team, DevSecOps). |
| [`skills/trilha-ciberseguranca/README.md`](skills/trilha-ciberseguranca/README.md) | `Criado` | Documentação humana da skill de trilha de cibersegurança. |
| [`agent/knowledge/security-basics.md`](agent/knowledge/security-basics.md) | `Criado` | Base de conhecimento com vulnerabilidade, ameaça, risco, tríade CID, matriz de severidade, OWASP, MITRE ATT&CK, boas práticas defensivas e DevSecOps. |
| [`agent/persona.md`](agent/persona.md) | `Alterado` | Adicionada a especialização em Segurança Defensiva e DevSecOps (contexto antes de ação, postura defensiva e mentalidade *Shift-Left*). |
| [`AGENTS.md`](AGENTS.md) | `Alterado` | Registrados `agent/knowledge/security-basics.md`, as novas skills na tabela de skills e a regra de segurança defensiva em *Limites e cuidados*. |
| [`docs/devsecops-checklist.md`](docs/devsecops-checklist.md) | `Criado` | Checklist pré-produção de 6 pilares usado na revisão DevSecOps. |
| [`docs/devsecops-workflow.md`](docs/devsecops-workflow.md) | `Criado` | Fluxo *Shift-Left Security* do desenvolvimento local até o CI/CD. |
| [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) | `Criado` | Template de Pull Request com checklist DevSecOps e resumo de risco. |
| [`.github/workflows/devsecops-check.yml`](.github/workflows/devsecops-check.yml) | `Criado` | Workflow do GitHub Actions com testes de regressão de segurança (`unittest`) e SAST (`bandit`). |
| [`lab/app_vulneravel.py`](lab/app_vulneravel.py) | `Criado` | Código de laboratório em SQLite propositalmente vulnerável a SQL Injection para o teste inicial de varredura. |
| [`lab/app_seguro.py`](lab/app_seguro.py) | `Criado` | Versão mitigada com consulta parametrizada (`?`) e hash seguro de senha (`scrypt` + `salt`) para validação pós-correção. |
| [`lab/test_sqli_lab.py`](lab/test_sqli_lab.py) | `Criado` | Testes automatizados (`unittest`) validando a mitigação do SQL Injection em laboratório. |
| [`lab/cenario-infra-ubuntu.md`](lab/cenario-infra-ubuntu.md) | `Criado` | Cenários extras de laboratório (servidor Ubuntu exposto na internet + configurações inseguras de SSH e Nginx). |
| [`lab/README.md`](lab/README.md) | `Criado` | Guia de execução local e resultado esperado do laboratório antes/depois. |
| [`docs/evidencias-laboratorio.md`](docs/evidencias-laboratorio.md) | `Criado` | Registro estruturado das evidências de análise (antes/depois, matriz de risco e comparativo agente vs. chat genérico). |
| [`docs/prints/README.md`](docs/prints/README.md) | `Criado` | Guia dos prints recomendados do Google Antigravity para anexar ao portfólio. |
| [`README.md`](README.md) | `Alterado` | Documentação completa do projeto evoluído, instruções de execução e evidências. |

---

## 🚀 Como rodar o agente no harness

Este projeto segue o padrão aberto **`AGENTS.md`**, funcionando diretamente no **Google Antigravity** e em outros harnesses compatíveis (*Claude Code, Codex, OpenCode, Hermes*).

### Passo a passo no Google Antigravity

1. **Clone o repositório** (ou baixe o ZIP):
   ```bash
   git clone https://github.com/marcossantosjrs-hue/olho-de-sauron.git
   ```
2. **Abra a pasta `olho-de-sauron` no Google Antigravity.**
   - O harness lê automaticamente [`AGENTS.md`](AGENTS.md) na raiz, carrega a persona em [`agent/persona.md`](agent/persona.md) e passa a reconhecer todas as skills registradas, incluindo `analise-vulnerabilidades`.
3. **Converse naturalmente com o agente.**
   - Você não precisa chamar a skill pelo nome — basta descrever o código, servidor de laboratório ou alteração que deseja revisar.

### 💬 Prompts recomendados para testar

<details open>
<summary><strong>1. Análise de código vulnerável (AppSec)</strong></summary>

```text
Atue como especialista em AppSec e analise o arquivo lab/app_vulneravel.py.
Encontre a falha, explique como ocorre a exploração de forma conceitual, cite a técnica do MITRE ATT&CK, avalie o risco na tríade CID e oriente a correção segura.
```

</details>

<details open>
<summary><strong>2. Validação pós-correção + Parecer DevSecOps</strong></summary>

```text
Corrigi o login usando consulta parametrizada e hash de senha no arquivo lab/app_seguro.py.
Faça uma nova varredura para validar se o SQL Injection foi mitigado e aplique o checklist DevSecOps pré-produção.
```

</details>

<details open>
<summary><strong>3. Teste conversacional de infraestrutura (contexto antes de comandos)</strong></summary>

```text
Tenho um servidor Ubuntu de laboratório exposto na internet. O que devo fazer para deixá-lo mais seguro?
```

> [!TIP]
> **Comportamento esperado:** em vez de despejar uma lista genérica de comandos, o agente deve primeiro fazer perguntas de contexto (uma por vez) sobre o ambiente, serviços/portas expostas e configurações atuais.

</details>

---

## 🧪 Laboratório e Validação Prática

Todos os testes deste projeto foram executados exclusivamente em **código e ambientes próprios de laboratório** (usando SQLite em memória `:memory:`):

```bash
python lab/app_vulneravel.py
python lab/app_seguro.py
python -m unittest discover -s lab -p "test_*.py" -v
```

| Etapa | Arquivo | Resultado no teste de entrada maliciosa (`admin' --`) | Status |
| :--- | :--- | :--- | :---: |
| **Antes (vulnerável)** | [`lab/app_vulneravel.py`](lab/app_vulneravel.py) | `Acesso Permitido!` (bypass via SQL Injection — OWASP A03:2021 / MITRE ATT&CK `T1190`) | ❌ Vulnerável |
| **Depois (corrigido)** | [`lab/app_seguro.py`](lab/app_seguro.py) | `Acesso Negado!` (consulta parametrizada com `?` + verificação de hash com `scrypt`) | ✅ Mitigado |
| **Testes automatizados** | [`lab/test_sqli_lab.py`](lab/test_sqli_lab.py) | 5 testes de regressão executados em SQLite `:memory:` | ✅ `5 tests OK` |
| **Infraestrutura extra** | [`lab/cenario-infra-ubuntu.md`](lab/cenario-infra-ubuntu.md) | Cenário de servidor Ubuntu exposto + configurações inseguras de SSH e Nginx | ✅ Pronto |

---

## 📸 Evidências dos Testes (Prints e Relatório)

O comparativo completo das análises (AppSec antes/depois, classificação **Impacto × Probabilidade → Severidade** e comportamento **Agente Especializado vs. Chat Genérico**) está documentado em [`docs/evidencias-laboratorio.md`](docs/evidencias-laboratorio.md).

> [!NOTE]
> As capturas de tela e o guia de evidências do Google Antigravity estão organizados em [`docs/prints/`](docs/prints/README.md).

1. **Análise do `lab/app_vulneravel.py`:** print do agente identificando o SQL Injection, explicando o impacto na tríade CID, citando o MITRE ATT&CK (`T1190`) e orientando a mitigação.
2. **Nova varredura no `lab/app_seguro.py` + Parecer DevSecOps:** print confirmando que o SQL Injection foi mitigado e exibindo a avaliação pelo checklist pré-produção.
3. **Cenário do servidor Ubuntu de laboratório:** print mostrando o agente fazendo perguntas de contexto **antes** de sugerir qualquer comando (e comparativo com um chat genérico).

---

## 🗂️ Estrutura do repositório

```text
olho-de-sauron/
├── README.md                              Documentação do projeto evoluído
├── AGENTS.md                              Definição do agente e tabela de skills (lida pelo harness)
├── CLAUDE.md                              Atalho para o Claude Code (importa AGENTS.md)
├── .github/
│   ├── PULL_REQUEST_TEMPLATE.md           Checklist DevSecOps automático para Pull Requests
│   └── workflows/
│       └── devsecops-check.yml            Pipeline CI de regressão de segurança + SAST (Bandit)
├── agent/
│   ├── persona.md                         Personalidade e postura defensiva/DevSecOps do agente
│   └── knowledge/
│       ├── dio-platform.md                Contexto sobre a plataforma DIO
│       ├── learning-experiences.md        Tipos de experiências educacionais da DIO
│       └── security-basics.md             Fundamentos de segurança, tríade CID e DevSecOps
├── skills/
│   ├── README.md                          Guia de criação de skills
│   ├── ai-builder-path/SKILL.md           Skill: Caminho AI Builder
│   ├── analise-vulnerabilidades/
│   │   ├── SKILL.md                       Skill: Análise de Vulnerabilidades e DevSecOps
│   │   └── README.md                      Documentação humana da skill
│   ├── explain-concept/SKILL.md           Skill: Explicar conceito
│   ├── portfolio-review/SKILL.md          Skill: Revisão de portfólio
│   ├── study-plan/SKILL.md                Skill: Plano de estudos
│   ├── testes-seguranca/
│   │   ├── SKILL.md                       Skill: Testes de Segurança em laboratório
│   │   └── README.md                      Documentação humana da skill
│   ├── trilha-ciberseguranca/
│   │   ├── SKILL.md                       Skill: Trilha de Cibersegurança
│   │   └── README.md                      Documentação humana da skill
│   ├── unblock-challenge/SKILL.md         Skill: Destravar desafio
│   └── web-search/SKILL.md                Skill: Pesquisa na web
├── lab/
│   ├── __init__.py                        Inicialização do pacote de laboratórios
│   ├── README.md                          Instruções do laboratório SQL Injection (antes/depois)
│   ├── app_vulneravel.py                  Exemplo vulnerável apenas para laboratório local
│   ├── app_seguro.py                      Versão corrigida com consulta parametrizada e hash
│   ├── test_sqli_lab.py                   Testes automatizados de regressão de segurança
│   └── cenario-infra-ubuntu.md            Cenários extras (servidor Ubuntu + SSH/Nginx)
└── docs/
    ├── devsecops-checklist.md             Checklist DevSecOps de revisão pré-produção
    ├── devsecops-workflow.md              Fluxo Shift-Left Security (local até CI)
    ├── evidencias-laboratorio.md          Evidências documentadas (antes/depois + comparativo)
    ├── glossary.md                        Glossário de termos de agentes de IA
    ├── prints/
    │   └── README.md                      Guia de prints de evidência para o portfólio
    └── youcom-mcp.md                      Como conectar a busca do You.com
```

---

## 🛡️ Aviso Ético

> [!WARNING]
> Todo o conteúdo, código e testes presentes neste repositório têm **finalidade estritamente educacional e defensiva**. Os testes foram feitos exclusivamente em ambiente local controlado e código próprio de laboratório. Nunca aplique testes de segurança em sistemas ou redes sem autorização expressa.
