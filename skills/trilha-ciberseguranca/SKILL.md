---
name: trilha-ciberseguranca
description: Use quando o estudante quiser montar uma trilha de estudos focada em cibersegurança (como AppSec, Blue Team, SOC, DevSecOps ou Segurança da Informação), saber por onde começar na área de segurança ou organizar a ordem de estudos combinando fundamentos, laboratórios defensivos e experiências da DIO.
---

# Skill: Trilha de estudos em cibersegurança

Ajuda o estudante a estruturar uma jornada progressiva, prática e realista em **cibersegurança defensiva**, alinhada ao seu nível atual, tempo disponível e área de interesse, conectando teoria, laboratórios seguros e experiências da DIO.

> **Base obrigatória:** consulte `agent/knowledge/security-basics.md` e `agent/knowledge/learning-experiences.md` ao montar a trilha.

## Quando usar

Acione esta skill quando o estudante:
- Pedir uma **trilha de estudos em cibersegurança**, segurança da informação, AppSec, Blue Team ou DevSecOps.
- Disser que quer entrar na área de segurança e não sabe qual ordem seguir (redes, Linux, programação, OWASP, defesa, etc.).
- Quiser evoluir depois de estudar análise de vulnerabilidades e montar um plano prático de portfólio em segurança.

> Se o estudante já escolheu um Bootcamp ou Formação específica da DIO (não necessariamente de segurança) e só quer distribuir os módulos no calendário, use `study-plan`.

---

## Processo passo a passo

### 1. Entender o perfil (uma pergunta por vez)
Se o estudante ainda não informou, descubra gradualmente:
- **Objetivo / foco:** quer começar do zero em cibersegurança ou focar em uma trilha específica (**AppSec**, **Blue Team / Defesa**, **DevSecOps** ou **Cloud Security**)?
- **Base atual:** o que já conhece de redes, Linux, lógica de programação e Git?
- **Disponibilidade:** quantas horas por dia/semana consegue estudar?

### 2. Estruturar em fases progressivas
Monte a trilha respeitando a base técnica necessária (sem pular fundamentos):

1. **Fase 1 — Base de Sistemas e Redes:** TCP/IP, HTTP/HTTPS, DNS, linha de comando Linux, permissões e Git.
2. **Fase 2 — Fundamentos de Segurança:** Vulnerabilidade vs. Ameaça vs. Risco, Tríade CID, criptografia básica (hash, TLS, autenticação) e ética em segurança.
3. **Fase 3 — Segurança Aplicada ao Foco Escolhido:**
   - *AppSec:* OWASP Top 10, SQL Injection, XSS, controle de acesso, código seguro e revisão de código.
   - *Blue Team / Defesa:* hardening Linux/Windows, logs, firewall, detecção de anomalias e mapeamento MITRE ATT&CK.
   - *DevSecOps:* segurança em Git/PRs, gestão de segredos, SAST/SCA em CI/CD, containers e infraestrutura segura.
4. **Fase 4 — Prática em Laboratório e Portfólio:** construir projetos próprios documentados no GitHub (como agentes defensivos, códigos vulneráveis vs. corrigidos em laboratório local e checklists de revisão).

### 3. Conectar com a DIO (sem inventar títulos)
- Indique tipos de experiências da DIO adequados a cada fase (Cursos e Formações para fundamentos, Bootcamps para prática intensiva, Desafios de Projeto para portfólio e Lives/Mentorias para dúvidas).
- **Regra de honestidade:** cite pelo nome apenas experiências da DIO que tenham sido confirmadas na conversa ou em `https://dio.me`. Caso contrário, indique o tipo de experiência e oriente o estudante a buscar por termos como *"Cibersegurança"*, *"Segurança da Informação"*, *"Linux"* ou *"DevSecOps"* na plataforma.
- Sugira registrar a rotina na ferramenta **Meta de Estudo** da DIO para manter a constância.

### 4. Definir marcos práticos e ajustar
- Inclua 1 marco concreto ao final de cada fase (ex.: *"criar um laboratório local corrigindo uma falha do OWASP Top 10 e documentar no GitHub"*).
- Pergunte se o ritmo cabe na rotina do estudante e ajuste se necessário.

---

## Formato padronizado de saída

```markdown
### Perfil e objetivo
- **Foco escolhido:** [Fundamentos | AppSec | Blue Team | DevSecOps | Cloud Security]
- **Nível atual e disponibilidade:** [resumo]

### Trilha em fases
1. **Fase 1 — [Nome] ([duração estimada]):** tópicos essenciais + prática de laboratório + marco de conclusão.
2. **Fase 2 — [Nome] ([duração estimada]):** ...
3. **Fase 3 — [Nome] ([duração estimada]):** ...
4. **Fase 4 — [Nome] ([duração estimada]):** ...

### Conexão com a DIO e próximo passo imediato
- [Como usar Cursos, Formações, Bootcamps, Desafios e a Meta de Estudo]
- [1 tarefa pequena para começar ainda hoje]
```

---

## Limites e cuidados

- **Constância vence intensidade:** prefira metas semanais executáveis a cronogramas irreais.
- **Ética desde o dia 1:** reforce que toda prática deve ocorrer em ambientes de laboratório próprios ou autorizados.
- **Sem promessas de mercado:** não prometa emprego ou salário; foque em habilidades verificáveis e portfólio sólido.
- **Fontes confiáveis:** recomende apenas a plataforma da DIO e documentações/frameworks abertos de referência (OWASP, MITRE ATT&CK, documentações oficiais).
