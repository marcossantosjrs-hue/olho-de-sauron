# Fundamentos de Segurança da Informação e DevSecOps

Base de conhecimento defensivo do agente **Olho de Sauron** (evolução do DIO Agent). Use este arquivo como referência conceitual ao analisar vulnerabilidades, explicar riscos a estudantes e conduzir revisões de segurança antes da produção.

---

## 1. Vulnerabilidade, Ameaça e Risco

Esses três termos costumam ser confundidos, mas cada um tem um papel claro na análise de segurança:

- **Vulnerabilidade:** é uma fraqueza, falha ou brecha em um código, configuração, sistema ou processo que pode ser explorada.
  - *Exemplo:* montar uma consulta SQL concatenando diretamente o texto digitado pelo usuário (`SQL Injection`).
- **Ameaça:** é qualquer agente, evento ou ação capaz de explorar uma vulnerabilidade e causar dano (um atacante, um script automatizado de varredura, um erro operacional ou uma falha de hardware).
  - *Exemplo:* um invasor ou bot enviando `' OR '1'='1` em um formulário de login exposto na internet.
- **Risco:** é a combinação da **probabilidade** de uma ameaça explorar uma vulnerabilidade com o **impacto** que isso causaria ao sistema, aos dados ou às pessoas.
  - *Relação prática:* `Risco = Probabilidade × Impacto` (existe risco real quando há uma ameaça encontrando uma vulnerabilidade em um ativo relevante).

> **Analogia rápida:** deixar a porta de casa destrancada é uma **vulnerabilidade**; alguém tentando abrir portas na rua é a **ameaça**; a chance real de entrarem e o prejuízo disso formam o **risco**.

---

## 2. Tríade CID (Confidencialidade, Integridade e Disponibilidade)

Conhecida internacionalmente como **CIA Triad**, representa os três pilares que a segurança da informação busca proteger:

| Pilar | O que protege | Exemplo de violação |
|-------|---------------|---------------------|
| **Confidencialidade** | Garante que apenas pessoas ou sistemas autorizados acessem os dados. | Vazamento de banco de dados de usuários, senhas salvas em texto puro ou chaves de API expostas no GitHub. |
| **Integridade** | Garante que dados e sistemas não sejam alterados de forma indevida ou sem autorização. | Atacante usando SQL Injection para alterar o saldo de uma conta ou injetar um usuário administrador. |
| **Disponibilidade** | Garante que o sistema e os dados estejam acessíveis quando usuários legítimos precisarem. | Ataque de negação de serviço (DoS/DDoS), ransomware ou servidor derrubado por má configuração. |

Sempre que explicar o impacto de uma vulnerabilidade, conecte-o a qual(is) pilar(es) da tríade CID estão ameaçados.

---

## 3. Classificação de Risco (Impacto, Probabilidade e Severidade)

Para comparar vulnerabilidades e ajudar o estudante a priorizar o que corrigir primeiro:

- **Impacto:** o tamanho do dano caso a falha seja explorada (Baixo, Médio ou Alto).
- **Probabilidade:** a facilidade e chance de a falha ser encontrada e explorada no contexto atual (Baixa, Média ou Alta).
- **Severidade final:**
  - **Crítica:** impacto alto + exploração direta/remota sem autenticação (ex.: SQL Injection em endpoint de login público, credenciais de produção vazadas em repositório público).
  - **Alta:** impacto alto ou acesso indevido significativo com poucas barreiras (ex.: quebra de controle de acesso / IDOR, execução de código ou comando).
  - **Média:** exige condições específicas ou gera exposição parcial (ex.: cabeçalhos de segurança ausentes, mensagens de erro verbosas revelando stack trace).
  - **Baixa:** impacto limitado e difícil de explorar isoladamente, mas vale corrigir como higiene de código.

---

## 4. Frameworks Defensivos de Referência

Use referências reconhecidas pelo mercado para ensinar vocabulário profissional sem complicar demais:

- **OWASP Top 10:** lista os riscos mais críticos em aplicações web. Exemplos frequentes em projetos de estudo:
  - *Broken Access Control* (falha no controle de acesso, como IDOR).
  - *Cryptographic Failures* (senhas sem hash seguro, dados sensíveis sem criptografia/TLS).
  - *Injection* (SQL Injection, Command Injection).
  - *Security Misconfiguration* (portas abertas desnecessariamente, modo `DEBUG=True` em produção, permissões excessivas).
  - *Vulnerable and Outdated Components* (bibliotecas e sistemas sem atualização de segurança).
- **MITRE ATT&CK:** base de conhecimento que mapeia táticas e técnicas usadas por atacantes, utilizada por times defensivos para entender *como* um ataque acontece e *como* detectá-lo e bloqueá-lo.
  - *Exemplo:* `T1190 — Exploit Public-Facing Application` (exploração de vulnerabilidade em aplicação exposta à internet, como SQL Injection em uma tela de login).
  - *Exemplo:* `T1110 — Brute Force` (tentativas repetidas de adivinhar credenciais em serviços expostos, como SSH sem proteção).

---

## 5. Boas Práticas de Segurança Defensiva

### Em código (AppSec)
- **Consultas parametrizadas (Prepared Statements / ORM seguro):** nunca concatene entrada do usuário diretamente em comandos SQL ou de sistema.
- **Validação e sanitização de entradas:** trate toda entrada externa (formulários, URLs, cabeçalhos, arquivos) como não confiável; valide tipo, tamanho e formato no servidor.
- **Armazenamento seguro de senhas:** nunca salve senhas em texto puro; utilize algoritmos de hash próprios para senha com salt (como Argon2, bcrypt ou scrypt).
- **Gestão de segredos:** nunca coloque senhas, tokens ou chaves de API no código-fonte (*hardcoded*). Use variáveis de ambiente (`.env` fora do Git) ou cofres de segredos.
- **Tratamento seguro de erros:** não exiba mensagens técnicas detalhadas (como erros de SQL ou caminhos internos) para o usuário final; registre internamente em logs sem dados sensíveis.

### Em servidores e infraestrutura
- **Princípio do menor privilégio:** cada usuário, processo e serviço deve ter apenas a permissão estritamente necessária.
- **Redução da superfície de ataque:** mantenha abertas apenas as portas indispensáveis (firewall configurado), desative serviços não utilizados e evite expor bancos de dados diretamente à internet.
- **Autenticação forte:** prefira chaves SSH em vez de login por senha, desative login direto como `root` e ative autenticação multifator (MFA) sempre que possível.
- **Atualizações e monitoramento:** aplique correções de segurança (*patches*) regularmente e habilite logs e alertas (como proteção contra força bruta).

---

## 6. DevSecOps: Segurança no Fluxo de Desenvolvimento

**DevSecOps** significa trazer a segurança para dentro do dia a dia do desenvolvimento (*Shift-Left Security*), em vez de deixar para verificar apenas depois que o sistema já está no ar.

Na prática, antes de cada alteração chegar à produção (em um commit ou Pull Request), revisamos:
1. **Segredos:** há chaves, tokens, senhas ou arquivos `.env` sendo enviados no commit?
2. **Entradas e dados:** todas as entradas externas estão validadas e as consultas ao banco são parametrizadas?
3. **Autenticação e autorização:** o novo trecho verifica quem é o usuário e se ele realmente tem permissão para aquela ação?
4. **Dependências:** alguma biblioteca nova ou desatualizada possui vulnerabilidades conhecidas?
5. **Configuração e exposição:** o código habilita modo debug, CORS permissivo demais (`*`) ou expõe portas/rotas internas?
6. **Logs e tratamento de erros:** os erros são tratados sem vazar dados sensíveis ou detalhes internos?

O checklist completo de revisão pré-produção está em `docs/devsecops-checklist.md`.

---

## 7. Limites Éticos e Uso Responsável

- **Ambiente controlado:** todo teste de segurança ensinado ou demonstrado deve acontecer exclusivamente em código próprio ou em servidores de laboratório criados pelo estudante para estudo.
- **Nunca testar sem autorização:** executar varreduras, tentativas de invasão ou exploração em sistemas de terceiros sem permissão expressa é antiético e ilegal.
- **Postura defensiva:** o foco do agente é identificar riscos, explicar impactos de forma conceitual e orientar correções seguras — jamais fornecer payloads ou instruções para atacar sistemas reais.
