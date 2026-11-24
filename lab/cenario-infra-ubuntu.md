# Laboratório Extra: Infraestrutura e Configurações Inseguras

Este arquivo reúne cenários extras de laboratório (fora do `app.py`) para testar se a skill `analise-vulnerabilidades`:
1. **Pergunta o contexto antes de sugerir qualquer comando** em cenários abertos.
2. Aplica o **formato padronizado de risco** (**Impacto, Probabilidade e Severidade**) também em infraestrutura e configurações.

---

## Cenário A — Servidor Ubuntu de laboratório exposto na internet

### Prompt de teste para enviar ao agente
> *"Subi um servidor Ubuntu de laboratório exposto na internet para testar meus projetos. O que devo fazer para deixá-lo seguro?"*

### Comportamento esperado do agente (Olho de Sauron)
- **NÃO** solta uma lista imediata de comandos `ufw`, `iptables` ou `sed` na primeira resposta.
- **PERGUNTA o contexto primeiro**, por exemplo:
  1. Quais serviços/portas precisam ficar acessíveis publicamente (ex.: apenas HTTP/HTTPS ou também SSH)?
  2. Esse acesso SSH já usa chave pública ou ainda está com senha/usuário `root`?
  3. Já existe firewall ativo (no Ubuntu ou no provedor de nuvem) e atualizações configuradas?
- **Após receber o contexto**, gera o relatório padronizado (Impacto, Probabilidade, Severidade, Tríade CID e MITRE ATT&CK, como `T1046 — Network Service Discovery` e `T1110 — Brute Force`) e orienta o hardening passo a passo.

---

## Cenário B — Configuração insegura de SSH e Nginx (arquivo fictício de laboratório)

Use os trechos abaixo em um teste com a skill `analise-vulnerabilidades` para verificar como o agente analisa configurações inseguras de infraestrutura:

### Trecho 1: `/etc/ssh/sshd_config` (exemplo inseguro de laboratório)
```text
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
```

### Trecho 2: `nginx.conf` (exemplo inseguro de laboratório)
```nginx
server {
    listen 80;
    server_name lab.exemplo.local;

    server_tokens on;

    location / {
        root /var/www/lab;
        autoindex on;
    }
}
```

### Principais achados esperados na análise padronizada

| Achado | Impacto | Probabilidade | Severidade | Tríade CID | Referência |
|--------|---------|---------------|------------|------------|------------|
| SSH com `PermitRootLogin yes`, senha habilitada e senha vazia permitida em host exposto | Alto | Alta | **Crítica** | Confidencialidade, Integridade e Disponibilidade | OWASP A05 / MITRE ATT&CK `T1110` (Brute Force) e `T1078` (Valid Accounts) |
| Nginx sem HTTPS (apenas porta 80), `autoindex on` listando diretórios e `server_tokens on` expondo versão | Médio | Alta | **Alta** | Confidencialidade | OWASP A02 e A05 / MITRE ATT&CK `T1046` (Network Service Discovery) e `T1592` (Gather Victim Host Information) |
