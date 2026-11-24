# Checklist DevSecOps de Revisão Pré-Produção

Este checklist traz a visão de **DevSecOps (*Shift-Left Security*)** para o fluxo de desenvolvimento: revisar cada alteração de código, configuração ou infraestrutura **antes** de subir para a branch principal ou para produção.

Você pode usar este guia manualmente antes de abrir um Pull Request ou pedir para o agente **Olho de Sauron** revisar o seu trecho de código / `git diff` seguindo estes critérios.

---

## 1. Segredos e Credenciais
- [ ] Não há senhas, chaves de API, tokens JWT, strings de conexão ou certificados *hardcoded* no código.
- [ ] Arquivos locais com segredos (como `.env`) estão listados no `.gitignore` e não foram incluídos no commit.
- [ ] Credenciais de exemplo na documentação usam valores claramente fictícios (ex.: `SUA_CHAVE_AQUI`).

## 2. Entradas do Usuário e Injeções
- [ ] Todas as consultas ao banco de dados usam **consultas parametrizadas** (*prepared statements*) ou ORM seguro — nenhuma concatenação de strings com entrada do usuário.
- [ ] Entradas externas (body, query params, headers, uploads) são validadas quanto a tipo, formato e tamanho no lado do servidor.
- [ ] Dados exibidos em interfaces web são escapados/sanitizados para prevenir XSS (*Cross-Site Scripting*).
- [ ] Não há chamadas a comandos de sistema (`os.system`, `subprocess` com `shell=True`, `eval`) com dados controlados pelo usuário.

## 3. Autenticação, Sessão e Controle de Acesso
- [ ] Senhas são armazenadas com hash seguro e salt (ex.: Argon2, bcrypt ou scrypt) — nunca em texto puro ou hashes fracos (MD5/SHA-1).
- [ ] Cada rota sensível valida **autenticação** (quem é o usuário) e **autorização** (se ele tem permissão para acessar aquele recurso específico — prevenindo IDOR).
- [ ] Princípio do menor privilégio aplicado a usuários de banco de dados, contas de serviço e tokens.

## 4. Configurações e Superfície de Exposição
- [ ] Modo `DEBUG` está desativado para ambientes de produção.
- [ ] Políticas de CORS não estão abertas indistintamente (`*`) em rotas que lidam com credenciais ou dados sensíveis.
- [ ] Serviços internos (bancos de dados, painéis administrativos) não estão expostos diretamente à internet.
- [ ] Em servidores de infraestrutura, o firewall libera apenas as portas estritamente necessárias.

## 5. Dependências e Cadeia de Suprimentos
- [ ] Bibliotecas e frameworks adicionados ou atualizados têm origem confiável e não possuem vulnerabilidades críticas conhecidas.
- [ ] Versões das dependências estão registradas (`requirements.txt`, `package-lock.json`, etc.) para builds reproduzíveis.

## 6. Tratamento de Erros e Logs
- [ ] Mensagens de erro retornadas ao usuário são genéricas e não vazam *stack traces*, estrutura de tabelas SQL ou caminhos do servidor.
- [ ] Logs de segurança registram eventos importantes (ex.: falhas repetidas de login) sem gravar senhas, tokens ou dados pessoais sensíveis.

---

## Como usar com o agente

Antes de fazer merge ou deploy, envie o código alterado (ou o `git diff`) para o agente e peça:

```text
Faça uma revisão DevSecOps pré-produção desta alteração.
- O que mudou: [descreva brevemente a feature ou correção]
- Ambiente alvo: [laboratório, homologação ou produção]
- Código / diff: [cole o trecho alterado]
```

O agente vai avaliar os itens acima, classificar eventuais riscos por **Impacto, Probabilidade e Severidade** e indicar o que precisa ser ajustado antes de publicar.
