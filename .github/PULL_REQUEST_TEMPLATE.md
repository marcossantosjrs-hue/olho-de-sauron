## 📝 Resumo da alteração

Descreva de forma objetiva o que foi criado ou alterado neste Pull Request.

---

## 🛡️ Checklist DevSecOps (pré-produção)

Revise os itens abaixo com o apoio da skill `analise-vulnerabilidades` antes de solicitar merge:

- [ ] **Entradas e consultas:** todas as entradas de usuário são validadas e consultas SQL usam parâmetros (sem concatenação de strings).
- [ ] **Credenciais e segredos:** nenhuma senha, token, chave de API ou arquivo `.env` foi commitado no código.
- [ ] **Autenticação e acesso:** senhas não são armazenadas/comparadas em texto puro e o princípio do menor privilégio foi respeitado.
- [ ] **Configuração segura:** modo debug desativado, mensagens de erro genéricas para usuários e portas/permissões mínimas.
- [ ] **Testes de regressão de segurança:** os testes defensivos em laboratório foram executados e passaram (`python -m unittest lab/test_sqli_lab.py`).
- [ ] **Classificação de risco revisada:** não existem achados de severidade **Alta** ou **Crítica** em aberto.

---

## 📊 Resumo da análise de risco (se aplicável)

| Achado | Impacto | Probabilidade | Severidade | Status |
|--------|---------|---------------|------------|--------|
| *(ex.: SQL Injection no login)* | Alto | Alta | Crítica | Mitigado |
