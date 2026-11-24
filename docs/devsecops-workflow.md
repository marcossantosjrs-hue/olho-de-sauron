# Fluxo DevSecOps com o Agente (Shift-Left Security)

Este guia mostra como levar a revisão de segurança do agente para dentro do fluxo diário de desenvolvimento, analisando cada alteração **antes de ir para produção** (conceito de *Shift-Left Security*).

---

## 🔄 Etapas do fluxo

```text
1. Desenvolvimento local
   └─> Revisão interativa com a skill `analise-vulnerabilidades` (AppSec + Matriz de Risco)
        │
2. Validação defensiva em laboratório
   └─> Testes automatizados de regressão com a skill `testes-seguranca` (`lab/test_sqli_lab.py`)
        │
3. Abertura de Pull Request (PR)
   └─> Preenchimento do checklist em `.github/PULL_REQUEST_TEMPLATE.md`
        │
4. Verificação automática no CI (GitHub Actions)
   └─> Execução de `.github/workflows/devsecops-check.yml` (testes de regressão + SAST com Bandit)
        │
5. Merge / Produção
   └─> Liberado apenas sem achados de Severidade Alta ou Crítica em aberto
```

---

## 🛠️ Como usar na prática antes de cada commit ou PR

1. **Antes de abrir o PR**, envie o diff ou os arquivos alterados para o agente no Google Antigravity usando o prompt:
   > *"Atue como revisor DevSecOps usando a skill `analise-vulnerabilidades`. Revise as alterações deste arquivo antes do meu Pull Request e entregue o relatório padronizado com Impacto, Probabilidade e Severidade."*
2. **Corrija qualquer risco Alto ou Crítico** (ex.: injeção SQL, credencial hardcoded, ausência de validação de entrada ou configuração insegura).
3. **Adicione ou execute um teste de regressão de segurança** (skill `testes-seguranca`) garantindo que a falha não possa ser reintroduzida.
4. **Abra o Pull Request** preenchendo o checklist padrão em [`.github/PULL_REQUEST_TEMPLATE.md`](../.github/PULL_REQUEST_TEMPLATE.md) e confirme que a esteira [`.github/workflows/devsecops-check.yml`](../.github/workflows/devsecops-check.yml) passou com sucesso.

---

## 🚦 Critérios de bloqueio (Quality Gate de Segurança)

| Severidade | Ação no fluxo DevSecOps |
|------------|-------------------------|
| **Crítica** | Bloqueia merge imediatamente; exige correção + teste de regressão antes de prosseguir. |
| **Alta** | Bloqueia merge até correção ou mitigação formal validada. |
| **Média** | Deve ser corrigida no PR atual ou registrada como issue priorizada com prazo. |
| **Baixa** | Recomendação de melhoria contínua (hardening / boas práticas). |
