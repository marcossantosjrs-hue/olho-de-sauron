# Prints de Evidência do Portfólio

Guarde nesta pasta os prints capturados durante a execução do agente **Olho de Sauron** no **Google Antigravity** para reforçar as evidências no seu portfólio da DIO:

1. `01-analise-app-vulneravel.png` — Análise do `lab/app_vulneravel.py` encontrando SQL Injection, citando MITRE ATT&CK (`T1190`) e classificando Impacto, Probabilidade e Severidade.
2. `02-revalidacao-app-corrigido.png` — Nova varredura após aplicar consulta parametrizada (`lab/app_seguro.py`) e execução de `lab/test_sqli_lab.py`.
3. `03-cenario-ubuntu-contexto.png` — Teste do servidor Ubuntu de laboratório mostrando o agente perguntando o contexto **antes** de sugerir qualquer comando.
4. `04-comparacao-chat-generico.png` *(opcional)* — Mesma pergunta do servidor Ubuntu feita em um chat genérico sem skill para evidenciar a evolução do agente.

Depois de salvar as imagens aqui, basta descomentar as linhas de imagem na seção de evidências do `README.md` na raiz do repositório.
