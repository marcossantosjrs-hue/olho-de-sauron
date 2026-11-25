"""Relatório Markdown para Pull Requests e GitHub Step Summary."""

from __future__ import annotations

from olho_de_sauron.models import Pillar, ScanResult, Severity, Verdict

_VERDICT_BADGE = {
    Verdict.APROVADO: "APROVADO",
    Verdict.AJUSTES_RECOMENDADOS: "AJUSTES RECOMENDADOS",
    Verdict.BLOQUEADO: "BLOQUEADO",
}


def render_markdown(result: ScanResult) -> str:
    """Gera relatório completo em Markdown pronto para PRs e Step Summary."""
    lines: list[str] = [
        "# Olho de Sauron — Relatório DevSecOps",
        "",
        f"- **Alvo:** `{result.target}`",
        f"- **Parecer:** **{_VERDICT_BADGE[result.verdict]}**",
        f"- **Pontuação:** **{result.score}/100** (Nota **{result.grade}**)",
        f"- **Arquivos analisados:** `{result.files_scanned}` (ignorados: `{result.files_skipped}`)",
        f"- **Achados:** `{len(result.findings)}` | **Duração:** `{result.duration_seconds:.2f}s`",
        "",
        "## Resumo por Severidade",
        "",
        "| Severidade | Quantidade |",
        "| :--- | :---: |",
    ]

    for sev in Severity:
        lines.append(f"| {sev.value} | {result.counts_by_severity.get(sev.value, 0)} |")

    lines.extend(
        [
            "",
            "## Cobertura dos 6 Pilares DevSecOps",
            "",
            "| Pilar | Ocorrências | Status |",
            "| :--- | :---: | :---: |",
        ]
    )

    for pillar in Pillar:
        count = result.counts_by_pillar.get(pillar.value, 0)
        status = "OK" if count == 0 else f"{count} alerta(s)"
        lines.append(f"| {pillar.value} | {count} | {status} |")

    lines.extend(["", "## Detalhamento dos Achados", ""])

    if not result.findings:
        lines.append("Nenhuma vulnerabilidade ou falha de configuração detectada.")
        return "\n".join(lines) + "\n"

    for idx, finding in enumerate(result.findings, start=1):
        cid = ", ".join(finding.cid_impact)
        lines.extend(
            [
                f"<details>",
                f"<summary><strong>[{finding.severity.value}] {finding.rule_id} — {finding.title}</strong> "
                f"(<code>{finding.file_path}:{finding.line}</code>)</summary>",
                "",
                f"- **Pilar DevSecOps:** {finding.pillar.value}",
                f"- **OWASP:** `{finding.owasp}` | **MITRE ATT&CK:** `{finding.mitre_attack}` | **CWE:** `{finding.cwe}`",
                f"- **Impacto CID:** {cid}",
                f"- **Motor:** `{finding.scanner}`",
                f"- **Descrição:** {finding.description}",
                f"- **Correção recomendada:** {finding.remediation}",
                "",
                "```text",
                finding.snippet or "(sem trecho)",
                "```",
                "",
                "</details>",
                "",
            ]
        )

    return "\n".join(lines)
