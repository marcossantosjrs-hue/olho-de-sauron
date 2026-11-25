"""Relatório estilizado para terminal com Rich e fallback automático Colorama."""

from __future__ import annotations

import io
from typing import Iterable

from colorama import Fore, Style, init as colorama_init

from olho_de_sauron import APP_NAME, __version__
from olho_de_sauron.models import Pillar, RuleMetadata, ScanResult, Severity, Verdict

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    _HAS_RICH = True
except ImportError:  # pragma: no cover - fallback testado explicitamente
    _HAS_RICH = False

colorama_init(autoreset=True)

_RICH_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold dark_orange",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_COLORAMA_SEV = {
    Severity.CRITICAL: Fore.RED + Style.BRIGHT,
    Severity.HIGH: Fore.LIGHTRED_EX + Style.BRIGHT,
    Severity.MEDIUM: Fore.YELLOW + Style.BRIGHT,
    Severity.LOW: Fore.CYAN,
    Severity.INFO: Fore.WHITE + Style.DIM,
}

_VERDICT_TEXT = {
    Verdict.APROVADO: "APROVADO PARA SEGUIR",
    Verdict.AJUSTES_RECOMENDADOS: "AJUSTES RECOMENDADOS",
    Verdict.BLOQUEADO: "BLOQUEADO (RISCO CRÍTICO/ALTO)",
}


def render_terminal(result: ScanResult, use_rich: bool | None = None) -> str:
    """Renderiza o relatório completo para terminal usando Rich ou fallback Colorama."""
    should_use_rich = _HAS_RICH if use_rich is None else (use_rich and _HAS_RICH)
    if should_use_rich:
        return _render_with_rich(result)
    return _render_with_colorama(result)


def render_rules_terminal(rules: Iterable[RuleMetadata], use_rich: bool | None = None) -> str:
    """Renderiza a tabela de regras catalogadas para o comando `sauron rules`."""
    rule_list = list(rules)
    should_use_rich = _HAS_RICH if use_rich is None else (use_rich and _HAS_RICH)

    if should_use_rich:
        buf = io.StringIO()
        console = Console(file=buf, width=110, force_terminal=False, color_system=None)
        table = Table(title=f"{APP_NAME} — Regras Ativas ({len(rule_list)})", box=box.ROUNDED)
        table.add_column("ID", style="bold yellow", no_wrap=True)
        table.add_column("Severidade", no_wrap=True)
        table.add_column("Pilar")
        table.add_column("OWASP / MITRE")
        table.add_column("Título")
        for r in rule_list:
            mitre_code = r.mitre_attack.split(" ")[0]
            owasp_code = r.owasp.split(" ")[0]
            table.add_row(r.rule_id, r.severity.value, r.pillar.value, f"{owasp_code} | {mitre_code}", r.title)
        console.print(table)
        return buf.getvalue()

    lines = [
        f"{Fore.YELLOW}{Style.BRIGHT}=== {APP_NAME} — Regras Ativas ({len(rule_list)}) ==={Style.RESET_ALL}",
        "",
    ]
    for r in rule_list:
        sev_color = _COLORAMA_SEV[r.severity]
        mitre_code = r.mitre_attack.split(" ")[0]
        owasp_code = r.owasp.split(" ")[0]
        lines.append(
            f"{Fore.YELLOW}{r.rule_id:<17}{Style.RESET_ALL} "
            f"{sev_color}{r.severity.value:<8}{Style.RESET_ALL} "
            f"[{r.pillar.value}] ({owasp_code} | {mitre_code}) - {r.title}"
        )
    return "\n".join(lines) + "\n"


def _render_with_rich(result: ScanResult) -> str:
    buf = io.StringIO()
    console = Console(file=buf, width=110, force_terminal=False, color_system=None)

    verdict_label = _VERDICT_TEXT[result.verdict]
    summary_text = (
        f"[bold]{APP_NAME} v{__version__}[/bold] — Análise DevSecOps Automatizada\n"
        f"Alvo: [cyan]{result.target}[/cyan] | Arquivos: [bold]{result.files_scanned}[/bold] "
        f"(ignorados: {result.files_skipped}) | Duração: {result.duration_seconds:.2f}s\n"
        f"Parecer: [bold]{verdict_label}[/bold] | Pontuação: [bold]{result.score}/100[/bold] "
        f"(Nota [bold]{result.grade}[/bold])"
    )
    console.print(Panel(summary_text, title="Olho de Sauron", border_style="yellow"))

    pillar_table = Table(title="6 Pilares DevSecOps", box=box.SIMPLE)
    pillar_table.add_column("Pilar")
    pillar_table.add_column("Ocorrências", justify="right")
    pillar_table.add_column("Status")
    for pillar in Pillar:
        cnt = result.counts_by_pillar.get(pillar.value, 0)
        status = "OK" if cnt == 0 else f"{cnt} alerta(s)"
        pillar_table.add_row(pillar.value, str(cnt), status)
    console.print(pillar_table)

    if not result.findings:
        console.print("[green]Nenhuma vulnerabilidade ou falha de configuração detectada.[/green]")
        return buf.getvalue()

    findings_table = Table(title=f"Achados ({len(result.findings)})", box=box.ROUNDED)
    findings_table.add_column("Severidade", no_wrap=True)
    findings_table.add_column("Regra", no_wrap=True)
    findings_table.add_column("Local")
    findings_table.add_column("Descrição / Correção")

    for finding in result.findings:
        loc = f"{finding.file_path}:{finding.line}"
        detail = (
            f"{finding.title}\n"
            f"[{finding.owasp} | {finding.mitre_attack} | {finding.cwe}]\n"
            f"Trecho: {finding.snippet}\n"
            f"Correção: {finding.remediation}"
        )
        findings_table.add_row(
            f"[{_RICH_SEV_STYLE[finding.severity]}]{finding.severity.value}[/]",
            finding.rule_id,
            loc,
            detail,
        )

    console.print(findings_table)
    return buf.getvalue()


def _render_with_colorama(result: ScanResult) -> str:
    verdict_label = _VERDICT_TEXT[result.verdict]
    if result.verdict == Verdict.APROVADO:
        verdict_color = Fore.GREEN + Style.BRIGHT
    elif result.verdict == Verdict.AJUSTES_RECOMENDADOS:
        verdict_color = Fore.YELLOW + Style.BRIGHT
    else:
        verdict_color = Fore.RED + Style.BRIGHT

    lines: list[str] = [
        f"{Fore.YELLOW}{Style.BRIGHT}======================================================================",
        f"  {APP_NAME} v{__version__} — Scanner DevSecOps Automatizado",
        f"======================================================================{Style.RESET_ALL}",
        f"Alvo      : {result.target}",
        f"Arquivos  : {result.files_scanned} analisados ({result.files_skipped} ignorados) em {result.duration_seconds:.2f}s",
        f"Parecer   : {verdict_color}{verdict_label}{Style.RESET_ALL}",
        f"Pontuação : {result.score}/100 (Nota {result.grade})",
        "",
        f"{Style.BRIGHT}Resumo por Severidade:{Style.RESET_ALL} "
        + " | ".join(
            f"{_COLORAMA_SEV[s]}{s.value}={result.counts_by_severity.get(s.value, 0)}{Style.RESET_ALL}"
            for s in Severity
        ),
        "",
        f"{Style.BRIGHT}6 Pilares DevSecOps:{Style.RESET_ALL}",
    ]

    for pillar in Pillar:
        cnt = result.counts_by_pillar.get(pillar.value, 0)
        status = f"{Fore.GREEN}OK{Style.RESET_ALL}" if cnt == 0 else f"{Fore.YELLOW}{cnt} alerta(s){Style.RESET_ALL}"
        lines.append(f"  - {pillar.value:<34} : {status}")

    lines.append("")
    if not result.findings:
        lines.append(f"{Fore.GREEN}{Style.BRIGHT}Nenhuma vulnerabilidade ou falha de configuração detectada.{Style.RESET_ALL}")
        return "\n".join(lines) + "\n"

    lines.append(f"{Style.BRIGHT}Achados Detalhados ({len(result.findings)}):{Style.RESET_ALL}")
    lines.append("-" * 70)
    for idx, finding in enumerate(result.findings, start=1):
        sev_c = _COLORAMA_SEV[finding.severity]
        lines.extend(
            [
                f"{idx}. [{sev_c}{finding.severity.value}{Style.RESET_ALL}] "
                f"{Fore.YELLOW}{finding.rule_id}{Style.RESET_ALL} — {finding.title}",
                f"   Local      : {finding.file_path}:{finding.line}",
                f"   Pilar      : {finding.pillar.value}",
                f"   Referência : {finding.owasp} | {finding.mitre_attack} | {finding.cwe}",
                f"   Trecho     : {finding.snippet}",
                f"   Correção   : {finding.remediation}",
                "",
            ]
        )
    return "\n".join(lines)
