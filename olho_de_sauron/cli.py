"""Interface de linha de comando (CLI) do Olho de Sauron."""

from __future__ import annotations

import json
import sys
import threading
import webbrowser
from pathlib import Path

import click

from olho_de_sauron import APP_NAME, APP_TAGLINE, __version__
from olho_de_sauron.analyzers import LinkSecurityAnalyzer, PdfSecurityAnalyzer
from olho_de_sauron.engine import ScanEngine, should_fail
from olho_de_sauron.models import Pillar, Severity
from olho_de_sauron.reporters import (
    render_html,
    render_json,
    render_markdown,
    render_sarif,
    render_terminal,
)
from olho_de_sauron.reporters.terminal import render_rules_terminal
from olho_de_sauron.rules_catalog import RULES_CATALOG

_DEFAULT_IGNORE_CONTENT = """# Padrões ignorados por padrão pelo Olho de Sauron
.git/
__pycache__/
.venv/
venv/
env/
node_modules/
dist/
build/
*.egg-info/
.pytest_cache/
reports/
docs/prints/
*.png
*.jpg
*.jpeg
*.pdf
*.zip
"""


def _safe_echo(text: str) -> None:
    """Imprime texto no stdout sem risco de UnicodeEncodeError no Windows."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass
    try:
        click.echo(text, nl=False if text.endswith("\n") else True)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "ascii"
        safe = text.encode(enc, errors="replace").decode(enc, errors="replace")
        click.echo(safe, nl=False if safe.endswith("\n") else True)


def _write_report(path_str: str, content: str) -> Path:
    dest = Path(path_str)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    return dest


@click.group(help=f"{APP_NAME} — {APP_TAGLINE}")
def main() -> None:
    """Grupo raiz da CLI `sauron`."""


@main.command("scan", help="Executa varredura automatizada DevSecOps em arquivos ou diretórios.")
@click.argument("targets", nargs=-1, type=click.Path(exists=False))
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json", "markdown", "sarif", "html"], case_sensitive=False),
    default="terminal",
    show_default=True,
    help="Formato principal de saída.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False),
    default=None,
    help="Salva a saída do formato principal em arquivo.",
)
@click.option("--html", "html_path", type=click.Path(dir_okay=False), default=None, help="Salva dashboard HTML.")
@click.option("--sarif", "sarif_path", type=click.Path(dir_okay=False), default=None, help="Salva relatório SARIF v2.1.0.")
@click.option("--json-out", "json_path", type=click.Path(dir_okay=False), default=None, help="Salva relatório JSON.")
@click.option("--md-out", "md_path", type=click.Path(dir_okay=False), default=None, help="Salva relatório Markdown.")
@click.option(
    "--min-severity",
    type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False),
    default="info",
    show_default=True,
    help="Severidade mínima exibida nos resultados.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["none", "low", "medium", "high", "critical"], case_sensitive=False),
    default="high",
    show_default=True,
    help="Severidade mínima que faz o comando falhar com código de saída 2.",
)
@click.option(
    "--exclude",
    multiple=True,
    help="Padrão adicional de arquivo/pasta para ignorar (pode ser repetido).",
)
@click.option(
    "--git-diff",
    is_flag=True,
    default=False,
    help="Analisa apenas arquivos modificados/novos no Git local.",
)
@click.option(
    "--no-ignore",
    is_flag=True,
    default=False,
    help="Ignora o arquivo `.sauronignore` e filtros padrão.",
)
def scan_cmd(
    targets: tuple[str, ...],
    output_format: str,
    output: str | None,
    html_path: str | None,
    sarif_path: str | None,
    json_path: str | None,
    md_path: str | None,
    min_severity: str,
    fail_on: str,
    exclude: tuple[str, ...],
    git_diff: bool,
    no_ignore: bool,
) -> None:
    """Executa a varredura de segurança e gera relatórios configurados."""
    scan_targets = targets if targets else (".",)
    engine = ScanEngine()

    try:
        result = engine.scan(
            targets=scan_targets,
            min_severity=Severity.from_str(min_severity),
            excludes=exclude,
            git_diff=git_diff,
            use_ignore=not no_ignore,
        )
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    format_map = {
        "terminal": render_terminal,
        "json": render_json,
        "markdown": render_markdown,
        "sarif": render_sarif,
        "html": render_html,
    }
    primary_content = format_map[output_format.lower()](result)

    if output:
        _write_report(output, primary_content)
        if output_format.lower() == "terminal":
            _safe_echo(primary_content)
        else:
            _safe_echo(f"Relatório ({output_format.lower()}) salvo em: {output}\n")
    else:
        _safe_echo(primary_content)

    # Artefatos extras solicitados na mesma execução
    extra_outputs = [
        (html_path, render_html, "HTML"),
        (sarif_path, render_sarif, "SARIF"),
        (json_path, render_json, "JSON"),
        (md_path, render_markdown, "Markdown"),
    ]
    for path_opt, renderer, label in extra_outputs:
        if path_opt:
            _write_report(path_opt, renderer(result))
            _safe_echo(f"[{label}] Relatório salvo em: {path_opt}\n")

    if should_fail(result, fail_on):
        sys.exit(2)


@main.command("rules", help="Lista todas as regras defensivas catalogadas no Olho de Sauron.")
@click.option(
    "--severity",
    type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Filtra regras por severidade.",
)
@click.option(
    "--pillar",
    type=str,
    default=None,
    help="Filtra regras pelo nome (ou parte do nome) do pilar DevSecOps.",
)
def rules_cmd(severity: str | None, pillar: str | None) -> None:
    """Exibe catálogo de regras com mapeamento OWASP e MITRE ATT&CK."""
    rules = list(RULES_CATALOG.values())
    if severity:
        target_sev = Severity.from_str(severity)
        rules = [r for r in rules if r.severity == target_sev]
    if pillar:
        needle = pillar.strip().lower()
        valid_pillars = [p.value for p in Pillar]
        rules = [r for r in rules if needle in r.pillar.value.lower()]
        if not rules:
            _safe_echo(f"Nenhuma regra encontrada para o pilar '{pillar}'. Pilares: {', '.join(valid_pillars)}\n")
            return
    _safe_echo(render_rules_terminal(rules))


@main.command("init-ignore", help="Cria um arquivo `.sauronignore` padrão no diretório alvo.")
@click.argument("target", default=".", type=click.Path(file_okay=False))
@click.option("--force", is_flag=True, default=False, help="Sobrescreve se `.sauronignore` já existir.")
def init_ignore_cmd(target: str, force: bool) -> None:
    """Gera `.sauronignore` no diretório especificado."""
    target_dir = Path(target)
    target_dir.mkdir(parents=True, exist_ok=True)
    ignore_file = target_dir / ".sauronignore"
    if ignore_file.exists() and not force:
        raise click.ClickException(
            f"O arquivo '{ignore_file}' já existe. Use --force para sobrescrever."
        )
    ignore_file.write_text(_DEFAULT_IGNORE_CONTENT, encoding="utf-8")
    _safe_echo(f"Arquivo criado: {ignore_file}\n")


@main.command("version", help="Exibe a versão da ferramenta e quantidade de regras ativas.")
def version_cmd() -> None:
    """Mostra informações de versão do Olho de Sauron."""
    _safe_echo(
        f"{APP_NAME} v{__version__} — {len(RULES_CATALOG)} regras defensivas ativas (6 pilares DevSecOps)\n"
    )


@main.command("web", help="Inicia a interface Web SOC interativa (PDFs, Links, Processos, Rede e Código).")
@click.option("--host", default="127.0.0.1", show_default=True, help="Endereço local de escuta.")
@click.option("--port", default=8000, show_default=True, type=int, help="Porta HTTP local.")
@click.option("--no-browser", is_flag=True, default=False, help="Não abrir o navegador automaticamente.")
def web_cmd(host: str, port: int, no_browser: bool) -> None:
    """Inicia o servidor FastAPI/Uvicorn com o painel Web do Olho de Sauron."""
    import uvicorn

    from olho_de_sauron.web.app import app

    url = f"http://{host}:{port}"
    _safe_echo(f"{APP_NAME} Web SOC iniciando em {url}\n")
    _safe_echo("Pressione Ctrl+C para encerrar o servidor.\n")

    if not no_browser:
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()

    uvicorn.run(app, host=host, port=port, log_level="info")


@main.command("scan-pdf", help="Analisa um arquivo PDF em busca de scripts, ações automáticas e links suspeitos.")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json"], case_sensitive=False),
    default="terminal",
    show_default=True,
)
def scan_pdf_cmd(file_path: str, output_format: str) -> None:
    """Executa análise estrutural segura no PDF informado."""
    pdf_path = Path(file_path)
    analyzer = PdfSecurityAnalyzer()
    try:
        result = analyzer.analyze_bytes(pdf_path.read_bytes(), filename=pdf_path.name)
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    if output_format.lower() == "json":
        _safe_echo(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        return

    lines = [
        f"=== {APP_NAME} — Análise de PDF ===",
        f"Arquivo   : {result['filename']} ({result['size_bytes']} bytes)",
        f"SHA-256   : {result['sha256']}",
        f"Veredito  : {result['verdict']} (Risco: {result['risk_score']}/100)",
        f"Estrutura : PDF {result['pdf_version'] or 'N/A'} | Páginas: {result['page_count']} | Objetos: {result['object_count']}",
        f"Achados   : {len(result['findings'])} | URLs extraídas: {len(result['extracted_urls'])}",
        "",
    ]
    for idx, f in enumerate(result["findings"], start=1):
        lines.append(f"{idx}. [{f['severity']}] {f['rule_id']} — {f['title']}")
        lines.append(f"   {f['description']}")
    if not result["findings"]:
        lines.append("Nenhum indicador estrutural suspeito detectado.")
    _safe_echo("\n".join(lines) + "\n")


@main.command("scan-link", help="Analisa uma URL quanto a phishing, ofuscação e indicadores suspeitos.")
@click.argument("url")
@click.option("--live", is_flag=True, default=False, help="Verifica headers HTTP/TLS ao vivo (com anti-SSRF).")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json"], case_sensitive=False),
    default="terminal",
    show_default=True,
)
def scan_link_cmd(url: str, live: bool, output_format: str) -> None:
    """Analisa uma URL informada pelo usuário."""
    analyzer = LinkSecurityAnalyzer()
    try:
        result = analyzer.analyze_url(url, check_live=live)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    if output_format.lower() == "json":
        _safe_echo(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        return

    lines = [
        f"=== {APP_NAME} — Análise de Link ===",
        f"URL      : {result['url']}",
        f"Host     : {result['host'] or '-'}",
        f"Veredito : {result['verdict']} (Risco: {result['risk_score']}/100)",
        f"Achados  : {result['findings_count']}",
        "",
    ]
    for idx, f in enumerate(result["findings"], start=1):
        lines.append(f"{idx}. [{f['severity']}] {f['rule_id']} — {f['title']}")
        lines.append(f"   {f['description']}")
    if not result["findings"]:
        lines.append("Nenhum indicador de phishing ou risco detectado.")
    _safe_echo("\n".join(lines) + "\n")
