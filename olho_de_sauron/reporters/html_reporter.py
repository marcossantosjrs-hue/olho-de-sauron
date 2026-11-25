"""Relatório HTML5 autocontido com tema escuro e filtros interativos."""

from __future__ import annotations

import html
import json

from olho_de_sauron import __version__
from olho_de_sauron.models import Pillar, ScanResult, Severity, Verdict

_VERDICT_META = {
    Verdict.APROVADO: ("APROVADO", "verdict-pass"),
    Verdict.AJUSTES_RECOMENDADOS: ("AJUSTES RECOMENDADOS", "verdict-warn"),
    Verdict.BLOQUEADO: ("BLOQUEADO", "verdict-fail"),
}


def render_html(result: ScanResult) -> str:
    """Gera dashboard HTML5 interativo sem dependências externas."""
    verdict_label, verdict_cls = _VERDICT_META[result.verdict]
    esc = html.escape

    sev_cards_html: list[str] = []
    for sev in Severity:
        count = result.counts_by_severity.get(sev.value, 0)
        sev_cards_html.append(
            f'<button class="kpi-card sev-{sev.value.lower()}" data-sev="{esc(sev.value)}" '
            f'type="button" onclick="toggleSeverity(\'{esc(sev.value)}\')">'
            f'<span class="kpi-label">{esc(sev.value)}</span>'
            f'<span class="kpi-value">{count}</span>'
            f"</button>"
        )

    max_pillar = max([1, *result.counts_by_pillar.values()])
    pillar_bars_html: list[str] = []
    for pillar in Pillar:
        count = result.counts_by_pillar.get(pillar.value, 0)
        pct = int((count / max_pillar) * 100) if count > 0 else 0
        state_cls = "pillar-ok" if count == 0 else "pillar-alert"
        pillar_bars_html.append(
            f'<button class="pillar-row {state_cls}" type="button" '
            f'data-pillar="{esc(pillar.value)}" onclick="togglePillar(this.dataset.pillar)">'
            f'<span class="pillar-name">{esc(pillar.value)}</span>'
            f'<span class="pillar-track"><span class="pillar-fill" style="width:{pct}%"></span></span>'
            f'<span class="pillar-count">{count}</span>'
            f"</button>"
        )

    findings_cards_html: list[str] = []
    for finding in result.findings:
        sev_lower = finding.severity.value.lower()
        cid_text = ", ".join(finding.cid_impact)
        search_blob = (
            f"{finding.rule_id} {finding.title} {finding.file_path} "
            f"{finding.owasp} {finding.mitre_attack} {finding.cwe} {finding.pillar.value}"
        ).lower()
        findings_cards_html.append(
            f"""
            <details class="finding-card sev-border-{sev_lower}"
                     data-sev="{esc(finding.severity.value)}"
                     data-pillar="{esc(finding.pillar.value)}"
                     data-search="{esc(search_blob)}">
              <summary class="finding-summary">
                <span class="badge badge-{sev_lower}">{esc(finding.severity.value)}</span>
                <span class="rule-id">{esc(finding.rule_id)}</span>
                <span class="finding-title">{esc(finding.title)}</span>
                <code class="finding-loc">{esc(finding.file_path)}:{finding.line}</code>
              </summary>
              <div class="finding-body">
                <div class="meta-row">
                  <span class="pill">Pilar: {esc(finding.pillar.value)}</span>
                  <span class="pill">{esc(finding.owasp)}</span>
                  <span class="pill">MITRE: {esc(finding.mitre_attack)}</span>
                  <span class="pill">{esc(finding.cwe)}</span>
                  <span class="pill">CID: {esc(cid_text)}</span>
                  <span class="pill">Motor: {esc(finding.scanner)}</span>
                </div>
                <p><strong>Descrição:</strong> {esc(finding.description)}</p>
                <p><strong>Remediação:</strong> {esc(finding.remediation)}</p>
                <pre class="snippet"><code>{esc(finding.snippet or "(sem trecho)")}</code></pre>
              </div>
            </details>
            """
        )

    if not findings_cards_html:
        findings_section = (
            '<div class="empty-state">'
            "<h3>Nenhuma vulnerabilidade detectada</h3>"
            "<p>Todos os arquivos analisados passaram nas verificações ativas do Olho de Sauron.</p>"
            "</div>"
        )
    else:
        findings_section = "\n".join(findings_cards_html)

    # Dados serializados com escape seguro contra fechamento de tag script
    safe_meta_json = json.dumps(
        {
            "target": result.target,
            "verdict": verdict_label,
            "score": result.score,
            "grade": result.grade,
        },
        ensure_ascii=False,
    ).replace("</", "<\\/")

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Olho de Sauron — Relatório DevSecOps</title>
  <style>
    :root {{
      --bg: #0b0d12;
      --surface: #141821;
      --surface-2: #1c2230;
      --border: #2a3245;
      --text: #e6ebf5;
      --muted: #9aa6be;
      --amber: #f59e0b;
      --crimson: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #38bdf8;
      --info: #94a3b8;
      --ok: #22c55e;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: radial-gradient(circle at top right, #1f1614 0%, var(--bg) 45%);
      color: var(--text);
      line-height: 1.5;
    }}
    .container {{ max-width: 1180px; margin: 0 auto; padding: 28px 20px 60px; }}
    header.hero {{
      display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
      gap: 20px; background: var(--surface); border: 1px solid var(--border);
      border-radius: 14px; padding: 22px 26px; box-shadow: 0 12px 32px rgba(0,0,0,.35);
    }}
    .brand h1 {{ margin: 0 0 6px; font-size: 1.6rem; color: var(--amber); letter-spacing: .3px; }}
    .brand p {{ margin: 0; color: var(--muted); font-size: .92rem; }}
    .score-box {{ display: flex; align-items: center; gap: 18px; }}
    .grade-circle {{
      width: 68px; height: 68px; border-radius: 50%; display: grid; place-items: center;
      font-size: 1.6rem; font-weight: 800; border: 3px solid var(--amber); background: var(--surface-2);
    }}
    .verdict-pill {{
      display: inline-block; padding: 6px 14px; border-radius: 999px;
      font-weight: 700; font-size: .85rem; letter-spacing: .5px;
    }}
    .verdict-pass {{ background: rgba(34,197,94,.18); color: #4ade80; border: 1px solid rgba(34,197,94,.45); }}
    .verdict-warn {{ background: rgba(234,179,8,.18); color: #facc15; border: 1px solid rgba(234,179,8,.45); }}
    .verdict-fail {{ background: rgba(239,68,68,.2); color: #f87171; border: 1px solid rgba(239,68,68,.5); }}
    .kpi-grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px; margin: 22px 0;
    }}
    .kpi-card {{
      background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
      padding: 14px 16px; text-align: left; color: var(--text); cursor: pointer;
      display: flex; justify-content: space-between; align-items: center; transition: transform .12s, border-color .12s;
    }}
    .kpi-card:hover {{ transform: translateY(-2px); border-color: var(--amber); }}
    .kpi-card.active {{ outline: 2px solid var(--amber); }}
    .kpi-label {{ font-size: .78rem; font-weight: 700; color: var(--muted); }}
    .kpi-value {{ font-size: 1.5rem; font-weight: 800; }}
    .sev-critical .kpi-value {{ color: var(--crimson); }}
    .sev-high .kpi-value {{ color: var(--high); }}
    .sev-medium .kpi-value {{ color: var(--medium); }}
    .sev-low .kpi-value {{ color: var(--low); }}
    .sev-info .kpi-value {{ color: var(--info); }}
    .panel {{
      background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
      padding: 18px 22px; margin-bottom: 22px;
    }}
    .panel h2 {{ margin: 0 0 14px; font-size: 1.05rem; color: var(--amber); }}
    .pillar-list {{ display: grid; gap: 10px; }}
    .pillar-row {{
      width: 100%; display: grid; grid-template-columns: 240px 1fr 48px; align-items: center;
      gap: 12px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px;
      padding: 8px 12px; color: var(--text); cursor: pointer; text-align: left;
    }}
    .pillar-row.active {{ outline: 2px solid var(--amber); }}
    .pillar-name {{ font-size: .88rem; font-weight: 600; }}
    .pillar-track {{ height: 8px; background: #0d1017; border-radius: 999px; overflow: hidden; }}
    .pillar-fill {{ display: block; height: 100%; background: linear-gradient(90deg, var(--amber), var(--crimson)); }}
    .pillar-ok .pillar-count {{ color: var(--ok); font-weight: 700; text-align: right; }}
    .pillar-alert .pillar-count {{ color: var(--amber); font-weight: 700; text-align: right; }}
    .toolbar {{
      display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 16px;
    }}
    .toolbar input {{
      flex: 1; min-width: 240px; padding: 10px 14px; border-radius: 8px;
      border: 1px solid var(--border); background: var(--surface-2); color: var(--text);
    }}
    .toolbar button {{
      padding: 10px 14px; border-radius: 8px; border: 1px solid var(--border);
      background: var(--surface-2); color: var(--text); cursor: pointer;
    }}
    .toolbar button:hover {{ border-color: var(--amber); }}
    .finding-card {{
      background: var(--surface); border: 1px solid var(--border); border-left-width: 4px;
      border-radius: 10px; margin-bottom: 12px; overflow: hidden;
    }}
    .sev-border-critical {{ border-left-color: var(--crimson); }}
    .sev-border-high {{ border-left-color: var(--high); }}
    .sev-border-medium {{ border-left-color: var(--medium); }}
    .sev-border-low {{ border-left-color: var(--low); }}
    .sev-border-info {{ border-left-color: var(--info); }}
    .finding-summary {{
      display: flex; flex-wrap: wrap; align-items: center; gap: 10px;
      padding: 13px 16px; cursor: pointer; list-style: none;
    }}
    .badge {{
      padding: 2px 9px; border-radius: 6px; font-size: .74rem; font-weight: 800; color: #0b0d12;
    }}
    .badge-critical {{ background: var(--crimson); color: #fff; }}
    .badge-high {{ background: var(--high); }}
    .badge-medium {{ background: var(--medium); }}
    .badge-low {{ background: var(--low); }}
    .badge-info {{ background: var(--info); }}
    .rule-id {{ font-family: ui-monospace, monospace; font-size: .85rem; color: var(--amber); font-weight: 700; }}
    .finding-title {{ font-weight: 600; flex: 1; min-width: 220px; }}
    .finding-loc {{ color: var(--muted); font-size: .84rem; }}
    .finding-body {{ padding: 0 16px 16px; border-top: 1px solid var(--border); }}
    .meta-row {{ display: flex; flex-wrap: wrap; gap: 6px; margin: 12px 0; }}
    .pill {{
      background: var(--surface-2); border: 1px solid var(--border); border-radius: 999px;
      padding: 3px 10px; font-size: .78rem; color: var(--muted);
    }}
    pre.snippet {{
      margin: 10px 0 0; padding: 12px; border-radius: 8px;
      background: #07090d; border: 1px solid var(--border); overflow-x: auto; color: #e2e8f0;
    }}
    .empty-state {{
      text-align: center; padding: 36px 20px; border: 1px dashed var(--ok);
      border-radius: 12px; color: #86efac;
    }}
    footer {{ text-align: center; color: var(--muted); font-size: .82rem; margin-top: 28px; }}
    @media (max-width: 700px) {{
      .pillar-row {{ grid-template-columns: 1fr 48px; }}
      .pillar-track {{ display: none; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header class="hero">
      <div class="brand">
        <h1>Olho de Sauron — Relatório DevSecOps</h1>
        <p>Alvo: <code>{esc(result.target)}</code> • Arquivos: <strong>{result.files_scanned}</strong> • Duração: <strong>{result.duration_seconds:.2f}s</strong> • {esc(result.started_at)}</p>
      </div>
      <div class="score-box">
        <div class="grade-circle" title="Nota de segurança">{esc(result.grade)}</div>
        <div>
          <div class="verdict-pill {verdict_cls}">{esc(verdict_label)}</div>
          <div style="margin-top:6px;font-size:.9rem;color:var(--muted);">Pontuação: <strong style="color:var(--text);">{result.score}/100</strong></div>
        </div>
      </div>
    </header>

    <section class="kpi-grid">
      {"".join(sev_cards_html)}
    </section>

    <section class="panel">
      <h2>Cobertura dos 6 Pilares DevSecOps</h2>
      <div class="pillar-list">
        {"".join(pillar_bars_html)}
      </div>
    </section>

    <section class="panel">
      <h2>Achados de Segurança ({len(result.findings)})</h2>
      <div class="toolbar">
        <input id="searchInput" type="search" placeholder="Filtrar por regra, arquivo, OWASP, MITRE ATT&amp;CK ou CWE..." oninput="applyFilters()">
        <button type="button" onclick="resetFilters()">Limpar filtros</button>
      </div>
      <div id="findingsContainer">
        {findings_section}
      </div>
    </section>

    <footer>Gerado por Olho de Sauron v{esc(__version__)} • Uso exclusivamente defensivo e educacional.</footer>
  </div>

  <script>
    const REPORT_META = {safe_meta_json};
    let activeSeverity = null;
    let activePillar = null;

    function toggleSeverity(sev) {{
      activeSeverity = activeSeverity === sev ? null : sev;
      document.querySelectorAll(".kpi-card").forEach(el => {{
        el.classList.toggle("active", el.dataset.sev === activeSeverity);
      }});
      applyFilters();
    }}

    function togglePillar(pillar) {{
      activePillar = activePillar === pillar ? null : pillar;
      document.querySelectorAll(".pillar-row").forEach(el => {{
        el.classList.toggle("active", el.dataset.pillar === activePillar);
      }});
      applyFilters();
    }}

    function resetFilters() {{
      activeSeverity = null;
      activePillar = null;
      document.getElementById("searchInput").value = "";
      document.querySelectorAll(".kpi-card, .pillar-row").forEach(el => el.classList.remove("active"));
      applyFilters();
    }}

    function applyFilters() {{
      const q = document.getElementById("searchInput").value.trim().toLowerCase();
      document.querySelectorAll(".finding-card").forEach(card => {{
        const matchSev = !activeSeverity || card.dataset.sev === activeSeverity;
        const matchPillar = !activePillar || card.dataset.pillar === activePillar;
        const matchText = !q || card.dataset.search.includes(q);
        card.style.display = (matchSev && matchPillar && matchText) ? "block" : "none";
      }});
    }}
  </script>
</body>
</html>
"""
