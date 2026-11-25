"""Formatadores de relatório do Olho de Sauron."""

from olho_de_sauron.reporters.html_reporter import render_html
from olho_de_sauron.reporters.json_reporter import render_json
from olho_de_sauron.reporters.markdown_reporter import render_markdown
from olho_de_sauron.reporters.sarif_reporter import render_sarif
from olho_de_sauron.reporters.terminal import render_terminal

__all__ = [
    "render_terminal",
    "render_json",
    "render_markdown",
    "render_sarif",
    "render_html",
]
