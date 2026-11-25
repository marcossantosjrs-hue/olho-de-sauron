"""Relatório JSON estruturado."""

from __future__ import annotations

import json

from olho_de_sauron.models import ScanResult


def render_json(result: ScanResult) -> str:
    """Renderiza o resultado da varredura em JSON UTF-8 indentado."""
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
