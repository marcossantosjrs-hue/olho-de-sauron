"""Interface base e utilitários comuns para scanners."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path

from olho_de_sauron.models import Finding

_IGNORE_RE = re.compile(
    r"(?:#|//)\s*sauron:\s*ignore(?:\[([A-Za-z0-9_,\-\s]+)\])?",
    re.IGNORECASE,
)


def is_line_suppressed(lines: list[str], line_no: int, rule_id: str) -> bool:
    """Verifica se a linha possui supressão inline (`# sauron: ignore` ou `[RULE-ID]`)."""
    if line_no < 1 or line_no > len(lines):
        return False

    line = lines[line_no - 1]
    match = _IGNORE_RE.search(line)
    if not match:
        return False

    rules_group = match.group(1)
    if not rules_group:
        return True

    allowed = {item.strip().upper() for item in rules_group.split(",") if item.strip()}
    return rule_id.upper() in allowed


def get_line_snippet(lines: list[str], line_no: int) -> str:
    """Extrai o texto da linha (1-based) de forma segura."""
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""


class BaseScanner(ABC):
    """Contrato base para todos os motores de análise do Olho de Sauron."""

    name: str = "base"

    @abstractmethod
    def supports(self, path: Path) -> bool:
        """Indica se este scanner analisa o arquivo informado."""

    @abstractmethod
    def scan_file(self, path: Path, rel_path: str, content: str) -> list[Finding]:
        """Executa a análise no conteúdo do arquivo e retorna os achados."""
