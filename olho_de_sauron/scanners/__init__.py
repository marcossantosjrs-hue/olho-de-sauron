"""Scanners especializados do Olho de Sauron."""

from olho_de_sauron.scanners.base import BaseScanner
from olho_de_sauron.scanners.configs import ConfigHardeningScanner
from olho_de_sauron.scanners.dependencies import DependencyScanner
from olho_de_sauron.scanners.python_ast import PythonAstScanner
from olho_de_sauron.scanners.secrets import SecretsScanner

__all__ = [
    "BaseScanner",
    "PythonAstScanner",
    "SecretsScanner",
    "ConfigHardeningScanner",
    "DependencyScanner",
    "default_scanners",
]


def default_scanners() -> list[BaseScanner]:
    """Retorna a lista padrão de scanners ativos no motor."""
    return [
        PythonAstScanner(),
        SecretsScanner(),
        ConfigHardeningScanner(),
        DependencyScanner(),
    ]
