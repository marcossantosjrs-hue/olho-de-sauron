"""Modelos de dados centrais do scanner Olho de Sauron."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Níveis de severidade alinhados à matriz Impacto × Probabilidade."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        """Peso de penalização usado no cálculo da pontuação (0-100)."""
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 7,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        return weights[self]

    @property
    def rank(self) -> int:
        """Ordem numérica para ordenação e comparação de limiares."""
        ranks = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return ranks[self]

    @property
    def sarif_level(self) -> str:
        """Mapeia severidade para nível padrão do esquema SARIF v2.1.0."""
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self is Severity.MEDIUM:
            return "warning"
        return "note"

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        """Converte string case-insensitive para Severity."""
        normalized = value.strip().upper()
        try:
            return cls(normalized)
        except ValueError as exc:
            valid = ", ".join(s.value.lower() for s in cls)
            raise ValueError(f"Severidade inválida '{value}'. Use: {valid}.") from exc


class Pillar(str, Enum):
    """Os 6 pilares DevSecOps definidos em docs/devsecops-checklist.md."""

    SECRETS = "Segredos e Credenciais"
    INJECTION = "Entradas e Injeções"
    AUTH = "Autenticação e Controle de Acesso"
    CONFIG = "Configurações e Exposição"
    DEPENDENCIES = "Dependências"
    LOGGING = "Tratamento de Erros e Logs"


class Verdict(str, Enum):
    """Parecer de prontidão DevSecOps emitido ao final da varredura."""

    APROVADO = "APROVADO"
    AJUSTES_RECOMENDADOS = "AJUSTES_RECOMENDADOS"
    BLOQUEADO = "BLOQUEADO"


@dataclass(frozen=True)
class RuleMetadata:
    """Definição catalogada de uma regra de segurança defensiva."""

    rule_id: str
    title: str
    severity: Severity
    pillar: Pillar
    owasp: str
    mitre_attack: str
    cwe: str
    cid_impact: tuple[str, ...]
    description: str
    remediation: str


@dataclass
class Finding:
    """Ocorrência detectada por um dos motores de análise."""

    rule_id: str
    title: str
    severity: Severity
    pillar: Pillar
    file_path: str
    line: int
    column: int
    snippet: str
    description: str
    remediation: str
    owasp: str
    mitre_attack: str
    cwe: str
    cid_impact: list[str]
    scanner: str

    def to_dict(self) -> dict[str, Any]:
        """Serializa o achado em dicionário compatível com JSON."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "pillar": self.pillar.value,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "description": self.description,
            "remediation": self.remediation,
            "owasp": self.owasp,
            "mitre_attack": self.mitre_attack,
            "cwe": self.cwe,
            "cid_impact": list(self.cid_impact),
            "scanner": self.scanner,
        }


@dataclass
class ScanResult:
    """Resultado consolidado de uma execução do scanner."""

    target: str
    started_at: str
    duration_seconds: float
    files_scanned: int
    files_skipped: int
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    verdict: Verdict = Verdict.APROVADO
    counts_by_severity: dict[str, int] = field(default_factory=dict)
    counts_by_pillar: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serializa o resultado completo da varredura para JSON."""
        return {
            "target": self.target,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_seconds, 4),
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "score": self.score,
            "grade": self.grade,
            "verdict": self.verdict.value,
            "counts_by_severity": dict(self.counts_by_severity),
            "counts_by_pillar": dict(self.counts_by_pillar),
            "total_findings": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
        }
