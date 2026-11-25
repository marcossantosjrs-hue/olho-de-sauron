"""Relatório SARIF v2.1.0 compatível com a aba Security do GitHub."""

from __future__ import annotations

import json
from typing import Any

from olho_de_sauron import APP_NAME, __version__
from olho_de_sauron.models import ScanResult
from olho_de_sauron.rules_catalog import RULES_CATALOG


def render_sarif(result: ScanResult) -> str:
    """Gera saída JSON estritamente conforme o esquema SARIF v2.1.0."""
    used_rule_ids = sorted({finding.rule_id for finding in result.findings})
    rules_payload: list[dict[str, Any]] = []

    for rule_id in used_rule_ids:
        meta = RULES_CATALOG[rule_id]
        rules_payload.append(
            {
                "id": meta.rule_id,
                "name": meta.rule_id,
                "shortDescription": {"text": meta.title},
                "fullDescription": {"text": meta.description},
                "help": {
                    "text": meta.remediation,
                    "markdown": (
                        f"**Pilar:** {meta.pillar.value}\n\n"
                        f"**OWASP:** {meta.owasp} | **MITRE ATT&CK:** {meta.mitre_attack} | **{meta.cwe}**\n\n"
                        f"**Remediação:** {meta.remediation}"
                    ),
                },
                "defaultConfiguration": {"level": meta.severity.sarif_level},
                "properties": {
                    "tags": ["security", meta.cwe, meta.owasp.split(" ")[0]],
                    "precision": "high",
                    "severity": meta.severity.value,
                },
            }
        )

    results_payload: list[dict[str, Any]] = []
    for finding in result.findings:
        uri = finding.file_path.replace("\\", "/").lstrip("./") or finding.file_path
        results_payload.append(
            {
                "ruleId": finding.rule_id,
                "level": finding.severity.sarif_level,
                "message": {
                    "text": (
                        f"[{finding.severity.value}] {finding.title}. "
                        f"{finding.description} Correção: {finding.remediation}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, finding.line),
                                "startColumn": max(1, finding.column),
                            },
                        }
                    }
                ],
                "properties": {
                    "pillar": finding.pillar.value,
                    "owasp": finding.owasp,
                    "mitre_attack": finding.mitre_attack,
                    "cwe": finding.cwe,
                    "scanner": finding.scanner,
                },
            }
        )

    sarif_doc: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": APP_NAME,
                        "version": __version__,
                        "informationUri": "https://github.com/marcossantosjrs-hue/olho-de-sauron",
                        "rules": rules_payload,
                    }
                },
                "results": results_payload,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2, ensure_ascii=False)
