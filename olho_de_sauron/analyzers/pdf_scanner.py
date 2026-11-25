"""Analisador estrutural de segurança de arquivos PDF (estilo pdfid + auditoria de URIs)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from olho_de_sauron.analyzers.link_scanner import LinkSecurityAnalyzer

MAX_PDF_BYTES = 15 * 1024 * 1024  # 15 MB

_PDF_HEADER_RE = re.compile(rb"%PDF-(\d+\.\d+)")
_HEX_NAME_RE = re.compile(rb"/([A-Za-z0-9_]*#[0-9A-Fa-f]{2}[A-Za-z0-9_#]*)")
_HEX_BYTE_RE = re.compile(rb"#([0-9A-Fa-f]{2})")
_URI_ACTION_RE = re.compile(rb"/URI\s*\(([^)]{4,500})\)")
_HTTP_URL_RE = re.compile(rb"https?://[^\s()<>\[\]\"'\\]{4,300}", re.IGNORECASE)

_INDICATOR_KEYWORDS: tuple[str, ...] = (
    "/JS",
    "/JavaScript",
    "/AA",
    "/OpenAction",
    "/Launch",
    "/EmbeddedFile",
    "/Filespec",
    "/XFA",
    "/SubmitForm",
    "/GoToR",
    "/RichMedia",
    "/URI",
    "/ObjStm",
    "/JBIG2Decode",
)

_METADATA_KEYS: tuple[str, ...] = (
    "Title",
    "Author",
    "Creator",
    "Producer",
    "CreationDate",
    "ModDate",
)

_SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 8,
    "INFO": 0,
}


def _decode_pdf_hex_names(raw: bytes) -> tuple[bytes, int]:
    """Decodifica nomes PDF ofuscados com `#xx` (ex.: `/J#61vaScript` -> `/JavaScript`)."""
    obfuscated_count = 0

    def _replace_token(match: re.Match[bytes]) -> bytes:
        nonlocal obfuscated_count
        obfuscated_count += 1
        token = match.group(0)
        return _HEX_BYTE_RE.sub(lambda m: bytes.fromhex(m.group(1).decode("ascii")), token)

    decoded = _HEX_NAME_RE.sub(_replace_token, raw)
    return decoded, obfuscated_count


def _extract_metadata(raw: bytes) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for key in _METADATA_KEYS:
        pattern = re.compile(rb"/" + key.encode("ascii") + rb"\s*\(([^()]{1,200})\)")
        match = pattern.search(raw)
        if match:
            val = match.group(1).decode("latin-1", errors="replace")
            cleaned = "".join(ch for ch in val if ch.isprintable()).strip()
            if cleaned:
                metadata[key] = cleaned
    return metadata


class PdfSecurityAnalyzer:
    """Inspeciona estrutura, scripts embutidos, ações automáticas e links dentro de PDFs."""

    def __init__(self) -> None:
        self._link_analyzer = LinkSecurityAnalyzer()

    def analyze_bytes(self, data: bytes, filename: str = "documento.pdf") -> dict[str, Any]:
        if not data:
            raise ValueError("Arquivo PDF vazio.")
        if len(data) > MAX_PDF_BYTES:
            raise ValueError("Arquivo excede o limite de 15 MB para análise.")

        sha256 = hashlib.sha256(data).hexdigest()
        header_match = _PDF_HEADER_RE.search(data[:1024])
        valid_header = header_match is not None
        pdf_version = header_match.group(1).decode("ascii", errors="ignore") if header_match else None

        decoded_bytes, hex_obfuscation_count = _decode_pdf_hex_names(data)
        text = decoded_bytes.decode("latin-1", errors="replace")

        indicators: dict[str, int] = {}
        for kw in _INDICATOR_KEYWORDS:
            # Word boundary evita confundir /JS com /JavaScript ou /JSON
            pat = re.compile(re.escape(kw) + r"(?![A-Za-z0-9_])")
            indicators[kw] = len(pat.findall(text))

        page_count = len(re.findall(r"/Type\s*/Page(?![A-Za-z])", text))
        object_count = len(re.findall(r"\b\d+\s+\d+\s+obj\b", text))
        stream_count = len(re.findall(r"\bstream\b", text))
        eof_count = len(re.findall(r"%%EOF", text))
        metadata = _extract_metadata(data)

        # Extração e auditoria automática de URLs
        raw_urls: list[str] = []
        for m in _URI_ACTION_RE.findall(decoded_bytes):
            raw_urls.append(m.decode("latin-1", errors="ignore").strip())
        for m in _HTTP_URL_RE.findall(decoded_bytes):
            raw_urls.append(m.decode("latin-1", errors="ignore").strip())

        seen_urls: set[str] = set()
        unique_urls: list[str] = []
        for u in raw_urls:
            if u and u not in seen_urls:
                seen_urls.add(u)
                unique_urls.append(u)
                if len(unique_urls) >= 50:
                    break

        audited_urls = [self._link_analyzer.analyze_url(u, check_live=False) for u in unique_urls]

        findings: list[dict[str, str]] = []

        if not valid_header:
            findings.append(
                {
                    "rule_id": "PDF-HEADER-008",
                    "severity": "HIGH",
                    "title": "Cabeçalho mágico '%PDF-' ausente no início do arquivo",
                    "description": "O arquivo não possui assinatura PDF válida nos primeiros bytes; pode ser arquivo mascarado ou corrompido.",
                    "mitre_attack": "T1036 - Masquerading",
                    "remediation": "Não abra o arquivo como PDF confiável e valide o tipo real do arquivo.",
                }
            )

        js_hits = indicators["/JS"] + indicators["/JavaScript"]
        if js_hits > 0:
            findings.append(
                {
                    "rule_id": "PDF-JS-001",
                    "severity": "CRITICAL",
                    "title": f"Código JavaScript embutido detectado ({js_hits} ocorrência(s))",
                    "description": "Objetos `/JS` ou `/JavaScript` em PDFs permitem executar scripts no leitor, vetor comum para exploração e phishing.",
                    "mitre_attack": "T1204.002 - Malicious File",
                    "remediation": "Abra o documento apenas em visualizador isolado (sandbox) sem suporte a JavaScript.",
                }
            )

        auto_hits = indicators["/OpenAction"] + indicators["/AA"]
        if auto_hits > 0:
            findings.append(
                {
                    "rule_id": "PDF-AUTO-002",
                    "severity": "CRITICAL",
                    "title": f"Ação automática na abertura detectada ({auto_hits} ocorrência(s))",
                    "description": "Tags `/OpenAction` ou `/AA` disparam ações automaticamente assim que o PDF é aberto.",
                    "mitre_attack": "T1204.002 - Malicious File",
                    "remediation": "Desative ações automáticas no leitor de PDF e inspecione o conteúdo antes de confiar.",
                }
            )

        if indicators["/Launch"] > 0:
            findings.append(
                {
                    "rule_id": "PDF-LAUNCH-003",
                    "severity": "CRITICAL",
                    "title": f"Ação '/Launch' para executar programas externos ({indicators['/Launch']}x)",
                    "description": "A tag `/Launch` tenta iniciar executáveis ou comandos do sistema operacional a partir do PDF.",
                    "mitre_attack": "T1204.002 - Malicious File",
                    "remediation": "Bloqueie este PDF imediatamente; documentos comuns não devem solicitar execução de programas.",
                }
            )

        embed_hits = indicators["/EmbeddedFile"] + indicators["/Filespec"]
        if embed_hits > 0:
            findings.append(
                {
                    "rule_id": "PDF-EMBED-004",
                    "severity": "HIGH",
                    "title": f"Arquivo ou anexo embutido dentro do PDF ({embed_hits} referência(s))",
                    "description": "PDFs podem carregar payloads ou executáveis ocultos dentro de streams `/EmbeddedFile`.",
                    "mitre_attack": "T1027.009 - Embedded Payloads",
                    "remediation": "Nunca extraia ou execute anexos embutidos sem validação prévia em sandbox.",
                }
            )

        form_hits = indicators["/XFA"] + indicators["/SubmitForm"] + indicators["/GoToR"]
        if form_hits > 0:
            findings.append(
                {
                    "rule_id": "PDF-FORM-005",
                    "severity": "HIGH",
                    "title": f"Formulário dinâmico XFA/SubmitForm ou referência externa ({form_hits}x)",
                    "description": "`/XFA`, `/SubmitForm` ou `/GoToR` podem enviar dados para servidores externos ou abusar de parsers XML.",
                    "mitre_attack": "T1566.001 - Spearphishing Attachment",
                    "remediation": "Evite preencher formulários dentro do PDF ou enviar dados sem validar o destino.",
                }
            )

        if hex_obfuscation_count > 0 or indicators["/RichMedia"] > 0 or indicators["/JBIG2Decode"] > 0:
            findings.append(
                {
                    "rule_id": "PDF-OBFUSC-007",
                    "severity": "HIGH",
                    "title": "Técnica de ofuscação ou mídia de risco detectada no PDF",
                    "description": (
                        f"Nomes hex-ofuscados (`#xx`): {hex_obfuscation_count}; "
                        f"`/RichMedia`: {indicators['/RichMedia']}; `/JBIG2Decode`: {indicators['/JBIG2Decode']}."
                    ),
                    "mitre_attack": "T1027 - Obfuscated Files or Information",
                    "remediation": "Trate o arquivo como suspeito de tentativa de evasão de antivírus/scanners.",
                }
            )

        if audited_urls:
            dangerous_urls = [u for u in audited_urls if u["verdict"] == "PERIGOSO"]
            suspicious_urls = [u for u in audited_urls if u["verdict"] == "SUSPEITO"]
            if dangerous_urls:
                findings.append(
                    {
                        "rule_id": "PDF-URI-006",
                        "severity": "HIGH",
                        "title": f"{len(dangerous_urls)} link(s) perigoso(s) encontrado(s) dentro do PDF",
                        "description": f"Exemplo: {dangerous_urls[0]['url']}",
                        "mitre_attack": "T1566.002 - Spearphishing Link",
                        "remediation": "Não clique nos links do PDF; consulte a lista de URLs auditadas abaixo.",
                    }
                )
            elif suspicious_urls:
                findings.append(
                    {
                        "rule_id": "PDF-URI-006",
                        "severity": "MEDIUM",
                        "title": f"{len(suspicious_urls)} link(s) suspeito(s) encontrado(s) dentro do PDF",
                        "description": f"Exemplo: {suspicious_urls[0]['url']}",
                        "mitre_attack": "T1566.002 - Spearphishing Link",
                        "remediation": "Verifique os domínios de destino antes de abrir qualquer link.",
                    }
                )
            else:
                findings.append(
                    {
                        "rule_id": "PDF-URI-006",
                        "severity": "INFO",
                        "title": f"{len(audited_urls)} link(s) externo(s) identificado(s) no PDF",
                        "description": "Todos os links extraídos passaram na triagem heurística estática.",
                        "mitre_attack": "T1566.002 - Spearphishing Link",
                        "remediation": "Mesmo com triagem limpa, confirme o remetente do documento.",
                    }
                )

        risk_score = min(100, sum(_SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings))
        if risk_score >= 50 or any(f["severity"] == "CRITICAL" for f in findings):
            verdict = "PERIGOSO"
        elif risk_score >= 15 or any(f["severity"] in {"HIGH", "MEDIUM"} for f in findings):
            verdict = "SUSPEITO"
        else:
            verdict = "SEGURO"

        return {
            "filename": filename,
            "size_bytes": len(data),
            "sha256": sha256,
            "valid_pdf_header": valid_header,
            "pdf_version": pdf_version,
            "page_count": page_count,
            "object_count": object_count,
            "stream_count": stream_count,
            "eof_count": eof_count,
            "hex_obfuscated_names": hex_obfuscation_count,
            "metadata": metadata,
            "indicators": indicators,
            "extracted_urls": audited_urls,
            "findings": findings,
            "risk_score": risk_score,
            "verdict": verdict,
        }
