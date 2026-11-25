"""Analisador heurístico de segurança de URLs e links com verificação ao vivo anti-SSRF."""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

_DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file"}

_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "is.gd",
    "rb.gy",
    "shorturl.at",
    "ow.ly",
    "goo.gl",
    "tiny.cc",
    "rebrand.ly",
}

_ABUSED_TLDS = {
    "xyz",
    "top",
    "click",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "zip",
    "mov",
    "buzz",
    "loan",
    "work",
    "support",
    "monster",
}

_EXECUTABLE_EXTENSIONS = (
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".scr",
    ".apk",
    ".iso",
    ".hta",
    ".lnk",
    ".jar",
)

_BRAND_OFFICIAL_DOMAINS: dict[str, tuple[str, ...]] = {
    "nubank": ("nubank.com.br", "nu.com.br"),
    "itau": ("itau.com.br",),
    "bradesco": ("bradesco.com.br", "banco.bradesco"),
    "santander": ("santander.com.br", "santander.com"),
    "caixa": ("caixa.gov.br",),
    "mercadolivre": ("mercadolivre.com.br", "mercadolibre.com"),
    "mercadopago": ("mercadopago.com.br", "mercadopago.com"),
    "correios": ("correios.com.br",),
    "paypal": ("paypal.com",),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com"),
    "google": ("google.com", "google.com.br", "accounts.google.com"),
    "apple": ("apple.com", "icloud.com"),
    "netflix": ("netflix.com",),
    "whatsapp": ("whatsapp.com",),
    "instagram": ("instagram.com",),
    "binance": ("binance.com",),
}

_SOCIAL_ENG_KEYWORDS = {
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "confirm",
    "wallet",
    "pix",
    "desbloqueio",
    "fatura",
    "premio",
    "urgente",
    "senha",
    "atualiza",
    "validacao",
}

_SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 8,
    "INFO": 0,
}

_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
)


def _is_ip_literal(host: str) -> bool:
    cleaned = host.strip("[]")
    if not cleaned:
        return False
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        pass
    # IP numérico decimal/hexadecimal (ex.: http://2130706433)
    if cleaned.isdigit() or re.fullmatch(r"0x[0-9a-fA-F]+", cleaned):
        return True
    return False


def _is_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str.strip("[]"))
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _matches_official_domain(host: str, allowed_domains: tuple[str, ...]) -> bool:
    for domain in allowed_domains:
        if host == domain or host.endswith(f".{domain}"):
            return True
    return False


class LinkSecurityAnalyzer:
    """Analisa links quanto a phishing, ofuscação, executáveis e proteção anti-SSRF."""

    def analyze_url(self, raw_url: str, check_live: bool = False) -> dict[str, Any]:
        url = raw_url.strip()
        if not url:
            raise ValueError("URL vazia informada para análise.")

        normalized = url
        if "://" not in url and not url.lower().startswith(("javascript:", "data:", "vbscript:", "file:")):
            normalized = f"https://{url}"

        parsed = urlparse(normalized)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
        path = parsed.path or "/"

        findings: list[dict[str, str]] = []

        # 1. Esquema perigoso
        if scheme in _DANGEROUS_SCHEMES:
            findings.append(
                {
                    "rule_id": "URL-SCHEME-001",
                    "severity": "CRITICAL",
                    "title": f"Esquema de URL potencialmente malicioso ({scheme}:)",
                    "description": "Esquemas `javascript:`, `data:`, `vbscript:` ou `file:` podem executar scripts ou acessar arquivos locais.",
                    "mitre_attack": "T1204.001 - Malicious Link",
                    "remediation": "Bloqueie este link imediatamente e aceite apenas URLs `https://` confiáveis.",
                }
            )

        # 2. Credencial/@ na autoridade
        if "@" in (parsed.netloc or ""):
            findings.append(
                {
                    "rule_id": "URL-AT-004",
                    "severity": "CRITICAL",
                    "title": "Presença de '@' na autoridade da URL (mascaramento de domínio)",
                    "description": "Navegadores ignoram o trecho antes do '@' como usuário, direcionando para o domínio real após o '@'.",
                    "mitre_attack": "T1566.002 - Spearphishing Link",
                    "remediation": "Desconfie de links com '@' antes do domínio e acesse o site oficial digitando o endereço.",
                }
            )

        # 3. IP literal no host
        if host and _is_ip_literal(host):
            findings.append(
                {
                    "rule_id": "URL-IP-003",
                    "severity": "HIGH",
                    "title": "URL aponta diretamente para endereço IP em vez de domínio",
                    "description": "Links legítimos de serviços raramente usam endereços IP diretos para login ou downloads.",
                    "mitre_attack": "T1071.001 - Web Protocols",
                    "remediation": "Verifique a legitimidade do host antes de abrir ou liberar em firewall.",
                }
            )

        # 4. Punycode / Homógrafo IDN
        if "xn--" in host or any(ord(ch) > 127 for ch in host):
            findings.append(
                {
                    "rule_id": "URL-PUNYCODE-005",
                    "severity": "HIGH",
                    "title": "Possível ataque homógrafo via Punycode/IDN",
                    "description": "Domínio usa prefixo `xn--` ou caracteres Unicode não-ASCII que imitam letras comuns.",
                    "mitre_attack": "T1036 - Masquerading",
                    "remediation": "Inspecione o domínio real em ASCII antes de confiar na página.",
                }
            )

        # 5. Impersonação de marca
        if host:
            host_and_path = f"{host}{path.lower()}"
            for brand, official_domains in _BRAND_OFFICIAL_DOMAINS.items():
                if brand in host_and_path and not _matches_official_domain(host, official_domains):
                    findings.append(
                        {
                            "rule_id": "URL-BRAND-008",
                            "severity": "HIGH",
                            "title": f"Possível impersonação da marca '{brand}' em domínio não oficial",
                            "description": f"O endereço cita '{brand}', mas o host '{host}' não pertence aos domínios oficiais ({', '.join(official_domains)}).",
                            "mitre_attack": "T1566.002 - Spearphishing Link",
                            "remediation": "Não insira credenciais nem dados pessoais; acesse o portal oficial diretamente.",
                        }
                    )
                    break

        # 6. Download direto de executável/script
        lower_path = path.lower()
        if any(lower_path.endswith(ext) for ext in _EXECUTABLE_EXTENSIONS):
            findings.append(
                {
                    "rule_id": "URL-EXT-011",
                    "severity": "HIGH",
                    "title": "Link aponta diretamente para arquivo executável ou script",
                    "description": f"O caminho '{path}' termina em extensão executável de alto risco.",
                    "mitre_attack": "T1204.002 - Malicious File",
                    "remediation": "Nunca execute arquivos baixados de links não verificados.",
                }
            )

        # 7. HTTP sem TLS
        if scheme == "http":
            findings.append(
                {
                    "rule_id": "URL-TLS-002",
                    "severity": "MEDIUM",
                    "title": "Link utiliza HTTP sem criptografia TLS",
                    "description": "Dados trafegam em texto claro e podem ser interceptados ou modificados em trânsito.",
                    "mitre_attack": "T1557 - Adversary-in-the-Middle",
                    "remediation": "Prefira conexões HTTPS com certificado válido.",
                }
            )

        # 8. Encurtador de URL
        if host in _SHORTENER_DOMAINS:
            findings.append(
                {
                    "rule_id": "URL-SHORTENER-006",
                    "severity": "MEDIUM",
                    "title": f"Uso de encurtador de URL ({host})",
                    "description": "Encurtadores ocultam o destino real do link, sendo comuns em campanhas de phishing.",
                    "mitre_attack": "T1566.002 - Spearphishing Link",
                    "remediation": "Expanda e valide o domínio de destino antes de abrir.",
                }
            )

        # 9. TLD frequentemente abusado
        if host and "." in host and not _is_ip_literal(host):
            tld = host.rsplit(".", 1)[-1]
            if tld in _ABUSED_TLDS:
                findings.append(
                    {
                        "rule_id": "URL-TLD-007",
                        "severity": "MEDIUM",
                        "title": f"TLD com alta incidência de abuso (.{tld})",
                        "description": f"O domínio utiliza o TLD '.{tld}', frequentemente associado a campanhas descartáveis.",
                        "mitre_attack": "T1583.001 - Domains",
                        "remediation": "Confirme a autenticidade da organização proprietária do domínio.",
                    }
                )

        # 10. Subdomínios excessivos / URL muito longa / hífens
        if host and not _is_ip_literal(host):
            labels = [lbl for lbl in host.split(".") if lbl]
            if len(labels) >= 4 or len(url) > 120 or host.count("-") >= 3:
                findings.append(
                    {
                        "rule_id": "URL-SUBDOMAIN-009",
                        "severity": "MEDIUM",
                        "title": "Estrutura anômala de subdomínios ou comprimento excessivo",
                        "description": "Múltiplos subdomínios, hífens em excesso ou URLs longas são usados para mascarar o domínio real.",
                        "mitre_attack": "T1036 - Masquerading",
                        "remediation": "Leia o domínio registrável imediatamente antes da primeira barra '/' para validar o destino.",
                    }
                )

        # 11. Porta não padrão
        if port is not None and port not in (80, 443):
            findings.append(
                {
                    "rule_id": "URL-PORT-010",
                    "severity": "MEDIUM",
                    "title": f"Porta não padrão especificada na URL (:{port})",
                    "description": "Serviços públicos legítimos normalmente operam nas portas 80/443.",
                    "mitre_attack": "T1571 - Non-Standard Port",
                    "remediation": "Confirme por que o serviço expõe porta alternativa antes de interagir.",
                }
            )

        # 12. Palavras-chave de engenharia social
        full_lower = normalized.lower()
        matched_kw = sorted({kw for kw in _SOCIAL_ENG_KEYWORDS if kw in full_lower})
        if len(matched_kw) >= 2:
            findings.append(
                {
                    "rule_id": "URL-KEYWORDS-012",
                    "severity": "MEDIUM",
                    "title": "Múltiplas palavras-chave típicas de engenharia social",
                    "description": f"Termos encontrados na URL: {', '.join(matched_kw)}.",
                    "mitre_attack": "T1566.002 - Spearphishing Link",
                    "remediation": "Valide por canal oficial se houve solicitação real de login, fatura ou desbloqueio.",
                }
            )

        live_check: dict[str, Any] | None = None
        if check_live and scheme in {"http", "https"} and host:
            live_check = self._perform_safe_live_check(normalized, host)

        risk_score = min(100, sum(_SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings))
        if risk_score >= 50 or any(f["severity"] == "CRITICAL" for f in findings):
            verdict = "PERIGOSO"
        elif risk_score >= 15 or findings:
            verdict = "SUSPEITO"
        else:
            verdict = "SEGURO"

        return {
            "url": url,
            "normalized_url": normalized,
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": path,
            "risk_score": risk_score,
            "verdict": verdict,
            "findings_count": len(findings),
            "findings": findings,
            "live_check": live_check,
        }

    def analyze_batch(self, urls: list[str], check_live: bool = False) -> dict[str, Any]:
        results = [self.analyze_url(u, check_live=check_live) for u in urls if u.strip()]
        counts = {"SEGURO": 0, "SUSPEITO": 0, "PERIGOSO": 0}
        for item in results:
            counts[item["verdict"]] = counts.get(item["verdict"], 0) + 1
        return {
            "total": len(results),
            "counts": counts,
            "results": results,
        }

    def _perform_safe_live_check(self, normalized_url: str, host: str) -> dict[str, Any]:
        """Executa verificação HTTP HEAD com proteção estrita anti-SSRF."""
        if _is_ip_literal(host) and not _is_public_ip(host):
            return {
                "checked": False,
                "blocked_ssrf": True,
                "error": "Bloqueado pela proteção anti-SSRF (IP privado, loopback ou reservado).",
            }

        try:
            addr_info = socket.getaddrinfo(host, None)
        except OSError as exc:
            return {
                "checked": False,
                "blocked_ssrf": False,
                "error": f"Falha ao resolver DNS: {exc}",
            }

        resolved_ips = sorted({info[4][0] for info in addr_info if info and info[4]})
        for ip_str in resolved_ips:
            if not _is_public_ip(ip_str):
                return {
                    "checked": False,
                    "blocked_ssrf": True,
                    "resolved_ips": resolved_ips,
                    "error": f"Bloqueado pela proteção anti-SSRF: host resolveu para IP não público ({ip_str}).",
                }

        req = urllib.request.Request(
            normalized_url,
            method="HEAD",
            headers={"User-Agent": "OlhoDeSauron-LinkAuditor/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=4) as resp:  # nosec B310
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                security_headers = {
                    hdr: headers_lower.get(hdr.lower()) for hdr in _SECURITY_HEADERS
                }
                return {
                    "checked": True,
                    "blocked_ssrf": False,
                    "status_code": resp.status,
                    "final_url": resp.geturl(),
                    "resolved_ips": resolved_ips,
                    "security_headers": security_headers,
                }
        except urllib.error.HTTPError as exc:
            return {
                "checked": True,
                "blocked_ssrf": False,
                "status_code": exc.code,
                "final_url": normalized_url,
                "resolved_ips": resolved_ips,
                "security_headers": {},
            }
        except Exception as exc:
            return {
                "checked": False,
                "blocked_ssrf": False,
                "resolved_ips": resolved_ips,
                "error": f"Não foi possível conectar ao host: {exc}",
            }
