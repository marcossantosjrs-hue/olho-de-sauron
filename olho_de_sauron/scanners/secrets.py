"""Scanner de segredos, credenciais hardcoded e arquivos .env expostos."""

from __future__ import annotations

import math
import re
from pathlib import Path

from olho_de_sauron.models import Finding
from olho_de_sauron.rules_catalog import build_finding
from olho_de_sauron.scanners.base import BaseScanner, is_line_suppressed

_TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".sh",
    ".bash",
    ".ps1",
    ".sql",
    ".tf",
    ".tfvars",
    ".properties",
    ".xml",
    ".go",
    ".java",
    ".rb",
    ".php",
}

_PROVIDER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("GitHub Fine-Grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe Live Key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
]

_PRIVATE_KEY_RE = re.compile(r"-----BEGIN\s+(?:[A-Z]+\s+)?PRIVATE\s+KEY-----")

_DB_URI_RE = re.compile(
    r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^/\s:@\"']+:[^/\s@\"']+@[^/\s\"']+",
    re.IGNORECASE,
)

_HARDCODED_ASSIGN_RE = re.compile(
    r"""(?ix)
    \b(?P<name>
        api_?key|secret_?key|jwt_?secret|access_?token|auth_?token|
        client_?secret|db_?password|database_?password|password|senha|secret|token
    )\b
    \s*(?:=|:)\s*
    (?P<quote>['"])(?P<val>[^'"]{8,160})(?P=quote)
    """
)

_ENV_LINE_RE = re.compile(
    r"""(?ix)
    ^(?:export\s+)?
    (?P<name>[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|SENHA|PASS)[A-Z0-9_]*)
    \s*=\s*
    ['"]?(?P<val>[^'"\s#]{8,160})['"]?
    """
)

_GENERIC_KEY_NAMES = {"key", "token", "secret", "password", "senha"}

_PLACEHOLDER_MARKERS = (
    "sua_chave",
    "seu_token",
    "sua_senha",
    "changeme",
    "change_me",
    "example",
    "placeholder",
    "your_",
    "dummy",
    "redacted",
    "sample",
    "fake",
    "***",
    "xxxx",
    "0000",
    "os.environ",
    "os.getenv",
)

_REAL_ENV_NAMES = {".env", ".env.local", ".env.production", ".env.staging", ".env.dev"}
_TEMPLATE_ENV_NAMES = {".env.example", ".env.sample", ".env.template", ".env.test"}


def shannon_entropy(data: str) -> float:
    """Calcula a entropia de Shannon (em bits por caractere) de uma string."""
    if not data:
        return 0.0
    length = len(data)
    counts: dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def redact_secret(line: str, secret_value: str) -> str:
    """Mascara o segredo na linha para exibição segura em relatórios."""
    if not secret_value:
        return line.strip()
    prefix = secret_value[:4] if len(secret_value) > 6 else ""
    masked = f"{prefix}***REDACTED***"
    return line.replace(secret_value, masked).strip()


def _is_placeholder(value: str) -> bool:
    low = value.strip().lower()
    if not low:
        return True
    if low.startswith("${") or (low.startswith("<") and low.endswith(">")):
        return True
    if any(marker in low for marker in _PLACEHOLDER_MARKERS):
        return True
    if len(set(low)) <= 2:
        return True
    return False


class SecretsScanner(BaseScanner):
    """Detector de segredos expostos, chaves privadas e arquivos .env reais."""

    name = "secrets"

    def supports(self, path: Path) -> bool:
        fname = path.name.lower()
        if fname.startswith(".env"):
            return True
        if fname in {"dockerfile", "containerfile"} or fname.startswith("dockerfile."):
            return True
        return path.suffix.lower() in _TEXT_EXTENSIONS

    def scan_file(self, path: Path, rel_path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fname = path.name.lower()
        is_env_template = fname in _TEMPLATE_ENV_NAMES
        is_real_env = fname in _REAL_ENV_NAMES

        # Regra 5: arquivo .env real presente no projeto
        if is_real_env and not is_line_suppressed(lines, 1, "SAURON-SEC-005"):
            findings.append(
                build_finding(
                    rule_id="SAURON-SEC-005",
                    file_path=rel_path,
                    line=1,
                    snippet=f"Arquivo sensível detectado: {rel_path}",
                    scanner=self.name,
                )
            )

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # 1. Chaves de provedores conhecidos
            matched_provider = False
            for provider, pattern in _PROVIDER_PATTERNS:
                m = pattern.search(line)
                if m and not is_line_suppressed(lines, idx, "SAURON-SEC-001"):
                    secret_val = m.group(0)
                    findings.append(
                        build_finding(
                            rule_id="SAURON-SEC-001",
                            file_path=rel_path,
                            line=idx,
                            column=m.start() + 1,
                            snippet=redact_secret(line, secret_val),
                            scanner=self.name,
                            extra_detail=provider,
                        )
                    )
                    matched_provider = True
                    break

            if matched_provider:
                continue

            # 2. Chaves privadas PEM
            pk_match = _PRIVATE_KEY_RE.search(line)
            if pk_match and not is_line_suppressed(lines, idx, "SAURON-SEC-002"):
                findings.append(
                    build_finding(
                        rule_id="SAURON-SEC-002",
                        file_path=rel_path,
                        line=idx,
                        column=pk_match.start() + 1,
                        snippet="-----BEGIN ***REDACTED PRIVATE KEY***-----",
                        scanner=self.name,
                    )
                )
                continue

            if is_env_template:
                continue

            # 3. URIs de banco com credenciais embutidas
            db_match = _DB_URI_RE.search(line)
            if db_match and not is_line_suppressed(lines, idx, "SAURON-SEC-003"):
                uri_val = db_match.group(0)
                if not _is_placeholder(uri_val):
                    at_idx = uri_val.rfind("@")
                    scheme_idx = uri_val.find("://")
                    secret_part = uri_val[scheme_idx + 3 : at_idx] if scheme_idx != -1 and at_idx != -1 else uri_val
                    findings.append(
                        build_finding(
                            rule_id="SAURON-SEC-003",
                            file_path=rel_path,
                            line=idx,
                            column=db_match.start() + 1,
                            snippet=redact_secret(line, secret_part),
                            scanner=self.name,
                        )
                    )
                    continue

            # 4. Atribuições hardcoded ou variáveis em .env
            assign_match = _HARDCODED_ASSIGN_RE.search(line)
            if not assign_match and fname.startswith(".env"):
                assign_match = _ENV_LINE_RE.search(stripped)

            if assign_match and not is_line_suppressed(lines, idx, "SAURON-SEC-004"):
                var_name = assign_match.group("name").lower()
                val = assign_match.group("val")
                if _is_placeholder(val):
                    continue
                if " " in val and var_name in _GENERIC_KEY_NAMES:
                    continue
                entropy = shannon_entropy(val)
                if var_name in _GENERIC_KEY_NAMES and entropy < 3.0 and len(val) < 12:
                    continue
                findings.append(
                    build_finding(
                        rule_id="SAURON-SEC-004",
                        file_path=rel_path,
                        line=idx,
                        column=assign_match.start() + 1,
                        snippet=redact_secret(line, val),
                        scanner=self.name,
                    )
                )

        return findings
