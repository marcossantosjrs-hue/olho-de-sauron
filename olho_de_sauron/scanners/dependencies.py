"""Scanner de dependências e cadeia de suprimentos (requirements.txt e package.json)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from olho_de_sauron.models import Finding
from olho_de_sauron.rules_catalog import build_finding
from olho_de_sauron.scanners.base import BaseScanner, is_line_suppressed

# Base curada local de pacotes depreciados ou versões mínimas recomendadas:
# pacote_normalizado -> (versão_mínima_segura ou None se totalmente depreciado, motivo)
_VULNERABLE_PACKAGES: dict[str, tuple[tuple[int, ...] | None, str]] = {
    "pycrypto": (None, "Biblioteca abandonada; migre para `cryptography`."),
    "pyyaml": ((5, 4), "Versões < 5.4 possuem falhas críticas de execução arbitrária."),
    "django": ((4, 2), "Versões < 4.2 estão fora de suporte LTS/segurança."),
    "flask": ((2, 2, 5), "Versões < 2.2.5 possuem falhas de vazamento de cookie/sessão."),
    "urllib3": ((1, 26, 18), "Versões < 1.26.18 possuem falhas de vazamento de credenciais em redirect."),
    "requests": ((2, 31, 0), "Versões < 2.31.0 expõem Proxy-Authorization em redirecionamentos."),
    "cryptography": ((41, 0, 0), "Versões < 41.0.0 contêm vulnerabilidades conhecidas de OpenSSL."),
    "pillow": ((10, 0, 1), "Versões < 10.0.1 possuem falhas críticas em decodificação de imagens."),
    "lodash": ((4, 17, 21), "Versões < 4.17.21 são vulneráveis a Prototype Pollution / Command Injection."),
    "axios": ((1, 6, 0), "Versões < 1.6.0 possuem falhas de exposição de token XSRF/SSRF."),
}

_REQ_NAME_VER_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9_.*+\-]+)?"
)
_INSECURE_HTTP_RE = re.compile(r"http://[^\s]+", re.IGNORECASE)


def _parse_version_tuple(version_str: str) -> tuple[int, ...] | None:
    """Extrai componentes numéricos iniciais de uma string de versão."""
    cleaned = version_str.strip().lstrip("^~>=<!v")
    parts = re.findall(r"\d+", cleaned.split("-", 1)[0])
    if not parts:
        return None
    return tuple(int(p) for p in parts[:4])


def _is_version_below(current: tuple[int, ...], minimum: tuple[int, ...]) -> bool:
    max_len = max(len(current), len(minimum))
    padded_cur = current + (0,) * (max_len - len(current))
    padded_min = minimum + (0,) * (max_len - len(minimum))
    return padded_cur < padded_min


class DependencyScanner(BaseScanner):
    """Analisa manifestos de dependências Python e Node.js."""

    name = "dependencies"

    def supports(self, path: Path) -> bool:
        fname = path.name.lower()
        return (fname.startswith("requirements") and path.suffix.lower() == ".txt") or fname == "package.json"

    def scan_file(self, path: Path, rel_path: str, content: str) -> list[Finding]:
        if path.name.lower() == "package.json":
            return self._scan_package_json(rel_path, content)
        return self._scan_requirements(rel_path, content)

    def _check_package_vulnerability(
        self,
        pkg_name: str,
        version_str: str | None,
        rel_path: str,
        line: int,
        snippet: str,
        lines: list[str],
    ) -> Finding | None:
        norm_name = pkg_name.lower().replace("_", "-")
        entry = _VULNERABLE_PACKAGES.get(norm_name)
        if not entry:
            return None

        min_version, reason = entry
        if min_version is None:
            if not is_line_suppressed(lines, line, "SAURON-DEP-002"):
                return build_finding(
                    rule_id="SAURON-DEP-002",
                    file_path=rel_path,
                    line=line,
                    snippet=snippet,
                    scanner=self.name,
                    extra_detail=reason,
                )
            return None

        if not version_str:
            return None
        parsed = _parse_version_tuple(version_str)
        if parsed and _is_version_below(parsed, min_version):
            if not is_line_suppressed(lines, line, "SAURON-DEP-002"):
                return build_finding(
                    rule_id="SAURON-DEP-002",
                    file_path=rel_path,
                    line=line,
                    snippet=snippet,
                    scanner=self.name,
                    extra_detail=reason,
                )
        return None

    def _scan_requirements(self, rel_path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for idx, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Remove comentários inline após espaço (mas preserva # sauron: ignore na verificação)
            code_part = stripped.split(" #", 1)[0].strip()
            if not code_part:
                continue

            # 1. URL insegura via HTTP
            if _INSECURE_HTTP_RE.search(code_part):
                if not is_line_suppressed(lines, idx, "SAURON-DEP-003"):
                    findings.append(
                        build_finding(
                            rule_id="SAURON-DEP-003",
                            file_path=rel_path,
                            line=idx,
                            snippet=code_part,
                            scanner=self.name,
                        )
                    )
                continue

            # Ignora flags de pip como -r, -e, --hash etc.
            if code_part.startswith("-"):
                continue

            match = _REQ_NAME_VER_RE.match(code_part)
            if not match:
                continue

            pkg_name, op, ver = match.group(1), match.group(2), match.group(3)
            if not op or not ver:
                if not is_line_suppressed(lines, idx, "SAURON-DEP-001"):
                    findings.append(
                        build_finding(
                            rule_id="SAURON-DEP-001",
                            file_path=rel_path,
                            line=idx,
                            snippet=code_part,
                            scanner=self.name,
                        )
                    )
            vuln_finding = self._check_package_vulnerability(
                pkg_name=pkg_name,
                version_str=ver,
                rel_path=rel_path,
                line=idx,
                snippet=code_part,
                lines=lines,
            )
            if vuln_finding:
                findings.append(vuln_finding)

        return findings

    def _scan_package_json(self, rel_path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return findings

        if not isinstance(data, dict):
            return findings

        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for pkg, ver in deps.items():
                if not isinstance(ver, str):
                    continue
                line_no = self._find_json_line(lines, pkg)
                snippet = f'"{pkg}": "{ver}"'

                if ver.strip().lower().startswith("http://"):
                    if not is_line_suppressed(lines, line_no, "SAURON-DEP-003"):
                        findings.append(
                            build_finding(
                                rule_id="SAURON-DEP-003",
                                file_path=rel_path,
                                line=line_no,
                                snippet=snippet,
                                scanner=self.name,
                            )
                        )
                    continue

                if ver.strip().lower() in {"*", "latest", ""}:
                    if not is_line_suppressed(lines, line_no, "SAURON-DEP-001"):
                        findings.append(
                            build_finding(
                                rule_id="SAURON-DEP-001",
                                file_path=rel_path,
                                line=line_no,
                                snippet=snippet,
                                scanner=self.name,
                            )
                        )
                    continue

                vuln_finding = self._check_package_vulnerability(
                    pkg_name=pkg,
                    version_str=ver,
                    rel_path=rel_path,
                    line=line_no,
                    snippet=snippet,
                    lines=lines,
                )
                if vuln_finding:
                    findings.append(vuln_finding)

        return findings

    @staticmethod
    def _find_json_line(lines: list[str], pkg_name: str) -> int:
        needle = f'"{pkg_name}"'
        for idx, line in enumerate(lines, start=1):
            if needle in line:
                return idx
        return 1
