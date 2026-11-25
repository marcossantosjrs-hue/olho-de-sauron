"""Scanner de hardening para Docker, Docker Compose, SSH, Nginx, CORS e Debug."""

from __future__ import annotations

import re
from pathlib import Path

from olho_de_sauron.models import Finding
from olho_de_sauron.rules_catalog import build_finding
from olho_de_sauron.scanners.base import BaseScanner, get_line_snippet, is_line_suppressed

_DOCKERFILE_FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)(?:\s+AS\s+([^\s]+))?", re.IGNORECASE)
_DOCKERFILE_USER_RE = re.compile(r"^\s*USER\s+([^\s:]+)", re.IGNORECASE)

_COMPOSE_PRIV_RE = re.compile(r"^\s*privileged\s*:\s*true\b", re.IGNORECASE)
_COMPOSE_SOCK_RE = re.compile(r"/var/run/docker\.sock")

_SSH_ROOT_RE = re.compile(r"^\s*PermitRootLogin\s+yes\b", re.IGNORECASE)
_SSH_PASS_RE = re.compile(r"^\s*PasswordAuthentication\s+yes\b", re.IGNORECASE)

_NGINX_TOKENS_RE = re.compile(r"^\s*server_tokens\s+on\b", re.IGNORECASE)
_NGINX_AUTOINDEX_RE = re.compile(r"^\s*autoindex\s+on\b", re.IGNORECASE)
_NGINX_WEAK_TLS_RE = re.compile(r"^\s*ssl_protocols\b.*\bTLSv1(?:\.1)?\b(?!\.\d)", re.IGNORECASE)

_CORS_HEADER_RE = re.compile(r"Access-Control-Allow-Origin[\"']?\s*[:=,]\s*[\"']\*[\"']", re.IGNORECASE)
_CORS_ALLOW_ORIGINS_RE = re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]")
_CORS_DJANGO_RE = re.compile(r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True")

_DEBUG_CFG_RE = re.compile(
    r"""(?ix)
    (?:^\s*(?:DEBUG|FLASK_DEBUG)\s*=\s*(?:true|1|yes)\s*$|
       ^\s*["']?debug["']?\s*:\s*true\b)
    """
)

_GENERAL_CFG_EXTENSIONS = {".yml", ".yaml", ".json", ".py", ".js", ".ts", ".conf"}


def _is_dockerfile(path: Path) -> bool:
    name = path.name.lower()
    return name == "dockerfile" or name.startswith("dockerfile.") or path.suffix.lower() == ".dockerfile"


def _is_compose(path: Path) -> bool:
    name = path.name.lower()
    return ("docker-compose" in name or name.startswith("compose")) and path.suffix.lower() in {".yml", ".yaml"}


def _is_sshd_config(path: Path) -> bool:
    return "sshd_config" in path.name.lower()


def _is_nginx_conf(path: Path) -> bool:
    name = path.name.lower()
    return "nginx" in name and path.suffix.lower() == ".conf"


class ConfigHardeningScanner(BaseScanner):
    """Analisa configurações de infraestrutura, containers e exposição da aplicação."""

    name = "config-hardening"

    def supports(self, path: Path) -> bool:
        name = path.name.lower()
        return (
            _is_dockerfile(path)
            or _is_compose(path)
            or _is_sshd_config(path)
            or _is_nginx_conf(path)
            or name.startswith(".env")
            or path.suffix.lower() in _GENERAL_CFG_EXTENSIONS
        )

    def scan_file(self, path: Path, rel_path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        if _is_dockerfile(path):
            findings.extend(self._scan_dockerfile(rel_path, lines))
        if _is_compose(path):
            findings.extend(self._scan_compose(rel_path, lines))
        if _is_sshd_config(path):
            findings.extend(self._scan_sshd(rel_path, lines))
        if _is_nginx_conf(path):
            findings.extend(self._scan_nginx(rel_path, lines))

        findings.extend(self._scan_general_exposure(path, rel_path, lines))
        return findings

    def _scan_dockerfile(self, rel_path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        stages: set[str] = set()
        last_user: tuple[int, str] | None = None
        last_from_line = 1

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            from_match = _DOCKERFILE_FROM_RE.match(line)
            if from_match:
                last_from_line = idx
                image = from_match.group(1)
                stage_alias = from_match.group(2)
                if stage_alias:
                    stages.add(stage_alias.lower())

                img_lower = image.lower()
                if img_lower != "scratch" and img_lower not in stages:
                    has_digest = "@sha256:" in img_lower
                    tag = img_lower.rsplit(":", 1)[1] if ":" in img_lower.rsplit("/", 1)[-1] else ""
                    if not has_digest and (not tag or tag == "latest"):
                        if not is_line_suppressed(lines, idx, "SAURON-INFRA-002"):
                            findings.append(
                                build_finding(
                                    rule_id="SAURON-INFRA-002",
                                    file_path=rel_path,
                                    line=idx,
                                    snippet=stripped,
                                    scanner=self.name,
                                )
                            )

            user_match = _DOCKERFILE_USER_RE.match(line)
            if user_match:
                last_user = (idx, user_match.group(1).lower())

        if last_user is None:
            if not is_line_suppressed(lines, last_from_line, "SAURON-INFRA-001"):
                findings.append(
                    build_finding(
                        rule_id="SAURON-INFRA-001",
                        file_path=rel_path,
                        line=last_from_line,
                        snippet=get_line_snippet(lines, last_from_line),
                        scanner=self.name,
                        extra_detail="Nenhuma diretiva USER não-root definida",
                    )
                )
        elif last_user[1] in {"root", "0"}:
            user_line = last_user[0]
            if not is_line_suppressed(lines, user_line, "SAURON-INFRA-001"):
                findings.append(
                    build_finding(
                        rule_id="SAURON-INFRA-001",
                        file_path=rel_path,
                        line=user_line,
                        snippet=get_line_snippet(lines, user_line),
                        scanner=self.name,
                        extra_detail=f"Último USER definido como {last_user[1]}",
                    )
                )

        return findings

    def _scan_compose(self, rel_path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if (_COMPOSE_PRIV_RE.search(line) or _COMPOSE_SOCK_RE.search(line)) and not is_line_suppressed(
                lines, idx, "SAURON-INFRA-003"
            ):
                findings.append(
                    build_finding(
                        rule_id="SAURON-INFRA-003",
                        file_path=rel_path,
                        line=idx,
                        snippet=stripped,
                        scanner=self.name,
                    )
                )
        return findings

    def _scan_sshd(self, rel_path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if (_SSH_ROOT_RE.match(line) or _SSH_PASS_RE.match(line)) and not is_line_suppressed(
                lines, idx, "SAURON-INFRA-004"
            ):
                findings.append(
                    build_finding(
                        rule_id="SAURON-INFRA-004",
                        file_path=rel_path,
                        line=idx,
                        snippet=stripped,
                        scanner=self.name,
                    )
                )
        return findings

    def _scan_nginx(self, rel_path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if (
                _NGINX_TOKENS_RE.match(line)
                or _NGINX_AUTOINDEX_RE.match(line)
                or _NGINX_WEAK_TLS_RE.search(line)
            ) and not is_line_suppressed(lines, idx, "SAURON-INFRA-005"):
                findings.append(
                    build_finding(
                        rule_id="SAURON-INFRA-005",
                        file_path=rel_path,
                        line=idx,
                        snippet=stripped,
                        scanner=self.name,
                    )
                )
        return findings

    def _scan_general_exposure(self, path: Path, rel_path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        name = path.name.lower()
        is_cfg_debug_target = name.startswith(".env") or path.suffix.lower() in {".yml", ".yaml", ".json"}

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            if (
                _CORS_HEADER_RE.search(line)
                or _CORS_ALLOW_ORIGINS_RE.search(line)
                or _CORS_DJANGO_RE.search(line)
            ) and not is_line_suppressed(lines, idx, "SAURON-CFG-008"):
                findings.append(
                    build_finding(
                        rule_id="SAURON-CFG-008",
                        file_path=rel_path,
                        line=idx,
                        snippet=stripped,
                        scanner=self.name,
                    )
                )

            if is_cfg_debug_target and _DEBUG_CFG_RE.search(line) and not is_line_suppressed(
                lines, idx, "SAURON-CFG-009"
            ):
                findings.append(
                    build_finding(
                        rule_id="SAURON-CFG-009",
                        file_path=rel_path,
                        line=idx,
                        snippet=stripped,
                        scanner=self.name,
                    )
                )

        return findings
