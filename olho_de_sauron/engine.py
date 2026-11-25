"""Motor principal de orquestração e pontuação do Olho de Sauron."""

from __future__ import annotations

import fnmatch
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from olho_de_sauron.models import Finding, Pillar, ScanResult, Severity, Verdict
from olho_de_sauron.scanners import BaseScanner, default_scanners

MAX_FILE_SIZE_BYTES = 1_048_576  # 1 MB

DEFAULT_IGNORE_PATTERNS: tuple[str, ...] = (
    ".git",
    ".git/*",
    "__pycache__",
    "__pycache__/*",
    ".venv",
    ".venv/*",
    "venv",
    "venv/*",
    "env",
    "env/*",
    "node_modules",
    "node_modules/*",
    "dist",
    "dist/*",
    "build",
    "build/*",
    "*.egg-info",
    "*.egg-info/*",
    ".pytest_cache",
    ".pytest_cache/*",
    "reports",
    "reports/*",
    "*.pyc",
    "*.pyo",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.ico",
    "*.pdf",
    "*.zip",
    "*.exe",
    "*.dll",
    "*.so",
    "*.bin",
)


def load_ignore_patterns(root: Path, use_ignore: bool = True) -> list[str]:
    """Carrega padrões default e do arquivo `.sauronignore`, se existir."""
    patterns = list(DEFAULT_IGNORE_PATTERNS)
    if not use_ignore:
        return patterns

    ignore_file = root / ".sauronignore"
    if ignore_file.is_file():
        for raw in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            cleaned = raw.strip()
            if cleaned and not cleaned.startswith("#"):
                patterns.append(cleaned)
    return patterns


def _matches_ignore(rel_path: str, is_dir: bool, patterns: Sequence[str]) -> bool:
    """Verifica se o caminho relativo casa com algum padrão estilo ignore."""
    posix = rel_path.replace("\\", "/").strip("/")
    parts = posix.split("/")
    name = parts[-1] if parts else posix

    for raw_pattern in patterns:
        pattern = raw_pattern.replace("\\", "/").strip()
        if not pattern:
            continue
        dir_only = pattern.endswith("/")
        pat = pattern.rstrip("/")

        if dir_only and not is_dir:
            if any(fnmatch.fnmatch(part, pat) for part in parts[:-1]):
                return True
            continue

        if fnmatch.fnmatch(posix, pat) or fnmatch.fnmatch(name, pat):
            return True
        if any(fnmatch.fnmatch(part, pat) for part in parts):
            return True
        if pat.endswith("/*") and posix.startswith(pat[:-1]):
            return True
    return False


def _is_binary_bytes(sample: bytes) -> bool:
    return b"\x00" in sample


def _collect_git_diff_files(repo_root: Path) -> list[Path]:
    """Coleta arquivos alterados ou não rastreados usando `git` com segurança."""
    changed: set[Path] = set()
    commands = [
        ["git", "-C", str(repo_root), "diff", "--name-only", "HEAD"],
        ["git", "-C", str(repo_root), "diff", "--cached", "--name-only"],
        ["git", "-C", str(repo_root), "ls-files", "--others", "--exclude-standard"],
    ]

    ran_ok = False
    last_error = ""
    for cmd in commands:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            ran_ok = True
            for line in proc.stdout.splitlines():
                rel = line.strip()
                if rel:
                    candidate = (repo_root / rel).resolve()
                    if candidate.is_file():
                        changed.add(candidate)
        else:
            last_error = proc.stderr.strip() or proc.stdout.strip()

    if not ran_ok:
        raise RuntimeError(
            f"Não foi possível obter alterações via Git em '{repo_root}': {last_error}"
        )
    return sorted(changed)


def compute_score_and_grade(findings: Sequence[Finding]) -> tuple[int, str]:
    """Calcula a pontuação (0-100) e nota alfabética (A-F) com base nos achados."""
    penalty = sum(f.severity.weight for f in findings)
    score = max(0, 100 - penalty)
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 55:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def compute_verdict(counts_by_severity: dict[str, int]) -> Verdict:
    """Emite o parecer de prontidão DevSecOps conforme severidades encontradas."""
    if counts_by_severity.get(Severity.CRITICAL.value, 0) > 0 or counts_by_severity.get(
        Severity.HIGH.value, 0
    ) > 0:
        return Verdict.BLOQUEADO
    if counts_by_severity.get(Severity.MEDIUM.value, 0) > 0 or counts_by_severity.get(
        Severity.LOW.value, 0
    ) > 0:
        return Verdict.AJUSTES_RECOMENDADOS
    return Verdict.APROVADO


def should_fail(result: ScanResult, fail_on: str) -> bool:
    """Indica se o exit code deve falhar conforme o limiar `--fail-on`."""
    if fail_on.strip().lower() == "none":
        return False
    threshold = Severity.from_str(fail_on)
    return any(finding.severity.rank >= threshold.rank for finding in result.findings)


class ScanEngine:
    """Orquestra a descoberta de arquivos, execução dos scanners e consolidação."""

    def __init__(self, scanners: Iterable[BaseScanner] | None = None) -> None:
        self.scanners: list[BaseScanner] = list(scanners) if scanners is not None else default_scanners()

    def scan(
        self,
        targets: str | Path | Sequence[str | Path] = ".",
        min_severity: Severity = Severity.INFO,
        excludes: Sequence[str] = (),
        git_diff: bool = False,
        use_ignore: bool = True,
    ) -> ScanResult:
        start_perf = time.perf_counter()
        started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

        if isinstance(targets, (str, Path)):
            target_list = [Path(targets)]
        else:
            target_list = [Path(t) for t in targets] or [Path(".")]

        resolved_targets = [t.resolve() for t in target_list]
        for t in resolved_targets:
            if not t.exists():
                raise FileNotFoundError(f"Alvo não encontrado: {t}")

        base_root = self._determine_base_root(resolved_targets)
        ignore_patterns = load_ignore_patterns(base_root, use_ignore=use_ignore)
        ignore_patterns.extend(excludes)

        files_to_scan, skipped_count = self._collect_files(
            targets=resolved_targets,
            base_root=base_root,
            ignore_patterns=ignore_patterns,
            git_diff=git_diff,
            use_ignore=use_ignore,
        )

        all_findings: list[Finding] = []
        scanned_count = 0

        for file_path in files_to_scan:
            rel_path = self._to_rel_posix(file_path, base_root)
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                    skipped_count += 1
                    continue
                raw_bytes = file_path.read_bytes()
            except OSError:
                skipped_count += 1
                continue

            if _is_binary_bytes(raw_bytes[:1024]):
                skipped_count += 1
                continue

            content = raw_bytes.decode("utf-8", errors="replace")
            scanned_count += 1

            for scanner in self.scanners:
                if scanner.supports(file_path):
                    all_findings.extend(scanner.scan_file(file_path, rel_path, content))

        filtered_findings = [
            f for f in all_findings if f.severity.rank >= min_severity.rank
        ]
        filtered_findings.sort(
            key=lambda f: (-f.severity.rank, f.file_path, f.line, f.rule_id)
        )

        counts_by_severity = {sev.value: 0 for sev in Severity}
        counts_by_pillar = {pillar.value: 0 for pillar in Pillar}
        for finding in filtered_findings:
            counts_by_severity[finding.severity.value] += 1
            counts_by_pillar[finding.pillar.value] += 1

        score, grade = compute_score_and_grade(filtered_findings)
        verdict = compute_verdict(counts_by_severity)
        duration = time.perf_counter() - start_perf
        target_label = ", ".join(str(t) for t in target_list)

        return ScanResult(
            target=target_label,
            started_at=started_at,
            duration_seconds=duration,
            files_scanned=scanned_count,
            files_skipped=skipped_count,
            findings=filtered_findings,
            score=score,
            grade=grade,
            verdict=verdict,
            counts_by_severity=counts_by_severity,
            counts_by_pillar=counts_by_pillar,
        )

    @staticmethod
    def _determine_base_root(targets: list[Path]) -> Path:
        if len(targets) == 1:
            t = targets[0]
            return t if t.is_dir() else t.parent
        cwd = Path.cwd().resolve()
        return cwd

    @staticmethod
    def _to_rel_posix(file_path: Path, base_root: Path) -> str:
        try:
            return file_path.resolve().relative_to(base_root.resolve()).as_posix()
        except ValueError:
            return file_path.name

    def _collect_files(
        self,
        targets: list[Path],
        base_root: Path,
        ignore_patterns: list[str],
        git_diff: bool,
        use_ignore: bool,
    ) -> tuple[list[Path], int]:
        if git_diff:
            diff_files = _collect_git_diff_files(base_root)
            selected: list[Path] = []
            skipped = 0
            for f in diff_files:
                rel = self._to_rel_posix(f, base_root)
                if use_ignore and _matches_ignore(rel, is_dir=False, patterns=ignore_patterns):
                    skipped += 1
                    continue
                selected.append(f)
            return selected, skipped

        collected: list[Path] = []
        seen: set[Path] = set()
        skipped = 0

        for target in targets:
            if target.is_file():
                rel = self._to_rel_posix(target, base_root)
                if use_ignore and _matches_ignore(rel, is_dir=False, patterns=ignore_patterns):
                    skipped += 1
                elif target not in seen:
                    seen.add(target)
                    collected.append(target)
                continue

            for item in sorted(target.rglob("*")):
                rel = self._to_rel_posix(item, base_root)
                if item.is_dir():
                    continue
                if use_ignore and _matches_ignore(rel, is_dir=False, patterns=ignore_patterns):
                    skipped += 1
                    continue
                if item not in seen:
                    seen.add(item)
                    collected.append(item)

        return collected, skipped
