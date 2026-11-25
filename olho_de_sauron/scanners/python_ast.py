"""Motor SAST via AST Python para detecção precisa de vulnerabilidades."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from olho_de_sauron.models import Finding
from olho_de_sauron.rules_catalog import build_finding
from olho_de_sauron.scanners.base import BaseScanner, get_line_snippet, is_line_suppressed

_SQL_KEYWORD_RE = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|WITH)\b",
    re.IGNORECASE,
)
_SENSITIVE_IDENTIFIERS = {
    "password",
    "passwd",
    "pwd",
    "senha",
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "private_key",
    "jwt_secret",
}
_LOG_METHODS = {"debug", "info", "warning", "warn", "error", "critical", "exception"}
_SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}


def _get_call_parts(func: ast.AST) -> tuple[str | None, str]:
    """Retorna (objeto_raiz, nome_metodo_ou_funcao) para uma chamada AST."""
    if isinstance(func, ast.Name):
        return None, func.id
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return func.value.id, func.attr
        if isinstance(func.value, ast.Attribute):
            return func.value.attr, func.attr
        return None, func.attr
    return None, ""


def _is_constant_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_constant_false(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _extract_constant_strings(node: ast.AST) -> list[str]:
    """Coleta fragmentos de strings constantes presentes em uma expressão."""
    texts: list[str] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            texts.append(sub.value)
    return texts


def _is_dynamic_string_expr(node: ast.AST) -> bool:
    """Identifica construção dinâmica de string (f-string, +, % ou .format)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(val, ast.FormattedValue) for val in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        has_var = any(isinstance(sub, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)) for sub in ast.walk(node))
        return has_var
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return True
    return False


def _looks_like_sql(node: ast.AST) -> bool:
    """Verifica se a expressão contém palavras-chave SQL típicas."""
    combined = " ".join(_extract_constant_strings(node))
    return bool(_SQL_KEYWORD_RE.search(combined))


def _contains_sensitive_identifier(node: ast.AST) -> bool:
    """Detecta referências a variáveis/atributos com nomes sensíveis."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id.lower() in _SENSITIVE_IDENTIFIERS:
            return True
        if isinstance(sub, ast.Attribute) and sub.attr.lower() in _SENSITIVE_IDENTIFIERS:
            return True
    return False


class _PythonSecurityVisitor(ast.NodeVisitor):
    """Visitor AST com rastreamento de variáveis SQL dinâmicas por escopo."""

    def __init__(self, rel_path: str, lines: list[str], scanner_name: str) -> None:
        self.rel_path = rel_path
        self.lines = lines
        self.scanner_name = scanner_name
        self.findings: list[Finding] = []
        self._scope_stack: list[set[str]] = [set()]
        self._seen: set[tuple[str, int]] = set()

    def _emit(self, rule_id: str, node: ast.AST, extra_detail: str | None = None) -> None:
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        if is_line_suppressed(self.lines, line, rule_id):
            return
        key = (rule_id, line)
        if key in self._seen:
            return
        self._seen.add(key)
        snippet = get_line_snippet(self.lines, line)
        self.findings.append(
            build_finding(
                rule_id=rule_id,
                file_path=self.rel_path,
                line=line,
                column=col,
                snippet=snippet,
                scanner=self.scanner_name,
                extra_detail=extra_detail,
            )
        )

    def _is_dynamic_sql_var(self, name: str) -> bool:
        return any(name in scope for scope in reversed(self._scope_stack))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope_stack.append(set())
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scope_stack.append(set())
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        # Registra variáveis locais montadas com SQL dinâmico
        if _is_dynamic_string_expr(node.value) and _looks_like_sql(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._scope_stack[-1].add(target.id)

        # DEBUG = True em nível de módulo
        if len(self._scope_stack) == 1 and _is_constant_true(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "DEBUG":
                    self._emit("SAURON-CFG-007", node)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and isinstance(node.target, ast.Name):
            if _is_dynamic_string_expr(node.value) and _looks_like_sql(node.value):
                self._scope_stack[-1].add(node.target.id)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        is_broad = node.type is None or (
            isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}
        )
        if is_broad and len(node.body) == 1:
            stmt = node.body[0]
            is_pass = isinstance(stmt, ast.Pass)
            is_ellipsis = (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and stmt.value.value is Ellipsis
            )
            if is_pass or is_ellipsis:
                self._emit("SAURON-ERR-008", node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        obj_name, func_name = _get_call_parts(node.func)
        kw_map = {kw.arg: kw.value for kw in node.keywords if kw.arg}

        # 1. SQL Injection em .execute() / .executemany()
        if func_name in {"execute", "executemany"} and node.args:
            first_arg = node.args[0]
            if _is_dynamic_string_expr(first_arg):
                self._emit("SAURON-SQLI-001", node)
            elif isinstance(first_arg, ast.Name) and self._is_dynamic_sql_var(first_arg.id):
                self._emit("SAURON-SQLI-001", node)

        # 2. Command Injection
        if obj_name == "os" and func_name in {"system", "popen"}:
            self._emit("SAURON-INJ-002", node)
        elif obj_name == "subprocess" and func_name in _SUBPROCESS_FUNCS:
            if _is_constant_true(kw_map.get("shell")):
                self._emit("SAURON-INJ-002", node)

        # 3. eval() / exec()
        if obj_name is None and func_name in {"eval", "exec"}:
            self._emit("SAURON-INJ-003", node)

        # 4. Desserialização insegura
        if obj_name == "pickle" and func_name in {"load", "loads"}:
            self._emit("SAURON-DESER-004", node)
        elif obj_name == "yaml" and func_name == "load":
            loader_node = kw_map.get("Loader")
            safe_loader = False
            if isinstance(loader_node, ast.Name) and loader_node.id in {"SafeLoader", "CSafeLoader"}:
                safe_loader = True
            elif isinstance(loader_node, ast.Attribute) and loader_node.attr in {"SafeLoader", "CSafeLoader"}:
                safe_loader = True
            if not safe_loader:
                self._emit("SAURON-DESER-004", node)

        # 5. Hash criptográfico fraco (MD5 / SHA-1)
        if obj_name == "hashlib":
            used_for_sec = kw_map.get("usedforsecurity")
            if not _is_constant_false(used_for_sec):
                if func_name in {"md5", "sha1"}:
                    self._emit("SAURON-CRYPTO-005", node)
                elif func_name == "new" and node.args:
                    algo = node.args[0]
                    if isinstance(algo, ast.Constant) and isinstance(algo.value, str):
                        if algo.value.lower() in {"md5", "sha1"}:
                            self._emit("SAURON-CRYPTO-005", node)

        # 6. Verificação TLS desabilitada
        if _is_constant_false(kw_map.get("verify")):
            self._emit("SAURON-CFG-006", node)
        elif obj_name == "ssl" and func_name == "_create_unverified_context":
            self._emit("SAURON-CFG-006", node)

        # 7. Debug / Bind 0.0.0.0 em servidores web
        if func_name == "run":
            if _is_constant_true(kw_map.get("debug")):
                self._emit("SAURON-CFG-007", node)
            host_arg = kw_map.get("host")
            if isinstance(host_arg, ast.Constant) and host_arg.value == "0.0.0.0":
                self._emit("SAURON-NET-010", node)

        if func_name == "bind" and node.args:
            arg0 = node.args[0]
            if isinstance(arg0, ast.Tuple) and arg0.elts:
                first_elt = arg0.elts[0]
                if isinstance(first_elt, ast.Constant) and first_elt.value == "0.0.0.0":
                    self._emit("SAURON-NET-010", node)

        # 8. Vazamento de dados sensíveis em logs
        if func_name in _LOG_METHODS and (
            obj_name in {"logging", "logger", "log"} or (obj_name and "log" in obj_name.lower())
        ):
            if any(_contains_sensitive_identifier(arg) for arg in node.args):
                self._emit("SAURON-LOG-009", node)

        self.generic_visit(node)


class PythonAstScanner(BaseScanner):
    """Analisador estático baseado na Árvore Sintática Abstrata do Python."""

    name = "python-ast"

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() == ".py"

    def scan_file(self, path: Path, rel_path: str, content: str) -> list[Finding]:
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError:
            return []

        lines = content.splitlines()
        visitor = _PythonSecurityVisitor(rel_path=rel_path, lines=lines, scanner_name=self.name)
        visitor.visit(tree)
        return visitor.findings
