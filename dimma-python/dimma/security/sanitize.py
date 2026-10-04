"""
Camada de sanitizacao de entrada (Python).

IMPORTANTE: a defesa definitiva contra SQL Injection e usar queries
parametrizadas / ORM (SQLAlchemy, Django ORM). Este modulo e uma camada
ADICIONAL de defesa em profundidade que barra os padroes mais comuns de
ataque antes de chegar nas views/rotas.
"""
import html
import re
from typing import Any, Dict, List

SQLI_PATTERNS = [
    re.compile(r"(%27|')\s*(or|and)\s+.{1,50}(=|like)", re.IGNORECASE),
    re.compile(r"(%27|')\s*(--|%23|#)"),
    re.compile(r"(%27|');", re.IGNORECASE),
    re.compile(r"\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", re.IGNORECASE),
    re.compile(r"\band\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", re.IGNORECASE),
    re.compile(r"\bunion\b.{1,100}\bselect\b", re.IGNORECASE),
    re.compile(r"\bselect\b.{1,100}\bfrom\b.{1,100}\bwhere\b", re.IGNORECASE),
    re.compile(r"\binsert\b\s+into\b", re.IGNORECASE),
    re.compile(r"\bdrop\b\s+table\b", re.IGNORECASE),
    re.compile(r"\bupdate\b.{1,100}\bset\b.{1,100}\bwhere\b", re.IGNORECASE),
    re.compile(r"\bdelete\b\s+from\b", re.IGNORECASE),
    re.compile(r"\bexec(\s|\+)+(x|s)p\w+", re.IGNORECASE),
    re.compile(r"--\s*$"),
]

XSS_PATTERNS = [
    re.compile(r"<\s*script.*?>", re.IGNORECASE),
    re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on\w+\s*=\s*[\"']?[^\"'>]+", re.IGNORECASE),
    re.compile(r"<\s*iframe", re.IGNORECASE),
    re.compile(r"<\s*img[^>]+src[^>]*=[^>]*onerror", re.IGNORECASE),
    re.compile(r"data:text/html", re.IGNORECASE),
]

# SEGURANCA (mitigacao de ReDoS): mesmo com quantificadores limitados
# ({1,100}), testar regex contra strings arbitrariamente grandes ainda
# degrada performance de forma desproporcional. Valores acima do limite
# sao rejeitados, nunca parcialmente analisados e aceitos.
MAX_SCAN_LENGTH = 4096


def contains_sql_injection(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if len(value) > MAX_SCAN_LENGTH:
        return True
    return any(p.search(value) for p in SQLI_PATTERNS)


def contains_xss(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if len(value) > MAX_SCAN_LENGTH:
        return True
    return any(p.search(value) for p in XSS_PATTERNS)


def escape_html(value: str) -> str:
    return html.escape(value, quote=True)


def escape_for_sql(value: str) -> str:
    """API mantida por compatibilidade; SQL deve usar parametros do driver/ORM."""
    raise RuntimeError(
        "escape_for_sql nao e suportado: use queries parametrizadas/prepared statements do driver ou ORM."
    )


def scan_object(obj: Any, path: str = "") -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if obj is None:
        return findings

    if isinstance(obj, str):
        if len(obj) > MAX_SCAN_LENGTH:
            findings.append({"path": path, "type": "input_too_large", "value": obj})
            return findings
        if contains_sql_injection(obj):
            findings.append({"path": path, "type": "sql_injection", "value": obj})
        if contains_xss(obj):
            findings.append({"path": path, "type": "xss", "value": obj})
        return findings

    if isinstance(obj, (list, tuple)):
        for i, item in enumerate(obj):
            findings.extend(scan_object(item, f"{path}[{i}]"))
        return findings

    if isinstance(obj, dict):
        for key, val in obj.items():
            findings.extend(scan_object(val, f"{path}.{key}" if path else str(key)))

    return findings
