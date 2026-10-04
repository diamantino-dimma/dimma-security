"""
dimma scan — scanner estatico de padroes de codigo inseguro (versao
Python, mesma logica e regras do core Node.js).

Veja src/scan.js no dimma-core para a explicacao completa do raciocinio
e das limitacoes honestas desta abordagem (analise por padroes, nao
dataflow/taint analysis completo).
"""
import os
import re
from dataclasses import dataclass
from typing import List, Optional

IGNORED_DIRS = {
    "node_modules", ".git", "dist", "build", ".next", "coverage",
    "__pycache__", "venv", ".venv", "env", ".cache", "vendor",
}

SCANNABLE_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".html"}


@dataclass
class Rule:
    id: str
    severity: str
    pattern: "re.Pattern"
    message: str
    extensions: Optional[List[str]] = None


RULES = [
    Rule("hardcoded-aws-key", "critical", re.compile(r"AKIA[0-9A-Z]{16}"),
         "Possivel chave de acesso AWS hardcoded no codigo."),
    Rule("hardcoded-private-key", "critical",
         re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
         "Chave privada embutida diretamente no codigo-fonte."),
    Rule("hardcoded-secret-assignment", "critical",
         re.compile(r"(api[_-]?key|secret|password|senha|token)\s*[:=]\s*['\"][A-Za-z0-9+/_\-]{16,}['\"]", re.IGNORECASE),
         "Possivel segredo/senha/token hardcoded (deveria vir de variavel de ambiente)."),
    Rule("sql-string-concat-js", "critical",
         re.compile(r"(SELECT|INSERT|UPDATE|DELETE)\b[^;'\"`]*['\"`]\s*\+\s*\w+", re.IGNORECASE),
         "Query SQL montada por concatenacao de string -- risco de SQL Injection. Use queries parametrizadas.",
         extensions=[".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]),
    Rule("sql-fstring-py", "critical",
         re.compile(r"f[\"'][^\"']*(SELECT|INSERT|UPDATE|DELETE)\b[^\"']*\{", re.IGNORECASE),
         "Query SQL montada com f-string -- risco de SQL Injection. Use parametros (?, %s) da lib de banco.",
         extensions=[".py"]),
    Rule("eval-usage-js", "high", re.compile(r"\beval\s*\("),
         '"eval()" executa string como codigo -- risco serio de execucao arbitraria.',
         extensions=[".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html"]),
    Rule("eval-usage-py", "high", re.compile(r"\b(eval|exec)\s*\("),
         '"eval()/exec()" executa string como codigo -- risco serio de execucao arbitraria.',
         extensions=[".py"]),
    Rule("command-injection-node", "high",
         re.compile(r"child_process\.exec\s*\(|require\(['\"]child_process['\"]\)\.exec\s*\("),
         '"child_process.exec()" com entrada nao sanitizada pode permitir injecao de comandos. Prefira execFile/spawn com array de argumentos.',
         extensions=[".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]),
    Rule("command-injection-py", "high",
         re.compile(r"subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True|os\.system\s*\("),
         'Execucao de shell com "shell=True"/"os.system()" pode permitir injecao de comandos.',
         extensions=[".py"]),
    Rule("insecure-deserialization-py", "critical",
         re.compile(r"pickle\.loads?\s*\(|yaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)"),
         "Desserializacao insegura (pickle/yaml.load sem SafeLoader) pode executar codigo arbitrario com dados nao confiaveis.",
         extensions=[".py"]),
    Rule("debug-mode-flask", "high",
         re.compile(r"app\.run\([^)]*debug\s*=\s*True"),
         "Modo debug do Flask ativo -- nunca deve rodar assim em producao (expoe debugger interativo).",
         extensions=[".py"]),
    Rule("innerhtml-assignment", "medium", re.compile(r"\.innerHTML\s*=(?!=)"),
         "Atribuicao direta a innerHTML com dados dinamicos e um vetor comum de XSS. Prefira textContent ou sanitize o HTML.",
         extensions=[".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html"]),
    Rule("dangerously-set-innerhtml", "medium", re.compile(r"dangerouslySetInnerHTML"),
         '"dangerouslySetInnerHTML" no React so deve ser usado com HTML sanitizado (ex: DOMPurify).',
         extensions=[".jsx", ".tsx"]),
    Rule("wildcard-cors", "medium",
         re.compile(r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*['\"]"),
         'CORS liberado para qualquer origem ("*") -- restrinja para os dominios que realmente precisam de acesso.'),
    Rule("http-credentials-in-url", "medium",
         re.compile(r"https?://[^\s'\"]+:[^\s'\"@]+@[^\s'\"]+"),
         "URL com credenciais embutidas (usuario:senha@host) -- evite, use headers de autenticacao/variaveis de ambiente."),
]

DESTRUCTURED_EXEC_IMPORT = re.compile(r"const\s*\{[^}]*\bexec\b[^}]*\}\s*=\s*require\(\s*['\"]child_process['\"]\s*\)")


def _should_skip_dir(name: str) -> bool:
    return name in IGNORED_DIRS or name.startswith(".")


def _walk(root_dir: str, errors: List[dict]) -> List[str]:
    files = []
    def _record_walk_error(error: OSError) -> None:
        errors.append({"path": error.filename or root_dir, "message": str(error)})

    for dirpath, dirnames, filenames in os.walk(root_dir, onerror=_record_walk_error):
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]
        for filename in filenames:
            if os.path.splitext(filename)[1] in SCANNABLE_EXTENSIONS:
                files.append(os.path.join(dirpath, filename))
    return files


def scan_project(root_dir: str) -> dict:
    root_dir = os.path.abspath(root_dir)
    errors: List[dict] = []
    files = _walk(root_dir, errors)
    findings = []

    for file_path in files:
        ext = os.path.splitext(file_path)[1]
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError as error:
            errors.append({"path": file_path, "message": str(error)})
            continue

        lines = content.splitlines()

        if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs") and DESTRUCTURED_EXEC_IMPORT.search(content):
            for index, line in enumerate(lines):
                if re.search(r"\bexec\s*\(", line) and not DESTRUCTURED_EXEC_IMPORT.search(line):
                    findings.append({
                        "file": os.path.relpath(file_path, root_dir),
                        "line": index + 1,
                        "rule_id": "command-injection-node-destructured",
                        "severity": "high",
                        "message": '"exec()" (importado de child_process) com entrada nao sanitizada pode permitir injecao de comandos. Prefira execFile/spawn com array de argumentos.',
                        "snippet": line.strip()[:120],
                    })

        for rule in RULES:
            if rule.extensions and ext not in rule.extensions:
                continue
            for index, line in enumerate(lines):
                if rule.pattern.search(line):
                    findings.append({
                        "file": os.path.relpath(file_path, root_dir),
                        "line": index + 1,
                        "rule_id": rule.id,
                        "severity": rule.severity,
                        "message": rule.message,
                        "snippet": line.strip()[:120],
                    })

    return {"findings": findings, "files_scanned": len(files), "errors": errors}


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_LABEL = {"critical": "CRITICO", "high": "ALTO", "medium": "MEDIO", "low": "BAIXO"}


def format_report(result: dict) -> str:
    lines = [f"\ndimma scan — {result['files_scanned']} arquivo(s) analisado(s)\n"]
    findings = result["findings"]
    errors = result.get("errors", [])

    if errors:
        lines.append(f"Cobertura incompleta: {len(errors)} erro(s) ao ler ficheiros/diretorios.")
        for error in errors:
            lines.append(f"[ERRO] {error['path']}: {error['message']}")
        lines.append("")

    if not findings:
        lines.append(
            "Nenhum padrao encontrado nos ficheiros legiveis; o scan esta incompleto."
            if errors else
            "Nenhum padrao inseguro conhecido foi encontrado. \u2705"
        )
        lines.append("(Lembrete: isto e uma analise estatica leve, nao substitui revisao de codigo nem prepared statements.)")
        return "\n".join(lines)

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]])
    counts: dict = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    summary = ", ".join(
        f"{count} {SEVERITY_LABEL[sev]}"
        for sev, count in sorted(counts.items(), key=lambda kv: SEVERITY_ORDER[kv[0]])
    )
    lines.append(f"Encontrados {len(findings)} problema(s): {summary}")
    lines.append("")

    for f in sorted_findings:
        lines.append(f"[{SEVERITY_LABEL[f['severity']]}] {f['file']}:{f['line']} ({f['rule_id']})")
        lines.append(f"  {f['message']}")
        lines.append(f"  > {f['snippet']}")
        lines.append("")

    return "\n".join(lines)
