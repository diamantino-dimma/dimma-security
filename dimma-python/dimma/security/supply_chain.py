"""
dimma supply_chain_guard — verificacao real de dependencias (versao
Python, mesma logica do supplyChain.js no dimma-core).

HONESTIDADE TECNICA: isto substitui a versao anterior, que nao existia
-- @supply_chain_guard estava documentado mas nao fazia nada. Cobre,
com meios estaticos e um check de rede opcional (fail-safe, nunca
bloqueia o CLI):

  1. Ausencia de ficheiro de lock (requirements.txt sem hashes / sem
     requirements.lock)                               (estatico)
  2. Possivel typosquatting/slopsquatting              (estatico, heuristica)
  3. Pacote recem-publicado (< N dias) no PyPI          (rede, OPT-IN)

NAO faz consulta de rede por padrao -- "dimma scan" nunca deve ligar a
internet sem o programador pedir explicitamente
(check_online=True / "dimma scan --supply-chain-online").
"""
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

POPULAR_PACKAGES = [
    "flask", "django", "requests", "numpy", "pandas", "scipy", "pytest",
    "sqlalchemy", "celery", "pillow", "boto3", "click", "jinja2", "pyyaml",
    "cryptography", "bcrypt", "redis", "gunicorn", "uvicorn", "fastapi",
    "pydantic", "aiohttp", "httpx", "setuptools", "wheel", "six", "urllib3",
]

_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*([=<>!~]{1,2}\s*[\w.\-]+)?")


def _levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    return dp[m][n]


def _parse_requirements(root_dir: str) -> Dict[str, Optional[str]]:
    """Le requirements.txt (e pyproject.toml, de forma simples) e devolve
    {nome_do_pacote: versao_ou_None}. Parser deliberadamente simples --
    nao resolve extras/markers complexos, so o que basta para auditoria."""
    deps: Dict[str, Optional[str]] = {}

    req_path = os.path.join(root_dir, "requirements.txt")
    if os.path.exists(req_path):
        with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = _REQ_LINE_RE.match(line)
                if m:
                    deps[m.group(1).lower()] = (m.group(2) or "").strip() or None

    pyproject_path = os.path.join(root_dir, "pyproject.toml")
    if os.path.exists(pyproject_path):
        with open(pyproject_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        # Extracao simples da lista "dependencies = [...]" do PEP 621,
        # sem exigir uma lib TOML -- suficiente para auditoria estatica.
        match = re.search(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
        if match:
            for raw in match.group(1).split(","):
                raw = raw.strip().strip('"').strip("'")
                if not raw:
                    continue
                m = _REQ_LINE_RE.match(raw)
                if m:
                    deps[m.group(1).lower()] = (m.group(2) or "").strip() or None

    return deps


def check_lockfile_presence(root_dir: str) -> List[Dict[str, Any]]:
    findings = []
    has_lock = any(
        os.path.exists(os.path.join(root_dir, name))
        for name in ("requirements.lock", "poetry.lock", "Pipfile.lock", "uv.lock")
    )
    has_hashes_in_requirements = False
    req_path = os.path.join(root_dir, "requirements.txt")
    if os.path.exists(req_path):
        with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
            has_hashes_in_requirements = "--hash=" in f.read()

    if not has_lock and not has_hashes_in_requirements:
        findings.append({
            "type": "lockfile-ausente",
            "severity": "medium",
            "package": None,
            "message": (
                "Nenhum ficheiro de lock (requirements.lock/poetry.lock/uv.lock) nem hashes em "
                "requirements.txt -- instalacoes nao sao reprodutiveis nem verificadas por hash. "
                "Gere um lockfile com 'pip-compile' ou use 'pip install --require-hashes'."
            ),
        })
    return findings


def check_typosquatting(declared_deps: Dict[str, Optional[str]]) -> List[Dict[str, Any]]:
    findings = []
    for name in declared_deps:
        for popular in POPULAR_PACKAGES:
            if name == popular:
                continue
            if abs(len(name) - len(popular)) > 2:
                continue
            dist = _levenshtein(name, popular)
            if dist == 1 and len(name) > 2:
                findings.append({
                    "type": "possivel-typosquatting",
                    "severity": "high",
                    "package": name,
                    "message": (
                        f'"{name}" e muito semelhante ao pacote popular "{popular}" '
                        "(distancia de edicao = 1). Confirme que nao e typosquatting/slopsquatting "
                        "antes de instalar -- um nome alucinado por IA registado por um atacante "
                        "tem exatamente este aspeto."
                    ),
                })
    return findings


def check_recently_published(
    declared_deps: Dict[str, Optional[str]],
    max_age_days: int = 7,
    registry_url: str = "https://pypi.org/pypi",
    timeout: float = 5.0,
) -> List[Dict[str, Any]]:
    """
    Consulta o PyPI para cada dependencia -- REDE, chamada apenas quando
    o chamador pedir explicitamente (check_online=True). Falha de forma
    segura: qualquer erro de rede/parsing so marca esse pacote como nao
    verificado, nunca interrompe a auditoria dos restantes.
    """
    findings = []
    now = datetime.now(timezone.utc)

    for name in declared_deps:
        try:
            url = f"{registry_url}/{name}/json"
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            releases = data.get("releases", {})
            info = data.get("info", {})
            latest_version = info.get("version")
            release_files = releases.get(latest_version, [])
            if not release_files:
                continue

            upload_time = release_files[0].get("upload_time_iso_8601")
            if not upload_time:
                continue

            published_at = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
            age_days = (now - published_at).total_seconds() / 86400

            if 0 <= age_days < max_age_days:
                findings.append({
                    "type": "pacote-recentemente-publicado",
                    "severity": "high",
                    "package": name,
                    "message": (
                        f'"{name}" (versao mais recente "{latest_version}") foi publicado ha '
                        f"{int(age_days)} dia(s) -- ainda nao teve tempo de ser escrutinado pela "
                        "comunidade. Reveja manualmente antes de confiar em producao."
                    ),
                })
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError, OSError):
            # Falha de rede/parsing: nunca quebra a auditoria, so deixa
            # de verificar esse pacote (falha segura).
            continue

    return findings


def audit_supply_chain(root_dir: str, check_online: bool = False, max_age_days: int = 7) -> Dict[str, Any]:
    declared_deps = _parse_requirements(root_dir)

    if not declared_deps:
        return {
            "findings": [],
            "dependencies_checked": 0,
            "skipped": True,
            "reason": "nenhuma dependencia encontrada em requirements.txt/pyproject.toml",
        }

    findings: List[Dict[str, Any]] = []
    findings.extend(check_lockfile_presence(root_dir))
    findings.extend(check_typosquatting(declared_deps))

    online_checked = False
    if check_online:
        findings.extend(check_recently_published(declared_deps, max_age_days=max_age_days))
        online_checked = True

    return {
        "findings": findings,
        "dependencies_checked": len(declared_deps),
        "online_check_performed": online_checked,
    }


SEVERITY_LABEL = {"critical": "CRITICO", "high": "ALTO", "medium": "MEDIO", "low": "BAIXO"}


def format_supply_chain_report(result: Dict[str, Any]) -> str:
    lines = ["\ndimma supply_chain_guard — auditoria de dependencias\n"]

    if result.get("skipped"):
        lines.append(f"Pulado: {result['reason']}")
        return "\n".join(lines)

    lines.append(f"{result['dependencies_checked']} dependencia(s) verificada(s).")
    lines.append(
        "Verificacao de idade de publicacao: ATIVA (consulta ao PyPI)."
        if result.get("online_check_performed")
        else "Verificacao de idade de publicacao: DESATIVADA (use --supply-chain-online para ativar)."
    )
    lines.append("")

    findings = result["findings"]
    if not findings:
        lines.append("Nenhum problema de supply chain encontrado. \u2705")
        return "\n".join(lines)

    for f in findings:
        pkg = f" [{f['package']}]" if f.get("package") else ""
        lines.append(f"[{SEVERITY_LABEL.get(f['severity'], f['severity'].upper())}]{pkg} ({f['type']})")
        lines.append(f"  {f['message']}")
        lines.append("")

    return "\n".join(lines)
