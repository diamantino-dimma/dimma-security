"""AbuseIPDB checks gated by local anomaly detection and a daily budget."""
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Optional

from .budget import consume_daily_budget


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_BLOCK_THRESHOLD = 75
DEFAULT_DAILY_BUDGET = 800
MAX_RESPONSE_BYTES = 64 * 1024


def _public_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("dimma-reputation: endereco IP invalido.") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global


def check_ip_reputation(
    ip: str,
    api_key: Optional[str] = None,
    max_age_days: int = 90,
    daily_budget: int = DEFAULT_DAILY_BUDGET,
    timeout: float = 3.0,
    urlopen: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    if not isinstance(ip, str):
        raise ValueError("dimma-reputation: endereco IP invalido.")
    is_public = _public_ip(ip)
    if not is_public:
        return {
            "checked": False,
            "reason": "IP privado, local ou nao global — nao consultado.",
            "abuseConfidenceScore": 0,
        }
    if not isinstance(max_age_days, int) or isinstance(max_age_days, bool) or not 1 <= max_age_days <= 365:
        raise ValueError("dimma-reputation: max_age_days deve estar entre 1 e 365.")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 10:
        raise ValueError("dimma-reputation: timeout deve estar entre 0 e 10 segundos.")

    selected_key = api_key or os.environ.get("ABUSEIPDB_API_KEY")
    if not selected_key:
        return {
            "checked": False,
            "reason": "ABUSEIPDB_API_KEY nao configurada.",
            "abuseConfidenceScore": 0,
        }
    if not isinstance(selected_key, str):
        raise ValueError("dimma-reputation: chave API deve ser texto.")

    budget = consume_daily_budget("abuseipdb", daily_budget)
    if not budget["allowed"]:
        return {
            "checked": False,
            "reason": "Orcamento diario de consultas AbuseIPDB esgotado.",
            "abuseConfidenceScore": 0,
        }

    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": max_age_days})
    request = urllib.request.Request(
        f"{ABUSEIPDB_URL}?{query}",
        headers={"Key": selected_key, "Accept": "application/json"},
        method="GET",
    )
    open_url = urlopen or urllib.request.urlopen
    try:
        with open_url(request, timeout=timeout) as response:
            status = getattr(response, "status", None)
            if status is None:
                status = response.getcode()
            if not 200 <= status < 300:
                raise RuntimeError(f"dimma-reputation: falha na API AbuseIPDB ({status}).")
            raw_response = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"dimma-reputation: falha na API AbuseIPDB ({error.code})."
        ) from None

    if len(raw_response) > MAX_RESPONSE_BYTES:
        raise RuntimeError("dimma-reputation: resposta demasiado grande da API AbuseIPDB.")
    try:
        body = json.loads(raw_response.decode("utf-8"))
        if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
            raise TypeError("invalid data object")
        data = body["data"]
        score = data["abuseConfidenceScore"]
        report_count = data["totalReports"]
        whitelisted_value = data.get("isWhitelisted", False)
        whitelisted = False if whitelisted_value is None else whitelisted_value
        checked_ip = data["ipAddress"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
        raise RuntimeError("dimma-reputation: resposta invalida da API AbuseIPDB.") from None

    if (
        not isinstance(score, int)
        or isinstance(score, bool)
        or not 0 <= score <= 100
        or not isinstance(report_count, int)
        or isinstance(report_count, bool)
        or report_count < 0
        or not isinstance(whitelisted, bool)
        or not isinstance(checked_ip, str)
        or checked_ip != ip
    ):
        raise RuntimeError("dimma-reputation: resposta invalida da API AbuseIPDB.")

    return {
        "checked": True,
        "ip": checked_ip,
        "abuseConfidenceScore": score,
        "totalReports": report_count,
        "countryCode": data.get("countryCode"),
        "isWhitelisted": whitelisted,
    }
