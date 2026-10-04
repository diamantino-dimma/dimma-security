"""Optional provider-backed AI review for anomaly signals, not request bodies."""
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

from .budget import consume_daily_budget

DEFAULT_DAILY_BUDGET = 200
DEFAULT_TIMEOUT_SECONDS = 5.0

SYSTEM_PROMPT = (
    "Voce e um classificador de seguranca ciberetica do .dimma. Recebe sinais "
    "minimizados de uma requisicao ja marcada localmente como suspeita. Responda "
    "estritamente em JSON: {\"malicious\": true|false, \"confidence\": 0-1, "
    "\"reason\": \"explicacao curta em portugues\"}."
)

PROVIDERS = {
    "nvidia": {
        "key_env": "NVIDIA_API_KEY",
        "model_env": "NVIDIA_MODEL",
        "default_model": "meta/llama-3.1-8b-instruct",
        "url": "https://integrate.api.nvidia.com/v1/chat/completions",
        "format": "openai",
        "label": "NVIDIA NIM",
    },
    "openai": {
        "key_env": "OPENAI_API_KEY",
        "model_env": "OPENAI_MODEL",
        "default_model": "gpt-4o-mini",
        "url": "https://api.openai.com/v1/chat/completions",
        "format": "openai",
        "label": "OpenAI",
    },
    "openrouter": {
        "key_env": "OPENROUTER_API_KEY",
        "model_env": "OPENROUTER_MODEL",
        "default_model": "meta-llama/llama-3.1-8b-instruct",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "format": "openai",
        "label": "OpenRouter",
    },
    "anthropic": {
        "key_env": "ANTHROPIC_API_KEY",
        "model_env": "ANTHROPIC_MODEL",
        "default_model": "claude-3-5-haiku-latest",
        "url": "https://api.anthropic.com/v1/messages",
        "format": "anthropic",
        "label": "Anthropic",
    },
    "gemini": {
        "key_env": "GEMINI_API_KEY",
        "model_env": "GEMINI_MODEL",
        "default_model": "gemini-2.0-flash",
        "url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "format": "gemini",
        "label": "Google Gemini",
    },
}

def _consume_daily_budget(provider: str, limit: int) -> bool:
    try:
        return bool(consume_daily_budget(f"ai:{provider}", limit)["allowed"])
    except ValueError as error:
        raise ValueError(f"dimma-ai: {error}") from None


def _provider_request(
    provider: str,
    definition: Dict[str, str],
    model: str,
    api_key: str,
    prompt: str,
) -> Tuple[str, Dict[str, str], Dict[str, Any]]:
    if provider == "anthropic":
        return (
            definition["url"],
            {
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            {
                "model": model,
                "max_tokens": 300,
                "temperature": 0,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}],
            },
        )

    if provider == "gemini":
        return (
            definition["url"].format(model=urllib.parse.quote(model, safe="")),
            {"Content-Type": "application/json", "x-goog-api-key": api_key},
            {
                "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0, "maxOutputTokens": 300},
            },
        )

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    if provider == "openrouter":
        headers["X-Title"] = "Dimma Security"
    return (
        definition["url"],
        headers,
        {
            "model": model,
            "temperature": 0,
            "max_tokens": 300,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        },
    )


def _extract_text(data: Dict[str, Any], provider_format: str) -> Optional[str]:
    if provider_format == "anthropic":
        parts = data.get("content")
        if isinstance(parts, list):
            return next(
                (
                    part.get("text")
                    for part in parts
                    if isinstance(part, dict) and part.get("type") == "text"
                ),
                None,
            )
        return None
    if provider_format == "gemini":
        try:
            parts = data["candidates"][0]["content"]["parts"]
            if not isinstance(parts, list):
                return None
            return "".join(
                text
                for part in parts
                if isinstance(part, dict)
                for text in [part.get("text", "")]
                if isinstance(text, str)
            )
        except (KeyError, IndexError, TypeError):
            return None
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None


def _parse_verdict(content: Optional[str]) -> Dict[str, Any]:
    if not isinstance(content, str) or not content.strip():
        raise ValueError("dimma-ai: resposta da IA sem conteudo de mensagem.")
    start = content.find("{")
    end = content.rfind("}")
    try:
        result = json.loads(content[start:end + 1] if start >= 0 and end > start else content.strip())
    except (json.JSONDecodeError, TypeError):
        raise ValueError("dimma-ai: resposta JSON invalida da IA.") from None

    confidence = result.get("confidence") if isinstance(result, dict) else None
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("malicious"), bool)
        or not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not 0 <= confidence <= 1
        or not isinstance(result.get("reason"), str)
    ):
        raise ValueError("dimma-ai: resposta da IA fora do formato esperado.")
    return {
        "malicious": result["malicious"],
        "confidence": float(confidence),
        "reason": result["reason"][:500],
    }


def classify_with_ai(
    payload: Dict[str, Any],
    provider: Optional[str] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    daily_budget: Optional[int] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    urlopen=None,
) -> Dict[str, Any]:
    if not isinstance(provider, (str, type(None))):
        raise ValueError("dimma-ai: provider deve ser texto.")
    selected_provider = (provider or os.environ.get("DIMMA_AI_PROVIDER") or "nvidia").lower()
    definition = PROVIDERS.get(selected_provider)
    if definition is None:
        raise ValueError(f'dimma-ai: provider invalido "{selected_provider}".')

    selected_key = api_key or os.environ.get(definition["key_env"])
    if not selected_key:
        return {
            "malicious": None,
            "confidence": 0.0,
            "reason": f"{definition['key_env']} nao configurada — IA nao consultada.",
        }
    if not isinstance(selected_key, str):
        raise ValueError("dimma-ai: chave do provider deve ser texto.")

    selected_model = (
        model
        or os.environ.get("DIMMA_AI_MODEL")
        or os.environ.get(definition["model_env"])
        or definition["default_model"]
    )
    if not isinstance(selected_model, str) or not selected_model.strip():
        raise ValueError("dimma-ai: model deve ser texto nao vazio.")
    if not isinstance(payload, dict):
        raise ValueError("dimma-ai: payload deve ser um objeto.")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("dimma-ai: timeout deve ser um numero positivo.")
    budget_limit = daily_budget
    if budget_limit is None:
        try:
            budget_limit = int(os.environ.get("DIMMA_AI_DAILY_BUDGET", DEFAULT_DAILY_BUDGET))
        except ValueError:
            raise ValueError("dimma-ai: DIMMA_AI_DAILY_BUDGET deve ser um inteiro.") from None
    if not _consume_daily_budget(selected_provider, budget_limit):
        return {
            "malicious": None,
            "confidence": 0.0,
            "reason": "Orcamento diario de chamadas de IA esgotado.",
        }

    endpoint, headers, body = _provider_request(
        selected_provider,
        definition,
        selected_model,
        selected_key,
        json.dumps(payload, ensure_ascii=False),
    )
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    open_url = urlopen or urllib.request.urlopen
    try:
        with open_url(request, timeout=timeout) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"dimma-ai: falha na API {definition['label']} ({response.status}).")
            raw_response = response.read(64 * 1024 + 1)
            if len(raw_response) > 64 * 1024:
                raise RuntimeError(f"dimma-ai: resposta demasiado grande de {definition['label']}.")
            data = json.loads(raw_response.decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"dimma-ai: falha na API {definition['label']} ({error.code}).") from None
    except urllib.error.URLError as error:
        if isinstance(error.reason, TimeoutError):
            raise RuntimeError(f"dimma-ai: timeout na consulta a {definition['label']}.") from None
        raise RuntimeError(f"dimma-ai: falha de conexao com {definition['label']}.") from None
    except TimeoutError:
        raise RuntimeError(f"dimma-ai: timeout na consulta a {definition['label']}.") from None
    except OSError:
        raise RuntimeError(f"dimma-ai: falha de conexao com {definition['label']}.") from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError(f"dimma-ai: resposta JSON invalida de {definition['label']}.") from None

    if not isinstance(data, dict):
        raise RuntimeError(f"dimma-ai: resposta JSON invalida de {definition['label']}.")
    return _parse_verdict(_extract_text(data, definition["format"]))
