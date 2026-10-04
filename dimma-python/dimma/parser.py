"""
Parser da linguagem .dimma (versao Python — mesma especificacao do core
Node.js, para garantir que um arquivo .dimma funcione identicamente em
qualquer stack).

Sintaxe:
    # comentario
    @comando: valor
    @comando lista: [item1, item2, item3]
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List


DEFAULTS: Dict[str, Any] = {
    "auto_protect": False,
    "encrypt_traffic": None,
    "protect_input": [],
    "rate_limit": {"max": 100, "window_ms": 60000},
    "exclude": [],
    "connect": [],
    "password_hashing": "bcrypt",
    "session_expiry_minutes": 30,
    "anomaly_detection": False,
    "ai_detection": False,
    "ai_provider": "nvidia",
    "ai_model": None,
    "csrf_protection": True,
    "security_headers": True,
    "passkey_support": False,
    "rp_id": None,
    "rp_origin": None,
    "supply_chain_guard": True,
}

COMMAND_MAP = {
    "auto_protect": "auto_protect",
    "encrypt traffic": "encrypt_traffic",
    "protect input": "protect_input",
    "rate_limit": "rate_limit",
    "exclude": "exclude",
    "connect": "connect",
    "override rate_limit": "rate_limit",
    "password_hashing": "password_hashing",
    "session_expiry": "session_expiry_minutes",
    "anomaly_detection": "anomaly_detection",
    "ai_detection": "ai_detection",
    "ai_provider": "ai_provider",
    "ai_model": "ai_model",
    "csrf_protection": "csrf_protection",
    "security_headers": "security_headers",
    "passkey_support": "passkey_support",
    "rp_id": "rp_id",
    "rp_origin": "rp_origin",
    "supply_chain_guard": "supply_chain_guard",
}

_RATE_RE = re.compile(r"^(\d+)\s*req/(sec|min|hour)$", re.IGNORECASE)
_NUM_RE = re.compile(r"^\d+(\.\d+)?$")


def _parse_value(raw: str) -> Any:
    trimmed = raw.strip()

    if trimmed == "true":
        return True
    if trimmed == "false":
        return False

    if trimmed.startswith("[") and trimmed.endswith("]"):
        return [v.strip() for v in trimmed[1:-1].split(",") if v.strip()]

    m = _RATE_RE.match(trimmed)
    if m:
        max_val = int(m.group(1))
        unit = m.group(2).lower()
        window_ms = {"sec": 1000, "min": 60000, "hour": 3600000}[unit]
        return {"max": max_val, "window_ms": window_ms}

    if _NUM_RE.match(trimmed):
        return float(trimmed) if "." in trimmed else int(trimmed)

    return trimmed


@dataclass
class DimmaCommand:
    command: str
    value: Any
    line: int


@dataclass
class DimmaConfig:
    values: Dict[str, Any] = field(default_factory=lambda: dict(DEFAULTS))
    raw_commands: List[DimmaCommand] = field(default_factory=list)

    def __getattr__(self, item):
        try:
            return self.values[item]
        except KeyError as exc:
            raise AttributeError(item) from exc

    def get(self, key, default=None):
        return self.values.get(key, default)


def parse_dimma(source: str) -> DimmaConfig:
    config = DimmaConfig()

    for line_number, raw_line in enumerate(source.removeprefix("\ufeff").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("@"):
            continue

        without_at = line[1:]
        if ":" not in without_at:
            raise SyntaxError(f'.dimma linha {line_number}: comando sem ":" -> "{line}"')

        sep = without_at.index(":")
        command_key = without_at[:sep].strip()
        raw_value = without_at[sep + 1:].strip()
        value = _parse_value(raw_value)

        config.raw_commands.append(DimmaCommand(command_key, value, line_number))

        if command_key in COMMAND_MAP:
            key = COMMAND_MAP[command_key]
            if key == "protect_input":
                existing = set(config.values.get(key, []))
                new_items = value if isinstance(value, list) else [value]
                config.values[key] = list(existing.union(new_items))
            elif key in ("exclude", "connect"):
                new_items = value if isinstance(value, list) else [value]
                config.values[key] = config.values.get(key, []) + new_items
            else:
                config.values[key] = value
        else:
            config.values[command_key.replace(" ", "_")] = value

    return config
