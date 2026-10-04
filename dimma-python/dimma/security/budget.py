"""Daily budgets for external service calls, shared through Redis when configured."""
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, Set, Tuple


_logger = logging.getLogger("dimma.budget")
_lock = threading.Lock()
_counts: Dict[Tuple[str, str], int] = {}
_warned: Set[str] = set()
_redis_client = None
_redis_url: str = ""
_REDIS_BUDGET_SCRIPT = (
    'local count = redis.call("INCR", KEYS[1])\n'
    'if count == 1 then redis.call("EXPIRE", KEYS[1], ARGV[1]) end\n'
    "return count"
)


def _warn_once(key: str, message: str, *args) -> None:
    with _lock:
        if key in _warned:
            return
        _warned.add(key)
    _logger.warning(message, *args)


def _next_utc_day_seconds(now: datetime) -> int:
    tomorrow = (now + timedelta(days=1)).date()
    midnight = datetime.combine(tomorrow, datetime.min.time(), tzinfo=timezone.utc)
    return max(1, int((midnight - now).total_seconds()) + 3600)


def _local_count(name: str, day: str) -> int:
    with _lock:
        for old_key in tuple(_counts):
            if old_key[1] != day:
                del _counts[old_key]
        key = (name, day)
        count = _counts.get(key, 0) + 1
        _counts[key] = count
        return count


def _get_redis_client(redis_module, redis_url: str):
    global _redis_client, _redis_url
    if _redis_client is not None and _redis_url == redis_url:
        return _redis_client
    _redis_client = redis_module.from_url(
        redis_url,
        socket_connect_timeout=1,
        socket_timeout=1,
        decode_responses=True,
    )
    _redis_url = redis_url
    return _redis_client


def consume_daily_budget(name: str, daily_limit: int) -> Dict[str, int]:
    if not isinstance(name, str) or not name.strip():
        raise ValueError("dimma-budget: name deve ser texto nao vazio.")
    if not isinstance(daily_limit, int) or isinstance(daily_limit, bool) or daily_limit < 0:
        raise ValueError("dimma-budget: daily_limit deve ser um inteiro nao negativo.")

    now = datetime.now(timezone.utc)
    day = now.date().isoformat()
    redis_url = os.environ.get("REDIS_URL")
    count = None
    redis_failed = False

    if redis_url:
        try:
            import redis
        except ImportError:
            redis = None
        if redis is None:
            redis_failed = True
            _warn_once(
                f"redis-missing:{day}",
                "REDIS_URL configurada, mas o extra dimma[redis] nao esta instalado; "
                "chamadas externas sujeitas a budget serao suspensas.",
            )
        else:
            try:
                client = _get_redis_client(redis, redis_url)
                count = int(client.eval(
                    _REDIS_BUDGET_SCRIPT,
                    1,
                    f"dimma:budget:{name}:{day}",
                    _next_utc_day_seconds(now),
                ))
                if count < 1:
                    raise ValueError("invalid Redis budget counter")
            except (redis.exceptions.RedisError, OSError, ValueError, TypeError) as error:
                redis_failed = True
                _warn_once(
                    f"redis-error:{day}",
                    "Redis indisponivel para budgets diarios; chamadas externas suspensas: %s",
                    type(error).__name__,
                )

    if count is None:
        if redis_failed:
            return {"allowed": 0, "remaining": 0, "count": 0}
        count = _local_count(name, day)

    return {
        "allowed": int(count <= daily_limit),
        "remaining": max(0, daily_limit - count),
        "count": count,
    }


def _reset_for_testing() -> None:
    global _redis_client, _redis_url
    with _lock:
        _counts.clear()
    _warned.clear()
    _redis_client = None
    _redis_url = ""
