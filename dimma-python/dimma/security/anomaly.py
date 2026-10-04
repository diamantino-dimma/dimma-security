"""
Deteccao de anomalias baseada em estatistica (media + desvio padrao,
z-score), por chave (IP). Mesma abordagem do core Node.js: um modelo
estatistico honesto, leve, que aprende o padrao de trafego normal de
cada IP e sinaliza rajadas fora do comum.
"""
import logging
import math
import statistics
import threading
import time
from collections import deque
from typing import Any, Dict, Optional

try:
    from redis.exceptions import RedisError
except ImportError:
    _REDIS_ERRORS = ()
else:
    _REDIS_ERRORS = (RedisError,)


_logger = logging.getLogger("dimma.anomaly")
_REDIS_ANOMALY_SCRIPT = (
    'redis.call("RPUSH", KEYS[1], ARGV[1])\n'
    'redis.call("LTRIM", KEYS[1], -tonumber(ARGV[2]), -1)\n'
    'redis.call("EXPIRE", KEYS[1], tonumber(ARGV[3]))\n'
    'return redis.call("LRANGE", KEYS[1], 0, -1)'
)


def compute_anomaly_from_timestamps(timestamps, z_score_threshold: float = 3.0) -> dict:
    if len(timestamps) < 10:
        return {"anomalous": False, "score": 0, "reason": "dados insuficientes"}

    intervals = [
        timestamps[index] - timestamps[index - 1]
        for index in range(1, len(timestamps))
    ]
    mean = statistics.fmean(intervals)
    standard_deviation = statistics.pstdev(intervals) or 1.0
    last_interval = intervals[-1]
    z_score = abs((last_interval - mean) / standard_deviation)
    bursty = last_interval < mean - z_score_threshold * standard_deviation

    return {
        "anomalous": bool(z_score > z_score_threshold and bursty),
        "score": round(z_score, 2),
        "mean_interval_ms": round(mean),
        "last_interval_ms": round(last_interval),
    }


class AnomalyDetector:
    """
    SEGURANCA (correcao de memory-DoS): a versao anterior guardava um
    bucket por chave (IP) para sempre, sem nunca o remover -- so o
    deque interno tinha limite (window_size). Trafego sustentado de
    muitos IPs distintos fazia este dict crescer sem limite ate
    esgotar a memoria do processo. Agora ha um limite rigido de chaves
    (max_keys, com remocao das mais antigas por ultimo acesso) e uma
    limpeza periodica e barata de chaves inativas (idle_expiry_seconds),
    amortizada a cada sweep_every_n_calls chamadas -- sem threads nem
    timers em background, so corre dentro do proprio observe().
    """

    def __init__(
        self,
        window_size: int = 200,
        z_score_threshold: float = 3.0,
        max_keys: int = 50_000,
        idle_expiry_seconds: float = 3600.0,
        sweep_every_n_calls: int = 500,
    ):
        self.window_size = window_size
        self.z_score_threshold = z_score_threshold
        self.max_keys = max_keys
        self.idle_expiry_seconds = idle_expiry_seconds
        self.sweep_every_n_calls = sweep_every_n_calls
        self._history: Dict[str, deque] = {}
        self._last_seen: Dict[str, float] = {}
        self._call_count = 0
        self._lock = threading.RLock()

    def _bucket(self, key: str) -> deque:
        if key not in self._history:
            self._history[key] = deque(maxlen=self.window_size)
        return self._history[key]

    def _sweep_idle(self, now_seconds: float) -> None:
        stale = [
            key for key, last in self._last_seen.items()
            if now_seconds - last > self.idle_expiry_seconds
        ]
        for key in stale:
            self._history.pop(key, None)
            self._last_seen.pop(key, None)

    def _evict_oldest_if_over_capacity(self) -> None:
        if len(self._history) <= self.max_keys:
            return
        target = int(self.max_keys * 0.9)
        oldest_first = sorted(self._last_seen.items(), key=lambda kv: kv[1])
        to_remove = len(oldest_first) - target
        for key, _ in oldest_first[:to_remove]:
            self._history.pop(key, None)
            self._last_seen.pop(key, None)

    def observe(self, key: str, timestamp: Optional[float] = None) -> dict:
        observed_at = timestamp if timestamp is not None else time.time() * 1000
        now_seconds = observed_at / 1000.0

        with self._lock:
            self._call_count += 1
            if self._call_count % self.sweep_every_n_calls == 0:
                self._sweep_idle(now_seconds)

            bucket = self._bucket(key)
            bucket.append(observed_at)
            self._last_seen[key] = now_seconds

            self._evict_oldest_if_over_capacity()

            return compute_anomaly_from_timestamps(
                list(bucket),
                z_score_threshold=self.z_score_threshold,
            )

    def reset(self, key: str) -> None:
        with self._lock:
            self._history.pop(key, None)
            self._last_seen.pop(key, None)


class RedisAnomalyDetector:
    """Share bounded per-client anomaly history between application workers."""

    def __init__(
        self,
        redis_client: Any,
        window_size: int = 200,
        z_score_threshold: float = 3.0,
        idle_expiry_seconds: int = 3600,
    ):
        if not 10 <= window_size <= 10_000:
            raise ValueError("window_size deve estar entre 10 e 10000.")
        self.redis_client = redis_client
        self.window_size = window_size
        self.z_score_threshold = z_score_threshold
        self.idle_expiry_seconds = idle_expiry_seconds
        self._warned_unavailable = False

    def observe(self, key: str, timestamp: Optional[float] = None) -> dict:
        observed_at = timestamp if timestamp is not None else time.time() * 1000
        redis_key = f"dimma:anomaly:{key}"
        try:
            raw_timestamps = self.redis_client.eval(
                _REDIS_ANOMALY_SCRIPT,
                1,
                redis_key,
                str(observed_at),
                self.window_size,
                self.idle_expiry_seconds,
            )
            if not isinstance(raw_timestamps, (list, tuple)) or len(raw_timestamps) > self.window_size:
                raise ValueError("invalid Redis anomaly history")
            timestamps = [float(value) for value in raw_timestamps]
            if any(not math.isfinite(value) for value in timestamps):
                raise ValueError("invalid Redis anomaly timestamp")
            if any(
                timestamps[index] > timestamps[index + 1]
                for index in range(len(timestamps) - 1)
            ):
                raise ValueError("unordered Redis anomaly history")
        except (OSError, TypeError, ValueError) + _REDIS_ERRORS as error:
            return self._unavailable(error)

        return compute_anomaly_from_timestamps(
            timestamps,
            z_score_threshold=self.z_score_threshold,
        )

    def _unavailable(self, error: Exception) -> dict:
        if not self._warned_unavailable:
            self._warned_unavailable = True
            _logger.warning(
                "Redis indisponivel para deteccao distribuida de anomalias; "
                "camadas de reputacao e IA nao serao acionadas: %s",
                type(error).__name__,
            )
        return {
            "anomalous": False,
            "score": 0,
            "reason": "redis indisponivel",
        }

    def reset(self, key: str) -> None:
        try:
            self.redis_client.delete(f"dimma:anomaly:{key}")
        except (OSError,) + _REDIS_ERRORS as error:
            self._unavailable(error)
