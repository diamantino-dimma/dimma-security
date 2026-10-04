"""
Deteccao de anomalias baseada em estatistica (media + desvio padrao,
z-score), por chave (IP). Mesma abordagem do core Node.js: um modelo
estatistico honesto, leve, que aprende o padrao de trafego normal de
cada IP e sinaliza rajadas fora do comum.
"""
import statistics
import time
from collections import deque
from typing import Dict, Optional


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
        timestamp = timestamp if timestamp is not None else time.time() * 1000
        now_seconds = timestamp / 1000.0

        self._call_count += 1
        if self._call_count % self.sweep_every_n_calls == 0:
            self._sweep_idle(now_seconds)

        bucket = self._bucket(key)
        bucket.append(timestamp)
        self._last_seen[key] = now_seconds

        self._evict_oldest_if_over_capacity()

        if len(bucket) < 10:
            return {"anomalous": False, "score": 0, "reason": "dados insuficientes"}

        timestamps = list(bucket)
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

        mean = statistics.fmean(intervals)
        std = statistics.pstdev(intervals) or 1.0
        last_interval = intervals[-1]
        z_score = abs((last_interval - mean) / std)
        bursty = last_interval < mean - self.z_score_threshold * std

        return {
            "anomalous": bool(z_score > self.z_score_threshold and bursty),
            "score": round(z_score, 2),
            "mean_interval_ms": round(mean),
            "last_interval_ms": round(last_interval),
        }

    def reset(self, key: str) -> None:
        self._history.pop(key, None)
        self._last_seen.pop(key, None)
