'use strict';

const { getRedisClient } = require('../redisClient');

/**
 * Deteccao de anomalias baseada em estatistica (media + desvio padrao,
 * z-score) por IP e por rota. E uma base HONESTA de "IA embutida":
 * nao e uma rede neural, e um modelo estatistico que aprende o
 * comportamento normal do trafego e sinaliza desvios. E leve, roda
 * embutido no processo Node, e pode ser evoluido para um classificador
 * mais robusto (ex: Isolation Forest) sem mudar a interface publica.
 */

function mean(arr) {
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stdDev(arr, m) {
  const variance = arr.reduce((sum, v) => sum + (v - m) ** 2, 0) / arr.length;
  return Math.sqrt(variance);
}

const REDIS_ANOMALY_SCRIPT = [
  'redis.call("RPUSH", KEYS[1], ARGV[1])',
  'redis.call("LTRIM", KEYS[1], -tonumber(ARGV[2]), -1)',
  'redis.call("EXPIRE", KEYS[1], tonumber(ARGV[3]))',
  'return redis.call("LRANGE", KEYS[1], 0, -1)',
].join('\n');

function computeAnomalyFromTimestamps(timestamps, zScoreThreshold) {
  if (timestamps.length < 10) {
    return { anomalous: false, score: 0, reason: 'dados insuficientes' };
  }

  const intervals = [];
  for (let i = 1; i < timestamps.length; i++) {
    intervals.push(timestamps[i] - timestamps[i - 1]);
  }

  const m = mean(intervals);
  const std = stdDev(intervals, m) || 1;
  const lastInterval = intervals[intervals.length - 1];
  const zScore = Math.abs((lastInterval - m) / std);
  const bursty = lastInterval < m - zScoreThreshold * std;

  return {
    anomalous: zScore > zScoreThreshold && bursty,
    score: Number(zScore.toFixed(2)),
    meanIntervalMs: Math.round(m),
    lastIntervalMs: Math.round(lastInterval),
  };
}

/**
 * Versao em memoria local (padrao para desenvolvimento/instancia unica).
 *
 * SEGURANCA (correcao de memory-DoS): a versao anterior guardava um
 * bucket por chave (IP) para sempre, sem nunca o remover -- so o
 * ARRAY dentro de cada bucket tinha limite (windowSize). Trafego
 * sustentado de muitos IPs distintos (real ou, se "trust proxy" estiver
 * mal configurado, forjado via X-Forwarded-For) fazia este Map crescer
 * sem limite ate esgotar a memoria do processo. Agora o detetor tem:
 *   1. um limite rigido de chaves (maxKeys) com remocao das mais
 *      antigas (por ultimo acesso) quando excedido;
 *   2. uma limpeza periodica e barata de chaves inativas ha mais de
 *      idleExpiryMs, amortizada (so corre a cada sweepEveryNCalls
 *      chamadas, nunca com setInterval -- nao mantem o processo vivo
 *      nem complica testes).
 */
class AnomalyDetector {
  constructor({
    windowSize = 200,
    zScoreThreshold = 3,
    maxKeys = 50000,
    idleExpiryMs = 60 * 60 * 1000, // 1h, mesmo valor do RedisAnomalyDetector
    sweepEveryNCalls = 500,
  } = {}) {
    this.windowSize = windowSize;
    this.zScoreThreshold = zScoreThreshold;
    this.maxKeys = maxKeys;
    this.idleExpiryMs = idleExpiryMs;
    this.sweepEveryNCalls = sweepEveryNCalls;
    // historico de intervalos entre requisicoes, por chave (ip ou ip+rota)
    this.history = new Map(); // key -> { timestamps: number[], lastSeen: number }
    this._callCount = 0;
  }

  _getBucket(key, now) {
    let bucket = this.history.get(key);
    if (!bucket) {
      bucket = { timestamps: [], lastSeen: now };
      this.history.set(key, bucket);
    }
    return bucket;
  }

  /** Remove chaves inativas ha mais de idleExpiryMs. Barato: so percorre o Map. */
  _sweepIdle(now) {
    for (const [key, bucket] of this.history) {
      if (now - bucket.lastSeen > this.idleExpiryMs) {
        this.history.delete(key);
      }
    }
  }

  /** Remove as chaves mais antigas (por lastSeen) ate caber em maxKeys. */
  _evictOldestIfOverCapacity() {
    if (this.history.size <= this.maxKeys) return;
    // Hysteresis: desce para 90% do limite para nao reavaliar a cada
    // chamada exatamente na fronteira.
    const target = Math.floor(this.maxKeys * 0.9);
    const entries = Array.from(this.history.entries());
    entries.sort((a, b) => a[1].lastSeen - b[1].lastSeen);
    const toRemove = entries.length - target;
    for (let i = 0; i < toRemove; i++) {
      this.history.delete(entries[i][0]);
    }
  }

  /**
   * Registra uma requisicao e retorna um score de anomalia (0 = normal,
   * quanto maior mais anomalo) baseado na frequencia de requisicoes
   * daquela chave (IP, ou IP+rota) comparada ao padrao historico dela.
   */
  observe(key, timestamp = Date.now()) {
    this._callCount++;
    if (this._callCount % this.sweepEveryNCalls === 0) {
      this._sweepIdle(timestamp);
    }

    const bucket = this._getBucket(key, timestamp);
    bucket.lastSeen = timestamp;
    bucket.timestamps.push(timestamp);
    if (bucket.timestamps.length > this.windowSize) {
      bucket.timestamps.shift();
    }

    this._evictOldestIfOverCapacity();

    return computeAnomalyFromTimestamps(bucket.timestamps, this.zScoreThreshold);
  }

  reset(key) {
    this.history.delete(key);
  }
}

/**
 * Versao distribuida via Redis: guarda os timestamps de cada chave numa
 * lista Redis compartilhada entre TODAS as instancias da aplicacao, para
 * que a estatistica de "trafego normal" de um IP seja a mesma nao
 * importa em qual instancia a requisicao caiu -- resolvendo o mesmo
 * problema de estado nao-distribuido corrigido no rate limiting.
 */
class RedisAnomalyDetector {
  constructor(redisClient, { windowSize = 200, zScoreThreshold = 3 } = {}) {
    this.redisClient = redisClient;
    this.windowSize = windowSize;
    this.zScoreThreshold = zScoreThreshold;
    this.keyPrefix = 'dimma:anomaly:';
    // Se uma chave ficar sem novas requisicoes por 1h, expira sozinha
    // (limpeza automatica, nao acumula lixo no Redis para sempre).
    this.idleExpirySeconds = 3600;
  }

  async observe(key, timestamp = Date.now()) {
    const redisKey = `${this.keyPrefix}${key}`;
    try {
      const raw = await this.redisClient.eval(
        REDIS_ANOMALY_SCRIPT,
        1,
        redisKey,
        String(timestamp),
        this.windowSize,
        this.idleExpirySeconds
      );
      const timestamps = raw.map(Number);
      return computeAnomalyFromTimestamps(timestamps, this.zScoreThreshold);
    } catch (err) {
      // Redis indisponivel: nunca quebra a aplicacao -- so deixa de
      // detectar anomalia temporariamente (falha segura).
      // eslint-disable-next-line no-console
      console.warn('[dimma] falha ao consultar Redis para deteccao de anomalia:', err.message);
      return { anomalous: false, score: 0, reason: 'redis indisponivel' };
    }
  }

  async reset(key) {
    await this.redisClient.del(`${this.keyPrefix}${key}`);
  }
}

/**
 * Middleware Express que usa o AnomalyDetector por IP (memoria local ou
 * Redis distribuido, dependendo de REDIS_URL estar configurada).
 * Nao bloqueia sozinho por padrao (evita falsos positivos derrubarem
 * usuarios legitimos) -- registra e chama onAnomaly para o app decidir
 * (logar, exigir captcha, bloquear temporariamente, etc.).
 */
function anomalyDetectionMiddleware(options = {}) {
  const redisClient = getRedisClient();
  const detector = redisClient ? new RedisAnomalyDetector(redisClient, options) : new AnomalyDetector(options);
  const onAnomaly = options.onAnomaly || (() => {});

  return async function dimmaAnomalyDetection(req, res, next) {
    const key = req.ip || 'unknown';
    const result = await detector.observe(key);
    if (result.anomalous) {
      onAnomaly(req, result);
      req.dimmaAnomaly = result;
    }
    next();
  };
}

module.exports = { AnomalyDetector, RedisAnomalyDetector, anomalyDetectionMiddleware };
