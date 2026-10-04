'use strict';

const { getRedisClient } = require('../redisClient');

/**
 * Circuit breaker de cota diaria para chamadas a APIs externas
 * (AbuseIPDB, Anthropic).
 *
 * PROBLEMA QUE ISSO RESOLVE: as camadas de IA e reputacao de IP so sao
 * chamadas quando a anomalia estatistica dispara -- mas um atacante pode
 * abusar exatamente disso: gerar rajadas propositais a partir de MUITOS
 * IPs diferentes, forcando o motor a consultar a API externa repetidas
 * vezes. Isso pode (a) esgotar a cota gratuita da AbuseIPDB (~1000/dia)
 * ou (b) gerar custo real na API de IA -- e depois que a cota acaba,
 * ninguem percebe que a camada inteligente parou de proteger.
 *
 * SOLUCAO: um orcamento diario configuravel por camada. Ao atingir o
 * limite, novas chamadas sao puladas (falha segura -- nunca bloqueia a
 * aplicacao por isso) e um aviso e logado UMA vez, nao a cada requisicao.
 *
 * Usa Redis (se configurado) para o orcamento ser compartilhado entre
 * multiplas instancias -- senao cada instancia teria sua propria cota
 * "cheia", multiplicando o gasto real pelo numero de instancias.
 */

const inMemoryCounters = new Map(); // key -> { count, resetAt }
const warnedExhausted = new Set();
const warnedRedisFallback = new Set();

const REDIS_BUDGET_SCRIPT = [
  'local count = redis.call("INCR", KEYS[1])',
  'if count == 1 then redis.call("EXPIRE", KEYS[1], ARGV[1]) end',
  'return count',
].join('\n');

function todayResetTimestamp() {
  const now = new Date();
  const nextMidnightUtc = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return nextMidnightUtc;
}

async function consumeBudget(name, dailyLimit) {
  if (!Number.isSafeInteger(dailyLimit) || dailyLimit < 0) {
    throw new TypeError('dimma-budget: dailyLimit deve ser um inteiro nao negativo.');
  }

  const redisClient = getRedisClient();
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD (UTC-ish, suficiente para o proposito)
  const key = `dimma:budget:${name}:${today}`;

  let count;

  if (redisClient) {
    try {
      count = Number(await redisClient.eval(REDIS_BUDGET_SCRIPT, 1, key, 60 * 60 * 26));
      rememberLocalCount(name, count);
    } catch (err) {
      // Redis indisponivel: limitar localmente e preferivel a permitir
      // chamadas ilimitadas, que poderiam gerar custo externo ou esgotar
      // uma cota de API.
      const warningKey = `${name}:${today}`;
      if (!warnedRedisFallback.has(warningKey)) {
        warnedRedisFallback.add(warningKey);
        // eslint-disable-next-line no-console
        console.warn(
          `[dimma-budget] falha Redis no orcamento de "${name}"; a usar limite local temporario:`,
          err.message
        );
      }
      count = consumeLocalBudget(name);
    }
  } else {
    count = consumeLocalBudget(name);
  }

  const allowed = count <= dailyLimit;

  if (!allowed) {
    const warnKey = `${name}:${today}`;
    if (!warnedExhausted.has(warnKey)) {
      warnedExhausted.add(warnKey);
      // eslint-disable-next-line no-console
      console.warn(
        `[dimma-budget] orcamento diario de "${name}" esgotado (${dailyLimit} chamadas). ` +
          'Novas chamadas a essa API externa serao puladas ate a virada do dia (UTC), ' +
          'como protecao contra abuso/exaustao de cota. A aplicacao continua funcionando ' +
          'normalmente, apenas sem essa camada extra ate a cota renovar.'
      );
    }
  }

  return { allowed, remaining: Math.max(0, dailyLimit - count) };
}

function _resetForTesting() {
  inMemoryCounters.clear();
  warnedExhausted.clear();
  warnedRedisFallback.clear();
}

function consumeLocalBudget(name) {
  const bucket = inMemoryCounters.get(name);
  const now = Date.now();
  if (!bucket || now >= bucket.resetAt) {
    inMemoryCounters.set(name, { count: 1, resetAt: todayResetTimestamp() });
    return 1;
  }
  bucket.count += 1;
  return bucket.count;
}

function rememberLocalCount(name, count) {
  const bucket = inMemoryCounters.get(name);
  if (!bucket || Date.now() >= bucket.resetAt || count > bucket.count) {
    inMemoryCounters.set(name, { count, resetAt: todayResetTimestamp() });
  }
}

module.exports = { consumeBudget, _resetForTesting };
