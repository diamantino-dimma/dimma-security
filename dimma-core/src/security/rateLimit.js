'use strict';

const rateLimit = require('express-rate-limit');
const { getRedisClient } = require('../redisClient');

const FIXED_WINDOW_SCRIPT = [
  "local count = redis.call('INCR', KEYS[1])",
  "if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end",
  "return { count, redis.call('PTTL', KEYS[1]) }",
].join('\n');

/**
 * Limitador distribuido, baseado em Redis, usando uma janela fixa.
 * Script Lua garante que incremento e configuracao/consulta de TTL sejam
 * atomicos; sem isso, uma falha entre INCR e PEXPIRE poderia deixar uma
 * chave sem expiracao e bloquear o IP indefinidamente.
 *
 * Nao e um algoritmo de janela deslizante perfeito (pode permitir um
 * pequeno excesso de requisicoes exatamente na borda da janela), mas e
 * correto o suficiente para o proposito de defesa contra abuso, e o
 * mesmo compromisso que a maioria dos rate limiters de producao aceita.
 */
async function redisFixedWindowHit(redisClient, key, windowMs) {
  const [rawCount, rawTtl] = await redisClient.eval(FIXED_WINDOW_SCRIPT, 1, key, windowMs);
  const count = Number(rawCount);
  const ttl = Number(rawTtl);
  return { count, retryAfterMs: ttl > 0 ? ttl : windowMs };
}

function redisRateLimitMiddleware(redisClient, rateConfig) {
  const keyPrefix = 'dimma:rl:';

  // SEGURANCA (correcao de "fail-open em cadeia"): se o Redis falhar,
  // a versao anterior deixava passar SEM NENHUM limite -- um atacante
  // que degrade o Redis (ou so espere uma instabilidade de rede)
  // desligava o rate limiting inteiro no momento exato em que mais
  // precisamos dele. Agora, em caso de falha do Redis, caimos para um
  // limitador LOCAL em memoria (por processo) em vez de "sem limite
  // nenhum" -- perde-se a coordenacao entre instancias enquanto o
  // Redis estiver indisponivel, mas a proteção nunca cai a zero.
  const localFallback = rateLimit({
    windowMs: rateConfig.window_ms,
    max: rateConfig.max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Muitas requisicoes. Bloqueado temporariamente pelo .dimma (modo local de contingencia).' },
  });

  let warnedFallback = false;

  return async function dimmaRedisRateLimit(req, res, next) {
    const ip = req.ip || 'unknown';
    const key = `${keyPrefix}${ip}`;

    try {
      const { count, retryAfterMs } = await redisFixedWindowHit(redisClient, key, rateConfig.window_ms);

      res.setHeader('RateLimit-Limit', String(rateConfig.max));
      res.setHeader('RateLimit-Remaining', String(Math.max(0, rateConfig.max - count)));

      if (count > rateConfig.max) {
        res.setHeader('Retry-After', String(Math.ceil(retryAfterMs / 1000)));
        return res.status(429).json({ error: 'Muitas requisicoes. Bloqueado temporariamente pelo .dimma.' });
      }

      return next();
    } catch (err) {
      // Redis falhou no meio da operacao (conexao caiu, etc.): nunca
      // derruba a aplicacao por causa disso, mas tambem nunca fica sem
      // NENHUMA proteção -- usa o limitador local como contingencia.
      if (!warnedFallback) {
        warnedFallback = true;
        // eslint-disable-next-line no-console
        console.warn(
          '[dimma] falha ao consultar Redis para rate limiting -- a usar limitador LOCAL de ' +
            'contingencia (nao coordenado entre instancias) enquanto o Redis estiver indisponivel:',
          err.message
        );
      }
      return localFallback(req, res, next);
    }
  };
}

/**
 * Cria o middleware de rate limiting a partir da configuracao do .dimma
 * (ex: @rate_limit: 100 req/min -> { max: 100, window_ms: 60000 }).
 *
 * Usa Redis como armazenamento compartilhado (se REDIS_URL configurada,
 * ou um cliente injetado via testing) para que o limite funcione
 * corretamente com multiplas instancias da aplicacao atras de um load
 * balancer -- caso contrario, cai para memoria local do processo
 * (express-rate-limit), adequado para desenvolvimento/instancia unica.
 */
function rateLimitMiddleware(rateConfig = { max: 100, window_ms: 60000 }) {
  const redisClient = getRedisClient();

  if (redisClient) {
    return redisRateLimitMiddleware(redisClient, rateConfig);
  }

  return rateLimit({
    windowMs: rateConfig.window_ms,
    max: rateConfig.max,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      error: 'Muitas requisicoes. Bloqueado temporariamente pelo .dimma.',
    },
  });
}

module.exports = { rateLimitMiddleware };

