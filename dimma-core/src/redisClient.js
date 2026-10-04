'use strict';

/**
 * Cliente Redis compartilhado, opcional.
 *
 * PROBLEMA QUE ISSO RESOLVE: rate limiting e deteccao de anomalia, por
 * padrao, guardam contadores na memoria do proprio processo Node. Se a
 * aplicacao roda com mais de uma instancia atras de um load balancer
 * (o cenario normal em producao), um atacante pode distribuir as
 * requisicoes entre as instancias -- cada uma ve so uma fracao do
 * trafego, e nenhuma sozinha atinge o limite configurado.
 *
 * SOLUCAO: se a variavel de ambiente REDIS_URL estiver configurada, o
 * motor usa Redis como armazenamento compartilhado entre todas as
 * instancias. Sem ela, cai de volta para memoria local (comportamento
 * anterior, adequado para desenvolvimento/instancia unica) -- nunca
 * quebra a aplicacao por falta de Redis.
 */

let client = null;
let attempted = false;
let warnedNoRedis = false;

function getRedisClient() {
  if (attempted) return client;
  attempted = true;

  const url = process.env.REDIS_URL;
  if (!url) {
    if (!warnedNoRedis) {
      warnedNoRedis = true;
      // eslint-disable-next-line no-console
      console.warn(
        '[dimma] REDIS_URL nao configurada — rate limiting e deteccao de anomalia ' +
          'usarao memoria local (nao compartilhada entre instancias). Se sua ' +
          'aplicacao roda com mais de uma instancia/processo, configure REDIS_URL ' +
          'para que essas protecoes funcionem corretamente contra ataques distribuidos.'
      );
    }
    return null;
  }

  // eslint-disable-next-line global-require
  const Redis = require('ioredis');
  client = new Redis(url, {
    maxRetriesPerRequest: 1,
    retryStrategy: () => null, // nao fica tentando reconectar indefinidamente
    lazyConnect: false,
  });

  client.on('error', (err) => {
    // eslint-disable-next-line no-console
    console.warn('[dimma] erro de conexao com Redis, protecoes cairao para memoria local quando possivel:', err.message);
  });

  return client;
}

/** Para testes: permite injetar um cliente fake (ex: ioredis-mock). */
function _setClientForTesting(fakeClient) {
  client = fakeClient;
  attempted = true;
}

function _resetForTesting() {
  client = null;
  attempted = false;
  warnedNoRedis = false;
}

module.exports = { getRedisClient, _setClientForTesting, _resetForTesting };
