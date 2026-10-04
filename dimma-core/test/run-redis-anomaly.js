'use strict';

const assert = require('assert');
const RedisMock = require('ioredis-mock');
const { RedisAnomalyDetector, AnomalyDetector } = require('../src/security/anomaly');

let passed = 0;
let failed = 0;

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed++;
      console.log(`  OK  - ${name}`);
    })
    .catch((err) => {
      failed++;
      console.log(`FALHOU - ${name}\n        ${err.message}`);
    });
}

async function run() {
  console.log('\n== Deteccao de anomalia distribuida via Redis (mock) ==');

  await test('RedisAnomalyDetector detecta rajada, igual a versao em memoria', async () => {
    const detector = new RedisAnomalyDetector(new RedisMock(), { zScoreThreshold: 2 });
    const now = Date.now();
    for (let i = 0; i < 15; i++) {
      // eslint-disable-next-line no-await-in-loop
      await detector.observe('1.2.3.4', now + i * 1000);
    }
    const result = await detector.observe('1.2.3.4', now + 14 * 1000 + 5);
    assert.strictEqual(result.anomalous, true);
  });

  await test('duas "instancias" da aplicacao, mesmo Redis: estatistica e compartilhada', async () => {
    const sharedRedis = new RedisMock();
    const detectorInstanceA = new RedisAnomalyDetector(sharedRedis, { zScoreThreshold: 2 });
    const detectorInstanceB = new RedisAnomalyDetector(sharedRedis, { zScoreThreshold: 2 });

    const now = Date.now();
    // Requisicoes normais do MESMO IP, alternando entre instancia A e B
    // (exatamente o cenario real: um load balancer distribuindo entre
    // processos diferentes, cada um com seu proprio RedisAnomalyDetector,
    // mas apontando para o mesmo Redis).
    for (let i = 0; i < 15; i++) {
      const detector = i % 2 === 0 ? detectorInstanceA : detectorInstanceB;
      // eslint-disable-next-line no-await-in-loop
      await detector.observe('9.9.9.9', now + i * 1000);
    }

    // A rajada acontece na instancia B, mas o padrao "normal" foi
    // aprendido pelas DUAS instancias juntas via Redis -- se o estado
    // fosse local (como no bug antigo), a instancia B teria poucos
    // dados e talvez nao detectasse nada.
    const result = await detectorInstanceB.observe('9.9.9.9', now + 14 * 1000 + 5);
    assert.strictEqual(result.anomalous, true);
  });

  await test('se o Redis falhar no meio da operacao, falha de forma segura (nao quebra)', async () => {
    const brokenRedis = {
      eval: async () => {
        throw new Error('conexao perdida');
      },
    };
    const detector = new RedisAnomalyDetector(brokenRedis, {});
    const result = await detector.observe('1.2.3.4');
    assert.strictEqual(result.anomalous, false);
  });

  await test('chaves diferentes (IPs diferentes) nao se misturam', async () => {
    const sharedRedis = new RedisMock();
    const detector = new RedisAnomalyDetector(sharedRedis, { zScoreThreshold: 2 });
    const now = Date.now();

    for (let i = 0; i < 15; i++) {
      // eslint-disable-next-line no-await-in-loop
      await detector.observe('1.1.1.1', now + i * 1000);
    }
    // IP diferente, primeira vez -- nao deve ser afetado pelo historico do outro IP
    const result = await detector.observe('2.2.2.2', now);
    assert.strictEqual(result.anomalous, false);
    assert.strictEqual(result.reason, 'dados insuficientes');
  });

  await test('observacoes concorrentes preservam o tamanho limitado da janela', async () => {
    const redis = new RedisMock();
    const detector = new RedisAnomalyDetector(redis, { windowSize: 5, zScoreThreshold: 2 });
    const now = Date.now();
    await Promise.all(
      Array.from({ length: 20 }, (_, index) => detector.observe('concurrent-ip', now + index * 1000))
    );

    const timestamps = await redis.lrange('dimma:anomaly:concurrent-ip', 0, -1);
    assert.strictEqual(timestamps.length, 5);
    assert.ok(Number(await redis.ttl('dimma:anomaly:concurrent-ip')) > 0);
  });

  console.log(`\n${passed} passaram, ${failed} falharam\n`);
  if (failed > 0) process.exit(1);
}

run();
