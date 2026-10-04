'use strict';

const assert = require('assert');
const express = require('express');
const request = require('supertest');
const RedisMock = require('ioredis-mock');
const { rateLimitMiddleware } = require('../src/security/rateLimit');
const { _setClientForTesting, _resetForTesting } = require('../src/redisClient');

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
  console.log('\n== Rate limiting distribuido via Redis (mock) ==');

  await test('sem Redis configurado, usa memoria local e ainda funciona', async () => {
    _resetForTesting();
    const app = express();
    app.use(rateLimitMiddleware({ max: 2, window_ms: 60000 }));
    app.get('/ping', (req, res) => res.json({ ok: true }));

    const agent = request.agent(app);
    await agent.get('/ping');
    await agent.get('/ping');
    const third = await agent.get('/ping');
    assert.strictEqual(third.status, 429);
  });

  await test('com Redis mockado, o limite e aplicado usando o store distribuido', async () => {
    _resetForTesting();
    _setClientForTesting(new RedisMock());

    const app = express();
    app.use(rateLimitMiddleware({ max: 2, window_ms: 60000 }));
    app.get('/ping', (req, res) => res.json({ ok: true }));

    const agent = request.agent(app);
    await agent.get('/ping');
    await agent.get('/ping');
    const third = await agent.get('/ping');
    assert.strictEqual(third.status, 429);
  });

  await test('duas "instancias" (dois apps) compartilhando o MESMO Redis contam juntas', async () => {
    _resetForTesting();
    const sharedRedis = new RedisMock();
    _setClientForTesting(sharedRedis);

    // App A representa a instancia 1 do servidor
    const appA = express();
    appA.use(rateLimitMiddleware({ max: 3, window_ms: 60000 }));
    appA.get('/ping', (req, res) => res.json({ instance: 'A' }));

    // App B representa a instancia 2, atras do MESMO load balancer,
    // compartilhando o mesmo Redis -- exatamente o cenario de producao
    // com multiplas instancias que o estado em memoria nao resolvia.
    _setClientForTesting(sharedRedis); // garante que ambos usem o mesmo client
    const appB = express();
    appB.use(rateLimitMiddleware({ max: 3, window_ms: 60000 }));
    appB.get('/ping', (req, res) => res.json({ instance: 'B' }));

    const agentA = request.agent(appA);
    const agentB = request.agent(appB);

    // Simula o MESMO IP de cliente batendo ora na instancia A, ora na B
    // (supertest usa 127.0.0.1 como IP por padrao em ambos os agents).
    await agentA.get('/ping'); // 1
    await agentB.get('/ping'); // 2
    await agentA.get('/ping'); // 3 (limite atingido)
    const fourth = await agentB.get('/ping'); // deveria ser bloqueado, pois o total ja e 4

    assert.strictEqual(fourth.status, 429);
  });

  await test('pedidos concorrentes nao ultrapassam o limite Redis', async () => {
    _resetForTesting();
    const redis = new RedisMock();
    await redis.flushall();
    _setClientForTesting(redis);
    const app = express();
    app.use(rateLimitMiddleware({ max: 5, window_ms: 60000 }));
    app.get('/ping', (req, res) => res.json({ ok: true }));

    const responses = await Promise.all(
      Array.from({ length: 20 }, () => request(app).get('/ping'))
    );
    const successful = responses.filter((response) => response.status === 200).length;
    const limited = responses.filter((response) => response.status === 429).length;
    assert.strictEqual(successful, 5, `statuses: ${responses.map((response) => response.status).join(',')}`);
    assert.strictEqual(limited, 15, `statuses: ${responses.map((response) => response.status).join(',')}`);
  });

  _resetForTesting();
  console.log(`\n${passed} passaram, ${failed} falharam\n`);
  if (failed > 0) process.exit(1);
}

run();
