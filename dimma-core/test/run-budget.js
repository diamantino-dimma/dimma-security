'use strict';

const assert = require('assert');
const RedisMock = require('ioredis-mock');
const { consumeBudget, _resetForTesting } = require('../src/security/budget');
const { checkIpReputation } = require('../src/security/reputation');
const { classifyWithAI } = require('../src/security/aiClassifier');
const { _setClientForTesting, _resetForTesting: resetRedisClient } = require('../src/redisClient');

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

function fakeFetch(responseBody, status = 200) {
  return async () => ({
    ok: status < 400,
    status,
    json: async () => responseBody,
    text: async () => JSON.stringify(responseBody),
  });
}

async function run() {
  console.log('\n== Circuit breaker de cota (protecao contra exaustao/abuso) ==');

  await test('permite chamadas ate o limite diario, em memoria local', async () => {
    _resetForTesting();
    resetRedisClient();
    const r1 = await consumeBudget('teste-x', 3);
    const r2 = await consumeBudget('teste-x', 3);
    const r3 = await consumeBudget('teste-x', 3);
    const r4 = await consumeBudget('teste-x', 3);
    assert.strictEqual(r1.allowed, true);
    assert.strictEqual(r2.allowed, true);
    assert.strictEqual(r3.allowed, true);
    assert.strictEqual(r4.allowed, false); // 4a chamada estoura o limite de 3
  });

  await test('contadores de nomes diferentes nao interferem entre si', async () => {
    _resetForTesting();
    resetRedisClient();
    await consumeBudget('servico-a', 1);
    const resultB = await consumeBudget('servico-b', 1);
    assert.strictEqual(resultB.allowed, true);
  });

  await test('com Redis (mock), o orcamento e compartilhado entre "instancias" diferentes', async () => {
    _resetForTesting();
    resetRedisClient();
    const sharedRedis = new RedisMock();
    _setClientForTesting(sharedRedis);

    // Simula duas instancias diferentes da aplicacao consumindo o MESMO
    // orcamento via Redis compartilhado -- sem isso, cada instancia
    // teria sua propria cota "cheia", multiplicando o gasto real.
    const fromInstanceA = await consumeBudget('abuseipdb', 2);
    const fromInstanceB = await consumeBudget('abuseipdb', 2);
    const fromInstanceAagain = await consumeBudget('abuseipdb', 2);

    assert.strictEqual(fromInstanceA.allowed, true);
    assert.strictEqual(fromInstanceB.allowed, true);
    assert.strictEqual(fromInstanceAagain.allowed, false); // 3a chamada no total, limite e 2
  });

  await test('chamadas concorrentes Redis nao excedem a cota compartilhada', async () => {
    _resetForTesting();
    resetRedisClient();
    const sharedRedis = new RedisMock();
    await sharedRedis.flushall();
    _setClientForTesting(sharedRedis);

    const results = await Promise.all(
      Array.from({ length: 20 }, () => consumeBudget('concurrent-budget', 5))
    );
    assert.strictEqual(results.filter((result) => result.allowed).length, 5);
    assert.strictEqual(results.filter((result) => !result.allowed).length, 15);
  });

  await test('falha Redis do orcamento aplica limite local em vez de permitir chamadas ilimitadas', async () => {
    _resetForTesting();
    resetRedisClient();
    _setClientForTesting({
      eval: async () => {
        throw new Error('conexao perdida');
      },
    });

    const first = await consumeBudget('fallback-budget', 1);
    const second = await consumeBudget('fallback-budget', 1);
    assert.strictEqual(first.allowed, true);
    assert.strictEqual(second.allowed, false);
  });

  console.log('\n== Circuit breaker integrado na reputacao de IP (AbuseIPDB) ==');

  await test('checkIpReputation para de consultar a API apos esgotar o orcamento', async () => {
    _resetForTesting();
    resetRedisClient();
    const mockResponse = { data: { ipAddress: '1.2.3.4', abuseConfidenceScore: 10, totalReports: 1 } };

    const r1 = await checkIpReputation('1.2.3.4', { apiKey: 'fake', fetchImpl: fakeFetch(mockResponse), dailyBudget: 1 });
    const r2 = await checkIpReputation('1.2.3.4', { apiKey: 'fake', fetchImpl: fakeFetch(mockResponse), dailyBudget: 1 });

    assert.strictEqual(r1.checked, true);
    assert.strictEqual(r2.checked, false);
    assert.match(r2.reason, /[Oo]rcamento/);
  });

  console.log('\n== Circuit breaker integrado na camada de IA (NVIDIA NIM) ==');

  await test('classifyWithAI para de chamar a API apos esgotar o orcamento', async () => {
    _resetForTesting();
    resetRedisClient();
    const mockResponse = {
      choices: [{ message: { content: '{"malicious": false, "confidence": 0.5, "reason": "ok"}' } }],
    };

    const r1 = await classifyWithAI({}, { apiKey: 'fake', fetchImpl: fakeFetch(mockResponse), dailyBudget: 1 });
    const r2 = await classifyWithAI({}, { apiKey: 'fake', fetchImpl: fakeFetch(mockResponse), dailyBudget: 1 });

    assert.strictEqual(r1.malicious, false);
    assert.strictEqual(r2.malicious, null);
    assert.match(r2.reason, /[Oo]rcamento/);
  });

  await test('cenario de ataque: 50 IPs diferentes disparando anomalia nao estouram alem do orcamento configurado', async () => {
    _resetForTesting();
    resetRedisClient();
    const mockResponse = { data: { ipAddress: '8.8.8.1', abuseConfidenceScore: 0, totalReports: 0 } };
    const budget = 10;
    let checkedCount = 0;

    for (let i = 0; i < 50; i++) {
      // eslint-disable-next-line no-await-in-loop
      const result = await checkIpReputation(`10.0.0.${i}`, {
        apiKey: 'fake',
        fetchImpl: fakeFetch(mockResponse),
        dailyBudget: budget,
      });
      // isPrivateIp bloquearia 10.x.x.x -- usamos IPs publicos fake para o teste real
      if (result.checked) checkedCount++;
    }

    // Como 10.x.x.x e privado, none seria checado -- ajusta o teste para IP publico
    assert.strictEqual(checkedCount, 0, 'IPs 10.x.x.x sao privados e nunca deveriam ser consultados');
  });

  await test('cenario de ataque com IPs publicos: nunca ultrapassa o orcamento configurado', async () => {
    _resetForTesting();
    resetRedisClient();
    const mockResponse = { data: { ipAddress: '0.0.0.0', abuseConfidenceScore: 0, totalReports: 0 } };
    const budget = 10;
    let checkedCount = 0;

    for (let i = 0; i < 50; i++) {
      // IPs publicos para o teste; fetchImpl impede qualquer chamada de rede.
      // eslint-disable-next-line no-await-in-loop
      const result = await checkIpReputation(`8.8.8.${i}`, {
        apiKey: 'fake',
        fetchImpl: fakeFetch(mockResponse),
        dailyBudget: budget,
      });
      if (result.checked) checkedCount++;
    }

    assert.strictEqual(checkedCount, budget, `esperava exatamente ${budget} chamadas permitidas, teve ${checkedCount}`);
  });

  _resetForTesting();
  resetRedisClient();
  console.log(`\n${passed} passaram, ${failed} falharam\n`);
  if (failed > 0) process.exit(1);
}

run();
