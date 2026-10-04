'use strict';

const assert = require('assert');
const { checkIpReputation, isPrivateIp } = require('../src/security/reputation');

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
  console.log('\n== dimma-reputation (AbuseIPDB) ==');

  await test('reconhece IPs privados/locais e nao consulta a API', () => {
    assert.strictEqual(isPrivateIp('192.168.1.10'), true);
    assert.strictEqual(isPrivateIp('127.0.0.1'), true);
    assert.strictEqual(isPrivateIp('169.254.10.2'), true);
    assert.strictEqual(isPrivateIp('100.64.0.1'), true);
    assert.strictEqual(isPrivateIp('192.0.2.1'), true);
    assert.strictEqual(isPrivateIp('224.0.0.1'), true);
    assert.strictEqual(isPrivateIp('::'), true);
    assert.strictEqual(isPrivateIp('fc00::1'), true);
    assert.strictEqual(isPrivateIp('fe80::1'), true);
    assert.strictEqual(isPrivateIp('::ffff:192.168.1.10'), true);
    assert.strictEqual(isPrivateIp('2001:db8::1'), true);
    assert.strictEqual(isPrivateIp('8.8.8.8'), false);
    assert.strictEqual(isPrivateIp('2606:4700:4700::1111'), false);
    assert.strictEqual(isPrivateIp('not-an-ip'), false);
  });

  await test('nao consulta API para IP privado (mesmo com chave configurada)', async () => {
    const result = await checkIpReputation('10.0.0.5', { apiKey: 'fake-key', fetchImpl: fakeFetch({}) });
    assert.strictEqual(result.checked, false);
  });

  await test('sem ABUSEIPDB_API_KEY, falha de forma segura', async () => {
    const result = await checkIpReputation('118.25.6.39', { apiKey: undefined, fetchImpl: fakeFetch({}) });
    assert.strictEqual(result.checked, false);
  });

  await test('interpreta corretamente um IP com score alto de abuso', async () => {
    const mockResponse = {
      data: {
        ipAddress: '118.25.6.39',
        abuseConfidenceScore: 100,
        totalReports: 1847,
        countryCode: 'CN',
        isWhitelisted: false,
      },
    };
    const result = await checkIpReputation('118.25.6.39', { apiKey: 'fake-key', fetchImpl: fakeFetch(mockResponse) });
    assert.strictEqual(result.checked, true);
    assert.strictEqual(result.abuseConfidenceScore, 100);
    assert.strictEqual(result.totalReports, 1847);
  });

  await test('interpreta corretamente um IP limpo (score 0)', async () => {
    const mockResponse = {
      data: { ipAddress: '8.8.8.8', abuseConfidenceScore: 0, totalReports: 0, isWhitelisted: true },
    };
    const result = await checkIpReputation('8.8.8.8', { apiKey: 'fake-key', fetchImpl: fakeFetch(mockResponse) });
    assert.strictEqual(result.abuseConfidenceScore, 0);
    assert.strictEqual(result.isWhitelisted, true);
  });

  await test('lida com erro HTTP da API sem derrubar a aplicacao', async () => {
    await assert.rejects(
      () => checkIpReputation('1.2.3.4', { apiKey: 'fake-key', fetchImpl: fakeFetch({ error: 'unauthorized' }, 401) }),
      (err) => /falha na API AbuseIPDB/.test(err.message) && !err.message.includes('unauthorized')
    );
  });

  await test('rejeita endereco IP invalido antes de consultar a API', async () => {
    let called = false;
    await assert.rejects(
      () => checkIpReputation('attacker-controlled', {
        apiKey: 'fake-key',
        fetchImpl: async () => {
          called = true;
          return fakeFetch({})();
        },
      }),
      /endereco IP invalido/
    );
    assert.strictEqual(called, false);
  });

  console.log(`\n${passed} passaram, ${failed} falharam\n`);
  if (failed > 0) process.exit(1);
}

run();
