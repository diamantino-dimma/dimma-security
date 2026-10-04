'use strict';

const assert = require('assert');
const { classifyWithAI, aiReviewMiddleware } = require('../src/security/aiClassifier');

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
  console.log('\n== dimma-ai (classificador via API NVIDIA NIM) ==');

  await test('sem NVIDIA_API_KEY, falha de forma segura (nao quebra a app)', async () => {
    const result = await classifyWithAI(
      { findings: [], rawInput: {} },
      { apiKey: undefined, fetchImpl: fakeFetch({}) }
    );
    assert.strictEqual(result.malicious, null);
  });

  await test('interpreta corretamente resposta da IA marcando como malicioso', async () => {
    const mockResponse = {
      choices: [{ message: { content: '{"malicious": true, "confidence": 0.92, "reason": "padrao de ataque conhecido"}' } }],
    };
    const result = await classifyWithAI(
      { findings: [], rawInput: {} },
      { apiKey: 'fake-key', fetchImpl: fakeFetch(mockResponse) }
    );
    assert.strictEqual(result.malicious, true);
    assert.strictEqual(result.confidence, 0.92);
  });

  await test('interpreta corretamente resposta da IA marcando como falso positivo', async () => {
    const mockResponse = {
      choices: [{ message: { content: '{"malicious": false, "confidence": 0.81, "reason": "trafego legitimo, apenas rajada de uso normal"}' } }],
    };
    const result = await classifyWithAI(
      { findings: [], rawInput: {} },
      { apiKey: 'fake-key', fetchImpl: fakeFetch(mockResponse) }
    );
    assert.strictEqual(result.malicious, false);
  });

  await test('tolera modelos "reasoning" que envolvem o JSON em texto extra', async () => {
    const mockResponse = {
      choices: [{ message: { content: 'Analisando o padrao...\n{"malicious": false, "confidence": 0.6, "reason": "sem indicios claros"}\nFim da analise.' } }],
    };
    const result = await classifyWithAI(
      { findings: [], rawInput: {} },
      { apiKey: 'fake-key', fetchImpl: fakeFetch(mockResponse) }
    );
    assert.strictEqual(result.malicious, false);
    assert.strictEqual(result.confidence, 0.6);
  });

  await test('lida com erro HTTP da API sem derrubar a aplicacao', async () => {
    await assert.rejects(
      () =>
        classifyWithAI(
          { findings: [], rawInput: {} },
          { apiKey: 'fake-key', fetchImpl: fakeFetch({ error: 'unauthorized' }, 401) }
        ),
      (err) => /falha na API NVIDIA NIM/.test(err.message) && !err.message.includes('unauthorized')
    );
  });

  await test('resposta malformada nao e convertida em decisao permissiva', async () => {
    await assert.rejects(
      () => classifyWithAI(
        { findings: [], rawInput: {} },
        {
          apiKey: 'fake-key',
          fetchImpl: fakeFetch({
            choices: [{ message: { content: '{"malicious": "false", "confidence": 9, "reason": 42}' } }],
          }),
        }
      ),
      /fora do formato esperado/
    );
  });

  await test('consulta externa tem timeout limitado e nao propaga erro bruto da rede', async () => {
    await assert.rejects(
      () => classifyWithAI(
        { findings: [], rawInput: {} },
        {
          apiKey: 'fake-key',
          timeoutMs: 10,
          fetchImpl: async (url, options) => new Promise((resolve, reject) => {
            options.signal.addEventListener('abort', () => reject(new Error('secret-bearing network error')), {
              once: true,
            });
          }),
        }
      ),
      (err) => /timeout na consulta/.test(err.message) && !err.message.includes('secret-bearing')
    );
  });

  await test('middleware nao envia IP nem corpo do pedido para NVIDIA NIM', async () => {
    let outgoingBody;
    const middleware = aiReviewMiddleware({
      apiKey: 'fake-key',
      fetchImpl: async (url, options) => {
        outgoingBody = JSON.parse(options.body);
        return {
          ok: true,
          json: async () => ({
            choices: [{ message: { content: '{"malicious": false, "confidence": 0.8, "reason": "normal"}' } }],
          }),
        };
      },
    });
    const req = {
      dimmaAnomaly: { anomalous: true, score: 4, reason: 'rajada' },
      path: '/login',
      method: 'POST',
      ip: '203.0.113.50',
      body: { password: 'do-not-send' },
    };
    let nextCalled = false;
    await middleware(req, {}, () => {
      nextCalled = true;
    });
    const externalPrompt = JSON.stringify(outgoingBody);
    assert.strictEqual(nextCalled, true);
    assert.ok(externalPrompt.includes('/login'));
    assert.ok(!externalPrompt.includes(req.ip));
    assert.ok(!externalPrompt.includes('do-not-send'));
  });

  await test('normaliza formatos OpenAI, OpenRouter, Anthropic e Gemini', async () => {
    const cases = [
      {
        provider: 'nvidia',
        response: { choices: [{ message: { content: '{"malicious": false, "confidence": 0.8, "reason": "ok"}' } }] },
        check: (url, options) => {
          assert.ok(url.includes('nvidia.com'));
          assert.ok(options.headers.Authorization.startsWith('Bearer '));
          assert.strictEqual(JSON.parse(options.body).messages[0].role, 'system');
        },
      },
      {
        provider: 'openai',
        response: { choices: [{ message: { content: '{"malicious": false, "confidence": 0.8, "reason": "ok"}' } }] },
        check: (url, options) => {
          assert.ok(url.startsWith('https://api.openai.com/'));
          assert.ok(options.headers.Authorization.startsWith('Bearer '));
        },
      },
      {
        provider: 'openrouter',
        response: { choices: [{ message: { content: '{"malicious": false, "confidence": 0.8, "reason": "ok"}' } }] },
        check: (url, options) => {
          assert.ok(url.startsWith('https://openrouter.ai/'));
          assert.ok(options.headers.Authorization.startsWith('Bearer '));
        },
      },
      {
        provider: 'anthropic',
        response: { content: [{ type: 'text', text: '{"malicious": false, "confidence": 0.8, "reason": "ok"}' }] },
        check: (url, options) => {
          assert.ok(url.startsWith('https://api.anthropic.com/'));
          assert.strictEqual(options.headers['x-api-key'], 'provider-test-key');
          assert.strictEqual(options.headers['anthropic-version'], '2023-06-01');
          assert.strictEqual(JSON.parse(options.body).messages[0].role, 'user');
        },
      },
      {
        provider: 'gemini',
        response: {
          candidates: [{
            content: { parts: [{ text: '{"malicious": false, "confidence": 0.8, "reason": "ok"}' }] },
          }],
        },
        check: (url, options) => {
          assert.ok(url.startsWith('https://generativelanguage.googleapis.com/'));
          assert.strictEqual(new URL(url).searchParams.has('key'), false);
          assert.strictEqual(options.headers['x-goog-api-key'], 'provider-test-key');
          assert.ok(JSON.parse(options.body).systemInstruction);
        },
      },
    ];

    for (const item of cases) {
      let outgoing;
      const result = await classifyWithAI(
        { findings: [{ type: 'test' }], rawInput: { method: 'GET', path: '/health' } },
        {
          provider: item.provider,
          apiKey: 'provider-test-key',
          dailyBudget: 100,
          fetchImpl: async (url, options) => {
            outgoing = { url, options };
            return { ok: true, json: async () => item.response };
          },
        }
      );
      item.check(outgoing.url, outgoing.options);
      assert.strictEqual(result.malicious, false, item.provider);
    }
  });

  await test('recusa providers desconhecidos e chave ausente nao chama a rede', async () => {
    await assert.rejects(
      () => classifyWithAI({}, { provider: 'unknown', apiKey: 'fake-key' }),
      /provider invalido/
    );
    const originalKey = process.env.OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    try {
      let called = false;
      const result = await classifyWithAI({}, {
        provider: 'openai',
        fetchImpl: async () => {
          called = true;
        },
      });
      assert.strictEqual(result.malicious, null);
      assert.strictEqual(called, false);
    } finally {
      if (originalKey !== undefined) process.env.OPENAI_API_KEY = originalKey;
    }
  });

  console.log(`\n${passed} passaram, ${failed} falharam\n`);
  if (failed > 0) process.exit(1);
}

run();
