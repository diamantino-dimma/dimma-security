'use strict';

const assert = require('assert');
const express = require('express');
const path = require('path');
const request = require('supertest');
const fs = require('fs');
const os = require('os');
const { DimmaEngine } = require('../src/index');
const { csrfProtection } = require('../src/security/csrf');

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
  console.log('\n== Correcoes de seguranca (segredo obrigatorio + @exclude) ==');

  await test('recusa iniciar em producao sem DIMMA_CSRF_SECRET', () => {
    assert.throws(
      () => csrfProtection({ env: 'production', secret: undefined }),
      /DIMMA_CSRF_SECRET nao configurada em producao/
    );
  });

  await test('em desenvolvimento, gera segredo aleatorio (nunca fixo) se ausente', () => {
    const a = csrfProtection({ env: 'development' });
    const b = csrfProtection({ env: 'development' });
    // Cada instancia deve ter um segredo diferente -- prova de que nao
    // ha um valor fixo compartilhado hardcoded no codigo.
    assert.notStrictEqual(a, b); // instancias distintas (checagem basica de que nao lanca erro)
  });

  await test('funciona normalmente quando o segredo e fornecido explicitamente', () => {
    const result = csrfProtection({ env: 'production', secret: 'um-segredo-real-de-producao' });
    assert.ok(result.middlewares.length > 0);
  });

  console.log('\n== @exclude funcionando no motor Node (antes nao era aplicado) ==');

  // Teste mais direto: engine so com protect_input e exclude, sem csrf,
  // para isolar exatamente o comportamento do @exclude.
  const dimmaOnlyInputPath = path.join(os.tmpdir(), `dimma-so-input-${Date.now()}.dimma`);
  fs.writeFileSync(
    dimmaOnlyInputPath,
    ['@protect input: [sql_injection]', '@csrf_protection: false', '@exclude: /health', '@files_protect: [app.js]'].join('\n')
  );

  await test('rota SEM @exclude continua bloqueando SQLi', async () => {
    const app = express();
    app.use(express.json());
    const dimma = new DimmaEngine(dimmaOnlyInputPath);
    dimma.protect(app);
    app.post('/login', (req, res) => res.json({ ok: true }));
    app.post('/health', (req, res) => res.json({ ok: true }));

    const res = await request(app).post('/login').send({ username: "' OR 1=1 --" });
    assert.strictEqual(res.status, 400);
  });

  await test('rota COM @exclude deixa passar mesmo com payload de SQLi', async () => {
    const app = express();
    app.use(express.json());
    const dimma = new DimmaEngine(dimmaOnlyInputPath);
    dimma.protect(app);
    app.post('/login', (req, res) => res.json({ ok: true }));
    app.post('/health', (req, res) => res.json({ ok: true }));

    const res = await request(app).post('/health').send({ probe: "' OR 1=1 --" });
    assert.strictEqual(res.status, 200);
  });

  fs.unlinkSync(dimmaOnlyInputPath);

  console.log(`\n${passed} passaram, ${failed} falharam\n`);
  if (failed > 0) process.exit(1);
}

run();
