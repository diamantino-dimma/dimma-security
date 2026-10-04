'use strict';

const assert = require('assert');
const express = require('express');
const path = require('path');
const request = require('supertest');
const { DimmaEngine } = require('../src/index');

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
  console.log('\n== Bloqueio de acesso direto ao .dimma ==');

  await test('bloqueia GET /security.dimma mesmo com express.static mal configurado', async () => {
    const app = express();
    const dimma = new DimmaEngine(path.join(__dirname, '..', 'example', 'security.dimma'));

    // Cenario de risco real: o programador serve a raiz do projeto como
    // estatica (erro comum), o que exporia o .dimma via HTTP se nao
    // fosse pelo bloqueio do dimma.protect rodando ANTES.
    dimma.protect(app);
    app.use(express.static(path.join(__dirname, '..', 'example')));

    const res = await request(app).get('/security.dimma');
    assert.strictEqual(res.status, 404);
  });

  await test('bloqueia qualquer caminho terminado em .dimma, nao so o nome exato', async () => {
    const app = express();
    const dimma = new DimmaEngine(path.join(__dirname, '..', 'example', 'security.dimma'));
    dimma.protect(app);

    const res = await request(app).get('/config/outro-nome.dimma');
    assert.strictEqual(res.status, 404);
  });

  await test('nao bloqueia rotas normais da aplicacao', async () => {
    const app = express();
    const dimma = new DimmaEngine(path.join(__dirname, '..', 'example', 'security.dimma'));
    dimma.protect(app);
    app.get('/health', (req, res) => res.json({ status: 'ok' }));

    const res = await request(app).get('/health');
    assert.strictEqual(res.status, 200);
  });

  console.log(`\n${passed} passaram, ${failed} falharam\n`);
  if (failed > 0) process.exit(1);
}

run();
