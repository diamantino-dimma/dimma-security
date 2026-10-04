'use strict';

const assert = require('assert');
const childProcess = require('child_process');
const fs = require('fs');
const net = require('net');
const http = require('http');
const os = require('os');
const path = require('path');
const express = require('express');
const request = require('supertest');
const { parseDimma } = require('../src/parser');
const {
  containsSqlInjection,
  containsXss,
  escapeHtml,
  escapeForSql,
  scanObject,
} = require('../src/security/sanitize');
const { hashPassword, verifyPassword } = require('../src/security/auth');
const { AnomalyDetector } = require('../src/security/anomaly');
const { startProxy } = require('../src/proxy');
const { blockDirectAccessMiddleware } = require('../src/security/blockAccess');
const { DimmaEngine } = require('../src/index');
const { injectFile, injectAll, ejectFile } = require('../src/injector');
const app = require('../example/app');

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
      console.log(`FALHOU - ${name}`);
      console.log(`        ${err.message}`);
    });
}

async function run() {
  console.log('\n== Inicializacao e injector ==');
  await test('cria e carrega .dimma padrao sem exigir @files_protect', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-init-test-'));
    const configPath = path.join(tempDir, 'security.dimma');
    try {
      const engine = new DimmaEngine(configPath);
      assert.ok(fs.existsSync(configPath));
      assert.strictEqual(engine.config.auto_protect, true);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  await test('injeta protect depois de criar app Express', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-inject-test-'));
    const filePath = path.join(tempDir, 'app.js');
    fs.writeFileSync(filePath, "const express = require('express');\nconst app = express();\n", 'utf-8');
    try {
      const result = injectFile(filePath, path.join(tempDir, 'security.dimma'));
      assert.strictEqual(result.injected, true);
      const source = fs.readFileSync(filePath, 'utf-8');
      assert.ok(source.indexOf('const app = express();') < source.indexOf('_dimma.protect(app);'));
      const syntax = childProcess.spawnSync(process.execPath, ['--check', filePath], { encoding: 'utf-8' });
      assert.strictEqual(syntax.status, 0, syntax.stderr);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  await test('injeta modulo ESM em ficheiros .mjs sem depender de imports estaticos existentes', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-inject-esm-'));
    const filePath = path.join(tempDir, 'app.mjs');
    fs.writeFileSync(filePath, "import express from 'express';\nconst app = express();\n", 'utf-8');
    try {
      const result = injectFile(filePath, path.join(tempDir, 'security.dimma'));
      assert.strictEqual(result.injected, true);
      const source = fs.readFileSync(filePath, 'utf-8');
      assert.ok(source.includes('import.meta.url'));
      assert.ok(!source.includes('__dirname'));
      assert.ok(source.indexOf('const app = express();') < source.indexOf('_dimma.protect(app);'));
      const syntax = childProcess.spawnSync(process.execPath, ['--check', filePath], { encoding: 'utf-8' });
      assert.strictEqual(syntax.status, 0, syntax.stderr);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  await test('injector ignora padroes Express que so aparecem em comentarios', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-inject-comments-'));
    const filePath = path.join(tempDir, 'app.js');
    const original = [
      "const express = require('express');",
      '// const app = express();',
      '',
    ].join('\n');
    fs.writeFileSync(filePath, original, 'utf-8');
    try {
      const result = injectFile(filePath, path.join(tempDir, 'security.dimma'));
      assert.strictEqual(result.injected, false);
      assert.strictEqual(fs.readFileSync(filePath, 'utf-8'), original);
      assert.strictEqual(fs.existsSync(`${filePath}.dimma.bak`), false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  await test('injector nao sobrescreve um backup anterior', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-inject-backup-'));
    const filePath = path.join(tempDir, 'app.js');
    const original = "const express = require('express');\nconst app = express();\n";
    const previousBackup = 'backup anterior importante';
    fs.writeFileSync(filePath, original, 'utf-8');
    fs.writeFileSync(`${filePath}.dimma.bak`, previousBackup, 'utf-8');
    try {
      const result = injectFile(filePath, path.join(tempDir, 'security.dimma'));
      assert.strictEqual(result.injected, false);
      assert.match(result.error, /injecao/);
      assert.strictEqual(fs.readFileSync(filePath, 'utf-8'), original);
      assert.strictEqual(fs.readFileSync(`${filePath}.dimma.bak`, 'utf-8'), previousBackup);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  await test('eject preserva alteracoes posteriores antes de restaurar o backup', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-eject-preserve-'));
    const filePath = path.join(tempDir, 'app.js');
    const original = "const express = require('express');\nconst app = express();\n";
    fs.writeFileSync(filePath, original, 'utf-8');
    try {
      const injected = injectFile(filePath, path.join(tempDir, 'security.dimma'));
      assert.strictEqual(injected.injected, true);
      fs.appendFileSync(filePath, '\n// user change after injection\n', 'utf-8');
      const result = ejectFile(filePath);
      assert.strictEqual(result.ejected, true);
      assert.strictEqual(fs.readFileSync(filePath, 'utf-8'), original);
      assert.ok(result.preservedCurrentFile);
      assert.ok(fs.readFileSync(result.preservedCurrentFile, 'utf-8').includes('user change after injection'));
      assert.strictEqual(fs.existsSync(`${filePath}.dimma.bak`), false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  await test('eject nao restaura backup se o ficheiro atual nao tiver marcador Dimma', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-eject-unmarked-'));
    const filePath = path.join(tempDir, 'app.js');
    const current = 'alteracoes independentes do utilizador';
    const backup = 'conteudo antigo do backup';
    fs.writeFileSync(filePath, current, 'utf-8');
    fs.writeFileSync(`${filePath}.dimma.bak`, backup, 'utf-8');
    try {
      const result = ejectFile(filePath);
      assert.strictEqual(result.ejected, false);
      assert.strictEqual(fs.readFileSync(filePath, 'utf-8'), current);
      assert.strictEqual(fs.readFileSync(`${filePath}.dimma.bak`, 'utf-8'), backup);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  await test('dimma inject --dry-run aceita a flag antes do caminho e nao altera ficheiros', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-cli-dryrun-'));
    const cliPath = path.join(__dirname, '..', 'src', 'cli.js');
    const appSource = "const express = require('express');\nconst app = express();\n";
    fs.writeFileSync(path.join(tempDir, 'app.js'), appSource, 'utf-8');
    fs.writeFileSync(
      path.join(tempDir, 'security.dimma'),
      '@files_protect: [app.js]\n@auto_protect: false\n',
      'utf-8'
    );
    try {
      const result = childProcess.spawnSync(process.execPath, [cliPath, 'inject', '--dry-run'], {
        cwd: tempDir,
        encoding: 'utf-8',
      });

      assert.strictEqual(result.status, 0, result.stderr || result.stdout);
      assert.strictEqual(fs.readFileSync(path.join(tempDir, 'app.js'), 'utf-8'), appSource);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  await test('dimma ai-check valida provider e chave sem fazer chamada externa', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-cli-ai-check-'));
    const cliPath = path.join(__dirname, '..', 'src', 'cli.js');
    fs.writeFileSync(
      path.join(tempDir, 'security.dimma'),
      '@ai_provider: openrouter\n@ai_model: vendor/test-model\n',
      'utf-8'
    );
    const env = { ...process.env };
    delete env.OPENROUTER_API_KEY;
    try {
      const result = childProcess.spawnSync(process.execPath, [cliPath, 'ai-check'], {
        cwd: tempDir,
        env,
        encoding: 'utf-8',
      });
      assert.strictEqual(result.status, 1);
      assert.match(result.stdout, /Provider configurado: openrouter/);
      assert.match(result.stdout, /OPENROUTER_API_KEY: ausente/);
      assert.doesNotMatch(result.stdout, /Ligacao com o provider: OK/);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  await test('injector recusa alvos fora do projeto sem modificar ficheiros', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-inject-boundary-'));
    const projectDir = path.join(tempDir, 'project');
    const outsideDir = path.join(tempDir, 'outside');
    fs.mkdirSync(projectDir);
    fs.mkdirSync(outsideDir);
    const outsideFile = path.join(outsideDir, 'app.js');
    const original = "const express = require('express');\nconst app = express();\n";
    fs.writeFileSync(outsideFile, original, 'utf-8');
    try {
      const [result] = injectAll(['../outside/app.js'], path.join(projectDir, 'security.dimma'), {
        cwd: projectDir,
      });
      assert.strictEqual(result.injected, false);
      assert.match(result.error, /fora do diretorio do projeto/);
      assert.strictEqual(fs.readFileSync(outsideFile, 'utf-8'), original);
      assert.strictEqual(fs.existsSync(`${outsideFile}.dimma.bak`), false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  console.log('\n== Parser .dimma ==');
  await test('parser le @auto_protect: true corretamente', () => {
    const { config } = parseDimma('@auto_protect: true');
    assert.strictEqual(config.auto_protect, true);
  });

  await test('parser converte "100 req/min" em max/window_ms', () => {
    const { config } = parseDimma('@rate_limit: 100 req/min');
    assert.strictEqual(config.rate_limit.max, 100);
    assert.strictEqual(config.rate_limit.window_ms, 60000);
  });

  await test('parser converte lista @protect input: [sql_injection, xss]', () => {
    const { config } = parseDimma('@protect input: [sql_injection, xss]');
    assert.deepStrictEqual(config.protect_input, ['sql_injection', 'xss']);
  });
  await test('parser permite selecionar provider e modelo de IA', () => {
    const { config } = parseDimma('@ai_provider: openrouter\n@ai_model: vendor/model-name');
    assert.strictEqual(config.ai_provider, 'openrouter');
    assert.strictEqual(config.ai_model, 'vendor/model-name');
  });
  await test('parser aceita ficheiros UTF-8 com BOM', () => {
    const { config } = parseDimma('\uFEFF@ai_provider: openai\n@ai_model: gpt-test');
    assert.strictEqual(config.ai_provider, 'openai');
    assert.strictEqual(config.ai_model, 'gpt-test');
  });

  console.log('\n== Deteccao de SQL Injection ==');
  await test('detecta "1 OR 1=1"', () => {
    assert.strictEqual(containsSqlInjection("1 OR 1=1"), true);
  });
  await test('detecta "UNION SELECT senha FROM usuarios"', () => {
    assert.strictEqual(containsSqlInjection("' UNION SELECT senha FROM usuarios --"), true);
  });
  await test('detecta "DROP TABLE usuarios"', () => {
    assert.strictEqual(containsSqlInjection("'; DROP TABLE usuarios; --"), true);
  });
  await test('NAO bloqueia texto legitimo comum', () => {
    assert.strictEqual(containsSqlInjection("Maria D'Angelo comprou 2 itens"), false);
  });
  await test('recusa escaping SQL generico e orienta usar queries parametrizadas', () => {
    assert.throws(() => escapeForSql("' OR 1=1 --"), /queries parametrizadas/);
  });
  await test('trata input maior que o limite como nao confiavel, sem truncar', () => {
    const longInput = `${'a'.repeat(4096)}' OR 1=1 --`;
    assert.strictEqual(containsSqlInjection(longInput), true);
    assert.strictEqual(containsXss(longInput), true);
    assert.strictEqual(scanObject({ value: longInput })[0].type, 'input_too_large');
  });

  console.log('\n== Deteccao de XSS ==');
  await test('detecta <script>', () => {
    assert.strictEqual(containsXss('<script>alert(1)</script>'), true);
  });
  await test('detecta onerror=', () => {
    assert.strictEqual(containsXss('<img src=x onerror=alert(1)>'), true);
  });
  await test('escapeHtml neutraliza tags', () => {
    assert.strictEqual(escapeHtml('<b>oi</b>'), '&lt;b&gt;oi&lt;/b&gt;');
  });

  console.log('\n== Hashing de senha ==');
  await test('hash e verificacao de senha funcionam', async () => {
    const hash = await hashPassword('senhaForte123');
    const ok = await verifyPassword('senhaForte123', hash);
    const fail = await verifyPassword('senhaErrada', hash);
    assert.strictEqual(ok, true);
    assert.strictEqual(fail, false);
  });
  await test('rejeita senha curta demais', async () => {
    await assert.rejects(() => hashPassword('123'));
  });
  await test('rejeita senha que ultrapassa o limite de 72 bytes do bcrypt', async () => {
    await assert.rejects(() => hashPassword('a'.repeat(73)), /72 bytes/);
    await assert.rejects(() => verifyPassword('a'.repeat(73), 'hash-nao-utilizado'), /72 bytes/);
  });

  console.log('\n== Deteccao de anomalia (estatistica) ==');
  await test('marca rajada de requisicoes como anomalia apos padrao estabelecido', () => {
    const detector = new AnomalyDetector({ zScoreThreshold: 2 });
    const now = Date.now();
    // 15 requisicoes normais, 1 a cada 1000ms
    for (let i = 0; i < 15; i++) detector.observe('1.2.3.4', now + i * 1000);
    // rajada: proxima requisicao 5ms depois da ultima (muito mais rapido que o padrao de 1000ms)
    const result = detector.observe('1.2.3.4', now + 14 * 1000 + 5);
    assert.strictEqual(result.anomalous, true);
  });

  console.log('\n== Integracao HTTP (Express + middlewares reais) ==');

  // Fluxo real de um app protegido por CSRF: o cliente busca o token
  // primeiro (GET), guarda o cookie, e reenvia o token no header em
  // toda requisicao que muda estado (POST/PUT/DELETE).
  const agent = request.agent(app);
  const tokenRes = await agent.get('/csrf-token');
  const csrfToken = tokenRes.body.csrfToken;

  await test('bloqueia SQL Injection no body do POST /login', async () => {
    const res = await agent
      .post('/login')
      .set('x-csrf-token', csrfToken)
      .send({ username: "admin' OR '1'='1" })
      .set('Content-Type', 'application/json');
    assert.strictEqual(res.status, 400);
  });

  await test('permite login legitimo (com token CSRF valido)', async () => {
    const res = await agent
      .post('/login')
      .set('x-csrf-token', csrfToken)
      .send({ username: 'diamantino' })
      .set('Content-Type', 'application/json');
    assert.strictEqual(res.status, 200);
  });

  await test('bloqueia POST sem token CSRF (protecao contra CSRF real)', async () => {
    const res = await request(app)
      .post('/login')
      .send({ username: 'diamantino' })
      .set('Content-Type', 'application/json');
    assert.strictEqual(res.status, 403);
  });

  await test('bloqueia body acima do limite de analise sem ignorar o sufixo', async () => {
    const res = await agent
      .post('/login')
      .set('x-csrf-token', csrfToken)
      .send({ username: `${'a'.repeat(4096)}' OR 1=1 --` })
      .set('Content-Type', 'application/json');
    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.body.details[0].type, 'input_too_large');
  });

  await test('aplica headers de seguranca (helmet)', async () => {
    const res = await agent.get('/health');
    assert.ok(res.headers['x-content-type-options']);
    assert.ok(res.headers['strict-transport-security']);
  });

  await test('endpoint de registro confirma sucesso sem devolver o hash da senha ao cliente', async () => {
    const res = await agent
      .post('/register')
      .set('x-csrf-token', csrfToken)
      .send({ password: 'minhaSenhaSegura1' })
      .set('Content-Type', 'application/json');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.passwordHash, undefined);
  });

  console.log('\n== Proxy autonomo ==');
  await test('endpoint de health nao expoe credenciais nem URL do upstream', async () => {
    const portProbe = net.createServer();
    await new Promise((resolve, reject) => {
      portProbe.once('error', reject);
      portProbe.listen(0, '127.0.0.1', resolve);
    });
    const port = portProbe.address().port;
    await new Promise((resolve, reject) => {
      portProbe.close((err) => (err ? reject(err) : resolve()));
    });

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-proxy-test-'));
    const dimmaPath = path.join(tempDir, 'security.dimma');
    fs.writeFileSync(
      dimmaPath,
      [
        '@target: http://health-user:health-secret@127.0.0.1:3000',
        `@listen: ${port}`,
        '@files_protect: [app.js]',
        '@csrf_protection: false',
        '@security_headers: false',
        '@rate_limit: false',
        '@anomaly_detection: false',
        '@ai_detection: false',
        '@ip_reputation_check: false',
      ].join('\n'),
      'utf-8'
    );

    let proxy;
    try {
      proxy = await startProxy(dimmaPath, { verbose: false });
      const res = await request(proxy.server).get('/__dimma/health');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.target, undefined);
      assert.ok(!JSON.stringify(res.body).includes('health-user'));
      assert.ok(!JSON.stringify(res.body).includes('health-secret'));
      assert.strictEqual(proxy.target, 'http://127.0.0.1:3000');
    } finally {
      if (proxy) {
        await new Promise((resolve, reject) => {
          proxy.server.close((err) => (err ? reject(err) : resolve()));
        });
      }
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  await test('proxy encaminha intactos POST JSON, urlencoded e multipart', async () => {
    const upstream = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', (chunk) => chunks.push(chunk));
      req.on('end', () => {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({
          method: req.method,
          contentType: req.headers['content-type'],
          body: Buffer.concat(chunks).toString('utf-8'),
        }));
      });
    });
    await new Promise((resolve, reject) => {
      upstream.once('error', reject);
      upstream.listen(0, '127.0.0.1', resolve);
    });
    const proxyPortProbe = net.createServer();
    await new Promise((resolve, reject) => {
      proxyPortProbe.once('error', reject);
      proxyPortProbe.listen(0, '127.0.0.1', resolve);
    });
    const proxyPort = proxyPortProbe.address().port;
    await new Promise((resolve, reject) => {
      proxyPortProbe.close((err) => (err ? reject(err) : resolve()));
    });
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-proxy-body-'));
    const dimmaPath = path.join(tempDir, 'security.dimma');
    fs.writeFileSync(
      dimmaPath,
      [
        `@target: http://127.0.0.1:${upstream.address().port}`,
        `@listen: ${proxyPort}`,
        '@auto_protect: false',
        '@protect input: [sql_injection]',
        '@csrf_protection: false',
        '@security_headers: false',
        '@rate_limit: false',
      ].join('\n'),
      'utf-8'
    );

    let proxy;
    try {
      proxy = await startProxy(dimmaPath, { verbose: false });
      const jsonResponse = await request(proxy.server).post('/json').send({ value: 'original' });
      assert.strictEqual(jsonResponse.status, 200);
      assert.deepStrictEqual(JSON.parse(jsonResponse.body.body), { value: 'original' });
      assert.strictEqual(jsonResponse.body.method, 'POST');

      const primitiveResponse = await request(proxy.server)
        .post('/json-primitive')
        .set('Content-Type', 'application/json')
        .send('false');
      assert.strictEqual(primitiveResponse.status, 200);
      assert.strictEqual(primitiveResponse.body.body, 'false');

      const formResponse = await request(proxy.server).post('/form').type('form').send({ value: 'original' });
      assert.strictEqual(formResponse.status, 200);
      assert.strictEqual(formResponse.body.body, 'value=original');

      const multipartBody = [
        '--dimma-boundary',
        'Content-Disposition: form-data; name="value"',
        '',
        'original',
        '--dimma-boundary--',
        '',
      ].join('\r\n');
      const multipartResponse = await request(proxy.server)
        .post('/multipart')
        .set('Content-Type', 'multipart/form-data; boundary=dimma-boundary')
        .send(multipartBody);
      assert.strictEqual(multipartResponse.status, 200);
      assert.strictEqual(multipartResponse.body.body, multipartBody);
    } finally {
      if (proxy) await new Promise((resolve) => proxy.server.close(resolve));
      await new Promise((resolve) => upstream.close(resolve));
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  await test('proxy disponibiliza token CSRF para permitir pedidos mutáveis', async () => {
    const upstream = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ method: req.method }));
    });
    await new Promise((resolve, reject) => {
      upstream.once('error', reject);
      upstream.listen(0, '127.0.0.1', resolve);
    });
    const proxyPortProbe = net.createServer();
    await new Promise((resolve, reject) => {
      proxyPortProbe.once('error', reject);
      proxyPortProbe.listen(0, '127.0.0.1', resolve);
    });
    const proxyPort = proxyPortProbe.address().port;
    await new Promise((resolve, reject) => {
      proxyPortProbe.close((err) => (err ? reject(err) : resolve()));
    });
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-proxy-csrf-'));
    const dimmaPath = path.join(tempDir, 'security.dimma');
    fs.writeFileSync(
      dimmaPath,
      [
        `@target: http://127.0.0.1:${upstream.address().port}`,
        `@listen: ${proxyPort}`,
        '@auto_protect: true',
        '@rate_limit: false',
        '@anomaly_detection: false',
        '@ip_reputation_check: false',
      ].join('\n'),
      'utf-8'
    );

    let proxy;
    try {
      proxy = await startProxy(dimmaPath, { verbose: false });
      const client = request.agent(proxy.server);
      const tokenResponse = await client.get('/__dimma/csrf-token');
      assert.strictEqual(tokenResponse.status, 200);
      assert.ok(tokenResponse.body.csrfToken);
      const postResponse = await client
        .post('/api')
        .set('x-csrf-token', tokenResponse.body.csrfToken)
        .send({ value: 'safe' });
      assert.strictEqual(postResponse.status, 200, postResponse.text);
      assert.strictEqual(postResponse.body.method, 'POST');
    } finally {
      if (proxy) await new Promise((resolve) => proxy.server.close(resolve));
      await new Promise((resolve) => upstream.close(resolve));
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  console.log('\n== Bloqueio de ficheiros .dimma ==');
  await test('bloqueia acesso a ficheiro .dimma com ponto percent-encoded', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-static-test-'));
    fs.writeFileSync(path.join(tempDir, 'security.dimma'), '@secret: do-not-serve', 'utf-8');
    fs.writeFileSync(path.join(tempDir, 'public.txt'), 'public content', 'utf-8');
    const staticApp = express();
    staticApp.use(blockDirectAccessMiddleware());
    staticApp.use(express.static(tempDir));

    try {
      for (const encodedPath of ['/security%2edimma', '/security%25252edimma']) {
        const res = await request(staticApp).get(encodedPath);
        assert.strictEqual(res.status, 404);
        assert.ok(!res.text.includes('do-not-serve'));
      }
      const publicRes = await request(staticApp).get('/public.txt');
      assert.strictEqual(publicRes.status, 200);
      assert.strictEqual(publicRes.text, 'public content');
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  console.log(`\n${passed} passaram, ${failed} falharam\n`);
  if (failed > 0) process.exit(1);
}

run();
