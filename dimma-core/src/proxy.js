'use strict';

/**
 * dimma-proxy — servidor proxy de segurança autónomo.
 *
 * Ativado por `dimma start`, lê o .dimma, sobe um servidor Express
 * que:
 *   1. Aplica todas as protecoes declaradas no .dimma
 *   2. Encaminha as requisicoes validas para @target (o servidor real)
 *   3. Devolve a resposta ao cliente
 *
 * O programador NAO precisa de alterar o codigo da aplicacao. O .dimma
 * senta-se na frente como uma camada de seguranca transparente.
 *
 *   Requisicao HTTP
 *       │
 *       ▼
 *   [dimma proxy :@listen]
 *       │  Aplica todas as protecoes
 *       │  (headers, CSRF, SQLi/XSS, rate limit, anomalia, IA, reputacao)
 *       ▼
 *   [Aplicacao real :@target]
 *       │  Resposta normal
 *       ▼
 *   [dimma proxy] ──devolve──► Cliente
 *
 * Exemplo de .dimma:
 *   @target: http://localhost:3000
 *   @listen: 8080
 *   @files_protect: [app.js, routes/api.js]
 *   @auto_protect: true
 *   @rate_limit: 100 req/min
 *   @anomaly_detection: true
 */

const express = require('express');
const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');
const { DimmaEngine } = require('./index');
const fs = require('fs');

function fixDimmaRequestBody(proxyReq, req) {
  if (
    req.readableLength === 0 &&
    Object.prototype.hasOwnProperty.call(req, 'body') &&
    (req.body === null || req.body === false || req.body === 0 || req.body === '')
  ) {
    const body = JSON.stringify(req.body);
    proxyReq.setHeader('Content-Length', Buffer.byteLength(body));
    proxyReq.write(body);
    return;
  }
  fixRequestBody(proxyReq, req);
}

/**
 * Sobe o proxy dimma.
 * @param {string} dimmaFilePath
 * @param {{verbose?: boolean}} options
 * @returns {Promise<{server, port, target}>}
 */
function startProxy(dimmaFilePath, options = {}) {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(dimmaFilePath)) {
      return reject(new Error(
        `Ficheiro .dimma nao encontrado: "${dimmaFilePath}"\n` +
        'Execute "dimma init" primeiro para criar o ficheiro de configuracao.'
      ));
    }

    const dimma = new DimmaEngine(dimmaFilePath);
    const cfg   = dimma.config;

    if (!cfg.target) {
      return reject(new Error(
        'O ficheiro .dimma nao tem @target configurado.\n' +
        'Adicione a URL da sua aplicacao, por exemplo:\n' +
        '  @target: http://localhost:3000'
      ));
    }

    const listenPort = Number(cfg.listen) || 8080;
    const targetUrl  = cfg.target;
    let targetLabel = '[redacted]';
    try {
      const parsedTarget = new URL(targetUrl);
      targetLabel = `${parsedTarget.protocol}//${parsedTarget.host}`;
    } catch {
      // Never include an unparsed target value in a response or log.
    }

    const app = express();
    // Aplicar todas as protecoes do .dimma
    dimma.protect(app);

    if (typeof dimma.generateCsrfToken === 'function') {
      app.get('/__dimma/csrf-token', (req, res) => {
        res.json({ csrfToken: dimma.generateCsrfToken(req, res) });
      });
    }

    // Rota de saude do proprio proxy
    app.get('/__dimma/health', (req, res) => {
      res.json({
        status: 'ok',
        proxy: `0.0.0.0:${listenPort}`,
        protections: {
          security_headers:    Boolean(cfg.security_headers || cfg.auto_protect),
          csrf_protection:     Boolean(cfg.csrf_protection  || cfg.auto_protect),
          input_protection:    cfg.protect_input?.length > 0 || Boolean(cfg.auto_protect),
          rate_limit:          Boolean(cfg.rate_limit),
          anomaly_detection:   Boolean(cfg.anomaly_detection),
          ai_detection:        Boolean(cfg.ai_detection),
          ip_reputation_check: Boolean(cfg.ip_reputation_check),
        },
      });
    });

    // Encaminhar tudo para @target
    app.use('/', createProxyMiddleware({
      target: targetUrl,
      changeOrigin: true,
      on: {
        error: (err, req, res) => {
          const msg = err.code === 'ECONNREFUSED'
            ? `A aplicacao alvo (${targetLabel}) nao esta disponivel. Verifique se o servidor esta a correr.`
            : `Erro ao encaminhar para ${targetLabel}.`;
          console.error(`[dimma-proxy] ${msg} Codigo: ${err.code || 'desconhecido'}`);
          if (!res.headersSent) {
            res.status(502).json({ error: msg });
          }
        },
        proxyReq: (proxyReq, req) => {
          // Adicionar header a identificar que a requisicao passou pelo dimma
          proxyReq.setHeader('X-Dimma-Protected', '1');
          proxyReq.setHeader('X-Dimma-Version', '1.0.0');
          fixDimmaRequestBody(proxyReq, req);
        },
      },
    }));

    const server = app.listen(listenPort, () => {
      if (options.verbose !== false) {
        console.log(`\n[dimma] Proxy de seguranca a correr`);
        console.log(`  Escutando em : http://0.0.0.0:${listenPort}`);
        console.log(`  Protegendo   : ${targetLabel}`);
        console.log(`  Estado       : http://localhost:${listenPort}/__dimma/health`);
        console.log('');
        console.log('  Protecoes activas:');
        if (cfg.security_headers || cfg.auto_protect)  console.log('    ✓ Headers de seguranca (CSP, HSTS, X-Frame-Options)');
        if (cfg.csrf_protection   || cfg.auto_protect)  console.log('    ✓ CSRF (double-submit cookie)');
        if (cfg.protect_input?.length || cfg.auto_protect) console.log('    ✓ Sanitizacao de input (SQL Injection, XSS)');
        if (cfg.rate_limit)          console.log(`    ✓ Rate limiting (${cfg.rate_limit.max} req/${cfg.rate_limit.window_ms / 1000}s)`);
        if (cfg.anomaly_detection)   console.log('    ✓ Deteccao de anomalia estatistica');
        if (cfg.ai_detection)        console.log('    ✓ Revisao por IA (NVIDIA NIM)');
        if (cfg.ip_reputation_check) console.log('    ✓ Reputacao de IP (AbuseIPDB)');
        if (cfg.files_protect?.length) {
          console.log(`    ✓ Ficheiros protegidos: ${cfg.files_protect.join(', ')}`);
        }
        console.log('');
        console.log('  Pressione Ctrl+C para parar.');
        console.log('');
      }
      resolve({ server, port: listenPort, target: targetLabel });
    });

    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        reject(new Error(
          `A porta ${listenPort} ja esta em uso.\n` +
          `Altere @listen no .dimma para outra porta, por exemplo:\n` +
          `  @listen: 9090`
        ));
      } else {
        reject(err);
      }
    });
  });
}

module.exports = { startProxy };
