'use strict';

const fs = require('fs');
const express = require('express');
const { parseDimma } = require('./parser');
const { DEFAULT_TEMPLATE } = require('./template');
const { securityHeadersMiddleware } = require('./security/headers');
const { rateLimitMiddleware } = require('./security/rateLimit');
const { inputProtectionMiddleware, escapeHtml, escapeForSql } = require('./security/sanitize');
const { csrfProtection } = require('./security/csrf');
const { hashPassword, verifyPassword, generateSecureToken } = require('./security/auth');
const { anomalyDetectionMiddleware } = require('./security/anomaly');
const { aiReviewMiddleware } = require('./security/aiClassifier');
const { ipReputationMiddleware } = require('./security/reputation');
const { blockDirectAccessMiddleware } = require('./security/blockAccess');
const { WebAuthnSupport } = require('./security/webauthn');

class DimmaEngine {
  /**
   * @param {string} dimmaFilePath caminho para o arquivo .dimma do projeto
   * @param {{autoCreate?: boolean}} options se o arquivo nao existir, cria
   *   automaticamente com o perfil padrao (default: true)
   */
  constructor(dimmaFilePath, options = {}) {
    const autoCreate = options.autoCreate !== false;

    if (!fs.existsSync(dimmaFilePath)) {
      if (!autoCreate) {
        throw new Error(
          `Arquivo .dimma nao encontrado em "${dimmaFilePath}". Rode "dimma init" ou passe { autoCreate: true }.`
        );
      }
      fs.writeFileSync(dimmaFilePath, DEFAULT_TEMPLATE, 'utf-8');
      // eslint-disable-next-line no-console
      console.log(
        `[dimma] "${dimmaFilePath}" nao existia — criado automaticamente com o perfil de seguranca padrao. Ajuste conforme necessario.`
      );
    }

    const source = fs.readFileSync(dimmaFilePath, 'utf-8');
    const { config, rawCommands } = parseDimma(source);
    this.config = config;
    this.rawCommands = rawCommands;
    this.filePath = dimmaFilePath;

    // Passkeys/WebAuthn: inicializado sob demanda (lazy) so quando
    // @passkey_support: true estiver no .dimma, pois exige rpID/origin
    // validos -- nao faz sentido instanciar isso para quem nao usa.
    this.webauthn = null;
    if (this.config.passkey_support) {
      const rpID = options.rpID || this.config.rp_id;
      const origin = options.origin || this.config.rp_origin;
      if (!rpID || !origin) {
        throw new Error(
          'dimma: @passkey_support esta ativo, mas faltam @rp_id e/ou @rp_origin no .dimma ' +
            '(ou options.rpID/options.origin ao criar o DimmaEngine). Exemplo: ' +
            '@rp_id: meusite.com  /  @rp_origin: https://meusite.com'
        );
      }
      this.webauthn = new WebAuthnSupport({ rpID, origin, rpName: options.rpName });
    }
  }

  /**
   * Envolve um middleware para que ele seja pulado em caminhos declarados
   * com @exclude no .dimma (ex: um endpoint de health-check).
   */
  _skipExcluded(middleware) {
    const excluded = new Set(this.config.exclude || []);
    if (excluded.size === 0) return middleware;

    return (req, res, next) => {
      if (excluded.has(req.path)) return next();
      return middleware(req, res, next);
    };
  }

  /**
   * Aplica todas as protecoes configuradas num app Express.
   * Uso:
   *   const dimma = new DimmaEngine('./security.dimma');
   *   dimma.protect(app);
   */
  protect(app) {
    const cfg = this.config;

    // SEGURANCA: rate limiting, deteccao de anomalia e verificacao de
    // reputacao de IP dependem de req.ip estar correto. Atras de um
    // proxy/load balancer sem "trust proxy" configurado, um atacante
    // pode forjar o header X-Forwarded-For e falsificar o IP de origem,
    // esvaziando essas tres protecoes de uma vez. Avisamos se isso
    // parece mal configurado (nao corrigimos automaticamente, porque
    // configurar "trust proxy" errado tambem e um risco -- depende da
    // infraestrutura real do usuario).
    const dependsOnClientIp = cfg.rate_limit || cfg.anomaly_detection || cfg.ip_reputation_check;
    if (dependsOnClientIp && app.get('trust proxy') === false) {
      // eslint-disable-next-line no-console
      console.warn(
        '[dimma] AVISO: rate limiting/deteccao de anomalia/reputacao de IP estao ativos, ' +
          'mas "trust proxy" nao esta configurado no Express. Se sua aplicacao roda atras ' +
          'de um proxy reverso ou load balancer (Nginx, Heroku, AWS ELB, etc.), um atacante ' +
          'pode forjar o header X-Forwarded-For e burlar essas protecoes. Configure com ' +
          'app.set(\'trust proxy\', 1) (ou o numero de proxies confiaveis na sua infra).'
      );
    }

    // SEMPRE ativo, independente de configuracao: nenhum arquivo .dimma
    // deve ser acessivel via HTTP. Registrado primeiro, antes de
    // qualquer outro middleware (incluindo express.static do usuario).
    // Nao e afetado por @exclude -- essa protecao nunca deve ter excecao.
    app.use(blockDirectAccessMiddleware());

    if (cfg.security_headers || cfg.auto_protect) {
      app.use(securityHeadersMiddleware());
    }

    if (cfg.rate_limit) {
      app.use(this._skipExcluded(rateLimitMiddleware(cfg.rate_limit)));
    }

    const protectTypes = cfg.protect_input.length
      ? cfg.protect_input
      : cfg.auto_protect
      ? ['sql_injection', 'xss']
      : [];

    if (protectTypes.length) {
      app.use(express.json({ limit: '1mb', strict: false }));
      app.use(express.urlencoded({ extended: true, limit: '1mb' }));
      app.use(this._skipExcluded(inputProtectionMiddleware({ protect: protectTypes })));
    }

    if (cfg.csrf_protection || cfg.auto_protect) {
      const csrf = csrfProtection();
      csrf.middlewares.forEach((mw) => app.use(this._skipExcluded(mw)));
      this.generateCsrfToken = csrf.generateToken;
    }

    if (cfg.anomaly_detection) {
      app.use(
        this._skipExcluded(
          anomalyDetectionMiddleware({
            onAnomaly: (req, result) => {
              // eslint-disable-next-line no-console
              console.warn(`[dimma] anomalia detectada em ${req.ip} (${req.method} ${req.path})`, result);
            },
          })
        )
      );
    }

    if (cfg.ip_reputation_check) {
      app.use(this._skipExcluded(ipReputationMiddleware()));
    }

    if (cfg.ai_detection) {
      app.use(this._skipExcluded(aiReviewMiddleware({
        provider: cfg.ai_provider,
        model: cfg.ai_model,
      })));
    }

    return app;
  }

  /** Utilitarios expostos para uso direto no codigo do programador. */
  static get utils() {
    return { escapeHtml, escapeForSql, hashPassword, verifyPassword, generateSecureToken };
  }
}

module.exports = { DimmaEngine, ...DimmaEngine.utils };
