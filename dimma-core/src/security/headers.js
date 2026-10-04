'use strict';

const helmet = require('helmet');

/**
 * Retorna o middleware de headers de seguranca (baseado em helmet,
 * biblioteca padrao de mercado), com configuracao segura por padrao:
 * CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.
 */
function securityHeadersMiddleware(config = {}) {
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    referrerPolicy: { policy: 'no-referrer' },
    ...config,
  });
}

module.exports = { securityHeadersMiddleware };
