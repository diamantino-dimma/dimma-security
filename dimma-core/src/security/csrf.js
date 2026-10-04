'use strict';

const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');

/**
 * Configura protecao CSRF (padrao double-submit cookie).
 * Retorna { middlewares, generateToken } para o app poder expor
 * o token ao frontend (ex: numa rota /csrf-token).
 *
 * SEGURANCA: nunca usamos um segredo padrao fixo no codigo. Um segredo
 * hardcoded compartilhado por TODOS os projetos que usam o dimma-core
 * sem configurar a variavel de ambiente permitiria a qualquer atacante
 * forjar tokens CSRF validos para qualquer um desses projetos.
 *
 * - Em producao (NODE_ENV=production): exige DIMMA_CSRF_SECRET
 *   explicitamente. Se ausente, o motor recusa iniciar (falha ruidosa,
 *   nunca silenciosa).
 * - Em desenvolvimento/teste: se DIMMA_CSRF_SECRET nao estiver definida,
 *   gera um segredo aleatorio unico por processo (nunca compartilhado
 *   entre instalacoes, nunca prevesivel), com aviso no console.
 */
function csrfProtection(options = {}) {
  const isProduction = (options.env || process.env.NODE_ENV) === 'production';
  let secret = options.secret || process.env.DIMMA_CSRF_SECRET;

  if (!secret) {
    if (isProduction) {
      throw new Error(
        'dimma: DIMMA_CSRF_SECRET nao configurada em producao. ' +
          'Defina essa variavel de ambiente com um valor aleatorio e secreto ' +
          '(ex: openssl rand -hex 32) antes de iniciar a aplicacao.'
      );
    }
    secret = crypto.randomBytes(32).toString('hex');
    // eslint-disable-next-line no-console
    console.warn(
      '[dimma] DIMMA_CSRF_SECRET nao configurada — usando segredo aleatorio ' +
        'gerado para esta execucao (valido apenas em desenvolvimento/teste). ' +
        'Configure a variavel de ambiente antes de ir para producao.'
    );
  }

  // O cookie so deve exigir HTTPS (flag Secure) em producao. Em
  // desenvolvimento/teste local (HTTP puro), Secure impediria o proprio
  // navegador de reenviar o cookie -- nao e uma falha de seguranca,
  // e o padrao correto de navegadores, entao adaptamos ao ambiente.
  const { doubleCsrfProtection, generateToken } = doubleCsrf({
    getSecret: () => secret,
    cookieName: 'dimma.csrf-token',
    cookieOptions: { sameSite: 'strict', secure: isProduction, httpOnly: true },
    size: 64,
  });

  return {
    middlewares: [cookieParser(), doubleCsrfProtection],
    generateToken,
  };
}

module.exports = { csrfProtection };

