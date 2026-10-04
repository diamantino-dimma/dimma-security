'use strict';

const net = require('net');
const { consumeBudget } = require('./budget');

/**
 * Verificacao de reputacao de IP via AbuseIPDB — API gratuita,
 * profissional e especializada em seguranca cibernetica, mantida pela
 * comunidade de administradores de sistema e analistas de seguranca.
 *
 * https://docs.abuseipdb.com/  (free tier: ~1000 consultas/dia)
 *
 * So consultamos a API quando a camada estatistica (anomaly.js) ja
 * sinalizou uma rajada suspeita -- isso preserva a cota gratuita e evita
 * gastar uma chamada de API por requisicao normal.
 */

const ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check';

// A AbuseIPDB recomenda nao usar score < 25% como base de acao (ruido
// demais); 75-100 e a faixa recomendada para bloqueio de negacao de
// servico / ataque confirmado.
const DEFAULT_BLOCK_THRESHOLD = 75;

// Circuit breaker: fica um pouco abaixo do limite gratuito real
// (~1000/dia) para deixar folga para uso manual/outras integracoes, e
// para impedir que um atacante distribuido esgote a cota inteira antes
// de alguem perceber.
const DEFAULT_DAILY_BUDGET = 800;

function parseIpv4(ip) {
  if (net.isIP(ip) !== 4) return null;
  return ip.split('.').map(Number);
}

function isPrivateIpv4(ip) {
  const octets = parseIpv4(ip);
  if (!octets) return true;
  const [a, b, c] = octets;

  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function parseIpv6(ip) {
  if (net.isIP(ip) !== 6) return null;
  const normalized = ip.toLowerCase();
  const embeddedIpv4 = normalized.match(/(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  const address = embeddedIpv4
    ? normalized.replace(embeddedIpv4[1], parseIpv4(embeddedIpv4[1])
      .map((octet) => octet.toString(16).padStart(2, '0'))
      .join('')
      .match(/.{1,4}/g)
      .join(':'))
    : normalized;
  const halves = address.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const zeroCount = 8 - left.length - right.length;
  const groups = [...left, ...Array(zeroCount).fill('0'), ...right];

  return groups.length === 8 ? groups.map((group) => parseInt(group || '0', 16)) : null;
}

function isPrivateIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) return isPrivateIpv4(ip);
  if (version !== 6) return false;

  const groups = parseIpv6(ip);
  if (!groups) return true;

  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
    const mappedIpv4 = [
      groups[6] >> 8,
      groups[6] & 0xff,
      groups[7] >> 8,
      groups[7] & 0xff,
    ].join('.');
    return isPrivateIpv4(mappedIpv4);
  }

  const first = groups[0];
  const globalUnicast = first >= 0x2000 && first <= 0x3fff;
  const documentation = first === 0x2001 && groups[1] === 0x0db8;
  return !globalUnicast || documentation;
}

/**
 * Consulta a AbuseIPDB para um IP especifico.
 * @param {string} ip
 * @param {{apiKey?: string, maxAgeInDays?: number, fetchImpl?: Function, dailyBudget?: number}} options
 */
async function checkIpReputation(ip, options = {}) {
  if (net.isIP(ip) === 0) {
    throw new TypeError('dimma-reputation: endereco IP invalido.');
  }
  const apiKey = options.apiKey || process.env.ABUSEIPDB_API_KEY;
  const fetchImpl = options.fetchImpl || fetch;
  const maxAgeInDays = options.maxAgeInDays || 90;
  const dailyBudget = options.dailyBudget || DEFAULT_DAILY_BUDGET;

  if (isPrivateIp(ip)) {
    return { checked: false, reason: 'IP privado/local — nao consultado.', abuseConfidenceScore: 0 };
  }

  if (!apiKey) {
    return { checked: false, reason: 'ABUSEIPDB_API_KEY nao configurada.', abuseConfidenceScore: 0 };
  }

  const budget = await consumeBudget('abuseipdb', dailyBudget);
  if (!budget.allowed) {
    return { checked: false, reason: 'Orcamento diario de consultas AbuseIPDB esgotado.', abuseConfidenceScore: 0 };
  }

  const url = new URL(ABUSEIPDB_URL);
  url.searchParams.set('ipAddress', ip);
  url.searchParams.set('maxAgeInDays', String(maxAgeInDays));

  const response = await fetchImpl(url.toString(), {
    method: 'GET',
    headers: { Key: apiKey, Accept: 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`dimma-reputation: falha na API AbuseIPDB (${response.status}).`);
  }

  const body = await response.json();
  const data = body.data || {};

  return {
    checked: true,
    ip: data.ipAddress,
    abuseConfidenceScore: data.abuseConfidenceScore ?? 0,
    totalReports: data.totalReports ?? 0,
    countryCode: data.countryCode ?? null,
    isWhitelisted: Boolean(data.isWhitelisted),
    isp: data.isp ?? null,
  };
}

/**
 * Middleware Express: so consulta a AbuseIPDB quando uma camada anterior
 * (anomaly.js) ja marcou `req.dimmaAnomaly.anomalous = true`. Bloqueia se
 * o score de abuso estiver acima do limiar configurado.
 */
function ipReputationMiddleware(options = {}) {
  const threshold = options.blockThreshold || DEFAULT_BLOCK_THRESHOLD;
  const dailyLimit = options.maxCallsPerDay || 900; // folga sob o teto gratuito de ~1000/dia

  return async function dimmaIpReputation(req, res, next) {
    const suspicious = req.dimmaAnomaly && req.dimmaAnomaly.anomalous;
    if (!suspicious) return next();

    const { allowed } = await consumeBudget('ip_reputation_check', dailyLimit);
    if (!allowed) {
      // Orcamento diario esgotado -- pula a consulta (falha segura),
      // continua confiando na camada estatistica anterior.
      return next();
    }

    try {
      const reputation = await checkIpReputation(req.ip, options);
      req.dimmaReputation = reputation;

      if (reputation.checked && !reputation.isWhitelisted && reputation.abuseConfidenceScore >= threshold) {
        return res.status(403).json({
          error: 'Requisicao bloqueada pelo .dimma: IP com historico de abuso conhecido (AbuseIPDB).',
          abuseConfidenceScore: reputation.abuseConfidenceScore,
          totalReports: reputation.totalReports,
        });
      }
    } catch (err) {
      // Nunca derruba a aplicacao por falha na API externa.
      // eslint-disable-next-line no-console
      console.warn('[dimma-reputation] falha ao consultar AbuseIPDB, seguindo sem bloqueio adicional:', err.message);
    }

    next();
  };
}

module.exports = { checkIpReputation, ipReputationMiddleware, isPrivateIp, DEFAULT_BLOCK_THRESHOLD };
