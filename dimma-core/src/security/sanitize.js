'use strict';

/**
 * Camada de sanitizacao de entrada.
 *
 * IMPORTANTE (honestidade tecnica): a defesa DEFINITIVA contra SQL Injection
 * e usar prepared statements / ORM com bind de parametros no acesso ao banco.
 * Nao existe filtro de string 100% infalivel. Este modulo funciona como uma
 * CAMADA ADICIONAL (defesa em profundidade): bloqueia os padroes mais comuns
 * de ataque ANTES do input chegar nas rotas, e fornece helpers para escapar
 * saida (contra XSS). Ele reduz drasticamente a superficie de ataque, mas
 * O helper `escapeForSql` e mantido por compatibilidade, mas recusa
 * gerar SQL: nao existe escaping generico seguro entre dialetos.
 * Use sempre queries parametrizadas.
 */

// Padroes que indicam tentativa de SQL Injection (heuristica, nao 100%).
// Evitamos bloquear por um apostrofo isolado (comum em nomes como
// "D'Angelo" ou "O'Brien") -- so consideramos suspeito quando a aspa
// aparece combinada com sintaxe/palavras-chave de SQL.
const SQLI_PATTERNS = [
  /(\%27|')\s*(or|and)\s+.{1,50}(=|like)/i, // ' or 1=1 / ' and x=y
  /(\%27|')\s*(--|\%23|#)/, // ' -- ou ' #
  /(\%27|');/i, // ';  (encerrar statement)
  /\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i, // or 1=1, or '1'='1'
  /\band\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i, // and 1=1
  /\bunion\b.{1,100}\bselect\b/i,
  /\bselect\b.{1,100}\bfrom\b.{1,100}\bwhere\b/i,
  /\binsert\b\s+into\b/i,
  /\bdrop\b\s+table\b/i,
  /\bupdate\b.{1,100}\bset\b.{1,100}\bwhere\b/i,
  /\bdelete\b\s+from\b/i,
  /\bexec(\s|\+)+(x|s)p\w+/i, // xp_cmdshell etc
  /--\s*$/, // comentario sql no fim da string (comum p/ truncar query)
];

// Padroes que indicam tentativa de XSS
const XSS_PATTERNS = [
  /<\s*script.*?>/i,
  /<\s*\/\s*script\s*>/i,
  /javascript\s*:/i,
  /on\w+\s*=\s*["']?[^"'>]+/i, // onerror=, onload=, etc.
  /<\s*iframe/i,
  /<\s*img[^>]+src[^>]*=[^>]*onerror/i,
  /data:text\/html/i,
];

// SEGURANCA (mitigacao de ReDoS): os padroes acima usam quantificadores
// limitados ({1,100}), mas testar regex contra strings arbitrariamente
// grandes ainda degrada performance de forma desproporcional (um
// atacante pode enviar um campo de texto com megabytes de dados
// repetitivos). Valores acima do limite sao rejeitados, nunca parcialmente
// analisados e aceitos.
const MAX_SCAN_LENGTH = 4096;

function containsSqlInjection(value) {
  if (typeof value !== 'string') return false;
  if (value.length > MAX_SCAN_LENGTH) return true;
  return SQLI_PATTERNS.some((re) => re.test(value));
}

function containsXss(value) {
  if (typeof value !== 'string') return false;
  if (value.length > MAX_SCAN_LENGTH) return true;
  return XSS_PATTERNS.some((re) => re.test(value));
}

/** Escapa HTML para prevenir XSS ao renderizar saida. */
function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Mantido para compatibilidade da API; escaping SQL depende do dialeto e
 * das opcoes da conexao. Recusa gerar uma string que possa ser insegura.
 */
function escapeForSql() {
  throw new Error(
    'escapeForSql nao e suportado: use queries parametrizadas/prepared statements do driver ou ORM.'
  );
}

/** Varre recursivamente um objeto (body/query/params) procurando ataques. */
function scanObject(obj, path = '') {
  const findings = [];
  if (obj === null || obj === undefined) return findings;

  if (typeof obj === 'string') {
    if (obj.length > MAX_SCAN_LENGTH) {
      findings.push({ path, type: 'input_too_large', value: obj });
      return findings;
    }
    if (containsSqlInjection(obj)) {
      findings.push({ path, type: 'sql_injection', value: obj });
    }
    if (containsXss(obj)) {
      findings.push({ path, type: 'xss', value: obj });
    }
    return findings;
  }

  if (Array.isArray(obj)) {
    obj.forEach((item, i) => findings.push(...scanObject(item, `${path}[${i}]`)));
    return findings;
  }

  if (typeof obj === 'object') {
    for (const key of Object.keys(obj)) {
      findings.push(...scanObject(obj[key], path ? `${path}.${key}` : key));
    }
  }

  return findings;
}

/**
 * Middleware Express: bloqueia requisicoes cujo body/query/params
 * contenham padroes de SQLi ou XSS.
 * @param {{protect: string[], onBlock?: Function}} options
 */
function inputProtectionMiddleware(options = {}) {
  const protect = options.protect || ['sql_injection', 'xss'];

  return function dimmaInputProtection(req, res, next) {
    const findings = [
      ...scanObject(req.body, 'body'),
      ...scanObject(req.query, 'query'),
      ...scanObject(req.params, 'params'),
    ].filter((f) => f.type === 'input_too_large' || protect.includes(f.type));

    if (findings.length > 0) {
      if (typeof options.onDetect === 'function') {
        options.onDetect(req, findings);
      }
      return res.status(400).json({
        error: 'Requisicao bloqueada pelo .dimma: entrada potencialmente maliciosa detectada.',
        details: findings.map((f) => ({ path: f.path, type: f.type })),
      });
    }

    next();
  };
}

module.exports = {
  containsSqlInjection,
  containsXss,
  escapeHtml,
  escapeForSql,
  scanObject,
  inputProtectionMiddleware,
};
