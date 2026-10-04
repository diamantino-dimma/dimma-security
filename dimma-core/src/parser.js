'use strict';

/**
 * Parser da linguagem .dimma
 *
 * Sintaxe suportada:
 *   # comentario
 *   @comando: valor
 *   @comando lista: [item1, item2, item3]
 *   @comando aninhado.chave: valor
 *
 * Exemplo:
 *   @auto_protect: true
 *   @encrypt traffic: TLS1.3
 *   @protect input: [sql_injection, xss]
 *   @rate_limit: 100 req/min
 *   @exclude: /admin/debug-route
 */

const DEFAULTS = Object.freeze({
  // ── Modo proxy autónomo ──────────────────────────────────
  target: null,           // @target: http://localhost:3000
  listen: 8080,           // @listen: 8080
  files_protect: [],      // @files_protect: [app.js, routes/api.js]
  // ── Protecções ──────────────────────────────────────────
  auto_protect: false,
  encrypt_traffic: null,
  protect_input: [],
  rate_limit: { max: 100, window_ms: 60000 },
  exclude: [],
  connect: [],
  password_hashing: 'bcrypt',
  session_expiry_minutes: 30,
  anomaly_detection: false,
  ai_detection: false,
  ai_provider: 'nvidia',
  ai_model: null,
  ip_reputation_check: false,
  supply_chain_guard: true,
  passkey_support: false,
  rp_id: null,
  rp_origin: null,
  csrf_protection: true,
  security_headers: true,
});

function parseValue(raw) {
  const trimmed = raw.trim();

  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;

  // Lista: [a, b, c]
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    return trimmed
      .slice(1, -1)
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean);
  }

  // Taxa: "100 req/min" -> { max: 100, window_ms: 60000 }
  const rateMatch = trimmed.match(/^(\d+)\s*req\/(sec|min|hour)$/i);
  if (rateMatch) {
    const max = parseInt(rateMatch[1], 10);
    const unit = rateMatch[2].toLowerCase();
    const windowMs = unit === 'sec' ? 1000 : unit === 'min' ? 60000 : 3600000;
    return { max, window_ms: windowMs };
  }

  // Numero
  if (/^\d+(\.\d+)?$/.test(trimmed)) return Number(trimmed);

  return trimmed;
}

// SEGURANCA (CWE-1321 — Prototype Pollution): comandos desconhecidos do
// .dimma chegam aqui com um "path" vindo diretamente do ficheiro de
// configuracao (ex: "__proto__.polluted"). Sem este filtro, um .dimma
// malicioso poderia poluir Object.prototype para TODO o processo Node
// (nao so para o dimma), permitindo bypass de logica noutras partes da
// mesma aplicacao. Bloqueamos qualquer segmento que tente escapar para
// a prototype chain.
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function setNested(obj, path, value) {
  const keys = path.split('.');

  if (keys.some((k) => DANGEROUS_KEYS.has(k))) {
    // eslint-disable-next-line no-console
    console.warn(
      `[dimma] AVISO: comando ".dimma" com segmento perigoso ("${path}") foi ignorado ` +
        'por seguranca (protecao contra prototype pollution). Verifique o seu ficheiro .dimma.'
    );
    return;
  }

  let cur = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    if (!Object.prototype.hasOwnProperty.call(cur, keys[i]) ||
        typeof cur[keys[i]] !== 'object' || cur[keys[i]] === null) {
      cur[keys[i]] = {};
    }
    cur = cur[keys[i]];
  }
  cur[keys[keys.length - 1]] = value;
}

const COMMAND_MAP = {
  // ── Modo proxy autónomo ──────────────────────────────────
  target: 'target',
  listen: 'listen',
  files_protect: 'files_protect',
  // ── Protecções ──────────────────────────────────────────
  auto_protect: 'auto_protect',
  'encrypt traffic': 'encrypt_traffic',
  'protect input': 'protect_input',
  rate_limit: 'rate_limit',
  exclude: 'exclude',
  connect: 'connect',
  'override rate_limit': 'rate_limit',
  password_hashing: 'password_hashing',
  session_expiry: 'session_expiry_minutes',
  anomaly_detection: 'anomaly_detection',
  ai_detection: 'ai_detection',
  ai_provider: 'ai_provider',
  ai_model: 'ai_model',
  ip_reputation_check: 'ip_reputation_check',
  supply_chain_guard: 'supply_chain_guard',
  passkey_support: 'passkey_support',
  rp_id: 'rp_id',
  rp_origin: 'rp_origin',
  csrf_protection: 'csrf_protection',
  security_headers: 'security_headers',
};

/**
 * Converte o texto de um arquivo .dimma numa configuracao normalizada.
 * @param {string} source Conteudo bruto do arquivo .dimma
 * @returns {object} configuracao resolvida (com defaults aplicados)
 */
function parseDimma(source) {
  const config = JSON.parse(JSON.stringify(DEFAULTS));
  const rawCommands = [];

  const lines = source.replace(/^\uFEFF/, '').split(/\r?\n/);
  for (let lineNumber = 0; lineNumber < lines.length; lineNumber++) {
    const line = lines[lineNumber];
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith('#')) continue;
    if (!trimmed.startsWith('@')) continue;

    const withoutAt = trimmed.slice(1);
    const sepIndex = withoutAt.indexOf(':');
    if (sepIndex === -1) {
      throw new SyntaxError(
        `.dimma linha ${lineNumber + 1}: comando sem ":" -> "${trimmed}"`
      );
    }

    const commandKey = withoutAt.slice(0, sepIndex).trim();
    const rawValue = withoutAt.slice(sepIndex + 1).trim();
    const value = parseValue(rawValue);

    rawCommands.push({ command: commandKey, value, line: lineNumber + 1 });

    if (COMMAND_MAP[commandKey]) {
      const key = COMMAND_MAP[commandKey];
      if (key === 'protect_input' && Array.isArray(config[key])) {
        config[key] = Array.from(new Set([...config[key], ...(Array.isArray(value) ? value : [value])]));
      } else if (key === 'exclude' || key === 'connect' || key === 'files_protect') {
        const arr = Array.isArray(value) ? value : [value];
        config[key] = [...config[key], ...arr];
      } else {
        config[key] = value;
      }
    } else {
      // comando desconhecido ou aninhado -> guarda em raw/extra
      setNested(config, commandKey.replace(/\s+/g, '_'), value);
    }
  }

  return { config, rawCommands };
}

module.exports = { parseDimma, DEFAULTS };
