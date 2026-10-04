'use strict';

const fs = require('fs');
const path = require('path');
const { consumeBudget } = require('./budget');

/**
 * dimma supply_chain_guard — verificacao real de dependencias.
 *
 * HONESTIDADE TECNICA: isto substitui a versao anterior deste ficheiro,
 * que nao existia -- @supply_chain_guard estava documentado mas nao
 * fazia nada. Esta implementacao cobre, com meios estaticos e um
 * check de rede opcional (fail-safe, nunca bloqueia o CLI):
 *
 *   1. Hash de integridade ausente no lockfile      (estatico)
 *   2. Possivel typosquatting/slopsquatting         (estatico, heuristica)
 *   3. Scripts postinstall/preinstall suspeitos      (estatico, heuristica)
 *   4. Pacote recem-publicado (< N dias)             (rede, OPT-IN)
 *
 * NAO faz consulta de rede por padrao -- "dimma scan" nunca deve ligar
 * a internet sem o programador pedir explicitamente (options.checkOnline
 * ou "dimma scan --supply-chain-online"), para nao surpreender ninguem
 * a correr isto num pipeline de CI isolado.
 */

const POPULAR_PACKAGES = [
  'express', 'react', 'react-dom', 'lodash', 'axios', 'chalk', 'commander',
  'request', 'moment', 'underscore', 'debug', 'async', 'webpack', 'babel',
  'eslint', 'jest', 'typescript', 'vue', 'redux', 'rxjs', 'jquery', 'dotenv',
  'cors', 'helmet', 'mongoose', 'sequelize', 'socket.io', 'uuid', 'yargs',
  'bcrypt', 'bcryptjs', 'jsonwebtoken', 'nodemon', 'prettier', 'next',
];

// Padroes de comandos tipicamente usados em ataques via postinstall (ex:
// o ataque ao axios de marco 2026 usou um script de install para exfiltrar
// dados). Heuristica, nao exaustiva -- falsos positivos sao esperados em
// pacotes legitimos que compilam binarios nativos (ex: node-gyp).
const SUSPICIOUS_SCRIPT_RE =
  /curl\s+|wget\s+|base64\s+(-d|--decode)|\bnode\s+-e\b|\beval\(|powershell|Invoke-Expression|\biex\b|\bcurl\b.*\|\s*sh\b/i;

/** Distancia de edicao (Levenshtein) simples, sem dependencias externas. */
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function checkLockfileIntegrity(rootDir, declaredDeps) {
  const findings = [];
  const lockPath = path.join(rootDir, 'package-lock.json');

  if (!fs.existsSync(lockPath)) {
    findings.push({
      type: 'lockfile-ausente',
      severity: 'medium',
      package: null,
      message: 'package-lock.json nao encontrado -- instalacoes nao sao reprodutiveis nem verificadas por hash.',
    });
    return { findings, dependenciesChecked: 0 };
  }

  let lock;
  try {
    lock = JSON.parse(fs.readFileSync(lockPath, 'utf-8'));
  } catch (err) {
    findings.push({
      type: 'lockfile-invalido',
      severity: 'medium',
      package: null,
      message: `package-lock.json nao pode ser interpretado: ${err.message}`,
    });
    return { findings, dependenciesChecked: 0 };
  }

  const packages = lock.packages || {};
  let dependenciesChecked = 0;

  for (const [key, meta] of Object.entries(packages)) {
    if (!key) continue; // entrada raiz do proprio projeto
    if (meta.link || meta.extraneous) continue; // symlinks/workspaces nao tem integrity
    dependenciesChecked++;
    if (!meta.integrity) {
      findings.push({
        type: 'hash-integrity-missing',
        severity: 'high',
        package: key.replace(/^node_modules\//, ''),
        message: 'Entrada do lockfile sem campo "integrity" -- bypass silencioso da verificacao de hash em "npm ci".',
      });
    }
  }

  return { findings, dependenciesChecked };
}

function checkTyposquatting(declaredDeps) {
  const findings = [];
  for (const name of Object.keys(declaredDeps)) {
    for (const popular of POPULAR_PACKAGES) {
      if (name === popular) continue;
      if (Math.abs(name.length - popular.length) > 2) continue; // corta ruido
      const dist = levenshtein(name, popular);
      if (dist === 1 && name.length > 2) {
        findings.push({
          type: 'possivel-typosquatting',
          severity: 'high',
          package: name,
          message: `"${name}" e muito semelhante ao pacote popular "${popular}" (distancia de edicao = 1). ` +
            'Confirme que nao e typosquatting/slopsquatting antes de instalar -- um nome alucinado por IA ' +
            'registado por um atacante tem exatamente este aspeto.',
        });
      }
    }
  }
  return findings;
}

function checkSuspiciousInstallScripts(rootDir, declaredDeps) {
  const findings = [];
  const nodeModules = path.join(rootDir, 'node_modules');
  if (!fs.existsSync(nodeModules)) return findings;

  for (const name of Object.keys(declaredDeps)) {
    const depPkgPath = path.join(nodeModules, name, 'package.json');
    if (!fs.existsSync(depPkgPath)) continue;

    let depPkg;
    try {
      depPkg = JSON.parse(fs.readFileSync(depPkgPath, 'utf-8'));
    } catch (err) {
      continue;
    }

    const scripts = depPkg.scripts || {};
    for (const hook of ['preinstall', 'install', 'postinstall']) {
      const cmd = scripts[hook];
      if (cmd && SUSPICIOUS_SCRIPT_RE.test(cmd)) {
        findings.push({
          type: 'postinstall-suspeito',
          severity: 'medium',
          package: name,
          message: `Script "${hook}" de "${name}" contem um padrao tipico de exfiltracao/execucao remota: "${cmd.slice(0, 160)}"`,
        });
      }
    }
  }

  return findings;
}

/**
 * Verifica se alguma das versoes instaladas foi publicada ha poucos dias
 * -- pacotes recem-publicados ainda nao foram escrutinados pela
 * comunidade e sao o alvo nº1 de contas de maintainer comprometidas.
 *
 * REDE, OPT-IN: so corre se options.checkOnline === true. Usa o mesmo
 * circuit breaker de orcamento diario (budget.js) que o resto do dimma,
 * e falha de forma segura -- se a rede/API falhar, o pacote e
 * simplesmente marcado como "nao verificado", nunca quebra o scan.
 */
async function checkRecentlyPublished(declaredDeps, options = {}) {
  const findings = [];
  const fetchImpl = options.fetchImpl || fetch;
  const maxAgeDays = options.maxAgeDays || 7;
  const dailyBudget = options.dailyBudget || 300;
  const registryUrl = options.registryUrl || 'https://registry.npmjs.org';

  for (const [name, versionRange] of Object.entries(declaredDeps)) {
    const budget = await consumeBudget('supply-chain-npm-registry', dailyBudget);
    if (!budget.allowed) {
      findings.push({
        type: 'supply-chain-orcamento-esgotado',
        severity: 'low',
        package: name,
        message: 'Orcamento diario de consultas ao registry esgotado -- verificacao de idade de publicacao pulada.',
      });
      break;
    }

    try {
      const res = await fetchImpl(`${registryUrl}/${encodeURIComponent(name)}`);
      if (!res.ok) continue;
      const data = await res.json();
      const distTags = data['dist-tags'] || {};
      const resolvedVersion = distTags.latest;
      const publishedAt = data.time && resolvedVersion ? data.time[resolvedVersion] : null;
      if (!publishedAt) continue;

      const ageDays = (Date.now() - new Date(publishedAt).getTime()) / (1000 * 60 * 60 * 24);
      if (ageDays >= 0 && ageDays < maxAgeDays) {
        findings.push({
          type: 'pacote-recentemente-publicado',
          severity: 'high',
          package: name,
          message: `"${name}" (versao "latest"=${resolvedVersion}) foi publicado ha ${Math.floor(ageDays)} dia(s) -- ` +
            'ainda nao teve tempo de ser escrutinado pela comunidade. Reveja manualmente antes de confiar em producao.',
        });
      }
    } catch (err) {
      // Falha de rede/API: nunca quebra o scan, so deixa de verificar
      // esse pacote (falha segura, mesmo padrao do resto do dimma).
      continue;
    }
  }

  return findings;
}

/**
 * Funcao principal: audita as dependencias declaradas em package.json.
 * @param {string} rootDir
 * @param {{checkOnline?: boolean, fetchImpl?: Function, maxAgeDays?: number}} options
 */
async function auditSupplyChain(rootDir, options = {}) {
  const pkgJsonPath = path.join(rootDir, 'package.json');

  if (!fs.existsSync(pkgJsonPath)) {
    return { findings: [], dependenciesChecked: 0, skipped: true, reason: 'package.json nao encontrado' };
  }

  let pkgJson;
  try {
    pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
  } catch (err) {
    return {
      findings: [{ type: 'package-json-invalido', severity: 'medium', package: null, message: err.message }],
      dependenciesChecked: 0,
    };
  }

  const declaredDeps = { ...(pkgJson.dependencies || {}), ...(pkgJson.devDependencies || {}) };

  const lockfileResult = checkLockfileIntegrity(rootDir, declaredDeps);
  const typosquattingFindings = checkTyposquatting(declaredDeps);
  const installScriptFindings = checkSuspiciousInstallScripts(rootDir, declaredDeps);

  let onlineFindings = [];
  if (options.checkOnline) {
    onlineFindings = await checkRecentlyPublished(declaredDeps, options);
  }

  return {
    findings: [
      ...lockfileResult.findings,
      ...typosquattingFindings,
      ...installScriptFindings,
      ...onlineFindings,
    ],
    dependenciesChecked: lockfileResult.dependenciesChecked || Object.keys(declaredDeps).length,
    onlineCheckPerformed: Boolean(options.checkOnline),
  };
}

const SEVERITY_LABEL = { critical: 'CRITICO', high: 'ALTO', medium: 'MEDIO', low: 'BAIXO' };

function formatSupplyChainReport(result) {
  const lines = [];
  lines.push('\ndimma supply_chain_guard — auditoria de dependencias\n');

  if (result.skipped) {
    lines.push(`Pulado: ${result.reason}`);
    return lines.join('\n');
  }

  lines.push(`${result.dependenciesChecked} dependencia(s) verificada(s).`);
  lines.push(
    result.onlineCheckPerformed
      ? 'Verificacao de idade de publicacao: ATIVA (consulta ao registry).'
      : 'Verificacao de idade de publicacao: DESATIVADA (use --supply-chain-online para ativar).'
  );
  lines.push('');

  if (result.findings.length === 0) {
    lines.push('Nenhum problema de supply chain encontrado. \u2705');
    return lines.join('\n');
  }

  for (const f of result.findings) {
    const pkg = f.package ? ` [${f.package}]` : '';
    lines.push(`[${SEVERITY_LABEL[f.severity] || f.severity.toUpperCase()}]${pkg} (${f.type})`);
    lines.push(`  ${f.message}`);
    lines.push('');
  }

  return lines.join('\n');
}

module.exports = {
  auditSupplyChain,
  checkLockfileIntegrity,
  checkTyposquatting,
  checkSuspiciousInstallScripts,
  checkRecentlyPublished,
  formatSupplyChainReport,
  levenshtein,
};
