#!/usr/bin/env node
'use strict';

const fs   = require('fs');
const path = require('path');
const { DEFAULT_TEMPLATE } = require('./template');
const { scanProject, formatReport } = require('./scan');
const { auditSupplyChain, formatSupplyChainReport } = require('./security/supplyChain');
const { checkPqcReadiness, formatPqcReport } = require('./security/pqc');
const { classifyWithAI, PROVIDERS } = require('./security/aiClassifier');
const { injectAll, ejectFile } = require('./injector');
const { startProxy } = require('./proxy');

// ── Detecção de stack e ficheiro principal ────────────────────────────────────
function detectStack(cwd) {
  if (fs.existsSync(path.join(cwd, 'package.json'))) return 'node';
  if (
    fs.existsSync(path.join(cwd, 'requirements.txt')) ||
    fs.existsSync(path.join(cwd, 'manage.py')) ||
    fs.existsSync(path.join(cwd, 'pyproject.toml'))
  ) return 'python';
  return 'desconhecida';
}

// Candidatos de ficheiro principal por stack
const NODE_CANDIDATES = ['app.js', 'server.js', 'index.js', 'src/app.js', 'src/index.js'];
const PY_CANDIDATES   = ['app.py', 'main.py', 'server.py', 'manage.py', 'src/app.py'];

function detectMainFile(cwd, stack) {
  const candidates = stack === 'node' ? NODE_CANDIDATES : PY_CANDIDATES;
  for (const f of candidates) {
    if (fs.existsSync(path.join(cwd, f))) return f;
  }
  return null;
}

// ── dimma init ────────────────────────────────────────────────────────────────
function init() {
  const cwd    = process.cwd();
  const target = path.join(cwd, 'security.dimma');

  if (fs.existsSync(target)) {
    console.log('security.dimma ja existe neste projeto. Nada foi sobrescrito.');
    return;
  }

  const stack    = detectStack(cwd);
  const mainFile = detectMainFile(cwd, stack);

  // Preencher @files_protect automaticamente se encontrou o ficheiro principal
  let template = DEFAULT_TEMPLATE;
  if (mainFile) {
    template = template.replace(
      '@files_protect: []',
      `@files_protect: [${mainFile}]`
    );
  }

  fs.writeFileSync(target, template, 'utf-8');

  console.log('\n[dimma] security.dimma criado com sucesso.');
  console.log(`Stack detectada : ${stack}`);

  if (mainFile) {
    console.log(`Ficheiro detectado: ${mainFile}`);
    console.log(`\n@files_protect foi preenchido automaticamente com "${mainFile}".`);
    console.log('Adicione mais ficheiros se necessario:');
    console.log(`  @files_protect: [${mainFile}, routes/api.js]\n`);
  } else {
    console.log('\nNao foi possivel detectar o ficheiro principal automaticamente.');
    console.log('Edite o security.dimma e preencha @files_protect manualmente:');
    if (stack === 'node') {
      console.log('  @files_protect: [app.js]\n');
    } else if (stack === 'python') {
      console.log('  @files_protect: [app.py]\n');
    } else {
      console.log('  @files_protect: [seu_ficheiro.js]  ou  [seu_ficheiro.py]\n');
    }
  }

  console.log('Instalar a biblioteca:');
  if (stack === 'node')   console.log('  npm install dimma-core');
  if (stack === 'python') console.log('  pip install dimma');
  console.log('');
  console.log('Depois de configurar @files_protect, injectar as proteccoes:');
  console.log('  dimma inject');
  console.log('');
  console.log('Ou correr como proxy autonomo (sem alterar o codigo):');
  console.log('  Adicione @target e @listen ao .dimma, depois:');
  console.log('  dimma start');
}

// ── dimma inject ──────────────────────────────────────────────────────────────
function inject(args) {
  const positional = args.filter((arg) => !arg.startsWith('--'));
  const unknownFlags = args.filter((arg) => arg.startsWith('--') && arg !== '--dry-run');
  if (unknownFlags.length) {
    console.error(`[dimma] Opcao(s) nao suportada(s): ${unknownFlags.join(', ')}`);
    process.exitCode = 1;
    return;
  }
  const dimmaPath = positional[0] || './security.dimma';
  const dryRun    = args.includes('--dry-run');

  if (!fs.existsSync(dimmaPath)) {
    console.error(`[dimma] Ficheiro nao encontrado: "${dimmaPath}". Execute "dimma init" primeiro.`);
    process.exit(1);
  }

  const { parseDimma } = require('./parser');
  const source = fs.readFileSync(dimmaPath, 'utf-8');
  const { config } = parseDimma(source);

  if (!config.files_protect || config.files_protect.length === 0) {
    console.error('[dimma] ERRO: @files_protect esta vazio.\n');
    console.error('O .dimma precisa de saber quais ficheiros deve proteger.');
    console.error('Adicione ao security.dimma:\n');
    console.error('  @files_protect: [app.js]          # Node.js');
    console.error('  @files_protect: [app.py]          # Python');
    console.error('  @files_protect: [app.js, api.js]  # varios ficheiros\n');
    process.exit(1);
  }

  console.log(`\n[dimma] A injectar proteccoes nos ficheiros declarados em @files_protect...\n`);
  if (dryRun) console.log('  (modo dry-run — nenhum ficheiro sera alterado)\n');

  const results = injectAll(config.files_protect, dimmaPath, { dryRun });

  let ok = 0, skip = 0, err = 0;
  for (const r of results) {
    if (r.error) {
      console.log(`  ✕ ERRO    ${r.file}: ${r.error}`);
      err++;
    } else if (!r.injected) {
      console.log(`  ↷ IGNORADO ${r.file}: ${r.reason}`);
      skip++;
    } else {
      const bak = r.dryRun ? ' (dry-run)' : ` (backup: ${r.backup})`;
      console.log(`  ✓ INJECTADO ${r.file}${bak}`);
      ok++;
    }
  }

  console.log(`\n  ${ok} injectado(s), ${skip} ignorado(s), ${err} erro(s)\n`);
  if (err > 0) process.exit(1);
}

// ── dimma eject ───────────────────────────────────────────────────────────────
function eject(args) {
  const files = args.filter((a) => !a.startsWith('--'));
  if (files.length === 0) {
    console.error('[dimma] Especifica os ficheiros: dimma eject app.js app.py');
    process.exit(1);
  }
  console.log('\n[dimma] A remover injecoes dos ficheiros...\n');
  for (const f of files) {
    const r = ejectFile(path.resolve(f));
    if (r.ejected) {
      console.log(`  ✓ REMOVIDO ${f} (metodo: ${r.method})`);
    } else {
      console.log(`  ✕ ERRO ${f}: ${r.error}`);
    }
  }
  console.log('');
}

// ── dimma start ───────────────────────────────────────────────────────────────
async function start(args) {
  const dimmaPath = args[0] || './security.dimma';
  try {
    await startProxy(dimmaPath);
    // Manter o processo vivo
    process.on('SIGINT', () => {
      console.log('\n[dimma] Proxy parado.');
      process.exit(0);
    });
  } catch (err) {
    console.error(`[dimma] Erro ao iniciar proxy:\n  ${err.message}`);
    process.exit(1);
  }
}

// ── dimma scan ────────────────────────────────────────────────────────────────
// Corre SEMPRE o scanner de padroes de codigo + o supply_chain_guard
// (verificacoes estaticas: integridade do lockfile, typosquatting,
// scripts de install suspeitos). A verificacao de "pacote
// recem-publicado" exige rede e e OPT-IN via --supply-chain-online,
// para o "dimma scan" nunca fazer chamadas de rede surpresa num
// pipeline de CI isolado.
async function scan(args = []) {
  const cwd = process.cwd();
  const checkOnline = args.includes('--supply-chain-online');

  const result = scanProject(cwd);
  console.log(formatReport(result));

  // Respeita @supply_chain_guard: false no security.dimma, se existir
  // (por padrao o guard corre sempre, mesmo sem .dimma, porque e uma
  // verificacao estatica independente de middleware).
  let supplyChainEnabled = true;
  let configurationError = false;
  const dimmaPath = path.join(cwd, 'security.dimma');
  if (fs.existsSync(dimmaPath)) {
    try {
      const { parseDimma } = require('./parser');
      const { config } = parseDimma(fs.readFileSync(dimmaPath, 'utf-8'));
      supplyChainEnabled = config.supply_chain_guard !== false;
    } catch (err) {
      configurationError = true;
      console.error(`[dimma] security.dimma invalido; supply-chain guard mantido ativo: ${err.message}`);
    }
  }

  let supplyChainResult = { findings: [], dependenciesChecked: 0, skipped: true, reason: 'desativado via @supply_chain_guard: false' };
  if (supplyChainEnabled) {
    supplyChainResult = await auditSupplyChain(cwd, { checkOnline });
  }
  console.log(formatSupplyChainReport(supplyChainResult));

  const hasCriticalOrHigh =
    result.findings.some((f) => ['critical', 'high'].includes(f.severity)) ||
    (supplyChainResult.findings || []).some((f) => ['critical', 'high'].includes(f.severity));

  if (hasCriticalOrHigh || result.errors.length > 0 || configurationError) process.exitCode = 1;
}

// ── dimma pqc-check ───────────────────────────────────────────────────────────
function pqcCheck() {
  console.log(formatPqcReport(checkPqcReadiness()));
}

async function aiCheck(args = []) {
  const unsupported = args.filter((arg) => arg !== '--test');
  if (unsupported.length > 0) {
    console.error(`[dimma] Opcao(s) nao suportada(s): ${unsupported.join(', ')}`);
    process.exitCode = 1;
    return;
  }

  const dimmaPath = path.resolve('./security.dimma');
  if (!fs.existsSync(dimmaPath)) {
    console.error('[dimma] security.dimma nao encontrado. Execute "dimma init" primeiro.');
    process.exitCode = 1;
    return;
  }

  const { parseDimma } = require('./parser');
  const { config } = parseDimma(fs.readFileSync(dimmaPath, 'utf-8'));
  const provider = String(config.ai_provider || 'nvidia').toLowerCase();
  const definition = PROVIDERS[provider];
  if (!definition) {
    console.error(`[dimma] Provider invalido: "${provider}".`);
    process.exitCode = 1;
    return;
  }

  const model = config.ai_model ||
    process.env.DIMMA_AI_MODEL ||
    process.env[definition.modelEnv] ||
    definition.defaultModel;
  const keyPresent = Boolean(process.env[definition.apiKeyEnv]);
  console.log(`[dimma] Provider configurado: ${provider} (${definition.label})`);
  console.log(`[dimma] Modelo: ${model}`);
  console.log(`[dimma] ${definition.apiKeyEnv}: ${keyPresent ? 'presente' : 'ausente'}`);

  if (!keyPresent) {
    process.exitCode = 1;
    return;
  }

  if (args.includes('--test')) {
    try {
      await classifyWithAI(
        { findings: [{ type: 'connectivity_check' }], rawInput: { method: 'GET', path: '/__dimma/ai-check' } },
        { provider, model }
      );
      console.log('[dimma] Ligacao com o provider: OK');
    } catch (err) {
      console.error(`[dimma] Ligacao com o provider: FALHOU (${err.message})`);
      process.exitCode = 1;
    }
  } else {
    console.log('[dimma] Diagnostico local concluido. Use --test para enviar uma chamada de teste ao provider.');
  }
}

// ── main ──────────────────────────────────────────────────────────────────────
async function main() {
  const [,, command, ...args] = process.argv;

  switch (command) {
    case 'init':      return init();
    case 'inject':    return inject(args);
    case 'eject':     return eject(args);
    case 'start':     return start(args);
    case 'scan':      return scan(args);
    case 'pqc-check': return pqcCheck();
    case 'ai-check':  return aiCheck(args);
    case '--version':
    case '-v':
      return console.log(require('../package.json').version);
    default:
      console.log('\nUso: dimma <comando>\n');
      console.log('  init             Cria o security.dimma e detecta ficheiro principal');
      console.log('  inject [.dimma]  Injeta proteccoes nos ficheiros de @files_protect');
      console.log('  eject <ficheiro> Remove a injecao de um ficheiro (restaura backup)');
      console.log('  start  [.dimma]  Corre o .dimma como proxy autonomo (@target + @listen)');
      console.log('  scan             Varre o codigo (padroes inseguros + supply_chain_guard)');
      console.log('    --supply-chain-online  tambem verifica pacotes recem-publicados (rede)');
      console.log('  pqc-check        Verifica prontidao para TLS pos-quantico');
      console.log('  ai-check         Verifica configuracao do provider IA (--test faz chamada externa)');
      console.log('');
      console.log('  Para comecar:  dimma init');
  }
}

main().catch((err) => {
  console.error(`[dimma] Erro inesperado: ${err.message}`);
  process.exitCode = 1;
});
