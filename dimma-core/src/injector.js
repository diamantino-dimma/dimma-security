'use strict';

/**
 * dimma-injector — injeta automaticamente o motor .dimma nos ficheiros
 * listados em @files_protect, sem que o programador precise escrever
 * nenhum codigo manualmente.
 *
 * Suporta:
 *   - Node.js / Express (.js, .mjs, .ts, .cjs)
 *   - Python / Flask (.py)
 *
 * O que faz em cada ficheiro:
 *   1. Detecta a linguagem pelo extension
 *   2. Verifica se o dimma JA foi injetado (evita duplicar)
 *   3. Detecta o nome da variavel do app Express/Flask (ex: app, server)
 *   4. Injeta o require/import + dimma.protect(app) no lugar certo
 *   5. Faz backup do ficheiro original antes de alterar (.dimma.bak)
 *
 * HONESTIDADE TECNICA: injecao automatica de codigo e uma operacao
 * delicada. O injector e conservador — se nao conseguir detectar o
 * padrao correto, recusa injetar e avisa o programador, em vez de
 * estragar o ficheiro.
 */

const fs = require('fs');
const path = require('path');

const DIMMA_MARKER_JS = '// [dimma-injected]';
const DIMMA_MARKER_PY = '# [dimma-injected]';

const JS_EXTENSIONS  = new Set(['.js', '.mjs', '.cjs', '.ts']);
const PY_EXTENSIONS  = new Set(['.py']);

// Padrao para detectar o nome da variavel do app Express
// ex: const app = express() → captura 'app'
const EXPRESS_APP_RE = /(?:const|let|var)\s+(\w+)\s*=\s*express\s*\(/;

// Padrao para detectar o nome do app Flask
// ex: app = Flask(__name__) → captura 'app'
const FLASK_APP_RE   = /(\w+)\s*=\s*Flask\s*\(/;

function detectAppVar(source, lang) {
  const re = lang === 'js' ? EXPRESS_APP_RE : FLASK_APP_RE;
  const match = source.match(re);
  return match ? match[1] : 'app';
}

function alreadyInjected(source, lang) {
  const marker = lang === 'js' ? DIMMA_MARKER_JS : DIMMA_MARKER_PY;
  return source.includes(marker);
}

function injectJS(source, dimmaPath, moduleFormat) {
  if (alreadyInjected(source, 'js')) {
    return { injected: false, reason: 'dimma ja esta injetado neste ficheiro.' };
  }

  const isEsm = moduleFormat === 'esm' || /^\s*import\s+(?:[\w*{]|['"])/m.test(source);
  const appMatch = source.match(/^[ \t]*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*express\s*\(\s*\)\s*;?/m);
  const expressAvailable =
    /^[ \t]*(?:const|let|var)\s+express\s*=\s*require\s*\(\s*['"]express['"]\s*\)\s*;?/m.test(source) ||
    /^[ \t]*import\s+(?:[\w*{][^\r\n]*\s+from\s+)?['"]express['"]/m.test(source);
  if (!appMatch || !expressAvailable) {
    return {
      injected: false,
      reason: 'nao foi possivel localizar com seguranca a criacao do app Express e o import de express; nenhum ficheiro foi alterado.',
    };
  }

  const appVar = appMatch[1];
  const relPath = JSON.stringify(dimmaPath.replace(/\\/g, '/'));
  const code = isEsm
    ? [
        `import { DimmaEngine as _DimmaEngine } from 'dimma';`,
        `import { fileURLToPath as _dimmaFileURLToPath } from 'node:url';`,
        `import { dirname as _dimmaDirname, resolve as _dimmaResolve } from 'node:path';`,
        `const _dimma = new _DimmaEngine(_dimmaResolve(_dimmaDirname(_dimmaFileURLToPath(import.meta.url)), ${relPath}));`,
        `_dimma.protect(${appVar});`,
      ]
    : [
        `const { DimmaEngine: _DimmaEngine } = require('dimma');`,
        `const _dimma = new _DimmaEngine(require('node:path').resolve(__dirname, ${relPath}));`,
        `_dimma.protect(${appVar});`,
      ];

  const insertion = [
    DIMMA_MARKER_JS,
    ...code,
    DIMMA_MARKER_JS,
  ].join('\n');
  const insertionIndex = appMatch.index + appMatch[0].length;
  const newSource = `${source.slice(0, insertionIndex)}\n${insertion}${source.slice(insertionIndex)}`;

  return { injected: true, source: newSource, appVar };
}

function injectPY(source, dimmaPath) {
  if (alreadyInjected(source, 'py')) {
    return { injected: false, reason: 'dimma ja esta injetado neste ficheiro.' };
  }

  const appVar = detectAppVar(source, 'py');
  const relPath = dimmaPath.replace(/\\/g, '/');

  const injection = [
    DIMMA_MARKER_PY,
    `from dimma.engine import DimmaEngine as _DimmaEngine`,
    `_dimma = _DimmaEngine('${relPath}')`,
    `_dimma.protect(${appVar})`,
    DIMMA_MARKER_PY,
    '',
  ].join('\n');

  // Injetar apos a linha do Flask(...) — o app tem de existir antes de protect()
  const flaskLineRe = /^(.*Flask\s*\(.*)$/m;

  let newSource;
  if (flaskLineRe.test(source)) {
    newSource = source.replace(flaskLineRe, `$1\n\n${injection}`);
  } else {
    newSource = `${injection}\n${source}`;
  }

  return { injected: true, source: newSource, appVar };
}

/**
 * Injeta o dimma num ficheiro especifico.
 * @param {string} filePath   caminho do ficheiro
 * @param {string} dimmaPath  caminho do .dimma (relativo ao ficheiro)
 * @param {{dryRun?: boolean}} options
 * @returns {{ file, injected, appVar?, reason?, error? }}
 */
function injectFile(filePath, dimmaPath = './security.dimma', options = {}) {
  const ext  = path.extname(filePath).toLowerCase();
  const lang = JS_EXTENSIONS.has(ext) ? 'js' : PY_EXTENSIONS.has(ext) ? 'py' : null;

  if (!lang) {
    return { file: filePath, injected: false, reason: `extensao '${ext}' nao suportada (suportadas: .js, .mjs, .ts, .cjs, .py)` };
  }

  let source;
  try {
    source = fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    return { file: filePath, injected: false, error: `nao foi possivel ler o ficheiro: ${err.message}` };
  }

  const moduleFormat = ext === '.mjs' || /^\s*import\s+(?:[\w*{]|['"])/m.test(source) ? 'esm' : 'cjs';
  const result = lang === 'js'
    ? injectJS(source, dimmaPath, moduleFormat)
    : injectPY(source, dimmaPath);

  if (!result.injected) {
    return { file: filePath, ...result };
  }

  if (!options.dryRun) {
    const backupPath = filePath + '.dimma.bak';
    try {
      fs.writeFileSync(backupPath, source, { encoding: 'utf-8', flag: 'wx' });
      fs.writeFileSync(filePath, result.source, 'utf-8');
    } catch (err) {
      return {
        file: filePath,
        injected: false,
        error: `nao foi possivel concluir a injecao: ${err.message}` +
          (fs.existsSync(backupPath) ? `; backup preservado em "${backupPath}".` : ''),
      };
    }
  }

  return {
    file: filePath,
    injected: true,
    appVar: result.appVar,
    backup: options.dryRun ? null : filePath + '.dimma.bak',
    dryRun: Boolean(options.dryRun),
  };
}

/**
 * Injeta o dimma em todos os ficheiros listados em @files_protect.
 * @param {string[]} files     lista de caminhos
 * @param {string}   dimmaPath caminho do .dimma
 * @param {{dryRun?: boolean, cwd?: string}} options
 */
function injectAll(files, dimmaPath = './security.dimma', options = {}) {
  const cwd = path.resolve(options.cwd || process.cwd());
  const rootPath = fs.realpathSync(cwd);
  const configPath = path.resolve(cwd, dimmaPath);
  return files.map((f) => {
    const fullPath = path.resolve(cwd, f);
    const relativePath = path.relative(rootPath, fullPath);
    const escapesRoot = relativePath === '..' ||
      relativePath.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relativePath);
    if (escapesRoot) {
      return {
        file: fullPath,
        injected: false,
        error: 'caminho fora do diretorio do projeto; nenhum ficheiro foi alterado.',
      };
    }

    try {
      const realPath = fs.realpathSync(fullPath);
      const realRelativePath = path.relative(rootPath, realPath);
      if (
        realRelativePath === '..' ||
        realRelativePath.startsWith(`..${path.sep}`) ||
        path.isAbsolute(realRelativePath)
      ) {
        return {
          file: fullPath,
          injected: false,
          error: 'caminho resolve para fora do diretorio do projeto; nenhum ficheiro foi alterado.',
        };
      }
    } catch (err) {
      // injectFile reports missing/unreadable target files using the normal result shape.
      if (err.code !== 'ENOENT') {
        return { file: fullPath, injected: false, error: `nao foi possivel validar o caminho: ${err.message}` };
      }
    }

    const relDimma = path.relative(path.dirname(fullPath), configPath);
    return injectFile(fullPath, relDimma.startsWith('.') ? relDimma : `./${relDimma}`, options);
  });
}

/**
 * Remove a injecao de um ficheiro (restaura do backup se disponivel,
 * ou remove os blocos marcados com [dimma-injected]).
 */
function ejectFile(filePath) {
  const backupPath = filePath + '.dimma.bak';
  const ejectBackupPath = filePath + '.dimma.eject.bak';
  let source;
  let sourceExists = true;

  try {
    source = fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    if (err.code !== 'ENOENT') return { file: filePath, ejected: false, error: err.message };
    sourceExists = false;
  }

  if (fs.existsSync(backupPath)) {
    const isInjected = sourceExists &&
      (source.includes(DIMMA_MARKER_JS) || source.includes(DIMMA_MARKER_PY));
    if (sourceExists && !isInjected) {
      return {
        file: filePath,
        ejected: false,
        error: 'o ficheiro atual nao contem o marcador Dimma; backup preservado para evitar sobrescrever alteracoes.',
      };
    }
    if (sourceExists && fs.existsSync(ejectBackupPath)) {
      return {
        file: filePath,
        ejected: false,
        error: `backup de seguranca ja existe em "${ejectBackupPath}"; nenhum ficheiro foi alterado.`,
      };
    }

    try {
      const original = fs.readFileSync(backupPath, 'utf-8');
      if (sourceExists) {
        fs.copyFileSync(filePath, ejectBackupPath, fs.constants.COPYFILE_EXCL);
      }
      fs.writeFileSync(filePath, original, 'utf-8');
      fs.unlinkSync(backupPath);
      return {
        file: filePath,
        ejected: true,
        method: 'backup',
        preservedCurrentFile: sourceExists ? ejectBackupPath : null,
      };
    } catch (err) {
      return {
        file: filePath,
        ejected: false,
        error: `nao foi possivel restaurar o backup: ${err.message}` +
          (fs.existsSync(ejectBackupPath) ? `; ficheiro anterior preservado em "${ejectBackupPath}".` : ''),
      };
    }
  }

  if (!sourceExists) {
    return { file: filePath, ejected: false, error: 'ficheiro nao encontrado e nenhum backup disponivel.' };
  }

  // Remove blocos entre os markers (incluindo o marker)
  const cleaned = source
    .replace(/\/\/ \[dimma-injected\][\s\S]*?\/\/ \[dimma-injected\]\n?/g, '')
    .replace(/# \[dimma-injected\][\s\S]*?# \[dimma-injected\]\n?/g, '');

  if (cleaned === source) {
    return { file: filePath, ejected: false, error: 'marcador Dimma nao encontrado; ficheiro nao foi alterado.' };
  }

  fs.writeFileSync(filePath, cleaned, 'utf-8');
  return { file: filePath, ejected: true, method: 'marker-removal' };
}

module.exports = { injectFile, injectAll, ejectFile };
