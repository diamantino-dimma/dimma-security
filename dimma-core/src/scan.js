'use strict';

const fs = require('fs');
const path = require('path');

/**
 * dimma scan — scanner estatico de padroes de codigo inseguro.
 *
 * PROBLEMA QUE ISSO RESOLVE: o Gartner aponta a IA agentica e o
 * "vibe coding" (codigo gerado por IA/no-code/low-code sem revisao
 * cuidadosa) como uma das maiores fontes de novas superficies de ataque
 * em 2026 -- codigo inseguro entra em producao mais rapido do que e
 * revisado. Este scanner varre o projeto procurando os padroes mais
 * comuns e perigosos ANTES do deploy.
 *
 * HONESTIDADE TECNICA: isto e uma analise estatica leve baseada em
 * padroes (regex), no estilo de um linter de seguranca -- nao e um SAST
 * completo com analise de fluxo de dados (dataflow/taint analysis) como
 * Semgrep ou CodeQL. Ele pega os erros mais obvios e mais comuns (o
 * "80%" do problema), mas pode ter falsos positivos/negativos. Serve
 * como uma rede de seguranca rapida, nao como auditoria completa.
 */

const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', 'coverage',
  '__pycache__', 'venv', '.venv', 'env', '.cache', 'vendor',
]);

const SCANNABLE_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.html']);

/**
 * Cada regra: id, severidade, regex, mensagem, e quais extensoes ela
 * se aplica (undefined = todas as scannable).
 */
const RULES = [
  {
    id: 'hardcoded-aws-key',
    severity: 'critical',
    pattern: /AKIA[0-9A-Z]{16}/,
    message: 'Possivel chave de acesso AWS hardcoded no codigo.',
  },
  {
    id: 'hardcoded-private-key',
    severity: 'critical',
    pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    message: 'Chave privada embutida diretamente no codigo-fonte.',
  },
  {
    id: 'hardcoded-secret-assignment',
    severity: 'critical',
    pattern: /(api[_-]?key|secret|password|senha|token)\s*[:=]\s*['"][A-Za-z0-9+/_\-]{16,}['"]/i,
    message: 'Possivel segredo/senha/token hardcoded (deveria vir de variavel de ambiente).',
  },
  {
    id: 'sql-string-concat-js',
    severity: 'critical',
    pattern: /(SELECT|INSERT|UPDATE|DELETE)\b[^;'"`]*['"`]\s*\+\s*\w+/i,
    message: 'Query SQL montada por concatenacao de string -- risco de SQL Injection. Use queries parametrizadas.',
    extensions: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'],
  },
  {
    id: 'sql-fstring-py',
    severity: 'critical',
    pattern: /f["'][^"']*(SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{/i,
    message: 'Query SQL montada com f-string -- risco de SQL Injection. Use parametros (?, %s) da lib de banco.',
    extensions: ['.py'],
  },
  {
    id: 'eval-usage-js',
    severity: 'high',
    pattern: /\beval\s*\(/,
    message: '"eval()" executa string como codigo -- risco serio de execucao arbitraria.',
    extensions: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.html'],
  },
  {
    id: 'eval-usage-py',
    severity: 'high',
    pattern: /\b(eval|exec)\s*\(/,
    message: '"eval()/exec()" executa string como codigo -- risco serio de execucao arbitraria.',
    extensions: ['.py'],
  },
  {
    id: 'command-injection-node',
    severity: 'high',
    pattern: /child_process\.exec\s*\(|require\(['"]child_process['"]\)\.exec\s*\(/,
    message: '"child_process.exec()" com entrada nao sanitizada pode permitir injecao de comandos. Prefira execFile/spawn com array de argumentos.',
    extensions: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'],
  },
  {
    id: 'command-injection-py',
    severity: 'high',
    pattern: /subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True|os\.system\s*\(/,
    message: 'Execucao de shell com "shell=True"/"os.system()" pode permitir injecao de comandos.',
    extensions: ['.py'],
  },
  {
    id: 'insecure-deserialization-py',
    severity: 'critical',
    pattern: /pickle\.loads?\s*\(|yaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)/,
    message: 'Desserializacao insegura (pickle/yaml.load sem SafeLoader) pode executar codigo arbitrario com dados nao confiaveis.',
    extensions: ['.py'],
  },
  {
    id: 'debug-mode-flask',
    severity: 'high',
    pattern: /app\.run\([^)]*debug\s*=\s*True/,
    message: 'Modo debug do Flask ativo -- nunca deve rodar assim em producao (expoe debugger interativo).',
    extensions: ['.py'],
  },
  {
    id: 'innerhtml-assignment',
    severity: 'medium',
    pattern: /\.innerHTML\s*=(?!=)/,
    message: 'Atribuicao direta a innerHTML com dados dinamicos e um vetor comum de XSS. Prefira textContent ou sanitize o HTML.',
    extensions: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.html'],
  },
  {
    id: 'dangerously-set-innerhtml',
    severity: 'medium',
    pattern: /dangerouslySetInnerHTML/,
    message: '"dangerouslySetInnerHTML" no React so deve ser usado com HTML sanitizado (ex: DOMPurify).',
    extensions: ['.jsx', '.tsx'],
  },
  {
    id: 'wildcard-cors',
    severity: 'medium',
    pattern: /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]/,
    message: 'CORS liberado para qualquer origem ("*") -- restrinja para os dominios que realmente precisam de acesso.',
  },
  {
    id: 'http-credentials-in-url',
    severity: 'medium',
    pattern: /https?:\/\/[^\s'"]+:[^\s'"@]+@[^\s'"]+/,
    message: 'URL com credenciais embutidas (usuario:senha@host) -- evite, use headers de autenticacao/variaveis de ambiente.',
  },
];

function shouldSkipDir(name) {
  return IGNORED_DIRS.has(name) || name.startsWith('.');
}

function walk(dir, files = [], errors = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    errors.push({ path: dir, message: err.message });
    return files;
  }

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!shouldSkipDir(entry.name)) {
        walk(path.join(dir, entry.name), files, errors);
      }
    } else if (SCANNABLE_EXTENSIONS.has(path.extname(entry.name))) {
      files.push(path.join(dir, entry.name));
    }
  }

  return files;
}

/**
 * Varre um diretorio de projeto procurando pelos padroes de RULES.
 * @param {string} rootDir
 * @returns {{findings: object[], filesScanned: number}}
 */
function scanProject(rootDir) {
  const rootPath = path.resolve(rootDir);
  const errors = [];
  const files = walk(rootPath, [], errors);
  const findings = [];

  const destructuredExecImport = /const\s*\{[^}]*\bexec\b[^}]*\}\s*=\s*require\(\s*['"]child_process['"]\s*\)/;

  for (const filePath of files) {
    const ext = path.extname(filePath);
    let content;
    try {
      content = fs.readFileSync(filePath, 'utf-8');
    } catch (err) {
      errors.push({ path: filePath, message: err.message });
      continue;
    }

    const lines = content.split(/\r?\n/);

    // Deteccao com contexto de arquivo inteiro: "const { exec } =
    // require('child_process')" seguido de uma chamada solta "exec(...)"
    // em outro lugar do arquivo -- regex por linha nao pega isso sozinho
    // porque a chamada nao menciona "child_process" na mesma linha.
    if (['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(ext) && destructuredExecImport.test(content)) {
      lines.forEach((line, index) => {
        if (/\bexec\s*\(/.test(line) && !destructuredExecImport.test(line)) {
          findings.push({
            file: path.relative(rootDir, filePath),
            line: index + 1,
            ruleId: 'command-injection-node-destructured',
            severity: 'high',
            message:
              '"exec()" (importado de child_process) com entrada nao sanitizada pode permitir injecao de comandos. Prefira execFile/spawn com array de argumentos.',
            snippet: line.trim().slice(0, 120),
          });
        }
      });
    }

    for (const rule of RULES) {
      if (rule.extensions && !rule.extensions.includes(ext)) continue;

      lines.forEach((line, index) => {
        if (rule.pattern.test(line)) {
          findings.push({
            file: path.relative(rootDir, filePath),
            line: index + 1,
            ruleId: rule.id,
            severity: rule.severity,
            message: rule.message,
            snippet: line.trim().slice(0, 120),
          });
        }
      });
    }
  }

  return { findings, filesScanned: files.length, errors };
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITY_LABEL = { critical: 'CRITICO', high: 'ALTO', medium: 'MEDIO', low: 'BAIXO' };
const SEVERITY_COLOR = { critical: 31, high: 91, medium: 33, low: 36 };

function colorEnabled(requested) {
  if (requested !== undefined) return requested;
  if (Object.prototype.hasOwnProperty.call(process.env, 'NO_COLOR')) return false;
  if (process.env.FORCE_COLOR && process.env.FORCE_COLOR !== '0') return true;
  return Boolean(process.stdout.isTTY);
}

function formatSeverity(severity, color) {
  const label = SEVERITY_LABEL[severity] || String(severity).toUpperCase();
  const ansiColor = SEVERITY_COLOR[severity];
  return color && ansiColor ? `\u001b[${ansiColor};1m${label}\u001b[0m` : label;
}

/** Formata os achados num relatorio Markdown legivel no terminal. */
function formatReport({ findings, filesScanned, errors = [] }, options = {}) {
  const color = colorEnabled(options.color);
  const counts = findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {});
  const lines = [
    '# Dimma Scan',
    '',
    `- **Ficheiros analisados:** ${filesScanned}`,
    `- **Total de achados:** ${findings.length}`,
    `- **Severidades:** ${['critical', 'high', 'medium', 'low']
      .map((severity) => `${formatSeverity(severity, color)} ${counts[severity] || 0}`)
      .join(' | ')}`,
  ];

  if (errors.length > 0) {
    lines.push('', '## Cobertura incompleta', '', `${errors.length} erro(s) ao ler ficheiros/diretorios:`);
    for (const error of errors) {
      lines.push(`- **${error.path}:** ${error.message}`);
    }
  }

  if (findings.length === 0) {
    lines.push(
      '',
      '## Resultado',
      '',
      errors.length > 0
        ? 'Nenhum padrao encontrado nos ficheiros que puderam ser lidos; o scan esta incompleto.'
        : 'Nenhum padrao inseguro conhecido foi encontrado. \u2705',
      '',
      '> Analise estatica por padroes; nao substitui revisao de codigo nem prepared statements.'
    );
    return lines.join('\n');
  }

  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  lines.push('', '## Achados');

  for (const f of sorted) {
    lines.push(
      '',
      `### [${formatSeverity(f.severity, color)}] ${f.file}:${f.line}`,
      '',
      `- **Regra:** \`${f.ruleId}\``,
      `- **Descricao:** ${f.message}`,
      `- **Evidencia:** ${f.snippet}`
    );
  }

  return lines.join('\n');
}

module.exports = { scanProject, formatReport, RULES };
