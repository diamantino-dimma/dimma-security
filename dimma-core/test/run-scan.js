'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanProject, formatReport } = require('../src/scan');
const { formatSupplyChainReport } = require('../src/security/supplyChain');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  OK  - ${name}`);
  } catch (err) {
    failed++;
    console.log(`FALHOU - ${name}\n        ${err.message}`);
  }
}

function makeTempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-scan-'));
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = path.join(dir, relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, 'utf-8');
  }
  return dir;
}

function findingIds(result) {
  return result.findings.map((f) => f.ruleId);
}

console.log('\n== dimma scan (scanner de codigo inseguro) ==');

test('detecta chave AWS hardcoded', () => {
  const dir = makeTempProject({ 'a.js': `const k = "AKIAABCDEFGHIJKLMNOP";` });
  const result = scanProject(dir);
  assert.ok(findingIds(result).includes('hardcoded-aws-key'));
});

test('detecta segredo generico hardcoded', () => {
  const dir = makeTempProject({ 'a.js': `const apiKey = "sk_live_ABCDEFGH1234567890AB";` });
  const result = scanProject(dir);
  assert.ok(findingIds(result).includes('hardcoded-secret-assignment'));
});

test('detecta SQL Injection por concatenacao (JS)', () => {
  const dir = makeTempProject({ 'a.js': `const q = "SELECT * FROM users WHERE id = " + id;` });
  const result = scanProject(dir);
  assert.ok(findingIds(result).includes('sql-string-concat-js'));
});

test('detecta SQL Injection por f-string (Python)', () => {
  const dir = makeTempProject({ 'a.py': `q = f"SELECT * FROM users WHERE id = {user_id}"` });
  const result = scanProject(dir);
  assert.ok(findingIds(result).includes('sql-fstring-py'));
});

test('detecta eval() em JS', () => {
  const dir = makeTempProject({ 'a.js': `eval(userInput);` });
  const result = scanProject(dir);
  assert.ok(findingIds(result).includes('eval-usage-js'));
});

test('detecta exec()/eval() em Python', () => {
  const dir = makeTempProject({ 'a.py': `exec(user_input)` });
  const result = scanProject(dir);
  assert.ok(findingIds(result).includes('eval-usage-py'));
});

test('detecta child_process.exec() direto', () => {
  const dir = makeTempProject({ 'a.js': `require('child_process').exec('ls ' + dir);` });
  const result = scanProject(dir);
  assert.ok(findingIds(result).includes('command-injection-node'));
});

test('detecta exec() desestruturado de child_process', () => {
  const dir = makeTempProject({
    'a.js': `const { exec } = require('child_process');\nexec('ls ' + userDir);`,
  });
  const result = scanProject(dir);
  assert.ok(findingIds(result).includes('command-injection-node-destructured'));
});

test('detecta subprocess com shell=True em Python', () => {
  const dir = makeTempProject({ 'a.py': `subprocess.run(cmd, shell=True)` });
  const result = scanProject(dir);
  assert.ok(findingIds(result).includes('command-injection-py'));
});

test('detecta pickle.loads inseguro', () => {
  const dir = makeTempProject({ 'a.py': `data = pickle.loads(raw_bytes)` });
  const result = scanProject(dir);
  assert.ok(findingIds(result).includes('insecure-deserialization-py'));
});

test('detecta debug=True no Flask', () => {
  const dir = makeTempProject({ 'a.py': `app.run(host="0.0.0.0", debug=True)` });
  const result = scanProject(dir);
  assert.ok(findingIds(result).includes('debug-mode-flask'));
});

test('detecta innerHTML com dado dinamico', () => {
  const dir = makeTempProject({ 'a.js': `el.innerHTML = userInput;` });
  const result = scanProject(dir);
  assert.ok(findingIds(result).includes('innerhtml-assignment'));
});

test('detecta dangerouslySetInnerHTML no React', () => {
  const dir = makeTempProject({ 'a.jsx': `<div dangerouslySetInnerHTML={{__html: data}} />` });
  const result = scanProject(dir);
  assert.ok(findingIds(result).includes('dangerously-set-innerhtml'));
});

test('nao gera falso positivo em codigo seguro', () => {
  const dir = makeTempProject({
    'a.js': [
      'const apiKey = process.env.API_KEY;',
      'const query = "SELECT * FROM users WHERE id = ?";',
      'db.query(query, [id]);',
      "el.textContent = userInput;",
    ].join('\n'),
  });
  const result = scanProject(dir);
  assert.strictEqual(result.findings.length, 0);
});

test('ignora node_modules e .git', () => {
  const dir = makeTempProject({
    'node_modules/pacote/ruim.js': `const k = "AKIAABCDEFGHIJKLMNOP";`,
    '.git/ruim.js': `const k = "AKIAABCDEFGHIJKLMNOP";`,
    'src/bom.js': `const x = 1;`,
  });
  const result = scanProject(dir);
  assert.strictEqual(result.findings.length, 0);
  assert.strictEqual(result.filesScanned, 1);
});

test('reporta erros de leitura como cobertura incompleta', () => {
  const missingDir = path.join(os.tmpdir(), `dimma-scan-missing-${Date.now()}`);
  const result = scanProject(missingDir);
  assert.strictEqual(result.filesScanned, 0);
  assert.strictEqual(result.errors.length, 1);
  const report = formatReport(result);
  assert.match(report, /Cobertura incompleta/);
  assert.match(report, /scan esta incompleto/);
});

test('formata o relatorio Markdown e diferencia as severidades por cor', () => {
  const result = {
    filesScanned: 4,
    errors: [],
    findings: ['critical', 'high', 'medium', 'low'].map((severity) => ({
      severity,
      file: 'src/example.js',
      line: 12,
      ruleId: `rule-${severity}`,
      message: `Finding ${severity}`,
      snippet: 'unsafe(value)',
    })),
  };
  const plain = formatReport(result, { color: false });
  assert.match(plain, /^# Dimma Scan/m);
  assert.match(plain, /\*\*Total de achados:\*\* 4/);
  assert.match(plain, /## Achados/);
  assert.ok(plain.indexOf('[CRITICO]') < plain.indexOf('[ALTO]'));
  assert.ok(plain.indexOf('[ALTO]') < plain.indexOf('[MEDIO]'));
  assert.ok(plain.indexOf('[MEDIO]') < plain.indexOf('[BAIXO]'));
  assert.doesNotMatch(plain, /\u001b\[/);

  const colored = formatReport(result, { color: true });
  assert.match(colored, /\u001b\[31;1mCRITICO\u001b\[0m/);
  assert.match(colored, /\u001b\[91;1mALTO\u001b\[0m/);
  assert.match(colored, /\u001b\[33;1mMEDIO\u001b\[0m/);
  assert.match(colored, /\u001b\[36;1mBAIXO\u001b\[0m/);
});

test('formata achados de supply chain com a mesma hierarquia de severidade', () => {
  const report = formatSupplyChainReport({
    dependenciesChecked: 2,
    onlineCheckPerformed: false,
    findings: [{
      severity: 'high',
      package: 'example-package',
      type: 'lockfile-ausente',
      message: 'Lockfile ausente.',
    }],
  }, { color: true });
  assert.match(report, /^## Supply chain guard/m);
  assert.match(report, /\u001b\[91;1mALTO\u001b\[0m/);
  assert.match(report, /example-package/);
  assert.match(report, /\*\*Regra:\*\* `lockfile-ausente`/);
});

console.log(`\n${passed} passaram, ${failed} falharam\n`);
if (failed > 0) process.exit(1);
