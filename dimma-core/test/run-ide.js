'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { installStyles } = require('../src/ide');

let passed = 0;
let failed = 0;
const workspaces = [];

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  OK  - ${name}`);
  } catch (error) {
    failed++;
    console.log(`FALHOU - ${name}\n        ${error.message}`);
  }
}

function makeWorkspace(settings) {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'dimma-ide-'));
  workspaces.push(workspace);
  fs.mkdirSync(path.join(workspace, '.vscode'));
  if (settings !== undefined) {
    fs.writeFileSync(
      path.join(workspace, '.vscode', 'settings.json'),
      JSON.stringify(settings),
      'utf8'
    );
  }
  return workspace;
}

console.log('\n== dimma styles ==');

test('instala VS Code, Cursor e VSCodium sem alterar as definicoes do workspace', () => {
  const workspace = makeWorkspace({ 'files.exclude': { build: true }, 'workbench.iconTheme': 'existing-theme' });
  const settingsPath = path.join(workspace, '.vscode', 'settings.json');
  const originalSettings = fs.readFileSync(settingsPath, 'utf8');
  const calls = [];
  installStyles({
    cwd: workspace,
    findExecutable: (editor) => ({ vscode: 'code', cursor: 'cursor', vscodium: 'codium' }[editor]),
    spawnSync: (...args) => {
      calls.push(args);
      return { status: 0 };
    },
  });
  assert.strictEqual(fs.readFileSync(settingsPath, 'utf8'), originalSettings);
  assert.strictEqual(calls.length, 3);
  assert.strictEqual(calls[0][1][0], '--install-extension');
  assert.strictEqual(calls[0][2].shell, false);
  assert.strictEqual(calls[2][0], 'codium');
});

test('nao le nem cria ficheiros de definicoes do workspace', () => {
  const workspace = makeWorkspace();
  const settingsPath = path.join(workspace, '.vscode', 'settings.json');
  fs.rmdirSync(path.join(workspace, '.vscode'));
  installStyles({
    cwd: workspace,
    findExecutable: () => 'code',
    spawnSync: () => ({ status: 0 }),
  });
  assert.strictEqual(fs.existsSync(settingsPath), false);
  assert.strictEqual(fs.existsSync(path.join(workspace, '.vscode')), false);
});

test('falha de instalacao nao altera settings existentes', () => {
  const workspace = makeWorkspace({ 'workbench.colorTheme': 'existing' });
  assert.throws(
    () => installStyles({
      cwd: workspace,
      findExecutable: (editor) => (editor === 'cursor' ? 'cursor' : null),
      spawnSync: () => ({ status: 1 }),
    }),
    /codigo 1/
  );
  assert.deepStrictEqual(
    JSON.parse(fs.readFileSync(path.join(workspace, '.vscode', 'settings.json'), 'utf8')),
    { 'workbench.colorTheme': 'existing' }
  );
});

test('sem CLI de editor, reporta erro antes de alterar settings', () => {
  const workspace = makeWorkspace({ 'files.exclude': { build: true } });
  let launched = false;
  assert.throws(
    () => installStyles({
      cwd: workspace,
      findExecutable: () => null,
      spawnSync: () => { launched = true; return { status: 0 }; },
    }),
    /Nao encontrei o CLI/
  );
  assert.strictEqual(launched, false);
  assert.deepStrictEqual(
    JSON.parse(fs.readFileSync(path.join(workspace, '.vscode', 'settings.json'), 'utf8')),
    { 'files.exclude': { build: true } }
  );
});

for (const workspace of workspaces) fs.rmSync(workspace, { recursive: true, force: true });

console.log(`\n${passed} passaram, ${failed} falharam\n`);
if (failed > 0) process.exit(1);
