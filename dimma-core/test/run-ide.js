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

function readSettings(workspace) {
  return JSON.parse(fs.readFileSync(path.join(workspace, '.vscode', 'settings.json'), 'utf8'));
}

console.log('\n== dimma styles ==');

test('instala em todos os editores detetados sem shell e preserva outras definicoes', () => {
  const workspace = makeWorkspace({ 'files.exclude': { build: true }, 'workbench.iconTheme': 'old-theme' });
  const calls = [];
  installStyles({
    cwd: workspace,
    findExecutable: (editor) => (editor === 'vscode' ? 'code' : 'cursor'),
    spawnSync: (...args) => {
      calls.push(args);
      return { status: 0 };
    },
  });
  assert.deepStrictEqual(readSettings(workspace), {
    'files.exclude': { build: true },
    'workbench.iconTheme': 'dimma-file-icons',
  });
  assert.strictEqual(calls.length, 2);
  assert.strictEqual(calls[0][1][0], '--install-extension');
  assert.strictEqual(calls[0][2].shell, false);
});

test('settings invalidos falham antes de executar o CLI', () => {
  const workspace = makeWorkspace();
  const settingsPath = path.join(workspace, '.vscode', 'settings.json');
  fs.writeFileSync(settingsPath, '{ // comment\n}', 'utf8');
  let launched = false;
  assert.throws(
    () => installStyles({
      cwd: workspace,
      findExecutable: () => 'code',
      spawnSync: () => { launched = true; return { status: 0 }; },
    }),
    /JSON valido/
  );
  assert.strictEqual(launched, false);
  assert.strictEqual(fs.readFileSync(settingsPath, 'utf8'), '{ // comment\n}');
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
  assert.deepStrictEqual(readSettings(workspace), { 'workbench.colorTheme': 'existing' });
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
  assert.deepStrictEqual(readSettings(workspace), { 'files.exclude': { build: true } });
});

for (const workspace of workspaces) fs.rmSync(workspace, { recursive: true, force: true });

console.log(`\n${passed} passaram, ${failed} falharam\n`);
if (failed > 0) process.exit(1);
