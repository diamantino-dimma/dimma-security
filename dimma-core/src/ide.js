'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const EDITORS = {
  vscode: { command: 'code', executable: 'Code.exe' },
  cursor: { command: 'cursor', executable: 'Cursor.exe' },
};
const ICON_THEME = 'dimma-file-icons';

function findExecutable(editor, options = {}) {
  const definition = EDITORS[editor];
  if (!definition) throw new Error('Editor invalido; use vscode ou cursor.');

  const platform = options.platform || process.platform;
  const env = options.env || process.env;
  const pathValue = env.PATH || env.Path || '';
  const pathExt = platform === 'win32'
    ? (env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';')
    : [''];

  for (const directory of pathValue.split(path.delimiter)) {
    if (!directory) continue;
    for (const extension of pathExt) {
      const candidate = path.resolve(directory, `${definition.command}${extension}`);
      try {
        if (!fs.statSync(candidate).isFile()) continue;
        if (platform !== 'win32') fs.accessSync(candidate, fs.constants.X_OK);
        if (platform === 'win32' && /\.(cmd|bat)$/i.test(candidate)) {
          let parent = path.dirname(candidate);
          for (let depth = 0; depth < 6; depth++) {
            const nativeExecutable = path.join(parent, definition.executable);
            if (fs.existsSync(nativeExecutable)) return nativeExecutable;
            const nextParent = path.dirname(parent);
            if (nextParent === parent) break;
            parent = nextParent;
          }
          throw new Error(
            `Encontrei "${candidate}", mas nao ${definition.executable}. ` +
            'Use o CLI do editor diretamente para instalar o VSIX.'
          );
        }
        return candidate;
      } catch (error) {
        if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
      }
    }
  }

  return null;
}

function readWorkspaceSettings(settingsPath) {
  if (!fs.existsSync(settingsPath)) return {};
  let settings;
  try {
    settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
  } catch (error) {
    throw new Error(
      `Nao foi possivel ler ${settingsPath} como JSON valido; nenhuma definicao foi alterada. ` +
      `Ative manualmente "${ICON_THEME}" em workbench.iconTheme. Detalhe: ${error.message}`
    );
  }
  if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
    throw new Error(`${settingsPath} deve conter um objeto JSON; nenhuma definicao foi alterada.`);
  }
  return settings;
}

function writeWorkspaceSettings(settingsPath, settings) {
  const directory = path.dirname(settingsPath);
  fs.mkdirSync(directory, { recursive: true });
  const temporaryPath = path.join(directory, `.dimma-settings-${process.pid}-${crypto.randomBytes(6).toString('hex')}.tmp`);
  let originalMode;
  try {
    originalMode = fs.statSync(settingsPath).mode & 0o777;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  try {
    fs.writeFileSync(temporaryPath, `${JSON.stringify(settings, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
    if (originalMode !== undefined) fs.chmodSync(temporaryPath, originalMode);
    fs.renameSync(temporaryPath, settingsPath);
  } catch (error) {
    try {
      fs.unlinkSync(temporaryPath);
    } catch (cleanupError) {
      if (cleanupError.code !== 'ENOENT') {
        error.message += `; tambem nao foi possivel remover o temporario: ${cleanupError.message}`;
      }
    }
    throw error;
  }
}

function installStyles(options = {}) {
  const workspace = path.resolve(options.cwd || process.cwd());
  const settingsDirectory = path.join(workspace, '.vscode');
  const settingsPath = path.join(settingsDirectory, 'settings.json');
  for (const target of [settingsDirectory, settingsPath]) {
    try {
      if (fs.lstatSync(target).isSymbolicLink()) {
        throw new Error('Por seguranca, nao altero .vscode/settings.json quando .vscode ou settings.json e um link simbolico.');
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  readWorkspaceSettings(settingsPath);
  const resolveEditor = options.findExecutable || findExecutable;
  const editors = Object.keys(EDITORS)
    .map((editor) => [editor, resolveEditor(editor, options.executableOptions)])
    .filter(([, executable]) => executable);
  if (editors.length === 0) {
    throw new Error('Nao encontrei o CLI de VS Code (code) nem Cursor (cursor) no PATH. Instale o editor ou adicione o respetivo CLI ao PATH.');
  }
  const extensionPath = path.resolve(__dirname, '..', 'assets', 'dimma-file-icons.vsix');
  if (!fs.statSync(extensionPath).isFile()) {
    throw new Error('O pacote Dimma nao contem o VSIX da extensao de icones.');
  }

  for (const [editor, executable] of editors) {
    const result = (options.spawnSync || spawnSync)(
      executable,
      ['--install-extension', extensionPath],
      { cwd: workspace, stdio: 'inherit', shell: false }
    );
    if (result.error) throw result.error;
    if (result.status !== 0) {
      throw new Error(
        `A instalacao da extensao em ${editor} falhou (codigo ${result.status}); as definicoes do workspace nao foram alteradas.`
      );
    }
  }

  const latestSettings = readWorkspaceSettings(settingsPath);
  latestSettings['workbench.iconTheme'] = ICON_THEME;
  writeWorkspaceSettings(settingsPath, latestSettings);
  console.log(`[dimma] Extensao instalada em ${editors.map(([editor]) => editor).join(', ')}; tema ${ICON_THEME} ativado em .vscode/settings.json.`);
}

module.exports = { findExecutable, installStyles, readWorkspaceSettings, writeWorkspaceSettings };
