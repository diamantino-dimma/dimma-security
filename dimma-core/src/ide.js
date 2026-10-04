'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const EDITORS = {
  vscode: { command: 'code', executable: 'Code.exe' },
  cursor: { command: 'cursor', executable: 'Cursor.exe' },
  vscodium: { command: 'codium', executable: 'VSCodium.exe' },
};

function findExecutable(editor, options = {}) {
  const definition = EDITORS[editor];
  if (!definition) throw new Error('Editor invalido; use vscode, cursor ou vscodium.');

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

function installStyles(options = {}) {
  const workspace = path.resolve(options.cwd || process.cwd());
  const resolveEditor = options.findExecutable || findExecutable;
  const editors = Object.keys(EDITORS)
    .map((editor) => [editor, resolveEditor(editor, options.executableOptions)])
    .filter(([, executable]) => executable);
  if (editors.length === 0) {
    throw new Error('Nao encontrei o CLI de VS Code (code), Cursor (cursor) nem VSCodium (codium) no PATH. Instale o editor ou adicione o respetivo CLI ao PATH.');
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
      throw new Error(`A instalacao da extensao em ${editor} falhou (codigo ${result.status}).`);
    }
  }

  console.log(
    `[dimma] Extensao de linguagem instalada em ${editors.map(([editor]) => editor).join(', ')}. ` +
    'O realce aplica-se a ficheiros .dimma; as definicoes e o tema de icones ativo foram preservados.'
  );
}

module.exports = { findExecutable, installStyles };
