# dimma

Security middleware and CLI for Node.js/Express projects using a shared
`security.dimma` configuration file.

## Install

```bash
npm install dimma express
```

Requires Node.js 20 or later.

## Quick start

```js
const express = require('express');
const { DimmaEngine } = require('dimma');

const app = express();
app.use(express.json());

const dimma = new DimmaEngine('./security.dimma');
dimma.protect(app);

app.get('/health', (_req, res) => res.json({ ok: true }));
```

For CLI setup and configuration, see the
[project README](https://github.com/diamantino-dimma/dimma-security#readme).

Run `npm exec -- dimma styles` from the project directory to install the
bundled extension in every detected VS Code/Cursor installation and activate its icon theme in
`.vscode/settings.json`. The explicit command preserves other valid JSON
settings, does not change global editor configuration, and stops if settings
contain JSONC comments. `npm install` itself does not modify the IDE.

`dimma scan` is a heuristic static scanner, not an active DAST/pentest
scanner or a security certification.
