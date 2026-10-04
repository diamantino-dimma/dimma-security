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

Run `npm exec -- dimma styles` to install the bundled `.dimma` language
extension in detected VS Code, Cursor, and VSCodium installations. It does not
read or modify workspace settings, and preserves the currently selected file
icon theme. Syntax highlighting applies only to `.dimma` files. The Dimma icon
theme remains an optional manual selection in the editor; selecting any file
icon theme replaces the currently active one. `npm install` itself does not
modify the IDE.

`dimma scan` is a heuristic static scanner, not an active DAST/pentest
scanner or a security certification.
