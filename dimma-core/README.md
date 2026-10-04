# dimma-core

Security middleware and CLI for Node.js/Express projects using a shared
`security.dimma` configuration file.

## Install

```bash
npm install dimma-core express
```

Requires Node.js 20 or later.

## Quick start

```js
const express = require('express');
const { DimmaEngine } = require('dimma-core');

const app = express();
app.use(express.json());

const dimma = new DimmaEngine('./security.dimma');
dimma.protect(app);

app.get('/health', (_req, res) => res.json({ ok: true }));
```

For CLI setup and configuration, see the
[project README](https://github.com/diamantino-dimma/dimma-security#readme).

`dimma scan` is a heuristic static scanner, not an active DAST/pentest
scanner or a security certification.
