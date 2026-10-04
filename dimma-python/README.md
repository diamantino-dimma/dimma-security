# dimma

Declarative security middleware for Python/Flask projects, configured with a
shared `security.dimma` file.

## Install

```bash
python -m pip install dimma
```

For Redis-backed shared rate limiting, install `dimma[redis]`.

## Quick start

```python
from flask import Flask
from dimma.engine import DimmaEngine

app = Flask(__name__)
app.config["SECRET_KEY"] = "load-a-random-secret-from-your-environment"

dimma = DimmaEngine("./security.dimma")
dimma.protect(app)
```

To check that the injector recognizes the module-level Flask app declared in
`@files_protect` without changing it, run:

```bash
dimma inject --dry-run
dimma inject
```

The dry run does not modify files or create backups. A real injection is
limited to `.py` files inside the project, requires exactly one recognizable
module-level Flask app, and creates an exclusive `.dimma.bak` backup before
writing. Keep application configuration such as `SECRET_KEY` in the module;
the injector places protection after the app setup and before its main guard
or a direct `app.run()` call.

Use `dimma eject app.py` to restore the backup. If the injected file was
edited after injection, the current copy is saved as `.dimma.eject.bak`;
unmarked files are never overwritten.

Create a configuration with `dimma init`. For CLI commands, configuration
options, security boundaries, and Node.js usage, see the project README in
the [public GitHub repository](https://github.com/diamantino-dimma/dimma-security#readme).

The current PyPI release is `1.0.1`; it does not yet include the unreleased
Python `inject`, `eject`, and reputation-parity changes in this working tree.
Starting with `dimma` 1.0.1, run `dimma styles` to install the bundled
`.dimma` language extension in detected VS Code, Cursor, and VSCodium
installations. It does not read or modify workspace settings, and preserves
the currently selected file icon theme. Syntax highlighting applies only to
`.dimma` files. The Dimma icon theme remains an optional manual selection in
the editor; selecting any file icon theme replaces the currently active one.
Package installation itself never changes the IDE.

`dimma scan` performs heuristic static checks; it is not an active
DAST/pentest scanner or a security certification.

IP reputation checking follows local anomaly detection and is disabled unless
`@ip_reputation_check: true` is configured. It requires `ABUSEIPDB_API_KEY`,
skips non-global IP addresses, applies a daily request budget, and fails open
on external-service errors while keeping local protections active. Set
`REDIS_URL` and install `dimma[redis]` to share daily API budgets across
instances; without a configured Redis URL, the budget is process-local. If
Redis is configured but unavailable, external reputation and AI calls are
skipped rather than falling back to a per-worker budget.

With `REDIS_URL` and `dimma[redis]`, the anomaly history and daily external
API budgets are shared across worker instances. If Redis fails, the anomaly
signal is suppressed and the reputation/AI lookups are skipped; local request
filtering, CSRF, headers, and rate limiting continue independently. Without
a configured Redis URL, anomaly history and daily budgets are process-local.
