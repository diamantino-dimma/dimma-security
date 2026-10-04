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

Create a configuration with `dimma init`. For CLI commands, configuration
options, security boundaries, and Node.js usage, see the project README in
the [public GitHub repository](https://github.com/diamantino-dimma/dimma-security#readme).

Starting with `dimma` 1.0.1, run `dimma styles` from your project directory to
install the bundled icon and syntax extension in detected
VS Code/Cursor installations and set `workbench.iconTheme` in that project's
`.vscode/settings.json`. It does not change global editor settings. If the
settings file uses JSONC comments instead of strict JSON, the command stops
without modifying it. Package installation itself never changes the IDE.

`dimma scan` performs heuristic static checks; it is not an active
DAST/pentest scanner or a security certification.
