'use strict';

const DEFAULT_TEMPLATE = `# security.dimma — configuracao de seguranca do projeto
# Gerado automaticamente pelo dimma — ajuste conforme a necessidade do seu projeto

# ─────────────────────────────────────────────────────────────────────────────
# Opcional: use @files_protect apenas com o comando "dimma inject".
# Exemplos:
#   @files_protect: [app.js]
#   @files_protect: [app.py]
#   @files_protect: [app.js, routes/api.js, routes/auth.js]
# ─────────────────────────────────────────────────────────────────────────────
@files_protect: []

# ── Modo proxy autónomo (opcional) ───────────────────────────────────────────
# @target: http://localhost:3000
# @listen: 8080

# ── Protecções ────────────────────────────────────────────────────────────────
@auto_protect: true
@protect input: [sql_injection, xss]
@rate_limit: 100 req/min
@csrf_protection: true
@security_headers: true
@anomaly_detection: true
@ip_reputation_check: true
# A analise por IA e opcional; configure uma chave de API no ambiente.
# Providers: nvidia | openai | openrouter | anthropic | gemini
# @ai_detection: true
# @ai_provider: nvidia
# @ai_model: meta/llama-3.1-8b-instruct
@password_hashing: bcrypt
@session_expiry: 30
`;

module.exports = { DEFAULT_TEMPLATE };
