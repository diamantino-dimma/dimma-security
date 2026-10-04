"""Template padrao do security.dimma, compartilhado entre o CLI e o
auto-geracao do DimmaEngine quando o arquivo nao existe ainda."""

DEFAULT_TEMPLATE = """# security.dimma — configuracao de seguranca do projeto
# Gerado automaticamente pelo dimma — ajuste conforme a necessidade do seu projeto

# Opcional: use @files_protect com o comando "dimma inject".
# Exemplos: @files_protect: [app.py] ou [app.py, routes/api.py]
@files_protect: []

# Modo proxy autonomo (disponivel no CLI Node.js).
# @target: http://localhost:3000
# @listen: 8080

@auto_protect: true
@protect input: [sql_injection, xss]
@rate_limit: 100 req/min
@csrf_protection: true
@security_headers: true
@anomaly_detection: true
@ip_reputation_check: true
# Optional external AI review (only on statistical anomalies):
# @ai_detection: true
# @ai_provider: nvidia
# @ai_model: meta/llama-3.1-8b-instruct
@password_hashing: bcrypt
@session_expiry: 30
"""
