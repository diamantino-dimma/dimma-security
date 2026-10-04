"""
DimmaEngine (Flask) — aplica no app Flask todas as protecoes descritas
num arquivo .dimma: headers de seguranca, rate limiting, sanitizacao
anti SQLi/XSS, CSRF, deteccao de anomalia e revisao opcional por IA.
"""
import os
import secrets
import time
import warnings
from urllib.parse import unquote

from flask import request, jsonify, g
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from werkzeug.exceptions import RequestEntityTooLarge

from .parser import parse_dimma
from .security.sanitize import scan_object
from .security.anomaly import AnomalyDetector
from .security.ai import classify_with_ai
from .security import auth as auth_utils
from .security.webauthn import WebAuthnSupport
from .template import DEFAULT_TEMPLATE


class DimmaEngine:
    def __init__(self, dimma_file_path: str, auto_create: bool = True, rp_id: str = None, rp_origin: str = None, rp_name: str = None):
        if not os.path.exists(dimma_file_path):
            if not auto_create:
                raise FileNotFoundError(
                    f"Arquivo .dimma nao encontrado em '{dimma_file_path}'. "
                    "Rode 'dimma init' ou passe auto_create=True."
                )
            with open(dimma_file_path, "w", encoding="utf-8") as f:
                f.write(DEFAULT_TEMPLATE)
            print(
                f"[dimma] '{dimma_file_path}' nao existia — criado automaticamente "
                "com o perfil de seguranca padrao. Ajuste conforme necessario."
            )

        with open(dimma_file_path, "r", encoding="utf-8") as f:
            source = f.read()
        self.config = parse_dimma(source)
        self.file_path = dimma_file_path
        self._anomaly_detector = AnomalyDetector()
        self.csrf = None

        # Passkeys/WebAuthn: inicializado sob demanda (lazy) so quando
        # @passkey_support: true estiver no .dimma.
        self.webauthn = None
        if self.config.get("passkey_support"):
            resolved_rp_id = rp_id or self.config.get("rp_id")
            resolved_origin = rp_origin or self.config.get("rp_origin")
            if not resolved_rp_id or not resolved_origin:
                raise ValueError(
                    "dimma: @passkey_support esta ativo, mas faltam @rp_id e/ou @rp_origin "
                    "no .dimma (ou os parametros rp_id/rp_origin ao criar o DimmaEngine). "
                    "Exemplo: @rp_id: meusite.com  /  @rp_origin: https://meusite.com"
                )
            self.webauthn = WebAuthnSupport(rp_id=resolved_rp_id, origin=resolved_origin, rp_name=rp_name)

    def protect(self, app):
        cfg = self.config
        excluded = set(cfg.get("exclude", []))

        # 1) Headers de seguranca (Talisman = equivalente Python do helmet)
        if cfg.get("security_headers") or cfg.get("auto_protect"):
            Talisman(
                app,
                content_security_policy={
                    "default-src": "'self'",
                    "script-src": "'self'",
                    "object-src": "'none'",
                },
                force_https=app.config.get("ENV") == "production",
                strict_transport_security=True,
                referrer_policy="no-referrer",
            )

        # 2) Rate limiting
        # SEGURANCA: por padrao, o Flask-Limiter guarda contadores na
        # memoria do processo -- com multiplas instancias atras de um
        # load balancer, um atacante distribui as requisicoes entre elas
        # e nenhuma sozinha atinge o limite. Se REDIS_URL estiver
        # configurada, usamos Redis como armazenamento compartilhado
        # (suporte nativo do Flask-Limiter via storage_uri); sem ela,
        # cai para memoria local (adequado para desenvolvimento/instancia
        # unica), com aviso.
        rate_cfg = cfg.get("rate_limit") or {"max": 100, "window_ms": 60000}
        redis_url = os.environ.get("REDIS_URL")
        storage_uri = redis_url if redis_url else "memory://"
        if not redis_url:
            warnings.warn(
                "[dimma] REDIS_URL nao configurada — rate limiting usara memoria "
                "local (nao compartilhada entre instancias). Se sua aplicacao roda "
                "com mais de uma instancia/processo, configure REDIS_URL.",
                stacklevel=2,
            )

        limiter = Limiter(
            get_remote_address,
            app=app,
            storage_uri=storage_uri,
            default_limits=[f"{rate_cfg['max']} per {max(1, rate_cfg['window_ms'] // 1000)} second"],
            default_limits_exempt_when=lambda: request.path in excluded,
        )
        self.limiter = limiter

        # 3) CSRF (flask-wtf, padrao de mercado no ecossistema Flask)
        if cfg.get("csrf_protection") or cfg.get("auto_protect"):
            # SEGURANCA: nunca usar um SECRET_KEY padrao fixo no codigo.
            # Um valor hardcoded compartilhado por todos os projetos que
            # usam esta lib sem configurar a variavel de ambiente
            # permitiria a um atacante forjar tokens CSRF/sessao validos
            # para qualquer um desses projetos.
            if not app.config.get("SECRET_KEY"):
                is_production = os.environ.get("FLASK_ENV") == "production" or app.config.get("ENV") == "production"
                if is_production:
                    raise RuntimeError(
                        "dimma: SECRET_KEY nao configurada em producao. Defina "
                        "app.config['SECRET_KEY'] (ou a variavel de ambiente "
                        "correspondente) com um valor aleatorio e secreto "
                        "(ex: python -c \"import secrets; print(secrets.token_hex(32))\") "
                        "antes de iniciar a aplicacao."
                    )
                app.config["SECRET_KEY"] = secrets.token_hex(32)
                warnings.warn(
                    "[dimma] SECRET_KEY nao configurada — usando valor aleatorio "
                    "gerado para esta execucao (valido apenas em desenvolvimento/"
                    "teste). Configure app.config['SECRET_KEY'] antes de ir para producao.",
                    stacklevel=2,
                )
            app.config.setdefault("WTF_CSRF_TIME_LIMIT", None)
            self.csrf = CSRFProtect(app)

        # 4) Sanitizacao de input (SQLi/XSS) via before_request
        protect_types = cfg.get("protect_input") or (["sql_injection", "xss"] if cfg.get("auto_protect") else [])
        anomaly_on = cfg.get("anomaly_detection")
        ai_on = cfg.get("ai_detection")
        if protect_types:
            max_request_bytes = 1024 * 1024
            configured_limit = app.config.get("MAX_CONTENT_LENGTH")
            effective_limit = min(configured_limit, max_request_bytes) if configured_limit is not None else max_request_bytes
            app.config["MAX_CONTENT_LENGTH"] = effective_limit

            @app.errorhandler(RequestEntityTooLarge)
            def _dimma_request_too_large(_error):
                return jsonify({
                    "error": f"Requisicao excede o limite de {effective_limit} bytes para inspecao de entrada."
                }), 413

        @app.before_request
        def _dimma_block_direct_access():
            # SEMPRE ativo: nenhum arquivo .dimma deve ser acessivel via
            # HTTP, o mesmo cuidado que se toma com um arquivo .env.
            request_path = request.path
            for _ in range(8):
                if request_path.lower().endswith(".dimma"):
                    return jsonify({"error": "Not Found"}), 404
                try:
                    decoded_path = unquote(request_path, errors="strict")
                except UnicodeDecodeError:
                    return jsonify({"error": "Bad Request"}), 400
                if decoded_path == request_path:
                    return None
                request_path = decoded_path
            return jsonify({"error": "Bad Request"}), 400

        @app.before_request
        def _dimma_before_request():
            if request.path in excluded:
                return None

            if protect_types:
                body = request.get_json(silent=True) if request.is_json else {}
                form = request.form.to_dict(flat=False)
                query = request.args.to_dict(flat=False)
                findings = [
                    f for f in (
                        scan_object(body, "body")
                        + scan_object(form, "form")
                        + scan_object(query, "query")
                        + scan_object(request.view_args or {}, "params")
                    )
                    if f["type"] == "input_too_large" or f["type"] in protect_types
                ]
                if findings:
                    return jsonify({
                        "error": "Requisicao bloqueada pelo .dimma: entrada potencialmente maliciosa detectada.",
                        "details": [{"path": f["path"], "type": f["type"]} for f in findings],
                    }), 400

            if anomaly_on:
                key = get_remote_address()
                result = self._anomaly_detector.observe(key, time.time() * 1000)
                g.dimma_anomaly = result
                if result["anomalous"]:
                    app.logger.warning(f"[dimma] anomalia detectada em {key}: {result}")
                    if ai_on:
                        try:
                            verdict = classify_with_ai(
                                {
                                    "findings": [result],
                                    "rawInput": {
                                        "path": request.url_rule.rule if request.url_rule else "/",
                                        "method": request.method,
                                    },
                                },
                                provider=cfg.get("ai_provider"),
                                model=cfg.get("ai_model"),
                            )
                            g.dimma_ai_verdict = verdict
                            if verdict["malicious"] is None:
                                app.logger.warning(
                                    "[dimma-ai] analise indisponivel: %s",
                                    verdict["reason"],
                                )
                            elif verdict["malicious"] is True and verdict["confidence"] >= 0.7:
                                return jsonify({
                                    "error": "Requisicao bloqueada pelo .dimma apos analise de IA.",
                                }), 403
                        except (RuntimeError, ValueError) as error:
                            app.logger.warning(
                                "[dimma-ai] falha na revisao externa; a manter a decisao local: %s",
                                error,
                            )

            return None

        return app

    # Utilitarios expostos para uso direto no codigo do programador.
    hash_password = staticmethod(auth_utils.hash_password)
    verify_password = staticmethod(auth_utils.verify_password)
    generate_secure_token = staticmethod(auth_utils.generate_secure_token)
