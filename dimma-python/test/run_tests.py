import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dimma.parser import parse_dimma
from dimma.security.sanitize import (
    contains_sql_injection,
    contains_xss,
    escape_html,
    escape_for_sql,
    scan_object,
)
from dimma.security.auth import hash_password, verify_password
from dimma.security.anomaly import AnomalyDetector

passed = 0
failed = 0


def test(name, fn):
    global passed, failed
    try:
        fn()
        passed += 1
        print(f"  OK  - {name}")
    except Exception as exc:  # noqa: BLE001
        failed += 1
        print(f"FALHOU - {name}\n        {exc}")


print("\n== Parser .dimma ==")


def _t_auto_protect():
    cfg = parse_dimma("@auto_protect: true")
    assert cfg.values["auto_protect"] is True


def _t_rate_limit():
    cfg = parse_dimma("@rate_limit: 100 req/min")
    assert cfg.values["rate_limit"]["max"] == 100
    assert cfg.values["rate_limit"]["window_ms"] == 60000


def _t_protect_input_list():
    cfg = parse_dimma("@protect input: [sql_injection, xss]")
    assert set(cfg.values["protect_input"]) == {"sql_injection", "xss"}


def _t_optional_ai_provider_configuration():
    cfg = parse_dimma(
        "@ai_detection: true\n"
        "@ai_provider: openrouter\n"
        "@ai_model: provider/model"
    )
    assert cfg.get("ai_detection") is True
    assert cfg.get("ai_provider") == "openrouter"
    assert cfg.get("ai_model") == "provider/model"


def _t_parser_accepts_utf8_bom():
    cfg = parse_dimma("\ufeff@ai_provider: openai\n@ai_model: gpt-test")
    assert cfg.get("ai_provider") == "openai"
    assert cfg.get("ai_model") == "gpt-test"


test("parser le @auto_protect: true", _t_auto_protect)
test("parser converte '100 req/min'", _t_rate_limit)
test("parser converte lista @protect input", _t_protect_input_list)
test("parser le provider e modelo opcional da IA", _t_optional_ai_provider_configuration)
test("parser le arquivos UTF-8 com BOM do Windows", _t_parser_accepts_utf8_bom)

print("\n== Deteccao de SQL Injection ==")


def _t_sqli_basic():
    assert contains_sql_injection("1 OR 1=1")


def _t_sqli_union():
    assert contains_sql_injection("' UNION SELECT senha FROM usuarios --")


def _t_sqli_drop():
    assert contains_sql_injection("'; DROP TABLE usuarios; --")


def _t_sqli_legit():
    assert contains_sql_injection("Maria D'Angelo comprou 2 itens") is False


def _t_escape_sql_rejected():
    try:
        escape_for_sql("' OR 1=1 --")
        raise AssertionError("escaping SQL generico deveria ser recusado")
    except RuntimeError as exc:
        assert "queries parametrizadas" in str(exc)


def _t_oversized_input_fails_closed():
    long_input = ("a" * 4096) + "' OR 1=1 --"
    assert contains_sql_injection(long_input) is True
    assert contains_xss(long_input) is True
    assert scan_object({"value": long_input})[0]["type"] == "input_too_large"


test("detecta '1 OR 1=1'", _t_sqli_basic)
test("detecta UNION SELECT", _t_sqli_union)
test("detecta DROP TABLE", _t_sqli_drop)
test("nao bloqueia texto legitimo", _t_sqli_legit)
test("recusa escaping SQL generico e orienta usar queries parametrizadas", _t_escape_sql_rejected)
test("rejeita input acima do limite sem truncar", _t_oversized_input_fails_closed)

print("\n== Deteccao de XSS ==")


def _t_xss_script():
    assert contains_xss("<script>alert(1)</script>")


def _t_xss_onerror():
    assert contains_xss("<img src=x onerror=alert(1)>")


def _t_escape_html():
    assert escape_html("<b>oi</b>") == "&lt;b&gt;oi&lt;/b&gt;"


test("detecta <script>", _t_xss_script)
test("detecta onerror=", _t_xss_onerror)
test("escape_html neutraliza tags", _t_escape_html)

print("\n== Hashing de senha ==")


def _t_hash():
    h = hash_password("senhaForte123")
    assert verify_password("senhaForte123", h) is True
    assert verify_password("senhaErrada", h) is False


def _t_short_password():
    try:
        hash_password("123")
        raise AssertionError("deveria ter rejeitado senha curta")
    except ValueError:
        pass


def _t_bcrypt_rejects_overlong_passwords():
    try:
        hash_password("a" * 73)
        raise AssertionError("deveria ter rejeitado senha acima de 72 bytes")
    except ValueError as exc:
        assert "72 bytes" in str(exc)

    assert verify_password("a" * 73, "$2b$12$invalid") is False


test("hash e verificacao de senha", _t_hash)
test("rejeita senha curta demais", _t_short_password)
test("rejeita senha acima do limite bcrypt de 72 bytes", _t_bcrypt_rejects_overlong_passwords)

print("\n== Deteccao de anomalia (estatistica) ==")


def _t_anomaly():
    detector = AnomalyDetector(z_score_threshold=2)
    now = 1_700_000_000_000
    for i in range(15):
        detector.observe("1.2.3.4", now + i * 1000)
    result = detector.observe("1.2.3.4", now + 14 * 1000 + 5)
    assert result["anomalous"] is True, result


test("marca rajada como anomalia", _t_anomaly)

print("\n== Integracao HTTP (Flask + middlewares reais) ==")

from example.app import app as flask_app  # noqa: E402

client = flask_app.test_client()


def _get_csrf_token():
    res = client.get("/csrf-token")
    token = res.get_json()["csrfToken"]
    cookie = res.headers.get("Set-Cookie", "")
    return token, cookie


def _t_blocks_sqli():
    token, cookie = _get_csrf_token()
    res = client.post(
        "/login",
        json={"username": "admin' OR '1'='1"},
        headers={"X-CSRFToken": token, "Cookie": cookie},
    )
    assert res.status_code == 400, res.status_code


def _t_blocks_sqli_form():
    token, cookie = _get_csrf_token()
    res = client.post(
        "/login",
        data={"username": "admin' OR '1'='1"},
        headers={"X-CSRFToken": token, "Cookie": cookie},
    )
    assert res.status_code == 400, res.status_code


def _t_blocks_oversized_input():
    token, cookie = _get_csrf_token()
    res = client.post(
        "/login",
        json={"username": ("a" * 4096) + "' OR 1=1 --"},
        headers={"X-CSRFToken": token, "Cookie": cookie},
    )
    assert res.status_code == 400, res.status_code
    assert res.get_json()["details"][0]["type"] == "input_too_large"


def _t_allows_legit_login():
    token, cookie = _get_csrf_token()
    res = client.post(
        "/login",
        json={"username": "diamantino"},
        headers={"X-CSRFToken": token, "Cookie": cookie},
    )
    assert res.status_code == 200, res.get_data(as_text=True)


def _t_blocks_missing_csrf():
    res = client.post("/login", json={"username": "diamantino"})
    assert res.status_code == 400, res.status_code


def _t_security_headers():
    res = client.get("/health")
    # Strict-Transport-Security so e enviado sobre HTTPS real (aqui o
    # teste roda em HTTP puro) -- checamos os headers aplicaveis sempre.
    assert "X-Content-Type-Options" in res.headers
    assert "X-Frame-Options" in res.headers
    assert "Content-Security-Policy" in res.headers


def _t_register_hashes_password():
    token, cookie = _get_csrf_token()
    res = client.post(
        "/register",
        json={"password": "minhaSenhaSegura1"},
        headers={"X-CSRFToken": token, "Cookie": cookie},
    )
    assert res.status_code == 200, res.get_data(as_text=True)
    data = res.get_json()
    assert data["success"] is True
    assert "passwordHash" not in data


test("bloqueia SQL Injection no POST /login", _t_blocks_sqli)
test("bloqueia SQL Injection em formulario", _t_blocks_sqli_form)
test("bloqueia input acima do limite sem truncar", _t_blocks_oversized_input)
test("permite login legitimo (com token CSRF)", _t_allows_legit_login)
test("bloqueia POST sem token CSRF", _t_blocks_missing_csrf)
test("aplica headers de seguranca (talisman)", _t_security_headers)
test("registro confirma sucesso sem expor hash da senha", _t_register_hashes_password)

print("\n== Bloqueio de acesso direto ao .dimma ==")


def _t_blocks_direct_dimma_access():
    res = client.get("/security.dimma")
    assert res.status_code == 404, res.status_code


def _t_blocks_any_dimma_path():
    res = client.get("/config/outro-nome.dimma")
    assert res.status_code == 404, res.status_code


def _t_allows_normal_routes():
    res = client.get("/health")
    assert res.status_code == 200


test("bloqueia GET /security.dimma", _t_blocks_direct_dimma_access)
test("bloqueia qualquer caminho terminado em .dimma", _t_blocks_any_dimma_path)
test("nao bloqueia rotas normais", _t_allows_normal_routes)

def _t_blocks_encoded_dimma_static():
    from flask import Flask
    from dimma.engine import DimmaEngine

    with tempfile.TemporaryDirectory(prefix="dimma-static-test-") as temp_dir:
        static_dir = os.path.join(temp_dir, "static")
        os.makedirs(static_dir)
        with open(os.path.join(static_dir, "security.dimma"), "w", encoding="utf-8") as file:
            file.write("@secret: do-not-serve")

        dimma_path = os.path.join(temp_dir, "test-config.dimma")
        with open(dimma_path, "w", encoding="utf-8") as file:
            file.write(
                "@csrf_protection: false\n"
                "@security_headers: false\n"
                "@anomaly_detection: false\n"
            )

        test_app = Flask("encoded_dimma_static", static_folder=static_dir)
        DimmaEngine(dimma_path).protect(test_app)
        test_client = test_app.test_client()
        for encoded_path in (
            "/static/security%2edimma",
            "/static/security%25252edimma",
        ):
            response = test_client.get(encoded_path)
            assert response.status_code == 404, response.status_code
            assert b"do-not-serve" not in response.data


test("bloqueia .dimma estatico com ponto percent-encoded", _t_blocks_encoded_dimma_static)

def _t_preserves_json_primitive_body():
    from flask import Flask, jsonify, request
    from dimma.engine import DimmaEngine

    with tempfile.TemporaryDirectory(prefix="dimma-json-primitive-") as temp_dir:
        config_path = os.path.join(temp_dir, "security.dimma")
        with open(config_path, "w", encoding="utf-8") as file:
            file.write(
                "@protect input: [sql_injection]\n"
                "@csrf_protection: false\n"
                "@security_headers: false\n"
                "@anomaly_detection: false\n"
            )

        test_app = Flask("json_primitive")
        DimmaEngine(config_path).protect(test_app)

        @test_app.post("/echo")
        def echo():
            return jsonify(value=request.get_json())

        response = test_app.test_client().post(
            "/echo", json=False, content_type="application/json"
        )
        assert response.status_code == 200, response.get_data(as_text=True)
        assert response.get_json() == {"value": False}


def _t_rejects_body_over_configured_limit():
    from flask import Flask
    from dimma.engine import DimmaEngine

    with tempfile.TemporaryDirectory(prefix="dimma-body-limit-") as temp_dir:
        config_path = os.path.join(temp_dir, "security.dimma")
        with open(config_path, "w", encoding="utf-8") as file:
            file.write(
                "@protect input: [sql_injection]\n"
                "@csrf_protection: false\n"
                "@security_headers: false\n"
                "@anomaly_detection: false\n"
            )

        test_app = Flask("body_limit")
        DimmaEngine(config_path).protect(test_app)
        response = test_app.test_client().post(
            "/unknown",
            data="x" * (1024 * 1024 + 1),
            content_type="application/json",
        )
        assert response.status_code == 413, response.status_code
        assert str(1024 * 1024) in response.get_json()["error"]


test("preserva JSON primitivo falsy durante a inspecao", _t_preserves_json_primitive_body)
test("limita bodies inspecionados a 1 MB", _t_rejects_body_over_configured_limit)

print("\n== Correcoes de seguranca (SECRET_KEY obrigatorio em producao) ==")


def _t_requires_secret_in_production():
    from flask import Flask
    from dimma.engine import DimmaEngine

    test_app = Flask(__name__)
    test_app.config["ENV"] = "production"
    dimma_test = DimmaEngine(
        os.path.join(os.path.dirname(__file__), "..", "example", "security.dimma")
    )
    try:
        dimma_test.protect(test_app)
        raise AssertionError("deveria ter recusado rodar sem SECRET_KEY em producao")
    except RuntimeError as exc:
        assert "SECRET_KEY" in str(exc)


test("recusa iniciar em producao sem SECRET_KEY", _t_requires_secret_in_production)

print("\n== Rate limiting distribuido via Redis (Flask-Limiter + fakeredis) ==")


def _t_redis_rate_limit_distributed():
    import fakeredis
    import redis as redis_module
    from flask import Flask, jsonify
    from dimma.engine import DimmaEngine

    # Duas "instancias" da aplicacao, MESMO Redis (fakeredis compartilhado
    # via o mesmo FakeServer), simulando duas instancias atras de um load
    # balancer -- devem contar as requisicoes JUNTAS.
    fake_server = fakeredis.FakeServer()
    dimma_path = os.path.join(os.path.dirname(__file__), "..", "example", "security.dimma")

    # A lib "limits" (usada pelo Flask-Limiter) cria o cliente chamando
    # redis.from_url(uri, **options) internamente -- interceptamos essa
    # funcao de fabrica para devolver um cliente fakeredis apontando para
    # o MESMO servidor fake em ambas as "instancias".
    original_from_url = redis_module.from_url
    redis_module.from_url = lambda uri, **kw: fakeredis.FakeStrictRedis(server=fake_server)

    try:
        os.environ["REDIS_URL"] = "redis://fake:6379/0"

        # As duas "instancias" rodam o MESMO codigo (mesmo nome de rota/
        # endpoint) -- e assim que multiplas instancias reais atras de um
        # load balancer funcionam. Nomes de endpoint diferentes fariam o
        # Flask-Limiter tratar como limites independentes por design,
        # mesmo compartilhando o Redis.
        def make_ping_route(app):
            @app.get("/ping", endpoint="ping")
            def ping():
                return jsonify(status="ok")

        app1 = Flask("instancia1")
        dimma1 = DimmaEngine(dimma_path)
        dimma1.protect(app1)
        make_ping_route(app1)

        app2 = Flask("instancia2")
        dimma2 = DimmaEngine(dimma_path)
        dimma2.protect(app2)
        make_ping_route(app2)

        client1 = app1.test_client()
        client2 = app2.test_client()

        # O security.dimma de exemplo permite 100 req/min -- fazemos
        # requisicoes suficientes alternando entre as duas "instancias"
        # para provar que o contador e compartilhado via Redis. Usamos
        # /ping (nao /health, que esta em @exclude no arquivo de exemplo).
        statuses = []
        for i in range(105):
            client = client1 if i % 2 == 0 else client2
            res = client.get("/ping", environ_overrides={"REMOTE_ADDR": "9.9.9.9"})
            statuses.append(res.status_code)

        assert 429 in statuses, "esperava que o limite compartilhado disparasse em algum momento"
    finally:
        redis_module.from_url = original_from_url
        os.environ.pop("REDIS_URL", None)


test("duas instancias compartilhando Redis contam as requisicoes juntas", _t_redis_rate_limit_distributed)

print(f"\n{passed} passaram, {failed} falharam\n")
sys.exit(1 if failed else 0)
