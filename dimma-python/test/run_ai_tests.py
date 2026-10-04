import json
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dimma.security.ai import classify_with_ai

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


class FakeResponse:
    status = 200

    def __init__(self, body):
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


def _provider_adapters():
    cases = [
        ("nvidia", {"choices": [{"message": {"content": '{"malicious": false, "confidence": 0.8, "reason": "ok"}'}}]}),
        ("openai", {"choices": [{"message": {"content": '{"malicious": false, "confidence": 0.8, "reason": "ok"}'}}]}),
        ("openrouter", {"choices": [{"message": {"content": '{"malicious": false, "confidence": 0.8, "reason": "ok"}'}}]}),
        ("anthropic", {"content": [{"type": "text", "text": '{"malicious": false, "confidence": 0.8, "reason": "ok"}'}]}),
        ("gemini", {"candidates": [{"content": {"parts": [{"text": '{"malicious": false, "confidence": 0.8, "reason": "ok"}'}]}}]}),
    ]

    for provider, response_body in cases:
        observed = {}

        def fake_urlopen(request, timeout):
            observed["request"] = request
            observed["timeout"] = timeout
            return FakeResponse(response_body)

        verdict = classify_with_ai(
            {"findings": [{"type": "test"}], "rawInput": {"path": "/health", "method": "GET"}},
            provider=provider,
            api_key="fake-provider-key",
            daily_budget=100,
            urlopen=fake_urlopen,
        )
        outgoing = observed["request"]
        headers = {name.lower(): value for name, value in outgoing.header_items()}
        body = json.loads(outgoing.data.decode("utf-8"))
        assert verdict["malicious"] is False
        assert observed["timeout"] == 5.0
        assert "health" in json.dumps(body)
        if provider == "anthropic":
            assert headers["x-api-key"] == "fake-provider-key"
            assert headers["anthropic-version"] == "2023-06-01"
        elif provider == "gemini":
            assert headers["x-goog-api-key"] == "fake-provider-key"
            assert "key=" not in outgoing.full_url
        else:
            assert headers["authorization"] == "Bearer fake-provider-key"


def _missing_key_does_not_call_network():
    original = os.environ.pop("OPENAI_API_KEY", None)
    try:
        called = False

        def fake_urlopen(_request, timeout):
            nonlocal called
            called = True
            raise AssertionError("nao devia consultar a rede")

        result = classify_with_ai({}, provider="openai", urlopen=fake_urlopen)
        assert result["malicious"] is None
        assert not called
    finally:
        if original is not None:
            os.environ["OPENAI_API_KEY"] = original


def _zero_budget_does_not_call_network():
    called = False

    def fake_urlopen(_request, timeout):
        nonlocal called
        called = True
        return FakeResponse({})

    result = classify_with_ai(
        {}, provider="openrouter", api_key="fake", daily_budget=0, urlopen=fake_urlopen
    )
    assert result["malicious"] is None
    assert not called


def _errors_do_not_disclose_provider_body():
    import urllib.error

    def failing_urlopen(_request, timeout):
        raise urllib.error.HTTPError(
            "https://provider.invalid/",
            401,
            "provider echoed secret-bearing response",
            {},
            None,
        )

    try:
        classify_with_ai(
            {}, provider="openai", api_key="fake", daily_budget=100, urlopen=failing_urlopen
        )
        raise AssertionError("devia falhar no status HTTP")
    except RuntimeError as error:
        assert "401" in str(error)
        assert "secret-bearing" not in str(error)


def _rejects_invalid_verdict():
    def fake_urlopen(_request, timeout):
        return FakeResponse({
            "choices": [{
                "message": {
                    "content": '{"malicious": "false", "confidence": 9, "reason": 42}'
                }
            }]
        })

    try:
        classify_with_ai(
            {}, provider="openai", api_key="fake", daily_budget=100, urlopen=fake_urlopen
        )
        raise AssertionError("devia rejeitar o formato")
    except ValueError as error:
        assert "fora do formato esperado" in str(error)


def _timeout_and_oversized_provider_responses_fail_explicitly():
    def timeout_urlopen(_request, timeout):
        raise TimeoutError("private network detail")

    try:
        classify_with_ai(
            {}, provider="openai", api_key="fake", daily_budget=100, urlopen=timeout_urlopen
        )
        raise AssertionError("devia reportar timeout")
    except RuntimeError as error:
        assert "timeout" in str(error)
        assert "private network detail" not in str(error)

    def oversized_urlopen(_request, timeout):
        response = FakeResponse({})
        response.body = b" " * (64 * 1024 + 1)
        return response

    try:
        classify_with_ai(
            {}, provider="openai", api_key="fake", daily_budget=100, urlopen=oversized_urlopen
        )
        raise AssertionError("devia rejeitar resposta excessiva")
    except RuntimeError as error:
        assert "demasiado grande" in str(error)


def _engine_only_sends_minimized_metadata_and_hides_ai_reason():
    from flask import Flask, jsonify
    import dimma.engine as engine_module
    from dimma.engine import DimmaEngine

    captured = {}
    original_classifier = engine_module.classify_with_ai

    def fake_classifier(payload, provider=None, model=None):
        captured["payload"] = payload
        captured["provider"] = provider
        captured["model"] = model
        return {
            "malicious": True,
            "confidence": 0.99,
            "reason": "texto de resposta controlado pelo provider",
        }

    try:
        engine_module.classify_with_ai = fake_classifier
        app = Flask("ai_metadata_minimization")
        with tempfile.TemporaryDirectory(prefix="dimma-ai-engine-") as temp_dir:
            config_path = os.path.join(temp_dir, "security.dimma")
            with open(config_path, "w", encoding="utf-8") as config_file:
                config_file.write(
                    "@csrf_protection: false\n"
                    "@security_headers: false\n"
                    "@anomaly_detection: true\n"
                    "@ai_detection: true\n"
                    "@ai_provider: openai\n"
                    "@ai_model: test-model\n"
                )

            engine = DimmaEngine(config_path)
            engine.protect(app)
            engine._anomaly_detector.observe = lambda _key, _time: {
                "anomalous": True,
                "score": 4.5,
                "reason": "burst",
            }

            @app.get("/account/<account_token>")
            def account(account_token):
                return jsonify(ok=True)

            response = app.test_client().get("/account/sensitive-path-token")
            assert response.status_code == 403
            assert captured["provider"] == "openai"
            assert captured["model"] == "test-model"
            serialized = json.dumps(captured["payload"])
            assert "/account/<account_token>" in serialized
            assert "sensitive-path-token" not in serialized
            assert "127.0.0.1" not in serialized
            assert "texto de resposta controlado" not in response.get_data(as_text=True)
    finally:
        engine_module.classify_with_ai = original_classifier


def _ai_check_is_local_unless_test_flag_is_explicit():
    from dimma import cli

    original_cwd = os.getcwd()
    original_classifier = cli.classify_with_ai
    output = StringIO()
    try:
        with tempfile.TemporaryDirectory(prefix="dimma-ai-check-") as temp_dir:
            try:
                with open(os.path.join(temp_dir, "security.dimma"), "w", encoding="utf-8") as config_file:
                    config_file.write("@ai_provider: openai\n@ai_model: test-model\n")

                def unexpected_network_call(*_args, **_kwargs):
                    raise AssertionError("diagnostico local nao pode chamar a rede")

                cli.classify_with_ai = unexpected_network_call
                os.chdir(temp_dir)
                with patch.dict(os.environ, {"OPENAI_API_KEY": "fake-key"}, clear=True):
                    with redirect_stdout(output):
                        cli.ai_check([])
                assert "Diagnostico local concluido" in output.getvalue()

                captured = {}

                def fake_classifier(payload, provider=None, model=None):
                    captured.update(payload=payload, provider=provider, model=model)
                    return {"malicious": False, "confidence": 1.0, "reason": "ok"}

                cli.classify_with_ai = fake_classifier
                with redirect_stdout(output):
                    with patch.dict(os.environ, {"OPENAI_API_KEY": "fake-key"}, clear=True):
                        cli.ai_check(["--test"])
                assert captured["provider"] == "openai"
                assert captured["model"] == "test-model"
                assert captured["payload"]["rawInput"]["path"] == "/__dimma/ai-check"

                with patch.dict(os.environ, {}, clear=True):
                    with redirect_stderr(StringIO()):
                        try:
                            cli.ai_check([])
                            raise AssertionError("sem chave deve falhar")
                        except SystemExit as error:
                            assert error.code == 1
            finally:
                os.chdir(original_cwd)
    finally:
        cli.classify_with_ai = original_classifier


print("\n== Classificacao opcional por IA (adapters Python) ==")
test("normaliza respostas NVIDIA, OpenAI, OpenRouter, Anthropic e Gemini", _provider_adapters)
test("chave ausente nao consulta a rede", _missing_key_does_not_call_network)
test("orcamento zero nao consulta a rede", _zero_budget_does_not_call_network)
test("erros HTTP nao propagam o corpo do provider", _errors_do_not_disclose_provider_body)
test("rejeita resposta fora do esquema sem decisao permissiva", _rejects_invalid_verdict)
test("timeout e resposta externa excessiva falham sem detalhes sensiveis", _timeout_and_oversized_provider_responses_fail_explicitly)
test("engine envia metadados minimizados e oculta razao externa", _engine_only_sends_minimized_metadata_and_hides_ai_reason)
test("ai-check e local por padrao e so consulta provider com --test", _ai_check_is_local_unless_test_flag_is_explicit)

print(f"\n{passed} passaram, {failed} falharam\n")
sys.exit(1 if failed else 0)
