import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dimma.security.webauthn import WebAuthnSupport

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


print("\n== Passkeys/WebAuthn Python (dimma-webauthn) ==")


def _t_requires_rp_id_and_origin():
    try:
        WebAuthnSupport(rp_id="", origin="")
        raise AssertionError("deveria ter recusado sem rp_id/origin")
    except ValueError:
        pass


def _t_generates_registration_options():
    webauthn = WebAuthnSupport(rp_id="localhost", origin="https://localhost")
    options_json = webauthn.generate_registration_options_json(
        user_id=b"user-123", user_name="diamantino@example.com"
    )
    assert '"rp"' in options_json
    assert '"localhost"' in options_json
    assert "diamantino@example.com" in options_json


def _t_generates_authentication_options():
    webauthn = WebAuthnSupport(rp_id="localhost", origin="https://localhost")
    options_json = webauthn.generate_authentication_options_json()
    assert '"challenge"' in options_json


def _t_rejects_invalid_registration_response():
    webauthn = WebAuthnSupport(rp_id="localhost", origin="https://localhost")
    result = webauthn.verify_registration({"id": "lixo", "response": {}}, expected_challenge=b"algo")
    assert result["verified"] is False


def _t_rejects_invalid_authentication_response():
    webauthn = WebAuthnSupport(rp_id="localhost", origin="https://localhost")
    fake_stored_credential = {"public_key": b"nao-e-uma-chave-real", "sign_count": 0}
    result = webauthn.verify_authentication(
        {"id": "credencial-1", "response": {}}, expected_challenge=b"algo", stored_credential=fake_stored_credential
    )
    assert result["verified"] is False


test("exige rp_id e origin ao construir", _t_requires_rp_id_and_origin)
test("gera opcoes de registro bem-formadas", _t_generates_registration_options)
test("gera opcoes de autenticacao bem-formadas", _t_generates_authentication_options)
test("rejeita resposta de registro invalida", _t_rejects_invalid_registration_response)
test("rejeita resposta de autenticacao invalida", _t_rejects_invalid_authentication_response)

print("\n== Integracao com DimmaEngine (@passkey_support) ==")


def _t_engine_requires_rp_config():
    import tempfile
    from dimma.engine import DimmaEngine

    with tempfile.NamedTemporaryFile(mode="w", suffix=".dimma", delete=False) as f:
        f.write("@passkey_support: true\n")
        path = f.name
    try:
        DimmaEngine(path)
        raise AssertionError("deveria ter recusado sem rp_id/rp_origin")
    except ValueError as exc:
        assert "rp_id" in str(exc)
    finally:
        os.unlink(path)


def _t_engine_activates_webauthn():
    import tempfile
    from dimma.engine import DimmaEngine

    with tempfile.NamedTemporaryFile(mode="w", suffix=".dimma", delete=False) as f:
        f.write("@passkey_support: true\n@rp_id: localhost\n@rp_origin: https://localhost\n")
        path = f.name
    try:
        dimma = DimmaEngine(path)
        assert isinstance(dimma.webauthn, WebAuthnSupport)
    finally:
        os.unlink(path)


def _t_engine_webauthn_none_by_default():
    from dimma.engine import DimmaEngine

    dimma = DimmaEngine(os.path.join(os.path.dirname(__file__), "..", "example", "security.dimma"))
    assert dimma.webauthn is None


test("recusa ativar passkeys sem @rp_id/@rp_origin", _t_engine_requires_rp_config)
test("ativa dimma.webauthn quando configurado corretamente", _t_engine_activates_webauthn)
test("dimma.webauthn fica None quando @passkey_support nao esta ativo", _t_engine_webauthn_none_by_default)

print(f"\n{passed} passaram, {failed} falharam\n")
print(
    "NOTA: fluxo positivo completo (registro/login com autenticador real) exige um "
    "navegador de verdade e nao e testavel de forma automatizada aqui."
)
sys.exit(1 if failed else 0)
