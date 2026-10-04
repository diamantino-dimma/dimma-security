"""
Suporte a Passkeys/WebAuthn (Python) — "identidade como o novo
perimetro". Veja src/security/webauthn.js no dimma-core para a
explicacao completa do raciocinio; esta e a mesma logica, usando a lib
`webauthn` (py_webauthn), equivalente Python da @simplewebauthn/server.

HONESTIDADE TECNICA: wrapper fino em cima de uma biblioteca de
criptografia vetada -- o .dimma nunca implementa WebAuthn por conta
propria.
"""
from typing import Any, Dict, List, Optional

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


class WebAuthnSupport:
    def __init__(self, rp_id: str, origin: str, rp_name: Optional[str] = None):
        if not rp_id or not origin:
            raise ValueError(
                "dimma-webauthn: e obrigatorio configurar rp_id e origin "
                '(ex: WebAuthnSupport(rp_id="meusite.com", origin="https://meusite.com")).'
            )
        self.rp_id = rp_id
        self.origin = origin
        self.rp_name = rp_name or rp_id

    def generate_registration_options_json(
        self,
        user_id: bytes,
        user_name: str,
        user_display_name: Optional[str] = None,
        existing_credentials: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Retorna as opcoes de registro como JSON pronto para enviar ao navegador."""
        exclude = [
            PublicKeyCredentialDescriptor(id=cred["id"]) for cred in (existing_credentials or [])
        ]
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user_id,
            user_name=user_name,
            user_display_name=user_display_name or user_name,
            attestation=AttestationConveyancePreference.NONE,
            exclude_credentials=exclude,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
        )
        return options_to_json(options)

    def verify_registration(self, credential: Dict[str, Any], expected_challenge: bytes) -> Dict[str, Any]:
        """
        Verifica a resposta de registro do navegador.
        Retorna {"verified": False} em qualquer falha -- nunca lanca a
        excecao da lib para fora sem tratamento, para o chamador poder
        responder com um erro HTTP adequado.
        """
        try:
            result = verify_registration_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
            )
        except Exception:
            return {"verified": False}

        return {
            "verified": True,
            # Isto e o que deve ser guardado no seu banco, associado ao
            # usuario. Nao ha "senha" para vazar aqui -- apenas uma
            # chave publica.
            "credential": {
                "id": result.credential_id,
                "public_key": result.credential_public_key,
                "sign_count": result.sign_count,
            },
        }

    def generate_authentication_options_json(
        self, allow_credentials: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        allow = [PublicKeyCredentialDescriptor(id=cred["id"]) for cred in (allow_credentials or [])]
        options = generate_authentication_options(
            rp_id=self.rp_id,
            allow_credentials=allow,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        return options_to_json(options)

    def verify_authentication(
        self,
        credential: Dict[str, Any],
        expected_challenge: bytes,
        stored_credential: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Verifica a resposta de login contra a credencial (chave publica)
        guardada no registro. Atualize `stored_credential["sign_count"]`
        com o `new_sign_count` retornado apos sucesso -- protege contra
        clonagem de autenticador.
        """
        try:
            result = verify_authentication_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                credential_public_key=stored_credential["public_key"],
                credential_current_sign_count=stored_credential["sign_count"],
            )
        except Exception:
            return {"verified": False}

        return {"verified": True, "new_sign_count": result.new_sign_count}
