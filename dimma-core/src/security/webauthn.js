'use strict';

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

/**
 * Suporte a Passkeys/WebAuthn — "identidade como o novo perimetro".
 *
 * CONTEXTO: analistas apontam que a identidade, nao a rede, e o
 * perimetro de seguranca mais importante hoje -- e senhas continuam
 * sendo o vetor de invasao nº1. Passkeys (WebAuthn) eliminam senhas por
 * design: a chave privada nunca sai do dispositivo do usuario, e o
 * servidor so guarda uma chave PUBLICA, entao nem um vazamento de banco
 * de dados expoe credenciais reutilizaveis.
 *
 * HONESTIDADE TECNICA: isto e um WRAPPER fino em cima da biblioteca
 * @simplewebauthn/server -- a mesma usada por GitHub, 1Password e outras
 * empresas serias. O .dimma NUNCA implementa a criptografia de WebAuthn
 * por conta propria (seria irresponsavel); ele apenas simplifica o uso
 * correto da biblioteca e cuida de detalhes faceis de errar (RP ID,
 * origin, armazenamento do challenge).
 *
 * FLUXO (quem usa isto precisa implementar em volta):
 *  1. Registro: gerar opcoes -> enviar ao browser -> browser cria a
 *     passkey -> backend verifica a resposta -> guardar a credencial
 *     (chave publica) associada ao usuario no SEU banco de dados.
 *  2. Login: gerar opcoes -> enviar ao browser -> browser assina com a
 *     passkey -> backend verifica a assinatura contra a chave publica
 *     guardada.
 *
 * O ARMAZENAMENTO de usuarios/credenciais/challenges e SEMPRE
 * responsabilidade da aplicacao -- o .dimma nao assume nenhum banco de
 * dados especifico.
 */

class WebAuthnSupport {
  /**
   * @param {{rpName: string, rpID: string, origin: string|string[]}} config
   *   rpID: dominio da aplicacao (ex: 'meusite.com', ou 'localhost' em dev)
   *   origin: origem(ns) esperada(s) (ex: 'https://meusite.com')
   */
  constructor(config = {}) {
    if (!config.rpID || !config.origin) {
      throw new Error(
        'dimma-webauthn: e obrigatorio configurar rpID e origin (ex: { rpID: "meusite.com", origin: "https://meusite.com" }).'
      );
    }
    this.rpName = config.rpName || config.rpID;
    this.rpID = config.rpID;
    this.origin = config.origin;
  }

  /**
   * Gera as opcoes de registro para enviar ao navegador do usuario.
   * Guarde `options.challenge` (associado ao usuario/sessao) para
   * verificar na etapa seguinte.
   */
  async generateRegistrationOptions({ userID, userName, userDisplayName, existingCredentials = [] }) {
    return generateRegistrationOptions({
      rpName: this.rpName,
      rpID: this.rpID,
      userName,
      userDisplayName: userDisplayName || userName,
      userID: Buffer.from(String(userID)),
      attestationType: 'none',
      excludeCredentials: existingCredentials.map((cred) => ({
        id: cred.id,
        transports: cred.transports,
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });
  }

  /**
   * Verifica a resposta de registro enviada pelo navegador.
   * @param {object} response resposta bruta do navegador (JSON)
   * @param {string} expectedChallenge o challenge que voce guardou na etapa anterior
   * @returns {Promise<{verified: boolean, credential?: object}>}
   */
  async verifyRegistrationResponse(response, expectedChallenge) {
    const result = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: this.origin,
      expectedRPID: this.rpID,
    });

    if (!result.verified || !result.registrationInfo) {
      return { verified: false };
    }

    const { credential } = result.registrationInfo;
    return {
      verified: true,
      // Isto e o que voce deve guardar no seu banco, associado ao usuario.
      // Nunca guarde nada alem disso -- nao ha "senha" para vazar aqui.
      credential: {
        id: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
        counter: credential.counter,
        transports: credential.transports,
      },
    };
  }

  /**
   * Gera as opcoes de autenticacao (login) para enviar ao navegador.
   */
  async generateAuthenticationOptions({ allowCredentials = [] } = {}) {
    return generateAuthenticationOptions({
      rpID: this.rpID,
      userVerification: 'preferred',
      allowCredentials: allowCredentials.map((cred) => ({
        id: cred.id,
        transports: cred.transports,
      })),
    });
  }

  /**
   * Verifica a resposta de login enviada pelo navegador contra a
   * credencial (chave publica) que voce guardou no registro.
   * @param {object} response resposta bruta do navegador (JSON)
   * @param {string} expectedChallenge o challenge que voce guardou na etapa anterior
   * @param {{id: string, publicKey: string, counter: number, transports?: string[]}} storedCredential
   */
  async verifyAuthenticationResponse(response, expectedChallenge, storedCredential) {
    const result = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: this.origin,
      expectedRPID: this.rpID,
      credential: {
        id: storedCredential.id,
        publicKey: Buffer.from(storedCredential.publicKey, 'base64url'),
        counter: storedCredential.counter,
        transports: storedCredential.transports,
      },
    });

    return {
      verified: result.verified,
      // Atualize o counter guardado com este valor apos login bem
      // sucedido -- protege contra clonagem de autenticador.
      newCounter: result.authenticationInfo ? result.authenticationInfo.newCounter : undefined,
    };
  }
}

module.exports = { WebAuthnSupport };
