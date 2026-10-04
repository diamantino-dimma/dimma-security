'use strict';

const assert = require('assert');
const { WebAuthnSupport } = require('../src/security/webauthn');
const { DimmaEngine } = require('../src/index');
const fs = require('fs');
const os = require('os');
const path = require('path');

let passed = 0;
let failed = 0;

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed++;
      console.log(`  OK  - ${name}`);
    })
    .catch((err) => {
      failed++;
      console.log(`FALHOU - ${name}\n        ${err.message}`);
    });
}

async function run() {
  console.log('\n== Passkeys/WebAuthn (dimma-webauthn) ==');

  await test('exige rpID e origin ao construir', () => {
    assert.throws(() => new WebAuthnSupport({}), /rpID e origin/);
  });

  const webauthn = new WebAuthnSupport({ rpID: 'localhost', origin: 'https://localhost' });

  await test('gera opcoes de registro bem-formadas', async () => {
    const options = await webauthn.generateRegistrationOptions({
      userID: 'user-123',
      userName: 'diamantino@example.com',
    });
    assert.ok(options.challenge, 'deve ter um challenge');
    assert.strictEqual(options.rp.id, 'localhost');
    assert.strictEqual(options.user.name, 'diamantino@example.com');
    assert.ok(Array.isArray(options.pubKeyCredParams) && options.pubKeyCredParams.length > 0);
  });

  await test('gera opcoes de registro excluindo credenciais existentes', async () => {
    const options = await webauthn.generateRegistrationOptions({
      userID: 'user-123',
      userName: 'diamantino@example.com',
      existingCredentials: [{ id: 'credencial-antiga', transports: ['internal'] }],
    });
    assert.strictEqual(options.excludeCredentials.length, 1);
    assert.strictEqual(options.excludeCredentials[0].id, 'credencial-antiga');
  });

  await test('gera opcoes de autenticacao bem-formadas', async () => {
    const options = await webauthn.generateAuthenticationOptions({
      allowCredentials: [{ id: 'credencial-1' }],
    });
    assert.ok(options.challenge);
    assert.strictEqual(options.allowCredentials.length, 1);
  });

  await test('rejeita resposta de registro invalida/malformada (sem quebrar a aplicacao)', async () => {
    const result = await webauthn
      .verifyRegistrationResponse({ id: 'lixo', rawId: 'lixo', response: {}, type: 'public-key' }, 'challenge-que-nao-bate')
      .catch((err) => ({ verified: false, error: err.message }));
    assert.strictEqual(result.verified, false);
  });

  await test('rejeita resposta de autenticacao invalida contra credencial armazenada', async () => {
    const fakeStoredCredential = {
      id: 'credencial-1',
      publicKey: Buffer.from('nao-e-uma-chave-publica-real').toString('base64url'),
      counter: 0,
    };
    const result = await webauthn
      .verifyAuthenticationResponse(
        { id: 'credencial-1', rawId: 'credencial-1', response: {}, type: 'public-key' },
        'challenge-que-nao-bate',
        fakeStoredCredential
      )
      .catch((err) => ({ verified: false, error: err.message }));
    assert.strictEqual(result.verified, false);
  });

  console.log('\n== Integracao com DimmaEngine (@passkey_support) ==');

  const dimmaPathSemConfig = path.join(os.tmpdir(), `dimma-passkey-sem-config-${Date.now()}.dimma`);
  fs.writeFileSync(dimmaPathSemConfig, '@passkey_support: true\n@files_protect: [app.js]\n');

  await test('recusa ativar passkeys sem @rp_id/@rp_origin configurados', () => {
    assert.throws(() => new DimmaEngine(dimmaPathSemConfig), /faltam @rp_id e\/ou @rp_origin/);
  });

  const dimmaPathComConfig = path.join(os.tmpdir(), `dimma-passkey-com-config-${Date.now()}.dimma`);
  fs.writeFileSync(
    dimmaPathComConfig,
    ['@passkey_support: true', '@rp_id: localhost', '@rp_origin: https://localhost', '@files_protect: [app.js]'].join('\n')
  );

  await test('ativa dimma.webauthn quando configurado corretamente', () => {
    const dimma = new DimmaEngine(dimmaPathComConfig);
    assert.ok(dimma.webauthn instanceof WebAuthnSupport);
  });

  await test('dimma.webauthn fica null quando @passkey_support nao esta ativo', () => {
    const dimmaSemPasskey = new DimmaEngine(
      path.join(__dirname, '..', 'example', 'security.dimma')
    );
    assert.strictEqual(dimmaSemPasskey.webauthn, null);
  });

  fs.unlinkSync(dimmaPathSemConfig);
  fs.unlinkSync(dimmaPathComConfig);

  console.log(`\n${passed} passaram, ${failed} falharam\n`);
  console.log(
    'NOTA: fluxo positivo completo (registro/login com autenticador real) exige um ' +
      'navegador de verdade e nao e testavel de forma automatizada aqui -- os testes acima ' +
      'cobrem a forma das opcoes geradas e a rejeicao correta de respostas invalidas.'
  );
  if (failed > 0) process.exit(1);
}

run();
