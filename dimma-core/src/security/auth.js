'use strict';

const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 12;
const BCRYPT_MAX_PASSWORD_BYTES = 72;

function ensureBcryptCompatiblePassword(password) {
  if (typeof password !== 'string') {
    throw new TypeError('Senha deve ser uma string.');
  }
  if (Buffer.byteLength(password, 'utf-8') > BCRYPT_MAX_PASSWORD_BYTES) {
    throw new RangeError(`Senha excede o limite seguro do bcrypt de ${BCRYPT_MAX_PASSWORD_BYTES} bytes.`);
  }
}

/** Faz o hash seguro de uma senha (bcrypt, custo 12). */
async function hashPassword(plainPassword) {
  if (typeof plainPassword !== 'string' || plainPassword.length < 8) {
    throw new Error('Senha deve ter no minimo 8 caracteres.');
  }
  ensureBcryptCompatiblePassword(plainPassword);
  return bcrypt.hash(plainPassword, SALT_ROUNDS);
}

/** Compara uma senha em texto plano com um hash armazenado. */
async function verifyPassword(plainPassword, hash) {
  ensureBcryptCompatiblePassword(plainPassword);
  return bcrypt.compare(plainPassword, hash);
}

/** Gera token aleatorio seguro (para sessao, reset de senha, etc). */
function generateSecureToken(bytes = 32) {
  return require('crypto').randomBytes(bytes).toString('hex');
}

module.exports = { hashPassword, verifyPassword, generateSecureToken };
