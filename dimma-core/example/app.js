'use strict';

const express = require('express');
const path = require('path');
const { DimmaEngine, hashPassword } = require('../src/index');

const app = express();
app.use(express.json());

const dimma = new DimmaEngine(path.join(__dirname, 'security.dimma'));
dimma.protect(app);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.get('/csrf-token', (req, res) => {
  const token = dimma.generateCsrfToken(req, res);
  res.json({ csrfToken: token });
});

app.post('/login', (req, res) => {
  const { username } = req.body;
  res.json({ message: `Login recebido para ${username}` });
});

app.post('/register', async (req, res) => {
  const { password } = req.body;
  try {
    // SEGURANCA: o hash NUNCA deve ser devolvido ao cliente -- mesmo
    // sendo um hash (nao a senha em texto puro), e informacao que so
    // interessa ao servidor guardar (ex: numa coluna "password_hash" da
    // tabela de utilizadores). Aqui so simulamos o calculo do hash;
    // numa app real, guarde-o na base de dados e responda apenas com
    // sucesso/insucesso.
    await hashPassword(password);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Dimma demo app rodando em http://localhost:${PORT}`));
}
