# Guia do Instrutor — Curso ".dimma: Segurança Cibernética Declarativa"

Este documento é o seu roteiro para gravar um curso completo sobre o
`.dimma`. Ele está organizado em módulos prontos para gravação, cada um
com objetivo, pontos de fala, comandos para demonstrar ao vivo, e
perguntas que os alunos provavelmente vão fazer.

---

## Como usar este guia

Cada módulo abaixo pode virar uma aula/vídeo separado. A ordem foi
pensada para ser sequencial (cada aula usa o que a anterior ensinou),
mas os módulos 7 a 12 podem ser reordenados ou até vendidos como um
"curso avançado" separado do "curso básico" (módulos 1 a 6).

Convenção usada neste guia:
- **Objetivo** — o que o aluno deve saber fazer ao final da aula
- **Pontos de fala** — o roteiro/argumento da aula
- **Demo ao vivo** — comandos exatos para rodar na tela
- **Perguntas frequentes** — antecipe essas dúvidas

---

## MÓDULO 1 — Por que existe o `.dimma`?

**Objetivo:** o aluno entende o problema que o `.dimma` resolve antes
de ver uma linha de código.

**Pontos de fala:**
- Hoje, um programador que quer proteger um site precisa configurar
  separadamente: headers de segurança, CSRF, sanitização de input, rate
  limiting, hashing de senha — cada um com uma biblioteca diferente, uma
  sintaxe diferente, uma curva de aprendizado diferente.
- Cite a tendência real: analistas apontam a IA agêntica e o "vibe
  coding" (código gerado por IA sem revisão cuidadosa) como uma das
  maiores fontes de novas vulnerabilidades em 2026 — código é escrito
  mais rápido do que é revisado.
- A proposta do `.dimma`: um arquivo de configuração declarativo
  (parecido com `docker-compose.yml` ou `.env`) que descreve a postura
  de segurança do projeto inteiro, e um motor (disponível em Node.js e
  Python) que lê esse arquivo e aplica as proteções automaticamente.
- Deixe claro desde o início: o `.dimma` não substitui boas práticas
  (prepared statements, TLS no servidor) — ele é uma camada declarativa
  por cima de bibliotecas já confiáveis do mercado (Helmet, bcrypt,
  Flask-Talisman, etc). Isso é importante para credibilidade do curso.

**Demo ao vivo:** nenhuma ainda — este módulo é conceitual. Mostre a
tela de um projeto Express/Flask "cru", sem nenhuma proteção, e liste
visualmente as ~8 coisas que precisariam ser configuradas manualmente.

**Perguntas frequentes:**
- "Isso substitui um firewall/WAF de verdade?" Não — é uma camada de
  aplicação, complementar a firewall/WAF de rede, não um substituto.
- "Funciona em produção de verdade?" Sim, mas enfatize desde já que
  este é um projeto educacional/em desenvolvimento ativo — recomende
  revisão de segurança humana antes de uso com dados reais de usuários.

---

## MÓDULO 2 — Anatomia da linguagem `.dimma`

**Objetivo:** o aluno consegue ler e escrever um arquivo `.dimma` do
zero.

**Pontos de fala:**
- Sintaxe inspirada em Markdown: comentários com `#`, comandos com `@`.
- Todo comando segue o padrão `@nome: valor`.
- Tipos de valor: booleano (`true`/`false`), lista (`[a, b, c]`),
  expressão de taxa (`100 req/min`), número, texto.
- Mostre que comandos de lista (`@protect input`, `@exclude`) se
  combinam se repetidos, não se sobrescrevem.

**Demo ao vivo:**
```
# security.dimma
@auto_protect: true
@protect input: [sql_injection, xss]
@rate_limit: 100 req/min
@exclude: /health
@exclude: /metrics
```
Rode o parser isoladamente pra mostrar o objeto de configuração resultante:
```bash
node -e "
const { parseDimma } = require('./dimma-core/src/parser');
const fs = require('fs');
console.log(parseDimma(fs.readFileSync('./security.dimma', 'utf-8')).config);
"
```

**Perguntas frequentes:**
- "Por que não usar YAML/JSON?" Decisão de design: sintaxe mais
  legível e menos verbosa para quem não é familiarizado com
  configuração estruturada; também facilita a leitura por não-devs.

---

## MÓDULO 3 — Instalação e primeiro projeto (`dimma init`)

**Objetivo:** o aluno sai deste módulo com um projeto rodando com
o `.dimma` ativo.

**Pontos de fala:**
- Dois pacotes chamados `dimma`, em registries distintos: npm para Node/Express
  e PyPI para Python/Flask — a mesma linguagem `.dimma`.
- Explique a auto-criação: se `DimmaEngine(caminho)` for chamado e o
  arquivo não existir, ele é criado automaticamente com o perfil padrão
  — não precisa rodar nada manualmente antes.
- Explique por que `pip install`/`npm install` sozinhos não conseguem
  criar o arquivo automaticamente (limitação real dos gerenciadores de
  pacote — nem Django, Prisma ou Playwright fazem isso).

**Demo ao vivo (Node):**
```bash
mkdir meu-projeto && cd meu-projeto
npm init -y && npm install express dimma
node -e "
const express = require('express');
const { DimmaEngine } = require('dimma');
const app = express();
const dimma = new DimmaEngine('./security.dimma'); // cria sozinho
dimma.protect(app);
app.get('/', (req, res) => res.send('Protegido pelo .dimma!'));
app.listen(3000);
"
```

**Demo ao vivo (Python):**
```bash
mkdir meu-projeto-py && cd meu-projeto-py
pip install flask dimma
python3 -c "
from flask import Flask
from dimma.engine import DimmaEngine
app = Flask(__name__)
dimma = DimmaEngine('./security.dimma')
dimma.protect(app)
"
```

**Perguntas frequentes:**
- "Preciso rodar `dimma init` sempre?" Não, é opcional — só útil se
  você quiser revisar/ajustar o arquivo antes de rodar a aplicação.

---

## MÓDULO 4 — As proteções fundamentais (headers, CSRF, sanitização)

**Objetivo:** o aluno entende e consegue demonstrar as 3 proteções
mais usadas.

**Pontos de fala:**
- Headers de segurança: CSP, HSTS, X-Frame-Options — via Helmet
  (Node) / Talisman (Python), bibliotecas padrão de mercado. Explique
  que HSTS só aparece em HTTPS real (não em localhost/HTTP puro) — isso
  é comportamento correto de navegador, não bug.
- CSRF: padrão double-submit cookie. Mostre o fluxo: cliente busca
  token em `/csrf-token`, reenvia no header `x-csrf-token` em toda
  requisição que muda estado.
- Sanitização SQLi/XSS: baseada em padrões (regex) que bloqueiam
  ataques comuns ANTES da rota rodar. Seja honesto: isso é defesa em
  profundidade, não substitui prepared statements.

**Demo ao vivo — mostre um ataque sendo bloqueado:**
```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'"'"' OR 1=1 --"}'
# Resposta esperada: 400, bloqueado pelo .dimma
```

**Perguntas frequentes:**
- "Isso pega TODO SQL Injection?" Não — é baseado em padrões
  conhecidos. Ofuscação avançada pode passar. Prepared statements
  continuam sendo a defesa real.

---

## MÓDULO 5 — Rate limiting e o problema da escala (Redis)

**Objetivo:** o aluno entende por que rate limiting "ingênuo" quebra
em produção com múltiplas instâncias, e como o `.dimma` resolve isso.

**Pontos de fala:**
- Rate limiting em memória (um Map/dict no processo) funciona numa
  instância só. Com load balancer e múltiplas instâncias, um atacante
  distribui requisições entre elas e nunca bate o limite.
- Solução: Redis compartilhado entre instâncias — `REDIS_URL` como
  variável de ambiente ativa isso automaticamente nos dois motores.
- Esse é um ótimo momento para uma demonstração ao vivo impressionante:
  suba duas instâncias locais em portas diferentes, mostre o rate limit
  falhando sem Redis, depois funcionando com Redis.

**Demo ao vivo:** monte duas instâncias Express na mesma máquina
(portas 3001 e 3002) compartilhando o mesmo `REDIS_URL`, e mostre com
`curl` em loop que o contador é somado entre as duas.

**Perguntas frequentes:**
- "Preciso de Redis desde o primeiro dia?" Não — só quando você
  escalar para mais de uma instância. Sem Redis, cai para memória local
  automaticamente (com aviso no console).

---

## MÓDULO 6 — Hashing de senha e sessões

**Objetivo:** o aluno nunca mais guarda senha em texto puro.

**Pontos de fala:**
- bcrypt, custo 12 — padrão de mercado. Mostre a diferença entre hash e
  criptografia (hash não é reversível).
- `@session_expiry` — apenas configuração exposta pro código do
  programador, o `.dimma` não gerencia sessão sozinho (é
  responsabilidade da aplicação).

**Demo ao vivo:**
```js
const { hashPassword, verifyPassword } = require('dimma');
const hash = await hashPassword('minhaSenhaForte123');
console.log(hash); // $2b$12$...
console.log(await verifyPassword('minhaSenhaForte123', hash)); // true
```

---

## MÓDULO 7 — Detecção de anomalia e a "IA embutida" honesta

**Objetivo:** o aluno entende a diferença entre marketing de IA e
implementação real.

**Pontos de fala:**
- Este é o módulo pra reforçar a credibilidade do curso: explique que
  "detecção de anomalia" aqui é estatística (z-score sobre intervalos
  entre requisições), não uma rede neural — e por que isso é uma escolha
  honesta e correta (leve, explicável, sem custo por requisição).
- Depois, mostre a camada de IA de verdade (`@ai_detection`): só é
  chamada quando a estatística já sinalizou algo suspeito — nunca em
  toda requisição (custo/latência). Fail-safe: se a API falhar ou faltar
  chave, nunca derruba a aplicação.
- Reforce: isso é um ótimo exemplo de arquitetura híbrida (regra
  rápida + IA só quando necessário) que vale a pena ensinar como padrão
  de design, não só como feature do `.dimma`.

**Demo ao vivo:** simule uma rajada de requisições do mesmo IP e
mostre o aviso de anomalia no console.

---

## MÓDULO 8 — Reputação de IP com AbuseIPDB

**Objetivo:** o aluno aprende a integrar uma API de terceiros de
forma resiliente (fail-safe).

**Pontos de fala:**
- Por que uma API especializada (AbuseIPDB) é melhor que "perguntar pra
  uma IA genérica se o IP é malicioso" — dados de reputação real,
  mantidos pela comunidade de segurança, gratuito até ~1000
  consultas/dia.
- O circuit breaker de cota (CallBudget): por que é necessário (um
  atacante pode gerar rajadas de propósito com muitos IPs pra esgotar
  sua cota gratuita), e como ele funciona (contador diário, opcionalmente
  distribuído via Redis).

**Demo ao vivo:** mostre o teste `run-budget.js` rodando e explique o
cenário de ataque que ele simula (50 IPs diferentes tentando esgotar a
cota).

---

## MÓDULO 9 — `dimma scan`: caçando código inseguro

**Objetivo:** o aluno sai sabendo rodar uma varredura de segurança no
próprio código antes de cada deploy.

**Pontos de fala:**
- Conecte com o Módulo 1: isso ataca diretamente o problema do "vibe
  coding" citado lá.
- Liste as categorias detectadas: segredos hardcoded, SQL Injection,
  eval/exec, injeção de comando, desserialização insegura, debug mode,
  innerHTML/dangerouslySetInnerHTML, CORS aberto.
- Seja transparente sobre limitações aqui — isso constrói muita
  credibilidade: mostre o próprio autor rodando `dimma scan` contra o
  código-fonte do `dimma-core` e encontrando só falsos positivos (linhas
  de teste/mensagens de erro que mencionam os padrões). Use isso pra
  ensinar uma lição maior: nenhuma ferramenta automática substitui
  revisão humana, seja o código feito por IA ou não.

**Demo ao vivo:**
```bash
mkdir demo-scan && cd demo-scan
echo 'const apiKey = "sk_live_ABCDEFGH1234567890AB";' > app.js
echo 'const q = "SELECT * FROM users WHERE id = " + id;' >> app.js
dimma scan
```

**Perguntas frequentes:**
- "Isso substitui Semgrep/CodeQL/Snyk?" Não — é mais leve e focado
  nos padrões mais comuns. Ferramentas de SAST completo fazem análise de
  fluxo de dados, algo que o `dimma scan` não faz. Recomende usar os
  dois juntos.

---

## MÓDULO 10 — Passkeys/WebAuthn: o fim da senha

**Objetivo:** o aluno entende por que passkeys são o futuro da
autenticação e como implementar com o `.dimma`.

**Pontos de fala:**
- Conecte com dados do setor: identidade é hoje o "novo perímetro" de
  segurança — mais importante que a rede. Senhas continuam sendo o
  vetor de invasão nº1.
- Como passkeys funcionam: a chave privada nunca sai do dispositivo do
  usuário; o servidor só guarda a chave pública. Um vazamento de banco
  de dados não expõe nada reutilizável.
- Reforce a decisão de arquitetura: o `.dimma` nunca implementa
  criptografia de WebAuthn por conta própria — usa bibliotecas vetadas
  (`@simplewebauthn/server`/`webauthn`). Ótimo gancho pra ensinar a
  regra geral: nunca reinvente criptografia.
- Seja honesto sobre o limite de teste: o fluxo completo exige um
  navegador real com autenticador (Face ID, digital, chave física) —
  não é testável 100% de forma automatizada.

**Demo ao vivo:** monte o fluxo completo com uma página HTML simples
usando a API `navigator.credentials` do navegador (grave isso com a tela
do navegador aberta em `https://localhost`, já que WebAuthn exige
contexto seguro).

---

## MÓDULO 11 — Prontidão pós-quântica (`dimma pqc-check`)

**Objetivo:** o aluno entende a próxima onda de mudança em
criptografia e o que realmente está no controle do programador.

**Pontos de fala:**
- Explique rapidamente o que é criptografia pós-quântica e por que
  importa (computadores quânticos futuros podem quebrar criptografia de
  chave pública atual).
- O grupo híbrido X25519MLKEM768, finalizado pelo NIST (FIPS 203).
- O ponto pedagógico mais importante deste módulo: distinguir
  conexões de SAÍDA (controladas pelo runtime Node/Python) de conexões
  de ENTRADA (controladas por onde o TLS termina — geralmente um
  proxy/CDN, fora do controle do código da aplicação). Isso é uma aula
  valiosa de arquitetura, não só sobre o `.dimma`.

**Demo ao vivo:**
```bash
dimma pqc-check
```
Compare o resultado em Node (geralmente pronto, OpenSSL embutido) vs
Python (geralmente não pronto, depende do SO) — ótimo contraste visual
para a aula.

---

## MÓDULO 12 — Construindo em cima do `.dimma`: próximos passos

**Objetivo:** encerramento do curso, com direção clara pro aluno.

**Pontos de fala:**
- Recapitule a arquitetura completa (use o diagrama de camadas do
  Apêndice C).
- Convide o aluno a contribuir: já que o projeto é jovem, contribuições
  reais (testes, novos adaptadores como Django, novas regras pro dimma
  scan) são bem-vindas.
- Encerramento honesto: reforce que isto é um projeto em evolução ativa,
  testado, mas não substituto de auditoria profissional em produtos que
  lidam com dados sensíveis reais.

---

## APÊNDICE A — Referência rápida de todos os comandos `.dimma`

| Comando | Tipo | O que faz |
|---|---|---|
| `@auto_protect` | booleano | Ativa o perfil padrão (headers, CSRF, SQLi/XSS) |
| `@protect input` | lista | `sql_injection`, `xss` |
| `@rate_limit` | taxa | Ex: `100 req/min` |
| `@override rate_limit` | taxa | Alias explícito de `@rate_limit` |
| `@csrf_protection` | booleano | Proteção CSRF (double-submit cookie) |
| `@security_headers` | booleano | Helmet/Talisman |
| `@anomaly_detection` | booleano | Detecção estatística de rajadas |
| `@ai_detection` | booleano | Revisão opcional de anomalias por provider de IA configurado pelo utilizador |
| `@ip_reputation_check` | booleano | Consulta AbuseIPDB em anomalias |
| `@passkey_support` | booleano | Ativa `dimma.webauthn` |
| `@rp_id` / `@rp_origin` | texto | Configuração do WebAuthn |
| `@password_hashing` | texto | Ex: `bcrypt` |
| `@session_expiry` | número | Minutos |
| `@exclude` | lista (repetível) | Caminhos isentos das checagens |
| `@connect` | lista (repetível) | Metadado informativo de arquivos relacionados |

## APÊNDICE B — Referência rápida do CLI

| Comando | O que faz |
|---|---|
| `dimma init` | Cria o `security.dimma` e detecta a stack |
| `dimma scan` | Varre o código procurando padrões inseguros |
| `dimma pqc-check` | Verifica prontidão para TLS pós-quântico |

## APÊNDICE C — Diagrama de camadas (para slide/desenho na tela)

```
Requisição HTTP chega
        |
        v
[1] Bloqueio de acesso direto a *.dimma  (sempre ativo)
        |
        v
[2] Headers de seguranca (Helmet/Talisman)
        |
        v
[3] Rate limiting (memoria ou Redis distribuido)
        |
        v
[4] Sanitizacao de input (SQLi/XSS por padrao)
        |
        v
[5] CSRF (double-submit cookie)
        |
        v
[6] Deteccao de anomalia (estatistica, por IP)
        |           |
        |           +--> [6a] Reputacao de IP (AbuseIPDB) - so se anomalo
        |           +--> [6b] Revisao por IA (NVIDIA NIM) - so se anomalo
        v
   Codigo da aplicacao (sua rota/view)
```

## APÊNDICE D — Números do projeto (para usar em slides de credibilidade)

- 120 testes reais passando (74 Node + 46 Python)
- 2 motores: Node.js/Express e Python/Flask, mesma linguagem `.dimma`
- 0 CVEs conhecidas nas dependências (verificado com `npm audit` e
  `pip-audit`)
- Bibliotecas de segurança usadas (nunca reimplementadas): Helmet,
  Flask-Talisman, bcrypt/bcryptjs, csrf-csrf, Flask-WTF,
  `@simplewebauthn/server`, `webauthn` (py_webauthn)

## APÊNDICE E — Erros honestos para mencionar no curso (constroem confiança)

Mencionar limitações reais no curso é o que separa um curso técnico
sério de um discurso de vendas. Use estes pontos ao longo das aulas:

1. Sanitização por regex tem limite — ofuscação avançada pode passar.
2. Detecção de anomalia é estatística, não é uma rede neural de verdade.
3. `dimma scan` gera falsos positivos (mostrado ao vivo no Módulo 9).
4. WebAuthn não é 100% testável sem navegador real.
5. PQC no Python depende do OpenSSL do sistema operacional, geralmente
   desatualizado — ao contrário do Node, que embute o seu próprio.
6. O projeto é jovem — recomende auditoria humana antes de uso com dados
   sensíveis reais em produção.
