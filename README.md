# .dimma — camada de segurança cibernética declarativa

Um único arquivo `.dimma` descreve as regras de segurança do seu projeto web
(headers, CSRF, sanitização anti SQL Injection/XSS, rate limiting, hashing de
senha e detecção de anomalias de tráfego). O mesmo arquivo funciona em
**Node.js/Express** e em **Python/Flask** sem alteração — a linguagem é
agnóstica de framework.

## Exemplo (`security.dimma`)

```
@auto_protect: true
@protect input: [sql_injection, xss]
@rate_limit: 100 req/min
@csrf_protection: true
@security_headers: true
@anomaly_detection: true
@password_hashing: bcrypt
@session_expiry: 30
@exclude: /health
```

Uma linha (`@auto_protect: true`) já ativa o perfil padrão com as proteções
mais importantes. O resto do arquivo permite ajustar o que quiser.

## O que cada proteção realmente faz

| Proteção | Como funciona | Nível de confiança |
|---|---|---|
| `security_headers` | Headers HTTP (CSP, HSTS, X-Frame-Options, etc.) via Helmet (Node) / Talisman (Python) — libs padrão de mercado | Alto — cobre configuração, não substitui TLS no servidor |
| `protect input: sql_injection` | Bloqueia padrões conhecidos de SQL Injection no body/query **antes** da rota | Defesa em profundidade — **não substitui** queries parametrizadas/ORM no seu código |
| `protect input: xss` | Bloqueia padrões de XSS + expõe `escapeHtml`/`escape_html` para você escapar saída | Alto para os padrões comuns |
| `csrf_protection` | Token CSRF (double-submit cookie) via csrf-csrf (Node) / Flask-WTF (Python) | Alto — padrão de mercado |
| `rate_limit` | Limita requisições por IP/janela de tempo | Alto |
| `password_hashing: bcrypt` | Hash de senha com bcrypt, custo 12, nunca guarda texto puro | Alto |
| `anomaly_detection` | Estatística (média/desvio-padrão) por IP — sinaliza rajadas fora do padrão | **Honesto**: é heurística estatística, não uma rede neural. Serve de alerta, não bloqueia sozinha por padrão (evita bloquear usuário legítimo por engano) |

**SQL:** `escapeForSql` (Node) e `escape_for_sql` (Python) permanecem na API
por compatibilidade, mas agora recusam gerar strings SQL. Escaping depende do
dialeto e da configuração do driver; use sempre parâmetros/prepared statements
ou o ORM do projeto. O filtro de entrada do Dimma é apenas defesa em
profundidade e não substitui essa regra.

**Senhas:** o helper bcrypt Node exige pelo menos 8 caracteres e recusa
entradas acima de 72 bytes, limite do bcrypt, para impedir que senhas longas
sejam truncadas antes do hash. Se o produto precisar aceitar senhas maiores,
use um algoritmo/password-hashing scheme sem esse limite e migre hashes com
uma estratégia explícita.

**Âmbito do scanner:** `dimma scan` faz análise estática heurística de
padrões no código e verificações de supply chain; não é um DAST/pentest
ativo. Não faz crawling, fuzzing contra uma aplicação em execução, varredura
de portas, nem validação de exploração real. Não o trate como certificação
de segurança nem o execute contra alvos sem autorização.

**Limites do filtro:** valores de texto acima de 4.096 caracteres são
rejeitados como `input_too_large`; o scanner não analisa apenas um prefixo e
deixa o restante passar. No Flask, a inspeção inclui JSON, formulários,
parâmetros de query (inclusive valores repetidos) e parâmetros de rota.
Mantenha ficheiros `.dimma` fora de diretórios públicos e registe a proteção
de acesso antes de `express.static`; o middleware também normaliza caminhos
percent-encoded e rejeita caminhos com codificação inválida/profundamente
aninhada. A verificação AbuseIPDB só envia endereços IP válidos e não
globais (incluindo IPv4 mapeado em IPv6) para o serviço externo.

## Ícone de ficheiros `.dimma` no VS Code

O SVG está em [`assets/dimma-file-icon.svg`](./assets/dimma-file-icon.svg).
Há uma extensão de tema de ícones em [`extensions/vscode/`](./extensions/vscode/)
que associa automaticamente a extensão `.dimma` ao escudo, inclusive em
`security.dimma`. Instale o `.vsix` pela paleta do VS Code e selecione
**Dimma File Icons** em **Preferences: File Icon Theme**. A mesma extensão
pode ser distribuída no Open VSX para ser encontrada no Cursor. Este tema
autónomo substitui o tema de ícones atualmente selecionado.

Para manter **Material Icon Theme**, copie o SVG para uma pasta `icons`
dentro de `%USERPROFILE%\.vscode\extensions\` (por exemplo,
`%USERPROFILE%\.vscode\extensions\icons\dimma.svg`) e acrescente a associação
às User Settings do VS Code:

```json
"material-icon-theme.files.associations": {
  "**.dimma": "../../icons/dimma"
}
```

Depois execute **Material Icons: Reset** ou reative o tema. O icon do editor
não é instalado por `npm install dimma-core` nem por `pip install dimma`.
Para IntelliJ IDEA e outros IDEs baseados na plataforma JetBrains, existe uma
integração de tipo de ficheiro em [`extensions/jetbrains/`](./extensions/jetbrains/);
construa e instale o plugin ZIP indicado no respetivo README. O Visual Studio
(IDE completo, não VS Code) ainda precisa de uma extensão VSIX própria e não é
coberto por estas integrações. O SVG sozinho não configura todos os IDEs.

## Preparar publicação

O guia de verificações, empacotamento e publicação nos registries está em
[`docs/PUBLISHING.md`](./docs/PUBLISHING.md). A extensão VS Code tem passos
próprios em [`extensions/vscode/README.md`](./extensions/vscode/README.md), e
a integração JetBrains em
[`extensions/jetbrains/README.md`](./extensions/jetbrains/README.md).

## Instalação global (para funcionar em qualquer computador)

Depois de publicado nos registries oficiais (npm/PyPI), qualquer programador
instala e usa sem precisar copiar arquivos manualmente:

```bash
# Node.js
npm install -g dimma-core
dimma init          # cria o security.dimma e detecta a stack do projeto

# Python
pip install dimma
dimma init
```

O reconhecimento do `.dimma` não depende do sistema operacional (como um
`.pdf` associado a um leitor) — ele é lido pela biblioteca dentro do próprio
projeto, do mesmo jeito que um `.env` ou `package.json` é lido pelas
ferramentas que o esperam.

## Uso — Node.js / Express

O arquivo `security.dimma` é criado automaticamente na primeira vez que
`DimmaEngine` é instanciado, se ainda não existir — não é preciso rodar
nada manualmente antes. Se preferir criar antes (para revisar/ajustar),
use `dimma init`.

```bash
cd dimma-core
npm install
```

```js
const express = require('express');
const { DimmaEngine, hashPassword } = require('dimma-core');

const app = express();
app.use(express.json());

const dimma = new DimmaEngine('./security.dimma');
dimma.protect(app);

app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: dimma.generateCsrfToken(req, res) });
});
```

Registe `dimma.protect(app)` antes das rotas para que os middlewares de
segurança e, quando a inspeção de entrada estiver ativa, os parsers
JSON/urlencoded (limite de 1 MB) possam inspecionar os pedidos. Com a
inspeção desativada, o body segue sem ser consumido pelo Dimma. A diretiva
`@files_protect` é opcional para o uso direto da API;
ela só é necessária para selecionar ficheiros com `dimma inject`.

Para aplicar a proteção automaticamente aos ficheiros declarados:

```bash
dimma inject
dimma inject --dry-run
```

O injector cria um backup `.dimma.bak` antes de alterar cada ficheiro e
recusa padrões Express que não consegue reconhecer com segurança. `dimma eject`
restaura esse original apenas se o marcador de injeção ainda existir e
preserva a versão atual como `.dimma.eject.bak`; sem marcador, não sobrescreve
o ficheiro. O modo
proxy autónomo com `@auto_protect: true` disponibiliza
`GET /__dimma/csrf-token` para obter o cookie e token necessários aos pedidos
mutáveis protegidos por CSRF.

Rodar os testes reais:
```bash
npm test
```

## Uso — Python / Flask

O mesmo comportamento vale aqui: `DimmaEngine("./security.dimma")` cria o
arquivo automaticamente na primeira vez, se ele ainda não existir.

```bash
cd dimma-python
pip install -r requirements.txt
```

```python
from flask import Flask
from dimma.engine import DimmaEngine

app = Flask(__name__)
dimma = DimmaEngine("./security.dimma")
dimma.protect(app)
```

Instalar também as dependências de teste e executar a suite Python completa:
```bash
pip install -r requirements-dev.txt
python test/run_all.py
```

Quando a inspeção de entrada está ativa, o Flask aplica um limite máximo de
1 MiB por request (respeitando um limite menor já configurado). Excesso
retorna HTTP 413 em JSON. O helper bcrypt recusa senhas com mais de 72 bytes
para impedir o truncamento próprio do algoritmo.

Para diagnosticar o provider de IA em Python:

```bash
python -m dimma.cli ai-check
python -m dimma.cli ai-check --test
```

O primeiro comando verifica a configuração sem fazer chamadas de rede; o
segundo envia explicitamente um pedido de teste e consome a cota do provider.
Configure o provider em `security.dimma` com `@ai_provider` e `@ai_model`,
e a chave correspondente no ambiente do processo. A revisão externa só é
usada quando `@anomaly_detection: true` e `@ai_detection: true` estão ativos.

## Importante — o que o `.dimma` NÃO substitui

Para o produto ser sério e confiável, é essencial ser honesto sobre limites:

- **TLS/HTTPS real** precisa ser configurado no servidor/proxy (Nginx, load
  balancer, certificado). O `.dimma` configura os headers corretos, mas não
  cria certificado nem força criptografia de rede sozinho.
- **Prepared statements/ORM continuam obrigatórios.** A sanitização do
  `.dimma` é uma camada extra — reduz drasticamente o risco, mas a defesa
  definitiva contra SQL Injection é nunca concatenar strings em queries.
- **Detecção estatística e análise opcional por IA são camadas distintas.**
  A deteção de anomalias local usa média/desvio padrão; com
  `@anomaly_detection: true` e `@ai_detection: true`, Node e Python podem
  enviar os sinais dessa deteção a um provider escolhido em `@ai_provider`
  (`nvidia`, `openai`,
  `openrouter`, `anthropic` ou `gemini`), com o modelo opcional
  `@ai_model`. Use `NVIDIA_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`,
  `ANTHROPIC_API_KEY` ou `GEMINI_API_KEY`, respetivamente. Node envia caminho
  e método; Flask envia o padrão da rota e método, não o caminho concreto.
  Nenhum middleware envia body ou IP do cliente. Em Python, a cota diária
  padrão é local ao processo (`DIMMA_AI_DAILY_BUDGET`, default 200) e não é
  partilhada entre instâncias.
  A resposta externa pode bloquear a requisição apenas se marcar maliciosa
  com confiança mínima de 0,7; falhas de rede/formato mantêm a decisão local.
  As chamadas vão a terceiros,
  dependem de disponibilidade/cota, e não substituem controlos locais.
  A IA permanece desativada por padrão; desative-a ou não configure chave se
  não aceitar este tratamento de dados.

  No Node, para verificar configuração sem rede, use `dimma ai-check`;
  `dimma ai-check --test` faz explicitamente uma chamada externa e consome
  orçamento diário. A cota Node pode ser partilhada via Redis; a implementação
  Python ainda mantém a cota apenas em memória.

## Funcionalidades adicionais (sessão de 17/09/2026)

- **`dimma scan`** — varre seu código procurando padrões inseguros conhecidos (chaves hardcoded, SQL Injection, `eval`, injeção de comando, etc). Erros de leitura são exibidos como cobertura incompleta e fazem o comando terminar com código diferente de zero. Veja `docs/DIMMA_SINTAXE.md` para a lista completa.
- **`dimma pqc-check`** — diagnóstico de prontidão para criptografia pós-quântica.
- **`@passkey_support`** — Passkeys/WebAuthn, wrapper sobre bibliotecas vetadas.
- **Circuit breaker de cota + estado distribuído via Redis** — rate limiting, anomalia, IA e reputação de IP agora funcionam corretamente com múltiplas instâncias do servidor.

Veja `CHANGELOG.md` para o histórico completo e `docs/` para a documentação técnica de cada comando.

## Próximos passos sugeridos

1. Adaptador para **Django** (reaproveitando o mesmo parser Python)
2. Painel/relatório de "score de segurança" a partir do arquivo `.dimma`
3. Evoluir a detecção de anomalia para um modelo treinável (scikit-learn)
4. Extensão de ícone de arquivo para IDEs (VS Code)
