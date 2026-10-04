# Changelog do projeto `.dimma`

Este arquivo regista a evolução do projeto a cada sessão de trabalho e indica
as validações efetivamente executadas; código não testado é identificado como
tal.

## Relatórios do comando `dimma scan`

- Os achados e a auditoria de dependências são apresentados em secções
  Markdown, com resumo por severidade, localização, regra, descrição e
  evidência.
- CRITICO, ALTO, MEDIO e BAIXO usam cores ANSI diferentes em terminais
  interativos. A cor é desativada para saída redirecionada e com `NO_COLOR`;
  `FORCE_COLOR=1` permite ativá-la explicitamente.

## Compatibilidade Python 3.9

- O CI confirmou que `flask-limiter>=4.1.0` já não pode ser instalado em
  Python 3.9. O pacote e as dependências de teste agora selecionam Flask-Limiter
  3.x para Python 3.9 e 4.x para Python 3.10 ou superior, mantendo a versão
  mínima Python declarada e a mesma API usada pelo Dimma.
- Corrigido também o requisito de Flask-WTF para `>=1.2.2`; o CI mostrou que
  `1.3.0` não está publicado no PyPI e impedia a instalação das dependências.
- Para Python 3.9, o pacote usa py_webauthn 2.x; confirmei que essa versão
  fornece os símbolos e gera as opções de registo/autenticação usados pelo
  wrapper. Python 3.10+ continua a usar py_webauthn 3.x.
- Removida `lupa` das dependências de teste: não é usada pelo código nem
  pelas suites e as versões recentes não suportam Python 3.9.

## 2026-10-04 — Comando único `dimma styles` e nome npm

- Os pacotes Python e Node incluem o VSIX de ícones e sintaxe. O comando
  explícito `dimma styles` deteta os CLIs de VS Code/Cursor disponíveis,
  instala a extensão e ativa `workbench.iconTheme` apenas em
  `.vscode/settings.json` do projeto atual.
- A instalação npm/PyPI não executa hooks nem altera o IDE. O comando preserva
  outras definições JSON e falha sem modificar o ficheiro se `settings.json`
  não for JSON válido; a ativação global e IDEs JetBrains não são alterados.
- As cópias VSIX são incluídas nos pacotes e precisam ser atualizadas junto com
  uma nova versão Python/npm quando a extensão mudar.
- Como `dimma==1.0.0` já foi publicado no PyPI, a versão Python foi preparada
  como `1.0.1`; ainda é necessário publicar essa versão para o comando chegar
  aos utilizadores de `pip install dimma`.
- O pacote Node foi renomeado de `dimma-core` para `dimma`; módulos gerados
  pelo injector e exemplos de instalação agora usam `require('dimma')`. A
  consulta pública npm devolveu E404 para ambos os nomes; confirme a
  disponibilidade e o acesso da conta no momento da publicação.

## 2026-10-04 — Exceção temporária e explícita no audit npm

- O gate de produção do `dimma-core` e o CI agora usam `better-npm-audit`,
  mantendo o nível `high` e excluindo apenas `GHSA-vfj7-8cjw-p6xm`. A advisory
  afeta `braces@3.0.3`; não foi encontrada uma versão corrigida publicada no
  npm durante esta validação.
- A exceção está documentada em `dimma-core/SECURITY_EXCEPTIONS.md`. A análise
  do proxy atual não encontrou um caminho para fornecer ao `braces` o padrão
  aninhado exigido: o middleware usa o caminho fixo `/`, sem glob configurável.
  A presença da dependência vulnerável continua reportada pelo audit original;
  isto não é uma correção upstream nem uma garantia para configurações futuras.
- `express` foi declarado também como dependência de desenvolvimento, mantendo
  a peer dependency pública. O lockfile ainda não o marca como `dev: true`,
  porque `express-rate-limit`, uma dependência de produção, também o exige como
  peer; não foi alterada a resolução de peers para forçar essa classificação.
- O audit original sem exclusão continua a reportar uma advisory única
  (`GHSA-vfj7-8cjw-p6xm`) nos três pacotes da cadeia; não foram encontradas
  outras advisories `high`/`critical` na árvore auditada.

## 2026-10-04 — Realce de sintaxe da linguagem `.dimma`

- A extensão VS Code/Cursor agora regista a linguagem `.dimma` e um TextMate
  grammar para diretivas, comentários, valores, booleanos, números, listas e
  strings.
- O plugin JetBrains agora associa um tipo de linguagem próprio e inclui lexer,
  realce de sintaxe e definições de cores configuráveis pelo esquema do IDE.
- JSON/manifests e cobertura das diretivas foram verificados localmente. O
  plugin JetBrains ainda requer build com JDK/Gradle e validação visual no IDE.

## 2026-10-04 — Primeira publicação no PyPI

- Publicado `dimma==1.0.0` no PyPI usando Trusted Publishing (OIDC) do
  GitHub Actions, sem token de publicação armazenado no repositório.
- Workflow repetiu os testes Python, compilação, build de wheel/sdist e
  `twine check`; todos passaram. Um ambiente virtual limpo instalou a versão
  pública e confirmou que `dimma --help` funciona.
- Atualizados README e guia com o comando de instalação PyPI.
- O pacote npm ainda não foi publicado: o audit encontrou três alertas high
  transitivos e o hook `prepublishOnly` permanece a bloqueá-lo até uma
  correção compatível ser testada.

## 2026-10-04 — Preparação dos pacotes e tema de ícones VS Code

- Adicionados README e LICENSE próprios a cada pacote; o pacote Python tem
  metadados de licença, URLs e um wheel/sdist que passa `twine check`. O npm
  limita o tarball a código e documentação, exige Node 20+ e executa testes
  e auditoria de dependências antes de publicar.
- Criados `.gitignore`, workflow CI para Node/Python e guia passo a passo de
  validação e publicação em npm, PyPI e nos marketplaces de extensões.
- Criada uma extensão VS Code que fornece um tema de ícones `.dimma`; também
  documentada a associação manual de Material Icon Theme.
- Adicionado um plugin JetBrains que associa `.dimma` ao tipo de ficheiro
  com o escudo do Dimma; documentada a distribuição da extensão VS Code no
  Open VSX para Cursor. O Visual Studio completo continua sem integração.
- Os manifestos XML/JSON e os SVGs passaram validação local. O plugin
  JetBrains ainda não foi compilado nem testado num IDE porque este ambiente
  não tem JDK ou Gradle instalados.
- Validação local: 106 testes Node e 65 testes Python passaram; npm pack,
  build Python/twine check e empacotamento VSIX foram validados.
- Na preparação inicial, ainda faltavam publisher/URLs definitivos e contas;
  o URL GitHub e a publicação Python foram concluídos depois. `npm audit
  --omit=dev` continua com três alertas high transitivos.

## 2026-10-04 — Python: diagnóstico de IA e suite unificada

- Implementado `dimma ai-check` também no CLI Python: valida o provider/modelo
  e a presença da chave sem rede; `--test` é necessário para chamar o serviço
  externo e consumir a cota.
- Os parsers Node e Python agora aceitam um BOM UTF-8 inicial, incluindo
  ficheiros `.dimma` guardados com a codificação UTF-8 comum no Windows.
- A IA Python valida os tipos de provider/modelo, limita a resposta externa a
  64 KiB, oculta detalhes de rede e limpa cotas de dias anteriores da memória.
- Adicionado `python test/run_all.py` para executar as quatro suites Python em
  sequência, e documentada a configuração dos providers e o tratamento de
  dados externos.
- Validação em Python 3.14.8: 33 testes principais, 16 do scanner, 8 WebAuthn
  e 8 de IA; compilação Python e `pip check` sem erros.

## 2026-10-03 — Python: limite de requests, bcrypt e cobertura do scanner

- Com inspeção ativa, o Flask limita requests a 1 MiB por padrão (sem elevar
  um limite menor já definido pela aplicação) e devolve HTTP 413 em JSON para
  corpos acima do teto.
- `hash_password` recusa senhas acima de 72 bytes, evitando o truncamento do
  bcrypt; `verify_password` falha fechado para essas entradas.
- O scanner Python agora relata erros de leitura como cobertura incompleta,
  e `dimma scan` termina com status não-zero nesses casos. Erros de parsing
  de `security.dimma` deixam de ser ignorados silenciosamente.
- Testes de regressão cobrem limite do body, JSON primitivo falsy, senha longa
  e saída de cobertura incompleta.

## 2026-10-03 — Node.js: inicialização, injeção e proxy

- `@files_protect` deixou de ser obrigatório ao iniciar o motor Express ou
  o proxy autónomo; continua a ser necessário quando `dimma inject` precisa
  de escolher os ficheiros a modificar.
- Com inspeção de entrada ativa, `DimmaEngine.protect(app)` regista parsers
  JSON/urlencoded de 1 MB antes da inspeção; sem inspeção, o body não é
  consumido. Registe o motor antes das rotas.
- O injector passa a inserir a proteção depois da criação reconhecida da
  aplicação Express, usa resolução de caminho compatível com CommonJS e ESM
  (incluindo `.mjs`) e recusa alterar ficheiros cujo padrão não reconhece.
- `dimma eject` exige o marcador antes de restaurar, preserva alterações
  posteriores em `.dimma.eject.bak` e mantém backups ambíguos sem sobrescrever
  o conteúdo atual.
- `dimma inject --dry-run` aceita a flag sem modificar ficheiros.
- O proxy repõe o body já analisado ao encaminhar JSON/formulários, inclui
  valores JSON falsy, e deixa o stream multipart intacto; quando CSRF está ativo, expõe
  `GET /__dimma/csrf-token`.
- Regressões Node cobrem inicialização sem `@files_protect`, sintaxe CJS/ESM
  injetada, `--dry-run`, corpos do proxy e o fluxo de token CSRF.

## 2026-10-03 — Node.js: limites de injeção, Redis e reputação de IP

- `dimma inject` recusa caminhos fora da raiz do projeto e caminhos
  existentes cujo destino real (por exemplo, via symlink) escape dessa raiz;
  não substitui backups existentes e ignora padrões Express que aparecem
  apenas em comentários.
- Contador de rate limit, janela de anomalias e orçamento diário de APIs no
  Redis agora são atualizados por scripts Lua atómicos. Se o Redis do
  orçamento falhar, aplica-se limite local em vez de permitir chamadas
  externas ilimitadas.
- A consulta AbuseIPDB valida o IP antes da chamada, ignora intervalos IPv4
  não globais e IPv6 não global/documental (incluindo IPv4 mapeado), e não
  inclui o corpo não confiável da API nas mensagens de erro.
- Hashing/verificação de senha recusa entradas acima de 72 bytes para impedir
  truncamento silencioso pelo bcrypt.
- Adicionados testes Node para concorrência do rate limit/janela de anomalia,
  contenção do injector, contingência do orçamento e IPs inválidos,
  reservados e mapeados.

## 2026-10-03 — Node.js: proteção da integração com IA

- O classificador adiciona adapters NVIDIA NIM, OpenAI, OpenRouter, Anthropic
  e Gemini; o provider/modelo podem ser escolhidos via `.dimma` ou variáveis
  de ambiente, sem chave obrigatória para quem desativa a função.
- Chamadas externas têm timeout de 5 segundos por padrão e não propagam
  corpos de erro, mensagens brutas da rede ou conteúdo inválido da resposta.
- O classificador valida estritamente o esquema/intervalo de confiança,
  limita o texto explicativo, usa orçamento diário separado por provider e o
  middleware não envia body nem IP do cliente.
- `dimma ai-check` valida provider/modelo/chave localmente; `--test` opt-in
  realiza uma chamada externa. O README documenta providers, env vars e dados
  transmitidos.
- `dimma scan` agora sinaliza erros de leitura como cobertura incompleta e
  termina com status não-zero em vez de reportar sucesso silencioso.

## 2026-10-03 — bloqueio do helper genérico de escaping SQL

- `escapeForSql` (Node) e `escape_for_sql` (Python) deixaram de devolver
  strings com barras invertidas, cujo efeito depende do dialeto e da
  configuração do banco. Os helpers mantêm o nome por compatibilidade,
  mas agora falham explicitamente e orientam o uso de queries
  parametrizadas/prepared statements.
- O bloqueio de ficheiros `.dimma` normaliza caminhos percent-encoded
  antes de permitir que a requisição chegue ao servidor de estáticos;
  codificação inválida ou excessivamente aninhada é rejeitada.
- Inputs acima de 4.096 caracteres passaram a ser rejeitados, em vez de
  truncados para análise. O Flask agora inspeciona também formulários,
  valores repetidos de query e parâmetros de rota.
- Adicionados testes de regressão para escaping, input longo, formulários
  Flask e exposição de `.dimma` por caminho codificado.

## 2026-10-03 — auditoria de segurança externa: correção de achados críticos e altos

Sessão de correção a partir de uma auditoria de segurança completa ao
código (ver `RELATORIO_SEGURANCA_DIMMA.md`). Todas as correções abaixo
foram validadas com execução real antes de serem consideradas concluídas.

### Corrigido (crítico)
- **`@supply_chain_guard` passou a existir de verdade.** Até agora a
  flag era lida pelo parser mas nunca usada por nenhum código —
  documentação prometia verificação de pacotes recém-publicados,
  typosquatting/slopsquatting e integridade de lockfile, e nada disso
  era aplicado. Implementados `src/security/supplyChain.js` (Node) e
  `dimma/security/supply_chain.py` (Python), ligados a `dimma scan`:
  - Deteção de entradas sem hash `integrity` no `package-lock.json`
    (Node) / ausência de lockfile ou hashes em `requirements.txt`
    (Python).
  - Heurística de typosquatting (distância de edição 1 contra uma lista
    de pacotes populares).
  - Scripts `preinstall`/`install`/`postinstall` com padrões suspeitos
    de exfiltração/execução remota (Node).
  - Verificação opcional (`--supply-chain-online`, nunca por padrão —
    o scan nunca liga à rede sem ser pedido) de pacotes publicados há
    menos de 7 dias, via registry.npmjs.org / PyPI, com circuit breaker
    de orçamento diário reutilizando `budget.js`.
  - `@supply_chain_guard: false` no `.dimma` desativa a verificação,
    tal como as outras proteções.
- **Prototype Pollution no parser Node (`src/parser.js`, `setNested`).**
  Um `.dimma` com um comando como `@__proto__.x: true` poluía
  `Object.prototype` para todo o processo (CWE-1321). Corrigido
  bloqueando `__proto__`/`constructor`/`prototype` como segmentos de
  caminho, com aviso no console em vez de falha silenciosa. Validado
  com exploit de prova de conceito antes/depois da correção.
- **Exemplos oficiais deixaram de devolver o hash da senha ao cliente.**
  `example/app.js` (Node) e `example/app.py` (Python) respondiam
  `{ passwordHash: hash }` em `/register` — exatamente o padrão que um
  programador copiaria para produção. Agora respondem apenas
  `{ success: true }`; o hash nunca sai do servidor.

## 2026-09-18 — troca de provedor de IA (Anthropic → NVIDIA NIM, gratuita)

### Alterado
- **`@ai_detection` agora usa a NVIDIA NIM** (`build.nvidia.com`) em vez
  da API da Anthropic, a pedido do usuário para eliminar custo. Endpoint
  compatível com o formato OpenAI, modelo padrão configurável (`meta/
  llama-3.1-8b-instruct`), variável de ambiente `NVIDIA_API_KEY` (chave
  gratuita, sem cartão de crédito). Documentado honestamente: o free
  tier é baseado em ~1000 créditos por conta e ~40 requisições/minuto —
  não é ilimitado — mas como a camada só é chamada em anomalias já
  sinalizadas, tende a durar bastante tempo no uso real. Parser tolerante
  a modelos "reasoning" que envolvem o JSON em texto extra. Todos os 5
  testes da camada de IA atualizados e passando, mais 1 teste do circuit
  breaker de orçamento corrigido para o novo formato de resposta.

## 2026-09-17 — quatro funcionalidades novas + auto-varredura de segurança

### Adicionado
- **Circuit breaker de cota (`CallBudget`)**: as camadas de IA e
  AbuseIPDB agora respeitam um teto diário de chamadas (distribuído via
  Redis quando configurado), evitando que um atacante esgote a cota
  gratuita ou gere custo de propósito espalhando rajadas entre muitos
  IPs. 7 testes cobrindo exatamente esse cenário de ataque.
- **Estado distribuído via Redis**: rate limiting e detecção de anomalia
  agora funcionam corretamente com múltiplas instâncias atrás de um load
  balancer — Node usa `ioredis` com implementação própria (INCR/EXPIRE
  para rate limit, listas para o histórico de anomalia); Python usa o
  suporte nativo do Flask-Limiter a `storage_uri` do Redis. Testado com
  `ioredis-mock`/`fakeredis` simulando duas instâncias reais.
- **`dimma scan`** (Node + Python): scanner estático de código inseguro.
  Detecta chaves AWS/segredos hardcoded, SQL Injection por concatenação
  (JS e Python), `eval`/`exec`, injeção de comando (`child_process.exec`
  direto e desestruturado, `subprocess`/`os.system`), desserialização
  insegura (`pickle`/`yaml.load`), `debug=True` no Flask, `innerHTML`/
  `dangerouslySetInnerHTML`, CORS com `*` e credenciais em URL. Sai com
  código 1 em achados críticos/altos (integração com CI). 15 testes em
  cada motor (30 no total), incluindo verificação de zero falsos
  positivos em código seguro.
- **`@pqc_ready` / `dimma pqc-check`**: diagnóstico de prontidão para
  criptografia pós-quântica (grupo híbrido `X25519MLKEM768`), honesto
  sobre cobrir apenas conexões de saída e explicar que o tráfego de
  entrada depende de onde o TLS termina (proxy/CDN).
- **`@passkey_support`/`@rp_id`/`@rp_origin` (Passkeys/WebAuthn)**:
  wrapper fino sobre bibliotecas vetadas (`@simplewebauthn/server` no
  Node, `webauthn`/py_webauthn no Python) — nunca criptografia própria.
  9 testes no Node, 8 no Python, cobrindo forma das opções geradas e
  rejeição correta de respostas inválidas (o fluxo positivo completo
  exige um navegador real com autenticador, documentado como limitação).

### Auto-verificação de segurança desta sessão
- `npm audit` e `pip-audit` rodados contra as dependências do projeto:
  **zero CVEs conhecidas** em ambos.
- `dimma scan` rodado contra o próprio código-fonte do `dimma-core`:
  21 achados, **todos falsos positivos** (strings de teste e mensagens
  de erro do próprio scanner que mencionam os padrões procurados) — zero
  problemas reais no código de producao (`src/`). Isso também expôs, na
  prática, a limitação já documentada da ferramenta: um scanner baseado
  em padrões não distingue "código perigoso" de "texto que menciona
  código perigoso".

### Testes
Total agora: **74 testes Node + 46 Python = 120 testes reais passando.**

## 2026-09-15 (parte 4) — correções de vulnerabilidades reais

Depois de uma revisão de segurança no próprio projeto (pensando como um
pentester revisaria o `.dimma`), três problemas reais foram corrigidos:

### Corrigido
- **[Crítico] Segredo padrão hardcoded (CSRF/SECRET_KEY)**: removido o
  fallback fixo `'dimma-default-secret-troque-em-producao'` compartilhado
  por todos os projetos. Agora: em produção, o motor **recusa iniciar**
  sem `DIMMA_CSRF_SECRET`/`SECRET_KEY` configurado explicitamente; em
  desenvolvimento, gera um segredo aleatório único por execução (nunca
  fixo, nunca compartilhado). Corrigido nos dois motores (Node e Python).
- **[Crítico] `@exclude` não era aplicado no motor Node** — só existia no
  Python. Agora rate limiting, sanitização de input, CSRF, detecção de
  anomalia, verificação de reputação de IP e revisão por IA respeitam
  `@exclude` no Node também (o bloqueio de acesso direto ao `.dimma`
  continua sendo a única exceção sem exclusão — nunca deve ter exceção).
- **[Alto] Aviso de spoofing de IP via proxy**: o motor Node agora
  detecta se `trust proxy` não está configurado no Express enquanto rate
  limiting/anomalia/reputação de IP estão ativos, e avisa no console —
  porque sem isso um atacante pode forjar `X-Forwarded-For` e burlar as
  três proteções de uma vez.

### Testes
- 5 novos testes Node cobrindo o segredo obrigatório em produção e o
  `@exclude` funcionando de fato.
- 1 novo teste Python cobrindo o `SECRET_KEY` obrigatório em produção.
- Total: **36 testes Node + 22 Python = 58 testes reais passando.**

### Vulnerabilidades conhecidas, documentadas, mas não corrigidas nesta
### sessão (limitações estruturais, não bugs)
- Bypass de sanitização por ofuscação de regex (comentários no meio do
  SQL, encoding duplo, homoglifos) — inerente a qualquer abordagem
  baseada em padrão; por isso a documentação já recomenda prepared
  statements como defesa real.
- Estado de rate limiting/anomalia em memória, não distribuído entre
  múltiplas instâncias atrás de um load balancer.
- Exaustão de cota gratuita da AbuseIPDB/custo da API de IA por um
  atacante gerando rajadas propositais de vários IPs.
- Potencial ReDoS nos padrões regex com quantificadores `.{1,100}`.

## 2026-09-15 (parte 3)

### Adicionado
- **Bloqueio automático de acesso HTTP direto a arquivos `.dimma`**: o
  motor (Node e Python) agora recusa, sempre, qualquer requisição cujo
  caminho termine em `.dimma` — retornando 404, mesmo que o programador
  tenha configurado `express.static`/arquivos estáticos de forma
  insegura servindo a pasta do projeto. Essa proteção roda antes de
  qualquer outro middleware e não é opcional. Documentação adicional
  (`BLOQUEIO_ACESSO_DIRETO.md`) explica a segunda camada de defesa —
  configuração no servidor web (Nginx/Apache/Vercel/Netlify) — e a
  boa prática de adicionar `*.dimma` ao `.gitignore`. 3 novos testes
  em cada motor (24 Node, 21 Python, 45 no total).

## 2026-09-15 (parte 2)

### Adicionado
- **Auto-criação do `security.dimma`**: se `DimmaEngine(caminho)` for
  chamado e o arquivo ainda não existir, o motor (Node e Python) agora
  cria automaticamente um `security.dimma` com o perfil de segurança
  padrão, em vez de travar com erro. Isso resolve, da forma
  tecnicamente correta, o pedido de "o arquivo aparecer sozinho depois
  da instalação" — como `pip install`/`npm install` não executam código
  pós-instalação de forma confiável (limitação real do pip/wheels),
  a auto-criação acontece no primeiro uso do `DimmaEngine`, e continua
  existindo o comando explícito `dimma init` para quem preferir esse
  fluxo. Testado manualmente nos dois motores, com validação de que a
  suíte completa de testes continua passando (28 Node + 18 Python).

## 2026-09-15

### Adicionado
- **`@ip_reputation_check: true`**: nova camada especializada em
  segurança cibernética, usando a API gratuita e profissional
  **AbuseIPDB** (banco de dados de reputação de IP mantido pela
  comunidade de sysadmins/analistas de segurança). Quando a detecção de
  anomalia sinaliza uma rajada suspeita, o motor consulta o histórico de
  abuso daquele IP e bloqueia se o score estiver acima do limiar
  recomendado (75). IPs privados/locais nunca são consultados. Falha de
  forma segura sem chave de API ou em erro de rede. 6 testes reais
  cobrindo score alto, score limpo, IP privado, chave ausente e erro de
  API.

## 2026-09-14

### Adicionado
- **Camada de IA embutida real (`@ai_detection: true`)**: quando a
  detecção de anomalia estatística sinaliza uma rajada suspeita, o motor
  agora pode consultar a API da Anthropic (Claude) para decidir, com
  contexto, se é um ataque real ou falso positivo — evitando bloquear
  usuários legítimos por engano. Falha de forma segura (nunca derruba a
  aplicação) se a chave de API não estiver configurada ou a chamada
  falhar. 4 testes reais cobrindo os casos de sucesso, falso positivo,
  ausência de chave e erro de rede.
- **CLI `dimma init`** (Node e Python): comando global que detecta
  automaticamente se o projeto é Node ou Python e cria o `security.dimma`
  inicial.
- **`pyproject.toml`** do pacote Python, pronto para publicação no PyPI.
- **Documentação completa da sintaxe `.dimma`** em inglês
  (`DIMMA_SYNTAX.md`) e português (`DIMMA_SINTAXE.md`), cobrindo todos os
  comandos, tipos de valor e limitações honestas do sistema.

## 2026-09-13 (sessão inicial)

### Adicionado
- Parser da linguagem `.dimma` (Node.js e Python), sintaxe compartilhada.
- Motor `dimma-core` (Node/Express): headers de segurança (Helmet),
  sanitização anti SQL Injection/XSS, rate limiting, proteção CSRF real
  (double-submit cookie), hashing de senha (bcrypt), detecção de anomalia
  estatística.
- Motor `dimma` (Python/Flask) com as mesmas proteções, usando
  Flask-Talisman, Flask-Limiter, Flask-WTF e bcrypt.
- 18 testes de integração HTTP reais em cada motor (36 no total),
  validando bloqueio de ataques reais e passagem de tráfego legítimo.
- Prova de que o mesmo arquivo `security.dimma` funciona sem alteração
  nos dois motores.

## Próximas melhorias planejadas
- Adaptador Django (reaproveitando o parser Python)
- Publicação real nos registries (npm/PyPI)
- Relatório de "score de segurança" gerado a partir do `.dimma`
- Evoluir a detecção estatística para um modelo treinável (scikit-learn)
  como complemento à IA via API
