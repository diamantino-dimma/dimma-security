# O `.dimma` explicado de um jeito bem simples

Este documento explica cada comando do `.dimma` sem usar palavras
técnicas difíceis. Se você não sabe o que é "algoritmo" ou nunca
programou na vida, este documento é pra você.

## Primeiro, uma analogia

Imagine que o seu site ou aplicativo é uma **casa**. As pessoas que
visitam seu site são como **visitantes** entrando nessa casa. Alguns
visitantes são gente de bem (seus clientes de verdade). Mas, de vez em
quando, aparece alguém querendo roubar, quebrar coisas, ou se passar por
outra pessoa.

O arquivo `.dimma` é como uma **lista de instruções para um segurança**
que fica na porta da sua casa. Em vez de você ter que ensinar o
segurança pessoalmente (o que ia levar dias), você escreve as regras
numa folha de papel (o arquivo `.dimma`), entrega pro segurança, e ele já
sabe o que fazer.

Cada linha que começa com `@` no arquivo `.dimma` é **uma instrução
para esse segurança**. Vamos ver cada uma.

---

## `@auto_protect: true`

**Em uma frase:** liga todas as proteções básicas de uma vez só.

**Explicando bem devagar:** imagine que, em vez de explicar pro
segurança 5 regras diferentes uma por uma, você simplesmente diz "faça
o básico que todo segurança bom sabe fazer". É isso que essa linha faz.
Com uma frase só, seu site já fica com as proteções mais importantes
ativas.

---

## `@protect input: [sql_injection, xss]`

**Em uma frase:** revista o que as pessoas escrevem nos formulários do
seu site, pra ver se não tem "pegadinha" escondida.

**Explicando bem devagar:** quando alguém preenche um formulário no seu
site (nome, mensagem, busca), normalmente ele escreve coisas normais,
tipo "Maria" ou "quero comprar um tênis". Mas tem gente má-intencionada
que, em vez de escrever algo normal, escreve um **truque disfarçado de
texto** — como uma senha secreta que engana o computador pra fazer
coisas que não devia (por exemplo, apagar informações do banco de dados,
ou roubar dados de outras pessoas que visitam o site).

- **"sql_injection"** é o nome desse tipo de truque quando a pessoa
  tenta enganar o banco de dados do seu site (o lugar onde ficam
  guardadas todas as informações, tipo uma gaveta gigante de arquivos).
  É como se alguém, em vez de escrever o nome dela numa ficha de
  cadastro, escrevesse uma instrução secreta pra bagunçar a gaveta
  inteira.
- **"xss"** é quando a pessoa tenta deixar uma "armadilha" escondida
  numa mensagem, pra que, quando OUTRA pessoa ler essa mensagem no seu
  site, aconteça algo ruim no computador dela (tipo roubar a sessão de
  login dela).

Esse comando diz pro segurança: "revista tudo que as pessoas escrevem
antes de deixar passar".

---

## `@rate_limit: 100 req/min`

**Em uma frase:** ninguém pode bater na porta mais de 100 vezes por
minuto.

**Explicando bem devagar:** imagine uma pessoa muito estranha que fica
tocando a campainha da sua casa centenas de vezes por segundo, sem
parar, só pra te incomodar ou tentar adivinhar a senha do seu cofre
testando uma senha atrás da outra bem rápido. Esse comando diz pro
segurança: "se alguém bater na porta rápido demais, mande esperar um
pouco antes de deixar bater de novo". Isso protege seu site de ficar
lento ou travado por causa de gente abusando.

---

## `@csrf_protection: true`

**Em uma frase:** cada visitante recebe uma "pulseirinha" secreta pra
provar que é ele mesmo, e não outra pessoa se fazendo passar por ele.

**Explicando bem devagar:** imagine que você está numa festa e, pra
pegar bebida no bar, você precisa mostrar uma pulseira que te deram na
entrada. Isso evita que alguém de fora, que nem entrou na festa, chegue
no bar e finja que é convidado. No mundo dos sites, essa "pulseira" é um
código secreto (chamado de "token") que o site dá pro visitante, e depois
confere se é o mesmo código antes de deixar ele fazer algo importante
(tipo mudar uma senha ou fazer uma compra). Isso impede que um site
malicioso engane o navegador da vítima pra fazer coisas em nome dela sem
ela saber.

---

## `@security_headers: true`

**Em uma frase:** manda um bilhete de instruções pro navegador de quem
está visitando, ensinando ele a se comportar com segurança.

**Explicando bem devagar:** quando alguém abre seu site no navegador
(Chrome, Safari, etc.), o navegador precisa saber algumas regras: "não
deixe outros sites espiarem o que está acontecendo aqui", "só carregue
coisas de fontes confiáveis", "sempre use conexão segura". Esse comando
manda automaticamente esse "bilhete de instruções" pra todo mundo que
visita, sem você precisar fazer nada manualmente.

---

## `@anomaly_detection: true`

**Em uma frase:** o segurança fica de olho em comportamentos estranhos,
tipo alguém que normalmente anda devagar e de repente começa a correr
muito rápido.

**Explicando bem devagar:** o segurança aprende, com o tempo, como é o
comportamento "normal" de cada visitante (de quanto em quanto tempo ele
costuma bater na porta). Se, de repente, alguém que sempre bateu devagar
começa a bater super rápido e sem parar, isso é estranho — pode ser
sinal de um ataque. Esse comando ativa esse "olhômetro" automático.

---

## `@ai_detection: true`

**Em uma frase:** quando o segurança percebe algo estranho, ele chama um
detetive mais experiente pra dar uma segunda opinião antes de expulsar
alguém.

**Explicando bem devagar:** o "olhômetro" do comando anterior às vezes
pode se enganar (uma pessoa de bem também pode, por acaso, mandar várias
mensagens rápido). Então, em vez de já expulsar essa pessoa na hora, o
segurança chama um detetive mais esperto (uma inteligência artificial)
só nesses casos duvidosos, pra examinar com calma e decidir se é
realmente perigo ou só um mal-entendido. Isso evita expulsar gente
inocente.

Para ativar essa segunda opinião, mantenha também
`@anomaly_detection: true` e escolha o provider no `security.dimma`:

```text
@anomaly_detection: true
@ai_detection: true
@ai_provider: openai
@ai_model: gpt-4o-mini
```

Configure a chave correspondente como variável de ambiente (`OPENAI_API_KEY`,
`NVIDIA_API_KEY`, `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY` ou
`GEMINI_API_KEY`). A IA fica desligada por padrão e só é consultada para
anomalias. O Flask envia o método, o padrão da rota e os sinais estatísticos;
não envia o corpo, o IP nem os valores concretos dos parâmetros da rota.
Uma resposta maliciosa com confiança de pelo menos 0,7 pode bloquear a
requisição; falha da API não interrompe a aplicação. As chamadas enviam
metadados a um serviço externo e consomem cota, portanto só ative se aceitar
esse tratamento de dados.

---

## `@ip_reputation_check: true`

**Em uma frase:** antes de deixar alguém entrar, o segurança confere numa
lista compartilhada com segurancas de outros prédios se essa pessoa já
foi pega aprontando em outro lugar.

**Explicando bem devagar:** existe uma espécie de "lista negra" mundial,
mantida por várias pessoas que cuidam de segurança de sites (chamada
AbuseIPDB), com o "endereço" (chamado de IP) de computadores que já
foram flagrados fazendo coisa errada em outros sites antes. Esse comando
consulta essa lista quando alguém age de forma estranha (ligado ao
comando anterior), pra saber se esse "endereço" já tem histórico ruim.

---

## `@passkey_support: true` (com `@rp_id` e `@rp_origin`)

**Em una frase:** em vez de decorar uma senha (que pode ser roubada),
a pessoa usa a digital ou o rosto dela pra entrar, do jeito que já
desbloqueia o celular.

**Explicando bem devagar:** senhas são um problema: as pessoas esquecem,
reutilizam a mesma senha em vários lugares, ou alguém rouba. Uma
"passkey" é como usar sua digital ou reconhecimento facial pra abrir uma
porta especial — a "chave" fica guardada dentro do seu próprio celular
ou computador, nunca sai de lá, e ninguém mais consegue copiar. `@rp_id`
e `@rp_origin` são só o "nome" e "endereço oficial" da sua casa, pra essa
tecnologia saber exatamente qual casa está sendo protegida.

---

## `@password_hashing: bcrypt`

**Em uma frase:** em vez de guardar a senha das pessoas escrita
normalmente, o site guarda um "código embaralhado" que não dá pra
desembaralhar de volta.

**Explicando bem devagar:** imagine que, em vez de escrever "a senha da
Maria é 123456" num papel (que, se alguém roubar o papel, já sabe a
senha dela), você passa essa senha numa máquina de picotar bem especial
que transforma ela num monte de números e letras aleatórias. Essa
máquina só anda pra frente — ninguém, nem você, consegue colocar os
pedaços de volta e descobrir a senha original. Quando a Maria tenta
entrar de novo, o site pega a senha que ela digitou, passa na mesma
máquina, e confere se o resultado bate com o que já tinha guardado.
Assim, mesmo se alguém roubar as informações do seu site, não vai
conseguir saber a senha de verdade de ninguém. "bcrypt" é só o nome
dessa "máquina de picotar" específica que o `.dimma` usa (uma das mais
confiáveis do mundo).

---

## `@session_expiry: 30`

**Em uma frase:** depois de 30 minutos sem novidade, pedimos pra pessoa
provar de novo quem ela é.

**Explicando bem devagar:** quando você entra num site com sua senha,
ele te dá uma "pulseirinha temporária" (parecida com a do CSRF) pra não
precisar digitar a senha toda hora. Mas, se você ficar muito tempo sem
usar essa pulseirinha, é mais seguro pedir pra você confirmar de novo
quem você é — assim, se alguém pegar seu celular desbloqueado e
esquecido, não consegue ficar usando sua conta pra sempre.

---

## `@exclude: /health`

**Em uma frase:** algumas portas da casa não precisam de tanta revista,
tipo a caixa de correio.

**Explicando bem devagar:** nem todo "lugar" do seu site precisa de
todas essas revistas e checagens. Por exemplo, um "sensor" que só serve
pra confirmar que o site está ligado (chamado de `/health`, em inglês
"saúde") pode ser consultado centenas de vezes por segundo por robôs de
monitoramento de forma totalmente normal — não é um ataque. Esse comando
diz "essa porta aqui, pula a revista".

---

## `@connect: routes/api.js`

**Em uma frase:** um bilhete de anotação dizendo "essas instruções valem
também pra esse outro cômodo da casa".

**Explicando bem devagar:** este comando ainda não faz uma ação
automática — é mais uma anotação organizacional, tipo um post-it,
lembrando que aquele arquivo `.dimma` está relacionado a outro arquivo
específico do seu projeto.

---

## Os "superpoderes extras" (comandos de terminal)

Além das regras do arquivo `.dimma`, existem 3 comandos especiais que
você digita no computador (não no arquivo `.dimma`):

### `dimma init`
**Em uma frase:** cria a folha de regras (o arquivo `.dimma`) do zero
com um clique, já com as regras básicas prontas — você só ajusta depois
se quiser.

### `dimma scan`
**Em uma frase:** um inspetor que passa o olho em TODO o código do seu
site procurando erros perigosos que um programador (ou uma IA) possa ter
deixado passar sem querer — tipo uma senha secreta esquecida escrita à
mostra no código, ou uma porta que ficou destrancada.

### `dimma pqc-check`
**Em uma frase:** confere se o seu site já está preparado pra um tipo de
tranca ainda mais forte, feita pra resistir até a computadores super
avançados do futuro (chamados de "computadores quânticos").

---

## Resumo bem rapidinho (pra colar num quadro)

| O que você escreve | O que isso quer dizer, em bom português |
|---|---|
| `@auto_protect` | Liga o "pacote básico" de segurança |
| `@protect input` | Revista o que as pessoas escrevem |
| `@rate_limit` | Não deixa ninguém bater na porta rápido demais |
| `@csrf_protection` | Dá uma pulseirinha secreta pra confirmar identidade |
| `@security_headers` | Ensina o navegador do visitante a se comportar |
| `@anomaly_detection` | Fica de olho em comportamento estranho |
| `@ai_detection` | Chama um detetive esperto pra casos duvidosos |
| `@ip_reputation_check` | Confere numa lista negra compartilhada |
| `@passkey_support` | Entra com digital/rosto em vez de senha |
| `@password_hashing` | Guarda a senha embaralhada, nunca visível |
| `@session_expiry` | Pede confirmação de novo depois de um tempo |
| `@exclude` | Algumas portas não precisam de revista |
| `@connect` | Anotação de qual arquivo se conecta com qual |

Se você entendeu esta página inteira, você já entende o `.dimma` melhor
do que a maioria das pessoas entende como funciona a segurança dos sites
que usam todos os dias. 🎉
