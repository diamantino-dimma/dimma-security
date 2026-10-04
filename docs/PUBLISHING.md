# Checklist de publicação do `.dimma`

Este projeto publica artefactos independentes:

| Artefacto | Registry/distribuição | Nome configurado |
|---|---|---|
| Motor Node.js | npm | `dimma-core` |
| Motor Python | PyPI | `dimma` |
| Tema de ícones VS Code/Cursor | Visual Studio Marketplace e Open VSX | `dimma-file-icons` |
| Tipo de ficheiro JetBrains | JetBrains Marketplace ou ZIP | `dimma-jetbrains-file-icons` |

Publicar um pacote não publica os outros nem instala um tema de ícones no IDE.
O Visual Studio (IDE completo) ainda não tem uma extensão Dimma própria.
Verificação em 2026-10-04: as APIs públicas do npm e PyPI responderam 404 para
`dimma-core` e `dimma`. Confirme novamente disponibilidade e conta/registry
imediatamente antes do primeiro envio.

## Estado e bloqueios antes de publicar npm/PyPI

Os metadados locais já apontam para o repositório público e identificam
`DiMMA` como autor/titular. Ainda não publique até fechar estes pontos:

- [x] **Titular/licença:** a pedido do titular, os avisos de copyright dos
  pacotes Node/Python já identificam `DiMMA`. Confirme que o titular autoriza
  a distribuição pública sob MIT, incluindo nome e logótipo.
- [x] **Identidade pública:** o URL `https://github.com/diamantino-dimma/dimma-security`
  foi adicionado aos metadados npm/PyPI e aos READMEs dos pacotes.
- [x] **Disponibilidade observada:** em 2026-10-04, npm e PyPI responderam
  404 para `dimma-core` e `dimma`. Confirme de novo imediatamente antes de
  enviar e garanta que a versão `1.0.0` continua disponível.
- [ ] **Auditoria npm:** a verificação executada em 2026-10-04 reportou três
  alertas high transitivos (`http-proxy-middleware` → `micromatch` → `braces`).
  O hook `prepublishOnly` bloqueia `npm publish` enquanto o audit reportar
  high. A opção recomendada é corrigir por atualização compatível e testar.
  Uma aceitação formal do risco, por si só, não desbloqueia o hook: só altere
  essa política com aprovação explícita e registo da decisão. Não use
  `npm audit fix --force` sem rever o downgrade breaking que o audit propõe.
- [ ] **Teste JetBrains:** instale JDK 17 e Gradle, execute `gradle buildPlugin`
  em `extensions/jetbrains/`, instale o ZIP gerado num IDE de teste e confirme
  o ícone em `security.dimma`. Esta compilação/teste ainda não foi executada
  neste ambiente.
- [ ] **Âmbito de IDEs:** se “todos os IDEs” inclui o Visual Studio completo,
  falta implementar e testar uma extensão específica para ele. VS Code,
  Cursor e JetBrains têm caminhos separados descritos abaixo.
- [ ] **Credenciais:** ative MFA nas contas de publicação. Use login/keyring
  ou os segredos protegidos dos marketplaces; nunca grave tokens no código,
  nos ficheiros `.dimma`, em comandos versionados ou no histórico do terminal.

Os nomes do npm/PyPI responderem 404 não valida licença, metadados, testes,
publisher nem direito de publicação: é apenas uma consulta de disponibilidade
naquele momento. A publicação da extensão VS Code/Cursor ou do plugin
JetBrains é um lançamento separado e fica fora do objetivo atual.

## 1. Antes de criar uma versão

1. Confirme que tem direito a publicar o código, o logótipo e o nome `.dimma`.
2. Substitua `[COPYRIGHT HOLDER]` nos ficheiros `LICENSE` pela pessoa ou
   entidade titular dos direitos.
3. Substitua `your-publisher-id` em
   `extensions/vscode/package.json` pelo ID da sua conta do Marketplace.
4. Adicione os URLs reais do repositório e do projeto aos metadados dos
   pacotes, quando já tiver o URL público definitivo.
5. Escolha uma versão que ainda não exista nos registries e atualize em
   conjunto `dimma-core/package.json`, `dimma-core/package-lock.json`,
   `dimma-python/pyproject.toml`, `extensions/vscode/package.json` e
   `extensions/jetbrains/build.gradle.kts` mais
   `extensions/jetbrains/src/main/resources/META-INF/plugin.xml` para os
   artefactos que serão lançados. As versões podem evoluir independentemente
   depois da primeira publicação.
6. Revise `CHANGELOG.md` e o README de cada pacote. Não descreva o scanner
   como pentest ativo ou produto certificado: `dimma scan` é heurístico e
   estático.

## 2. Validar localmente

Na raiz do repositório, execute:

```powershell
npm --prefix .\dimma-core ci
npm --prefix .\dimma-core test
npm --prefix .\dimma-core audit --omit=dev
npm --prefix .\dimma-core pack --dry-run

Set-Location .\dimma-python
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe test\run_all.py
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pip install --upgrade build twine
.\.venv\Scripts\python.exe -m build
.\.venv\Scripts\python.exe -m twine check dist/*
Set-Location ..
```

Inspecione o conteúdo do `.tgz`, do `.whl` e do `.tar.gz` antes de enviar.
Confirme que incluem README e LICENSE, não incluem `.venv`, `node_modules`,
ficheiros `.env`, chaves ou artefactos de teste desnecessários.

**Bloqueio conhecido:** `npm audit --omit=dev` reportou três vulnerabilidades
high na cadeia `http-proxy-middleware` → `micromatch` → `braces`. O `npm audit`
propõe uma alteração breaking com `--force`; não publique um release de
segurança com este alerta sem primeiro rever uma correção compatível ou
documentar formalmente a aceitação do risco.

## 3. Publicar no npm

1. Crie/verifique a conta npm e ative MFA para publicação.
2. No terminal, autentique-se e confirme a identidade:

   ```powershell
   npm login
   npm whoami
   ```

3. Volte à raiz e publique; o `prepublishOnly` executa os testes e bloqueia
   o envio se a auditoria encontrar vulnerabilidades high na árvore de
   produção:

   ```powershell
   npm publish --prefix .\dimma-core --access public
   ```

4. Verifique a página do pacote e faça uma instalação limpa num projeto de
   teste:

   ```powershell
   npm view dimma-core version
   npm install dimma-core express
   ```

Nunca coloque um token npm no repositório nem o inclua na linha de comando.
O lançamento permanece bloqueado pelo audit até os alertas high serem
resolvidos e os testes repetidos com sucesso.

## 4. Publicar no PyPI

1. Crie uma conta separada em [TestPyPI](https://test.pypi.org/account/register/)
   e confirme o endereço de email. TestPyPI é o ambiente de teste; a conta e
   os tokens não são os mesmos do PyPI oficial.
2. Em TestPyPI, abra **Account settings → API tokens** e crie um token para
   upload. Como o projeto ainda não existe no índice, poderá ser necessário
   um token com âmbito da conta. Guarde-o num gestor de segredos.
3. Gere e valide os artefactos conforme a secção 2. A versão precisa estar
   disponível em TestPyPI; não é possível substituir uma versão já enviada.
4. Publique primeiro em TestPyPI:

   ```powershell
   Set-Location .\dimma-python
   .\.venv\Scripts\python.exe -m twine upload --repository testpypi dist/*
   ```

   Quando solicitado, use `__token__` como nome de utilizador e cole o token
   TestPyPI como senha. Nunca o incluas na linha de comando, num ficheiro
   versionado ou nesta conversa.

5. Verifique que a versão aparece em
   [TestPyPI](https://test.pypi.org/project/dimma/) e teste a instalação num
   ambiente virtual descartável. O índice oficial é usado para dependências:

   ```powershell
   .\.venv\Scripts\python.exe -m venv "$env:TEMP\dimma-testpypi-venv"
   & "$env:TEMP\dimma-testpypi-venv\Scripts\python.exe" -m pip install `
     --index-url https://test.pypi.org/simple/ `
     --extra-index-url https://pypi.org/simple/ "dimma==1.0.0"
   & "$env:TEMP\dimma-testpypi-venv\Scripts\python.exe" -m pip show dimma
   ```

6. Só depois do teste, crie/confirme a conta PyPI oficial em
   [pypi.org/account/register](https://pypi.org/account/register/), ative MFA,
   e crie um token separado para o PyPI. Confirme imediatamente antes de
   enviar que `dimma==1.0.0` continua disponível.
7. Envie os mesmos artefactos já testados para PyPI oficial; Twine pede as
   credenciais no terminal:

   ```powershell
   .\.venv\Scripts\python.exe -m twine upload dist/*
   ```

   Usa `__token__` e o token PyPI (não o de TestPyPI) nas solicitações.
8. Verifique a página do projeto e teste a instalação oficial:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install dimma
   ```

Nunca publique tokens, nem os grave no histórico do PowerShell ou em ficheiros
versionados. Se os tokens ficarem comprometidos, revogue-os imediatamente.

## 5. Distribuir o ícone no VS Code

1. Crie um publisher no Visual Studio Marketplace e substitua
   `your-publisher-id` em `extensions/vscode/package.json`.
2. Instale/execute `@vscode/vsce` e empacote:

   ```powershell
   Set-Location .\extensions\vscode
   npx --yes @vscode/vsce package
   ```

3. Instale o `.vsix` localmente no VS Code, selecione **Dimma File Icons** e
   confirme tanto `security.dimma` como outros ficheiros `*.dimma`.
4. Para listar no Marketplace, autentique `vsce` usando o publisher correto
   e publique só depois da validação:

   ```powershell
   npx --yes @vscode/vsce publish
   ```

O tema autónomo substitui o tema de ícones ativo. Para continuar a usar
Material Icon Theme, configure a associação personalizada nas definições do
utilizador conforme descrito no README principal.

### Publicar para Cursor (Open VSX)

Cursor usa o Open VSX para extensões de terceiros; publicar apenas no Visual
Studio Marketplace não garante que a extensão apareça no Cursor. Crie/confirme
o publisher no Open VSX, use o mesmo ID de publisher do `package.json`, gere
o `.vsix` com `@vscode/vsce package` e carregue esse artefacto no portal oficial
do [Open VSX](https://open-vsx.org/). Depois de a publicação ser indexada,
procure `Dimma File Icons` no painel Extensions do Cursor e confirme
`security.dimma`. Consulte a documentação de
[extensões do Cursor](https://cursor.com/help/customization/extensions).

## 6. Distribuir no IntelliJ IDEA e IDEs JetBrains

O plugin independente em `extensions/jetbrains/` regista `.dimma` como tipo
de ficheiro e usa o SVG do escudo. Requer JDK 17 e Gradle compatível com o
Gradle Plugin da IntelliJ Platform configurado no projeto.

```powershell
Set-Location .\extensions\jetbrains
gradle buildPlugin
```

O ZIP instalável é gerado em `build\distributions\`. Antes de publicar,
instale-o pelo **Settings | Plugins | ⚙ | Install Plugin from Disk...** numa
instalação de teste do IntelliJ IDEA e confirme `security.dimma` e outros
ficheiros `.dimma`. Para o JetBrains Marketplace, crie uma conta de publisher,
confirme que o ID `com.dimma.fileicons` está disponível e siga o processo de
upload do Marketplace. Não publique antes de validar o ZIP no IDE e confirmar
o titular legal dos direitos.

## 7. Visual Studio (IDE completo)

A extensão VS Code/Cursor não funciona no Visual Studio completo. Essa
integração requer um VSIX independente com suporte próprio de editor/tipo de
ficheiro e validação na versão do Visual Studio que será suportada. Não há
instrução de instalação para esse IDE até esse VSIX ser implementado e
testado.

## 8. Depois da publicação

- Teste instalação em ambiente limpo para cada registry e em cada runtime
  que declarar suportado.
- Verifique os artefactos e a página pública; confirme que a documentação
  não revela segredos nem apresenta o scanner como DAST.
- Crie uma tag de release correspondente ao código publicado e publique
  notas de versão.
- Mantenha MFA e tokens de publicação protegidos; prefira trusted publishing
  por OIDC quando o registry e o pipeline estiverem configurados para isso.
- O workflow `.github/workflows/ci.yml` testa Node.js e Python e valida os
  artefactos Python em pull requests/pushes; não publica automaticamente.
