# Checklist de publicação do `.dimma`

Este projeto publica artefactos independentes:

| Artefacto | Registry/distribuição | Nome configurado |
|---|---|---|
| Motor Node.js | npm | `dimma` |
| Motor Python | PyPI | `dimma` |
| Tema de ícones VS Code/Cursor | Visual Studio Marketplace e Open VSX | `dimma-file-icons` |
| Tipo de ficheiro JetBrains | JetBrains Marketplace ou ZIP | `dimma-jetbrains-file-icons` |

Publicar um pacote não publica os outros nem instala um tema de ícones no IDE.
O Visual Studio (IDE completo) ainda não tem uma extensão Dimma própria.
Em 2026-10-04, `dimma==1.0.0` foi publicado no PyPI. Em 2026-10-04, consultas
sem autenticação ao npm devolveram `E404` para `dimma` e `dimma-core`; isto
não confirma a disponibilidade do nome para publicação pela conta autenticada.
Confirme novamente antes de publicar.

## Estado antes de publicar no npm

Os metadados locais já apontam para o repositório público e identificam
`DiMMA` como autor/titular.

- [x] **Titular/licença:** a pedido do titular, os avisos de copyright dos
  pacotes Node/Python já identificam `DiMMA`. Confirme que o titular autoriza
  a distribuição pública sob MIT, incluindo nome e logótipo.
- [x] **Identidade pública:** o URL `https://github.com/diamantino-dimma/dimma-security`
  foi adicionado aos metadados npm/PyPI e aos READMEs dos pacotes.
- [x] **Auditoria npm:** `prepublishOnly` e CI mantêm o nível `high` com
  `better-npm-audit` e excluem apenas `GHSA-vfj7-8cjw-p6xm`, documentada em
  `dimma-core/SECURITY_EXCEPTIONS.md`. Remova a exceção quando houver fix
  upstream; não use `npm audit fix --force` sem rever o downgrade breaking.
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

O pacote Python já está publicado; os passos dele abaixo ficam como referência
para releases futuros. A publicação da extensão VS Code/Cursor ou do plugin
JetBrains é separada e fica fora do objetivo atual.

## 1. Antes de criar uma versão

1. Confirme que DiMMA detém ou tem autorização para publicar o código, o
   logótipo e o nome, e que a licença MIT representa essa decisão.
2. Confirme que o nome e a versão estão disponíveis no registry de destino.
   Não tente reenviar uma versão já publicada; aumente a versão e reconstrua
   os artefactos para um release futuro.
3. Mantenha as versões dos pacotes independentes: atualize
   `dimma-core/package.json` e o lockfile para npm; atualize
   `dimma-python/pyproject.toml` para PyPI.
4. Revise `CHANGELOG.md` e o README de cada pacote. Não descreva o scanner
   como pentest ativo ou produto certificado: `dimma scan` é heurístico e
   estático.

## 2. Validar localmente

Na raiz do repositório, execute:

```powershell
npm --prefix .\dimma-core ci
npm --prefix .\dimma-core test
npm --prefix .\dimma-core exec -- better-npm-audit audit --production --level high --exclude GHSA-vfj7-8cjw-p6xm
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

**Exceção conhecida:** o audit npm ainda reporta a advisory high
`GHSA-vfj7-8cjw-p6xm` na cadeia `http-proxy-middleware` → `micromatch` →
`braces`. O gate exclui somente essa GHSA e continua a bloquear outras
advisories high/critical. Reveja `dimma-core/SECURITY_EXCEPTIONS.md`.

## 3. Publicar no npm

1. Crie/verifique a conta npm, confirme que `dimma` está disponível para a
   conta e ative MFA para publicação. A consulta pública E404 não é garantia
   de disponibilidade para essa conta.
2. No terminal, autentique-se e confirme a identidade:

   ```powershell
   npm login
   npm whoami
   ```

3. Volte à raiz e publique como pacote público; o `prepublishOnly` executa os
    testes e bloqueia o envio se a auditoria encontrar outras vulnerabilidades
    high na árvore de produção:

   ```powershell
   npm publish --prefix .\dimma-core --access public
   ```

4. Verifique a página do pacote e faça uma instalação limpa num projeto de
   teste:

   ```powershell
   npm view dimma version
   npm install dimma express
   ```

Nunca coloque um token npm no repositório nem o inclua na linha de comando.
O pacote `dimma` é unscoped e público; npm documenta a publicação de pacotes
unscoped públicos sem exigir um plano pago. `--access public` deixa a intenção
explícita.

## 4. PyPI — já publicado

O pacote `dimma==1.0.0` já está publicado: [PyPI](https://pypi.org/project/dimma/).
Foi instalado num ambiente virtual temporário limpo e o comando `dimma --help`
foi verificado. A instalação para utilizadores é:

```powershell
python -m pip install dimma
dimma init
```

O workflow `.github/workflows/publish-pypi.yml` usa Trusted Publishing (OIDC),
sem guardar um token PyPI no GitHub, e pode ser usado para versões futuras.
Não o executes novamente para a versão `1.0.0`; o PyPI não permite substituir
os ficheiros dessa versão.

### Trusted Publisher configurado

O publisher foi configurado no PyPI e usado com sucesso. Os valores
configurados foram:

| Campo no PyPI | Valor |
|---|---|
| PyPI Project Name | `dimma` |
| Owner | `diamantino-dimma` |
| Repository name | `dimma-security` |
| Workflow name | `publish-pypi.yml` |
| Environment name | `pypi` |

O repositório contém `.github/workflows/publish-pypi.yml` e o ambiente `pypi`
está criado em **Settings → Environments**. O nome do workflow registado no
PyPI é o nome do ficheiro dentro de `.github/workflows/`, não o título
apresentado no GitHub Actions. O upload da versão `1.0.0` confirmou que os
valores OIDC estão alinhados.

### Testar e publicar

1. Para um release futuro, escolhe uma versão nova em
   `dimma-python/pyproject.toml`; não reutilizes `1.0.0`.
2. Antes do release, executa localmente as verificações da secção 2.
   O workflow repetirá as suites Python, construirá wheel/sdist e executará
   `twine check` antes de solicitar a publicação.
3. Confirma que a versão nova nunca foi publicada no PyPI.
4. Cria e publica uma GitHub Release com tag correspondente à versão. Isso
   inicia `Publish Python package to PyPI`. Para uma tentativa falhada, abre
   **Actions → Publish Python package to PyPI → Run workflow**, escolhe `main`
   e executa uma única vez, depois de corrigir a causa. O workflow envia os
   artefactos de `dimma-python/dist/`.
5. Acompanha **Actions** no GitHub. Se uma tentativa falhar, lê o passo
   vermelho antes de repetir; não faças várias execuções simultâneas. Só
   declares o release concluído quando o
   job tiver terminado com sucesso e a página
   [pypi.org/project/dimma](https://pypi.org/project/dimma/) mostrar a versão.
6. Testa a instalação da nova versão num ambiente limpo:

   ```powershell
   py -m venv "$env:TEMP\dimma-release-check"
   & "$env:TEMP\dimma-release-check\Scripts\python.exe" -m pip install "dimma==<NOVA_VERSAO>"
   & "$env:TEMP\dimma-release-check\Scripts\python.exe" -m pip show dimma
   ```

TestPyPI é um índice separado e opcional. Para o utilizar, cria lá uma conta e
configura um publisher OIDC e workflow que enviem explicitamente para
TestPyPI; a configuração de produção deste repositório aponta para PyPI.

OIDC evita tokens de publicação de longa duração. Nunca adiciones segredos
PyPI ao workflow nem ao repositório. Para detalhes oficiais, consulta
[Trusted Publishers](https://docs.pypi.org/trusted-publishers/).

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
