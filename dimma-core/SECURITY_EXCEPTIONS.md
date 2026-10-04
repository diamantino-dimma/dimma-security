# Exceções temporárias de segurança

## GHSA-vfj7-8cjw-p6xm / CVE-2026-93687 (`braces`)

**Estado:** exceção temporária no audit de dependências de produção, revista em
2026-10-04.

A advisory reporta esgotamento de stack ao interpretar padrões de chavetas
profundamente aninhados. A árvore de dependências atual contém
`http-proxy-middleware` → `micromatch` → `braces@3.0.3`. Na data desta revisão,
o npm não disponibiliza uma versão corrigida de `braces`; a advisory identifica
`3.0.3` como afetada e não indica uma versão corrigida.

O proxy atual em `src/proxy.js` monta o middleware numa rota fixa (`/`) e não
define `pathFilter` glob, nem deriva um padrão de glob de input recebido. A
entrada HTTP é testada como caminho, não interpretada como padrão de chavetas.
Assim, a análise do uso atual não encontrou um caminho para acionar o caso
vulnerável a partir de um pedido externo. Esta avaliação é específica à
configuração atual e deve ser refeita se o middleware ou o filtro de rotas mudar.

Os gates continuam a falhar em advisories `high` ou superiores, exceto esta
GHSA específica. **Remover `GHSA-vfj7-8cjw-p6xm` de `--exclude`** no script
`prepublishOnly` e no workflow CI assim que uma versão corrigida de `braces`
estiver publicada; depois atualizar o lockfile, executar o audit sem exceção e
remover esta entrada. Rever manualmente esta exceção periodicamente, pois não
há verificação automática de disponibilidade do fix upstream.
