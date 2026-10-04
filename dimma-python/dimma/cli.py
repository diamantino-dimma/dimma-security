"""CLI do dimma: comando global `dimma init` para projetos Python."""
import os
import sys
from pathlib import Path

from .template import DEFAULT_TEMPLATE as TEMPLATE
from .scan import scan_project, format_report
from .security.supply_chain import audit_supply_chain, format_supply_chain_report
from .security.pqc import check_pqc_readiness, format_pqc_report
from .security.ai import PROVIDERS, classify_with_ai
from .ide import install_styles
from .injector import eject_all, inject_all


def detect_stack(cwd: str) -> str:
    if os.path.exists(os.path.join(cwd, "manage.py")):
        return "django"
    if os.path.exists(os.path.join(cwd, "requirements.txt")) or os.path.exists(
        os.path.join(cwd, "pyproject.toml")
    ):
        return "python"
    if os.path.exists(os.path.join(cwd, "package.json")):
        return "node"
    return "desconhecida"


def init() -> None:
    cwd = os.getcwd()
    target = os.path.join(cwd, "security.dimma")

    if os.path.exists(target):
        print("security.dimma ja existe neste projeto. Nada foi sobrescrito.")
        return

    with open(target, "w", encoding="utf-8") as f:
        f.write(TEMPLATE)

    stack = detect_stack(cwd)
    print("security.dimma criado com sucesso.")
    print(f"Stack detectada: {stack}")

    if stack in ("python", "django"):
        print("\nProximo passo:")
        print("  pip install dimma")
        print("  from dimma.engine import DimmaEngine")
        print('  dimma = DimmaEngine("./security.dimma")')
        print("  dimma.protect(app)")
    elif stack == "node":
        print("\nProximo passo:")
        print("  npm install dimma")
    else:
        print("\nNao foi possivel detectar a stack automaticamente.")


def scan(args=None) -> None:
    args = args or []
    check_online = "--supply-chain-online" in args

    cwd = os.getcwd()
    result = scan_project(cwd)
    print(format_report(result))

    # Respeita @supply_chain_guard: false no security.dimma, se existir.
    supply_chain_enabled = True
    configuration_error = False
    dimma_path = os.path.join(cwd, "security.dimma")
    if os.path.exists(dimma_path):
        try:
            from .parser import parse_dimma
            with open(dimma_path, "r", encoding="utf-8") as f:
                dimma_config = parse_dimma(f.read())
            supply_chain_enabled = dimma_config.get("supply_chain_guard") is not False
        except (OSError, SyntaxError, UnicodeError) as exc:
            configuration_error = True
            print(
                f"[dimma] security.dimma invalido; supply-chain guard mantido ativo: {exc}",
                file=sys.stderr,
            )

    if supply_chain_enabled:
        supply_chain_result = audit_supply_chain(cwd, check_online=check_online)
    else:
        supply_chain_result = {
            "findings": [], "dependencies_checked": 0,
            "skipped": True, "reason": "desativado via @supply_chain_guard: false",
        }
    print(format_supply_chain_report(supply_chain_result))

    has_critical_or_high = any(
        f["severity"] in ("critical", "high") for f in result["findings"]
    ) or any(
        f["severity"] in ("critical", "high") for f in supply_chain_result.get("findings", [])
    )
    if has_critical_or_high or result.get("errors") or configuration_error:
        sys.exit(1)  # util para falhar um pipeline de CI


def pqc_check() -> None:
    result = check_pqc_readiness()
    print(format_pqc_report(result))


def inject(args=None) -> None:
    args = args or []
    dry_run = "--dry-run" in args
    positional = [arg for arg in args if not arg.startswith("--")]
    unsupported = [
        arg for arg in args if arg.startswith("--") and arg != "--dry-run"
    ]
    if unsupported or len(positional) > 1:
        details = unsupported or positional[1:]
        print(f"[dimma] Opcao(s) nao suportada(s): {', '.join(details)}", file=sys.stderr)
        print("Uso: dimma inject [security.dimma] [--dry-run]", file=sys.stderr)
        sys.exit(2)

    cwd = Path.cwd()
    config_path = (cwd / (positional[0] if positional else "security.dimma")).resolve()
    if not config_path.is_file():
        print(f'[dimma] Ficheiro nao encontrado: "{config_path}". Execute "dimma init" primeiro.', file=sys.stderr)
        sys.exit(1)

    try:
        from .parser import parse_dimma

        config = parse_dimma(config_path.read_text(encoding="utf-8-sig"))
    except (OSError, SyntaxError, UnicodeError) as error:
        print(f"[dimma] Nao foi possivel ler o ficheiro .dimma: {error}", file=sys.stderr)
        sys.exit(1)

    files = config.get("files_protect", [])
    if not isinstance(files, list) or not all(
        isinstance(file_path, str) and file_path.strip() for file_path in files
    ):
        print("[dimma] @files_protect deve ser uma lista de caminhos de ficheiros.", file=sys.stderr)
        sys.exit(1)
    if not files:
        print("[dimma] ERRO: @files_protect esta vazio.", file=sys.stderr)
        print("Adicione ao security.dimma, por exemplo:", file=sys.stderr)
        print("  @files_protect: [app.py]", file=sys.stderr)
        sys.exit(1)

    print("\n[dimma] A preparar injecao nos ficheiros de @files_protect...\n")
    if dry_run:
        print("  (modo dry-run - nenhum ficheiro sera alterado)\n")

    results = inject_all(files, config_path, cwd=cwd, dry_run=dry_run)
    injected = skipped = errors = 0
    for result in results:
        if result.get("error"):
            print(f"  X ERRO      {result['file']}: {result['error']}")
            errors += 1
        elif not result["injected"]:
            print(f"  - IGNORADO  {result['file']}: {result['reason']}")
            skipped += 1
        else:
            suffix = " (dry-run)" if result.get("dry_run") else f" (backup: {result['backup']})"
            print(f"  OK INJETADO {result['file']}{suffix}")
            injected += 1

    print(f"\n  {injected} injetado(s), {skipped} ignorado(s), {errors} erro(s)\n")
    if errors:
        sys.exit(1)


def eject(args=None) -> None:
    args = args or []
    if not args or any(arg.startswith("--") for arg in args):
        print("Uso: dimma eject <ficheiro.py> [mais_ficheiros.py ...]", file=sys.stderr)
        sys.exit(2)

    results = eject_all(args)
    failures = 0
    for result in results:
        if result["ejected"]:
            preserved = result.get("preserved_current_file")
            detail = f" (versao atual preservada em {preserved})" if preserved else ""
            print(f"  OK REMOVIDO {result['file']} ({result['method']}){detail}")
        else:
            print(f"  X ERRO {result['file']}: {result['error']}")
            failures += 1
    if failures:
        sys.exit(1)


def ai_check(args=None) -> None:
    args = args or []
    unsupported = [arg for arg in args if arg != "--test"]
    if unsupported:
        print(f"[dimma] Opcao(s) nao suportada(s): {', '.join(unsupported)}", file=sys.stderr)
        sys.exit(1)

    dimma_path = os.path.join(os.getcwd(), "security.dimma")
    if not os.path.exists(dimma_path):
        print('[dimma] security.dimma nao encontrado. Execute "dimma init" primeiro.', file=sys.stderr)
        sys.exit(1)

    try:
        from .parser import parse_dimma

        with open(dimma_path, "r", encoding="utf-8") as config_file:
            config = parse_dimma(config_file.read())
    except (OSError, SyntaxError, UnicodeError) as error:
        print(f"[dimma] Nao foi possivel ler security.dimma: {error}", file=sys.stderr)
        sys.exit(1)

    provider = config.get("ai_provider") or "nvidia"
    if not isinstance(provider, str) or not provider.strip():
        print("[dimma] ai_provider deve ser texto nao vazio.", file=sys.stderr)
        sys.exit(1)
    provider = provider.lower()
    definition = PROVIDERS.get(provider)
    if definition is None:
        print(f'[dimma] Provider invalido: "{provider}".', file=sys.stderr)
        sys.exit(1)

    model = (
        config.get("ai_model")
        or os.environ.get("DIMMA_AI_MODEL")
        or os.environ.get(definition["model_env"])
        or definition["default_model"]
    )
    if not isinstance(model, str) or not model.strip():
        print("[dimma] ai_model deve ser texto nao vazio.", file=sys.stderr)
        sys.exit(1)
    key_present = bool(os.environ.get(definition["key_env"]))
    print(f"[dimma] Provider configurado: {provider} ({definition['label']})")
    print(f"[dimma] Modelo: {model}")
    print(f"[dimma] {definition['key_env']}: {'presente' if key_present else 'ausente'}")

    if not key_present:
        sys.exit(1)

    if "--test" not in args:
        print("[dimma] Diagnostico local concluido. Use --test para enviar uma chamada ao provider.")
        return

    try:
        result = classify_with_ai(
            {
                "findings": [{"type": "connectivity_check"}],
                "rawInput": {"method": "GET", "path": "/__dimma/ai-check"},
            },
            provider=provider,
            model=model,
        )
        if result["malicious"] is None:
            raise RuntimeError(result["reason"])
        print("[dimma] Ligacao com o provider: OK")
    except (RuntimeError, ValueError) as error:
        print(f"[dimma] Ligacao com o provider: FALHOU ({error})", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    args = sys.argv[1:]
    command = args[0] if args else None

    if command == "init":
        init()
    elif command == "inject":
        inject(args[1:])
    elif command == "eject":
        eject(args[1:])
    elif command == "scan":
        scan(args[1:])
    elif command == "pqc-check":
        pqc_check()
    elif command == "ai-check":
        ai_check(args[1:])
    elif command == "styles":
        try:
            install_styles(args[1:])
        except (OSError, RuntimeError) as error:
            print(f"[dimma] Ativacao dos estilos falhou: {error}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Uso:")
        print("  dimma init        Cria um security.dimma na pasta atual e detecta a stack do projeto.")
        print("  dimma inject      Injeta protecoes Flask nos ficheiros de @files_protect (--dry-run simula).")
        print("    Uso: dimma inject [security.dimma] [--dry-run]")
        print("  dimma eject       Remove injecao Dimma e restaura o backup, se disponivel.")
        print("  dimma scan        Varre o codigo (padroes inseguros + supply_chain_guard).")
        print("    --supply-chain-online  tambem verifica pacotes recem-publicados no PyPI (rede)")
        print("  dimma pqc-check   Verifica se o runtime suporta troca de chaves TLS pos-quantica.")
        print("  dimma ai-check    Verifica a configuracao de IA (--test faz chamada externa).")
        print("  dimma styles      Instala realce .dimma em VS Code, Cursor ou VSCodium sem alterar settings.")


if __name__ == "__main__":
    main()
