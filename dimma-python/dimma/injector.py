"""Conservative source injection for module-level Flask applications."""
import ast
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


MARKER = "# [dimma-injected]"


def _flask_app_name(tree: ast.Module) -> Optional[str]:
    flask_classes: Set[str] = set()
    flask_modules: Set[str] = set()

    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "flask":
            for alias in node.names:
                if alias.name == "Flask":
                    flask_classes.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "flask":
                    flask_modules.add(alias.asname or alias.name.split(".")[0])

    app_names: List[str] = []
    for node in tree.body:
        targets: List[ast.expr] = []
        value: Optional[ast.expr] = None
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value

        if value is None or not isinstance(value, ast.Call):
            continue
        is_flask_call = (
            isinstance(value.func, ast.Name) and value.func.id in flask_classes
        ) or (
            isinstance(value.func, ast.Attribute)
            and value.func.attr == "Flask"
            and isinstance(value.func.value, ast.Name)
            and value.func.value.id in flask_modules
        )
        if not is_flask_call:
            continue

        app_names.extend(
            target.id for target in targets if isinstance(target, ast.Name)
        )

    if len(app_names) == 1:
        return app_names[0]
    return None


def _unique_name(base: str, used_names: Set[str]) -> str:
    name = base
    suffix = 1
    while name in used_names:
        name = f"{base}_{suffix}"
        suffix += 1
    used_names.add(name)
    return name


def _injected_source(source: str, config_path: Path, file_path: Path) -> Dict[str, Any]:
    if MARKER in source:
        return {"injected": False, "reason": "dimma ja esta injetado neste ficheiro."}

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError as error:
        return {
            "injected": False,
            "reason": f"ficheiro Python invalido na linha {error.lineno}: {error.msg}.",
        }

    app_name = _flask_app_name(tree)
    if app_name is None:
        return {
            "injected": False,
            "reason": (
                "nao foi possivel localizar exatamente uma aplicacao Flask "
                "criada no modulo; nenhum ficheiro foi alterado."
            ),
        }

    used_names = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.alias):
            used_names.add(node.asname or node.name.split(".")[0])
    engine_name = _unique_name("_DimmaEngine", used_names)
    path_name = _unique_name("_DimmaPath", used_names)
    instance_name = _unique_name("_dimma", used_names)

    relative_config = os.path.relpath(config_path, file_path.parent).replace("\\", "/")
    injection = [
        MARKER,
        f"from dimma.engine import DimmaEngine as {engine_name}",
        f"from pathlib import Path as {path_name}",
        (
            f"{instance_name} = {engine_name}("
            f"str({path_name}(__file__).resolve().parent / {relative_config!r}))"
        ),
        f"{instance_name}.protect({app_name})",
        MARKER,
        "",
    ]

    newline = "\r\n" if "\r\n" in source else "\n"
    lines = source.splitlines(keepends=True)
    main_guard_line = next(
        (
            node.lineno - 1
            for node in tree.body
            if isinstance(node, ast.If) and _is_main_guard(node.test)
        ),
        len(lines),
    )
    if main_guard_line == len(lines):
        run_line = next(
            (
                node.lineno - 1
                for node in tree.body
                if _contains_app_run(node, app_name)
            ),
            len(lines),
        )
        main_guard_line = run_line
    block = newline.join(injection)

    if main_guard_line == len(lines):
        separator = "" if not source or source.endswith(("\n", "\r")) else newline
        updated_source = f"{source}{separator}{block}"
    else:
        lines.insert(main_guard_line, f"{block}{newline}")
        updated_source = "".join(lines)

    return {
        "injected": True,
        "source": updated_source,
        "app_name": app_name,
    }


def _is_main_guard(test: ast.expr) -> bool:
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq) or len(test.comparators) != 1:
        return False
    left, right = test.left, test.comparators[0]
    return (
        isinstance(left, ast.Name)
        and left.id == "__name__"
        and isinstance(right, ast.Constant)
        and right.value == "__main__"
    ) or (
        isinstance(right, ast.Name)
        and right.id == "__name__"
        and isinstance(left, ast.Constant)
        and left.value == "__main__"
    )


def _contains_app_run(node: ast.AST, app_name: str) -> bool:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
        return False
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == app_name
    ):
        return True
    return any(_contains_app_run(child, app_name) for child in ast.iter_child_nodes(node))


def inject_file(
    file_path: Path,
    config_path: Path,
    dry_run: bool = False,
) -> Dict[str, Any]:
    if file_path.suffix.lower() != ".py":
        return {
            "file": str(file_path),
            "injected": False,
            "reason": "extensao nao suportada (o injector Python aceita apenas .py).",
        }

    try:
        original_bytes = file_path.read_bytes()
        source = original_bytes.decode("utf-8-sig")
    except (OSError, UnicodeError) as error:
        return {
            "file": str(file_path),
            "injected": False,
            "error": f"nao foi possivel ler o ficheiro: {error}",
        }

    result = _injected_source(source, config_path, file_path)
    if not result["injected"]:
        return {"file": str(file_path), **result}
    if dry_run:
        return {
            "file": str(file_path),
            "injected": True,
            "dry_run": True,
            "app_name": result["app_name"],
        }

    backup_path = Path(f"{file_path}.dimma.bak")
    try:
        with backup_path.open("xb") as backup:
            backup.write(original_bytes)
            backup.flush()
            os.fsync(backup.fileno())
    except OSError as error:
        return {
            "file": str(file_path),
            "injected": False,
            "error": f"nao foi possivel criar backup sem sobrescrever um existente: {error}",
        }

    temporary_path: Optional[str] = None
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{file_path.name}.", suffix=".dimma-tmp", dir=file_path.parent
        )
        with os.fdopen(descriptor, "wb") as temporary:
            encoding_prefix = b"\xef\xbb\xbf" if original_bytes.startswith(b"\xef\xbb\xbf") else b""
            temporary.write(encoding_prefix + result["source"].encode("utf-8"))
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_path, stat.S_IMODE(file_path.stat().st_mode))
        os.replace(temporary_path, file_path)
    except OSError as error:
        return {
            "file": str(file_path),
            "injected": False,
            "error": f"nao foi possivel concluir a injecao: {error}; backup preservado em \"{backup_path}\".",
        }
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)

    return {
        "file": str(file_path),
        "injected": True,
        "backup": str(backup_path),
        "app_name": result["app_name"],
    }


def inject_all(
    files: List[str],
    config_path: Path,
    cwd: Optional[Path] = None,
    dry_run: bool = False,
) -> List[Dict[str, Any]]:
    root = (cwd or Path.cwd()).resolve()
    config_path = config_path.resolve()
    results = []

    for configured_path in files:
        try:
            full_path = (root / configured_path).resolve()
        except (OSError, RuntimeError) as error:
            results.append({
                "file": str(root / configured_path),
                "injected": False,
                "error": f"nao foi possivel validar o caminho: {error}",
            })
            continue
        try:
            full_path.relative_to(root)
        except ValueError:
            results.append({
                "file": str(full_path),
                "injected": False,
                "error": "caminho fora do diretorio do projeto; nenhum ficheiro foi alterado.",
            })
            continue
        results.append(inject_file(full_path, config_path, dry_run=dry_run))

    return results


def _atomic_replace(file_path: Path, content: bytes, mode: int) -> None:
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{file_path.name}.", suffix=".dimma-tmp", dir=file_path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, file_path)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def eject_file(file_path: Path) -> Dict[str, Any]:
    backup_path = Path(f"{file_path}.dimma.bak")
    preserved_path = Path(f"{file_path}.dimma.eject.bak")
    try:
        current = file_path.read_bytes()
    except FileNotFoundError:
        current = None
    except OSError as error:
        return {"file": str(file_path), "ejected": False, "error": str(error)}

    try:
        original = backup_path.read_bytes()
    except FileNotFoundError:
        original = None
    except OSError as error:
        return {"file": str(file_path), "ejected": False, "error": str(error)}

    if original is not None:
        if current is not None and MARKER.encode("ascii") not in current:
            if current == original:
                try:
                    backup_path.unlink()
                except OSError as error:
                    return {
                        "file": str(file_path),
                        "ejected": False,
                        "error": f"ficheiro ja restaurado, mas nao foi possivel remover o backup: {error}",
                    }
                return {"file": str(file_path), "ejected": True, "method": "backup"}
            return {
                "file": str(file_path),
                "ejected": False,
                "error": "ficheiro atual sem marcador Dimma; backup preservado para evitar sobrescrever alteracoes.",
            }

        if current is not None:
            if preserved_path.exists():
                return {
                    "file": str(file_path),
                    "ejected": False,
                    "error": f'backup de seguranca ja existe em "{preserved_path}".',
                }
            try:
                with preserved_path.open("xb") as preserved:
                    preserved.write(current)
                    preserved.flush()
                    os.fsync(preserved.fileno())
            except OSError as error:
                return {
                    "file": str(file_path),
                    "ejected": False,
                    "error": f"nao foi possivel preservar o ficheiro atual: {error}",
                }

        try:
            mode = stat.S_IMODE(file_path.stat().st_mode) if current is not None else 0o600
            _atomic_replace(file_path, original, mode)
        except OSError as error:
            return {
                "file": str(file_path),
                "ejected": False,
                "error": f"nao foi possivel restaurar o backup: {error}",
            }
        try:
            backup_path.unlink()
        except OSError as error:
            return {
                "file": str(file_path),
                "ejected": False,
                "error": f"ficheiro restaurado; backup original ainda preservado: {error}",
            }
        return {
            "file": str(file_path),
            "ejected": True,
            "method": "backup",
            "preserved_current_file": str(preserved_path) if current is not None else None,
        }

    if current is None:
        return {
            "file": str(file_path),
            "ejected": False,
            "error": "ficheiro nao encontrado e nenhum backup disponivel.",
        }

    try:
        source = current.decode("utf-8-sig")
    except UnicodeError as error:
        return {"file": str(file_path), "ejected": False, "error": str(error)}
    marker_pattern = re.compile(
        r"(?m)^# \[dimma-injected\]\r?\n[\s\S]*?^# \[dimma-injected\]\r?\n?"
    )
    cleaned, count = marker_pattern.subn("", source, count=1)
    if count == 0:
        return {
            "file": str(file_path),
            "ejected": False,
            "error": "marcador Dimma nao encontrado; ficheiro nao foi alterado.",
        }

    try:
        mode = stat.S_IMODE(file_path.stat().st_mode)
        encoding_prefix = b"\xef\xbb\xbf" if current.startswith(b"\xef\xbb\xbf") else b""
        _atomic_replace(file_path, encoding_prefix + cleaned.encode("utf-8"), mode)
    except OSError as error:
        return {"file": str(file_path), "ejected": False, "error": str(error)}
    return {"file": str(file_path), "ejected": True, "method": "marker-removal"}


def eject_all(files: List[str], cwd: Optional[Path] = None) -> List[Dict[str, Any]]:
    root = (cwd or Path.cwd()).resolve()
    results = []
    for configured_path in files:
        try:
            full_path = (root / configured_path).resolve()
            full_path.relative_to(root)
        except (OSError, RuntimeError, ValueError) as error:
            results.append({
                "file": str(root / configured_path),
                "ejected": False,
                "error": (
                    "caminho fora do diretorio do projeto."
                    if isinstance(error, ValueError)
                    else f"nao foi possivel validar o caminho: {error}"
                ),
            })
            continue
        results.append(eject_file(full_path))
    return results
