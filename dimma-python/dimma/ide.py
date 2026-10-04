"""Opt-in installation of the bundled editor icon theme."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from importlib import resources
from stat import S_IMODE


EDITOR_COMMANDS = {"vscode": "code", "cursor": "cursor"}
ICON_THEME = "dimma-file-icons"


def _resolve_editor_command(editor: str) -> str:
    command_name = EDITOR_COMMANDS[editor]
    executable = shutil.which(command_name)
    if executable is None:
        raise RuntimeError(
            f'Nao encontrei o comando "{command_name}" no PATH. '
            f'Instale o editor ou adicione o respetivo CLI ao PATH.'
        )

    if sys.platform == "win32" and os.path.splitext(executable)[1].lower() in (".cmd", ".bat"):
        executable_name = "Code.exe" if editor == "vscode" else "Cursor.exe"
        directory = os.path.dirname(os.path.abspath(executable))
        for _ in range(6):
            candidate = os.path.join(directory, executable_name)
            if os.path.isfile(candidate):
                return candidate
            parent = os.path.dirname(directory)
            if parent == directory:
                break
            directory = parent
        raise RuntimeError(
            f'Encontrei "{executable}", mas nao o executavel {executable_name}. '
            "Use o CLI do editor diretamente para instalar o VSIX."
        )

    return executable


def _available_editor_commands() -> dict:
    available = {}
    for editor, command_name in EDITOR_COMMANDS.items():
        if shutil.which(command_name) is not None:
            available[editor] = _resolve_editor_command(editor)
    return available


def _read_workspace_settings(settings_path: str) -> dict:
    if not os.path.exists(settings_path):
        return {}
    try:
        with open(settings_path, "r", encoding="utf-8") as settings_file:
            settings = json.load(settings_file)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"Nao foi possivel ler {settings_path} como JSON valido; "
            "nenhuma definicao foi alterada. Ative manualmente "
            f'"{ICON_THEME}" em workbench.iconTheme. Detalhe: {error}'
        ) from error
    if not isinstance(settings, dict):
        raise RuntimeError(
            f"{settings_path} deve conter um objeto JSON; nenhuma definicao foi alterada."
        )
    return settings


def _write_workspace_settings(settings_path: str, settings: dict) -> None:
    directory = os.path.dirname(settings_path)
    os.makedirs(directory, exist_ok=True)
    original_mode = (
        S_IMODE(os.stat(settings_path).st_mode)
        if os.path.exists(settings_path)
        else None
    )
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=directory,
            prefix=".dimma-settings-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name
            json.dump(settings, temporary_file, ensure_ascii=False, indent=2)
            temporary_file.write("\n")
        if original_mode is not None:
            os.chmod(temporary_path, original_mode)
        os.replace(temporary_path, settings_path)
    except OSError:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)
        raise


def install_styles(args=None) -> None:
    args = args or []
    if args:
        raise RuntimeError("Uso: dimma styles")
    workspace = os.path.abspath(os.getcwd())
    settings_directory = os.path.join(workspace, ".vscode")
    settings_path = os.path.join(settings_directory, "settings.json")
    if os.path.islink(settings_directory) or os.path.islink(settings_path):
        raise RuntimeError(
            "Por seguranca, nao altero .vscode/settings.json quando .vscode "
            "ou settings.json e um link simbolico."
        )
    _read_workspace_settings(settings_path)
    editors = _available_editor_commands()
    if not editors:
        raise RuntimeError(
            "Nao encontrei o CLI de VS Code (code) nem Cursor (cursor) no PATH. "
            "Instale o editor ou adicione o respetivo CLI ao PATH."
        )

    with resources.as_file(
        resources.files("dimma").joinpath("assets").joinpath("dimma-file-icons.vsix")
    ) as extension_path:
        if not os.path.isfile(extension_path):
            raise RuntimeError("O pacote Dimma nao contem o VSIX da extensao de icones.")
        for editor, executable in editors.items():
            result = subprocess.run(
                [executable, "--install-extension", str(extension_path)],
                cwd=workspace,
                check=False,
                shell=False,
            )
            if result.returncode:
                raise RuntimeError(
                    f"A instalacao da extensao em {editor} falhou "
                    f"(codigo {result.returncode}); as definicoes do workspace "
                    "nao foram alteradas."
                )

    latest_settings = _read_workspace_settings(settings_path)
    latest_settings["workbench.iconTheme"] = ICON_THEME
    _write_workspace_settings(settings_path, latest_settings)
    print(
        f"[dimma] Extensao instalada em {', '.join(editors)}; tema {ICON_THEME} "
        f"ativado em {os.path.relpath(settings_path, workspace)}."
    )
