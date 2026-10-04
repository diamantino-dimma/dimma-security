"""Opt-in installation of the .dimma language extension."""
import os
import shutil
import subprocess
import sys
from importlib import resources


EDITOR_COMMANDS = {"vscode": "code", "cursor": "cursor", "vscodium": "codium"}


def _resolve_editor_command(editor: str) -> str:
    command_name = EDITOR_COMMANDS[editor]
    executable = shutil.which(command_name)
    if executable is None:
        raise RuntimeError(
            f'Nao encontrei o comando "{command_name}" no PATH. '
            f'Instale o editor ou adicione o respetivo CLI ao PATH.'
        )

    if sys.platform == "win32" and os.path.splitext(executable)[1].lower() in (".cmd", ".bat"):
        executable_name = {
            "vscode": "Code.exe",
            "cursor": "Cursor.exe",
            "vscodium": "VSCodium.exe",
        }[editor]
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


def install_styles(args=None) -> None:
    args = args or []
    if args:
        raise RuntimeError("Uso: dimma styles")
    workspace = os.path.abspath(os.getcwd())
    editors = _available_editor_commands()
    if not editors:
        raise RuntimeError(
            "Nao encontrei o CLI de VS Code (code), Cursor (cursor) nem "
            "VSCodium (codium) no PATH. "
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
                    f"(codigo {result.returncode})."
                )

    print(
        f"[dimma] Extensao de linguagem instalada em {', '.join(editors)}. "
        "O realce aplica-se a ficheiros .dimma; as definicoes e o tema de "
        "icones ativo foram preservados."
    )
