"""Tests for the explicit IDE extension installer."""
import json
import os
import shutil
import sys
import tempfile
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dimma import ide


passed = 0
failed = 0
workspaces = []


def test(name, fn):
    global passed, failed
    try:
        fn()
        passed += 1
        print(f"  OK  - {name}")
    except Exception as error:  # noqa: BLE001
        failed += 1
        print(f"FALHOU - {name}\n        {error}")


def make_workspace(settings=None):
    workspace = tempfile.mkdtemp(prefix="dimma-ide-")
    workspaces.append(workspace)
    if settings is not None:
        settings_dir = os.path.join(workspace, ".vscode")
        os.makedirs(settings_dir)
        with open(os.path.join(settings_dir, "settings.json"), "w", encoding="utf-8") as file:
            file.write(settings if isinstance(settings, str) else json.dumps(settings))
    return workspace


def _t_installs_detected_editors_and_preserves_workspace_settings():
    original_settings = '{"files.exclude":{"build":true},"workbench.iconTheme":"existing-theme"}'
    workspace = make_workspace(original_settings)
    settings_path = os.path.join(workspace, ".vscode", "settings.json")
    calls = []
    with mock.patch.object(ide.os, "getcwd", return_value=workspace), \
         mock.patch.object(ide, "_available_editor_commands", return_value={
             "vscode": "code.exe", "cursor": "cursor.exe", "vscodium": "codium.exe",
         }), \
         mock.patch.object(ide.subprocess, "run", side_effect=lambda args, **kwargs: calls.append((args, kwargs)) or mock.Mock(returncode=0)):
        ide.install_styles()
    with open(settings_path, encoding="utf-8") as file:
        assert file.read() == original_settings
    assert len(calls) == 3
    assert calls[0][0][1] == "--install-extension"
    assert calls[1][0][1] == "--install-extension"
    assert calls[2][0][1] == "--install-extension"
    assert calls[0][1]["shell"] is False


def _t_does_not_read_or_create_workspace_settings():
    workspace = make_workspace()
    settings_path = os.path.join(workspace, ".vscode", "settings.json")
    with mock.patch.object(ide.os, "getcwd", return_value=workspace), \
         mock.patch.object(ide, "_available_editor_commands", return_value={"vscode": "code.exe"}), \
         mock.patch.object(ide.subprocess, "run", return_value=mock.Mock(returncode=0)):
        ide.install_styles()
    assert not os.path.exists(settings_path)
    assert not os.path.exists(os.path.dirname(settings_path))


def _t_failed_extension_install_keeps_settings_unchanged():
    original_settings = '{ // keep JSONC untouched\n"workbench.iconTheme": "existing-theme"\n}'
    workspace = make_workspace(original_settings)
    with mock.patch.object(ide.os, "getcwd", return_value=workspace), \
         mock.patch.object(ide, "_available_editor_commands", return_value={"cursor": "cursor.exe"}), \
         mock.patch.object(ide.subprocess, "run", return_value=mock.Mock(returncode=1)):
        try:
            ide.install_styles()
        except RuntimeError:
            pass
        else:
            raise AssertionError("failed extension install should be reported")
    with open(os.path.join(workspace, ".vscode", "settings.json"), encoding="utf-8") as file:
        assert file.read() == original_settings


def _t_no_detected_editor_fails_without_writing_settings():
    workspace = make_workspace({"files.exclude": {"build": True}})
    with mock.patch.object(ide.os, "getcwd", return_value=workspace), \
         mock.patch.object(ide, "_available_editor_commands", return_value={}), \
         mock.patch.object(ide.subprocess, "run") as run:
        try:
            ide.install_styles()
        except RuntimeError as error:
            assert "Nao encontrei o CLI" in str(error)
        else:
            raise AssertionError("must report when no supported editor is available")
    run.assert_not_called()
    with open(os.path.join(workspace, ".vscode", "settings.json"), encoding="utf-8") as file:
        assert json.load(file) == {"files.exclude": {"build": True}}


test("instala VS Code, Cursor e VSCodium sem alterar as definicoes do workspace", _t_installs_detected_editors_and_preserves_workspace_settings)
test("nao le nem cria ficheiros de definicoes do workspace", _t_does_not_read_or_create_workspace_settings)
test("falha de instalacao mantem as definicoes, incluindo JSONC, intactas", _t_failed_extension_install_keeps_settings_unchanged)
test("reporta ausencia de editores sem alterar as definicoes", _t_no_detected_editor_fails_without_writing_settings)

for workspace in workspaces:
    shutil.rmtree(workspace, ignore_errors=True)

print(f"\n{passed} passaram, {failed} falharam\n")
raise SystemExit(1 if failed else 0)
