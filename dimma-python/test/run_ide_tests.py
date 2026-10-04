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
    settings_dir = os.path.join(workspace, ".vscode")
    os.makedirs(settings_dir)
    if settings is not None:
        with open(os.path.join(settings_dir, "settings.json"), "w", encoding="utf-8") as file:
            json.dump(settings, file)
    return workspace


def read_settings(workspace):
    with open(os.path.join(workspace, ".vscode", "settings.json"), encoding="utf-8") as file:
        return json.load(file)


def _t_installs_all_detected_editors_and_merges_settings():
    workspace = make_workspace({"files.exclude": {"build": True}, "workbench.iconTheme": "old-theme"})
    calls = []
    with mock.patch.object(ide.os, "getcwd", return_value=workspace), \
         mock.patch.object(ide, "_available_editor_commands", return_value={"vscode": "code.exe", "cursor": "cursor.exe"}), \
         mock.patch.object(ide.subprocess, "run", side_effect=lambda args, **kwargs: calls.append((args, kwargs)) or mock.Mock(returncode=0)):
        ide.install_styles()
    settings = read_settings(workspace)
    assert settings["files.exclude"] == {"build": True}
    assert settings["workbench.iconTheme"] == "dimma-file-icons"
    assert len(calls) == 2
    assert calls[0][0][1] == "--install-extension"
    assert calls[1][0][1] == "--install-extension"
    assert calls[0][1]["shell"] is False


def _t_malformed_settings_fails_before_install():
    workspace = make_workspace()
    settings_path = os.path.join(workspace, ".vscode", "settings.json")
    with open(settings_path, "w", encoding="utf-8") as file:
        file.write("{ // comment\n}")
    with mock.patch.object(ide.os, "getcwd", return_value=workspace), \
         mock.patch.object(ide, "_available_editor_commands", return_value={"vscode": "code.exe"}), \
         mock.patch.object(ide.subprocess, "run") as run:
        try:
            ide.install_styles()
        except RuntimeError:
            pass
        else:
            raise AssertionError("invalid JSON should be rejected")
    run.assert_not_called()
    with open(settings_path, encoding="utf-8") as file:
        assert file.read() == "{ // comment\n}"


def _t_failed_extension_install_keeps_settings_unchanged():
    workspace = make_workspace({"workbench.colorTheme": "existing"})
    with mock.patch.object(ide.os, "getcwd", return_value=workspace), \
         mock.patch.object(ide, "_available_editor_commands", return_value={"cursor": "cursor.exe"}), \
         mock.patch.object(ide.subprocess, "run", return_value=mock.Mock(returncode=1)):
        try:
            ide.install_styles()
        except RuntimeError:
            pass
        else:
            raise AssertionError("failed extension install should be reported")
    assert read_settings(workspace) == {"workbench.colorTheme": "existing"}


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
    assert read_settings(workspace) == {"files.exclude": {"build": True}}


test("instala em todos os editores detetados e preserva as restantes definicoes", _t_installs_all_detected_editors_and_merges_settings)
test("recusa settings invalidos sem tentar instalar a extensao", _t_malformed_settings_fails_before_install)
test("nao altera settings se a instalacao da extensao falhar", _t_failed_extension_install_keeps_settings_unchanged)
test("reporta ausencia de editores sem alterar as definicoes", _t_no_detected_editor_fails_without_writing_settings)

for workspace in workspaces:
    shutil.rmtree(workspace, ignore_errors=True)

print(f"\n{passed} passaram, {failed} falharam\n")
raise SystemExit(1 if failed else 0)
