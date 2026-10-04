"""Tests for the Python CLI source injector."""
import ast
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from dimma.injector import _injected_source, eject_all, inject_all, inject_file
from dimma.parser import parse_dimma


APP_SOURCE = (
    "from flask import Flask\n"
    "app = Flask(__name__)\n"
    "app.config['SECRET_KEY'] = 'configured-before-protection'\n"
    "@app.get('/')\n"
    "def index():\n"
    "    return 'ok'\n"
    "\n"
    "if __name__ == '__main__':\n"
    "    app.run()\n"
)


class InjectorTests(unittest.TestCase):
    def test_parser_reads_files_protect_list(self):
        config = parse_dimma("@files_protect: [app.py, src/server.py]")
        self.assertEqual(config.get("files_protect"), ["app.py", "src/server.py"])

    def test_dry_run_reports_injection_without_changing_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app_path = root / "app.py"
            config_path = root / "security.dimma"
            app_path.write_text(APP_SOURCE, encoding="utf-8")
            config_path.write_text("@files_protect: [app.py]\n", encoding="utf-8")

            results = inject_all(["app.py"], config_path, cwd=root, dry_run=True)

            self.assertTrue(results[0]["injected"])
            self.assertTrue(results[0]["dry_run"])
            self.assertEqual(app_path.read_text(encoding="utf-8"), APP_SOURCE)
            self.assertFalse(Path(f"{app_path}.dimma.bak").exists())

    def test_real_injection_is_valid_python_and_makes_exclusive_backup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app_path = root / "app.py"
            config_path = root / "security.dimma"
            app_path.write_text(APP_SOURCE, encoding="utf-8")
            config_path.write_text("@files_protect: [app.py]\n", encoding="utf-8")

            result = inject_file(app_path, config_path)

            updated = app_path.read_text(encoding="utf-8")
            ast.parse(updated)
            self.assertTrue(result["injected"])
            self.assertEqual(Path(result["backup"]).read_text(encoding="utf-8"), APP_SOURCE)
            self.assertLess(updated.index("app.config['SECRET_KEY']"), updated.index("_dimma.protect(app)"))
            self.assertLess(updated.index("_dimma.protect(app)"), updated.index("if __name__"))

            second_result = inject_file(app_path, config_path)
            self.assertFalse(second_result["injected"])
            self.assertEqual(Path(result["backup"]).read_text(encoding="utf-8"), APP_SOURCE)

    def test_injection_precedes_unprotected_module_level_app_run(self):
        source = "from flask import Flask\napp = Flask(__name__)\napp.run()\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app_path = root / "app.py"
            config_path = root / "security.dimma"
            app_path.write_text(source, encoding="utf-8")
            config_path.write_text("@files_protect: [app.py]\n", encoding="utf-8")

            result = inject_file(app_path, config_path, dry_run=True)

            self.assertTrue(result["injected"])
            generated = inject_all(["app.py"], config_path, cwd=root, dry_run=True)
            generated_source = app_path.read_text(encoding="utf-8")
            self.assertTrue(generated[0]["injected"])
            self.assertEqual(generated_source, source)
            injected_source = _injected_source(source, config_path, app_path)["source"]
            self.assertLess(injected_source.index(".protect(app)"), injected_source.index("app.run()"))

    def test_skips_non_python_files_without_modifying_them(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "server.txt"
            config_path = root / "security.dimma"
            target.write_text(APP_SOURCE, encoding="utf-8")
            config_path.write_text("@files_protect: [server.txt]\n", encoding="utf-8")

            result = inject_all(["server.txt"], config_path, cwd=root)[0]

            self.assertFalse(result["injected"])
            self.assertIn("apenas .py", result["reason"])
            self.assertEqual(target.read_text(encoding="utf-8"), APP_SOURCE)
            self.assertFalse(Path(f"{target}.dimma.bak").exists())

    def test_rejects_targets_outside_project_and_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            outside_app = Path(outside_dir) / "app.py"
            outside_app.write_text(APP_SOURCE, encoding="utf-8")
            config_path = root / "security.dimma"
            config_path.write_text("@files_protect: [../outside.py]\n", encoding="utf-8")

            escaped = inject_all(["../outside.py"], config_path, cwd=root)[0]
            self.assertIn("fora do diretorio", escaped["error"])
            self.assertEqual(outside_app.read_text(encoding="utf-8"), APP_SOURCE)

            link = root / "linked.py"
            try:
                link.symlink_to(outside_app)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks indisponiveis neste ambiente")
            linked = inject_all(["linked.py"], config_path, cwd=root)[0]
            self.assertIn("fora do diretorio", linked["error"])
            self.assertEqual(outside_app.read_text(encoding="utf-8"), APP_SOURCE)

    def test_cli_dry_run_accepts_flag_without_mutating_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app_path = root / "app.py"
            app_path.write_text(APP_SOURCE, encoding="utf-8")
            (root / "security.dimma").write_text(
                "@files_protect: [app.py]\n", encoding="utf-8"
            )
            environment = os.environ.copy()
            current_pythonpath = environment.get("PYTHONPATH")
            environment["PYTHONPATH"] = (
                str(PROJECT_ROOT)
                if not current_pythonpath
                else str(PROJECT_ROOT) + os.pathsep + current_pythonpath
            )

            result = subprocess.run(
                [sys.executable, "-m", "dimma.cli", "inject", "--dry-run"],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("(dry-run)", result.stdout)
            self.assertEqual(app_path.read_text(encoding="utf-8"), APP_SOURCE)
            self.assertFalse(Path(f"{app_path}.dimma.bak").exists())

    def test_eject_restores_original_and_preserves_post_injection_edits(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app_path = root / "app.py"
            config_path = root / "security.dimma"
            app_path.write_text(APP_SOURCE, encoding="utf-8")
            config_path.write_text("@files_protect: [app.py]\n", encoding="utf-8")
            inject_file(app_path, config_path)
            injected_source = app_path.read_text(encoding="utf-8") + "\n# user edit\n"
            app_path.write_text(injected_source, encoding="utf-8")

            result = eject_all(["app.py"], cwd=root)[0]

            self.assertTrue(result["ejected"])
            self.assertEqual(app_path.read_text(encoding="utf-8"), APP_SOURCE)
            self.assertEqual(
                Path(result["preserved_current_file"]).read_text(encoding="utf-8"),
                injected_source,
            )
            self.assertFalse(Path(f"{app_path}.dimma.bak").exists())

    def test_eject_refuses_to_restore_over_unmarked_changes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app_path = root / "app.py"
            backup_path = Path(f"{app_path}.dimma.bak")
            current = "independent user changes\n"
            backup = APP_SOURCE
            app_path.write_text(current, encoding="utf-8")
            backup_path.write_text(backup, encoding="utf-8")

            result = eject_all(["app.py"], cwd=root)[0]

            self.assertFalse(result["ejected"])
            self.assertEqual(app_path.read_text(encoding="utf-8"), current)
            self.assertEqual(backup_path.read_text(encoding="utf-8"), backup)


if __name__ == "__main__":
    unittest.main()
