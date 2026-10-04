import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dimma.scan import scan_project, format_report

passed = 0
failed = 0


def test(name, fn):
    global passed, failed
    try:
        fn()
        passed += 1
        print(f"  OK  - {name}")
    except Exception as exc:  # noqa: BLE001
        failed += 1
        print(f"FALHOU - {name}\n        {exc}")


def make_temp_project(files: dict) -> str:
    d = tempfile.mkdtemp(prefix="dimma-scan-py-")
    for rel_path, content in files.items():
        full_path = os.path.join(d, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
    return d


def finding_ids(result):
    return [f["rule_id"] for f in result["findings"]]


print("\n== dimma scan Python (scanner de codigo inseguro) ==")


def _t_aws_key():
    d = make_temp_project({"a.js": 'const k = "AKIAABCDEFGHIJKLMNOP";'})
    result = scan_project(d)
    assert "hardcoded-aws-key" in finding_ids(result)
    shutil.rmtree(d)


def _t_secret_assignment():
    d = make_temp_project({"a.py": 'API_KEY = "sk_live_ABCDEFGH1234567890AB"'})
    result = scan_project(d)
    assert "hardcoded-secret-assignment" in finding_ids(result)
    shutil.rmtree(d)


def _t_sql_concat_js():
    d = make_temp_project({"a.js": 'const q = "SELECT * FROM users WHERE id = " + id;'})
    result = scan_project(d)
    assert "sql-string-concat-js" in finding_ids(result)
    shutil.rmtree(d)


def _t_sql_fstring_py():
    d = make_temp_project({"a.py": 'q = f"SELECT * FROM users WHERE id = {user_id}"'})
    result = scan_project(d)
    assert "sql-fstring-py" in finding_ids(result)
    shutil.rmtree(d)


def _t_eval_js():
    d = make_temp_project({"a.js": "eval(userInput);"})
    result = scan_project(d)
    assert "eval-usage-js" in finding_ids(result)
    shutil.rmtree(d)


def _t_eval_py():
    d = make_temp_project({"a.py": "exec(user_input)"})
    result = scan_project(d)
    assert "eval-usage-py" in finding_ids(result)
    shutil.rmtree(d)


def _t_command_injection_node():
    d = make_temp_project({"a.js": "require('child_process').exec('ls ' + dir);"})
    result = scan_project(d)
    assert "command-injection-node" in finding_ids(result)
    shutil.rmtree(d)


def _t_command_injection_node_destructured():
    d = make_temp_project({"a.js": "const { exec } = require('child_process');\nexec('ls ' + userDir);"})
    result = scan_project(d)
    assert "command-injection-node-destructured" in finding_ids(result)
    shutil.rmtree(d)


def _t_command_injection_py():
    d = make_temp_project({"a.py": "subprocess.run(cmd, shell=True)"})
    result = scan_project(d)
    assert "command-injection-py" in finding_ids(result)
    shutil.rmtree(d)


def _t_insecure_deserialization():
    d = make_temp_project({"a.py": "data = pickle.loads(raw_bytes)"})
    result = scan_project(d)
    assert "insecure-deserialization-py" in finding_ids(result)
    shutil.rmtree(d)


def _t_debug_mode_flask():
    d = make_temp_project({"a.py": 'app.run(host="0.0.0.0", debug=True)'})
    result = scan_project(d)
    assert "debug-mode-flask" in finding_ids(result)
    shutil.rmtree(d)


def _t_innerhtml():
    d = make_temp_project({"a.js": "el.innerHTML = userInput;"})
    result = scan_project(d)
    assert "innerhtml-assignment" in finding_ids(result)
    shutil.rmtree(d)


def _t_dangerously_set_innerhtml():
    d = make_temp_project({"a.jsx": "<div dangerouslySetInnerHTML={{__html: data}} />"})
    result = scan_project(d)
    assert "dangerously-set-innerhtml" in finding_ids(result)
    shutil.rmtree(d)


def _t_no_false_positive():
    d = make_temp_project({
        "a.js": "\n".join([
            "const apiKey = process.env.API_KEY;",
            'const query = "SELECT * FROM users WHERE id = ?";',
            "db.query(query, [id]);",
            "el.textContent = userInput;",
        ])
    })
    result = scan_project(d)
    assert len(result["findings"]) == 0
    shutil.rmtree(d)


def _t_ignores_ignored_dirs():
    d = make_temp_project({
        "node_modules/pacote/ruim.js": 'const k = "AKIAABCDEFGHIJKLMNOP";',
        ".git/ruim.js": 'const k = "AKIAABCDEFGHIJKLMNOP";',
        "src/bom.js": "const x = 1;",
    })
    result = scan_project(d)
    assert len(result["findings"]) == 0
    assert result["files_scanned"] == 1
    shutil.rmtree(d)


test("detecta chave AWS hardcoded", _t_aws_key)
test("detecta segredo generico hardcoded", _t_secret_assignment)
test("detecta SQL Injection por concatenacao (JS)", _t_sql_concat_js)
test("detecta SQL Injection por f-string (Python)", _t_sql_fstring_py)
test("detecta eval() em JS", _t_eval_js)
test("detecta exec()/eval() em Python", _t_eval_py)
test("detecta child_process.exec() direto", _t_command_injection_node)
test("detecta exec() desestruturado de child_process", _t_command_injection_node_destructured)
test("detecta subprocess com shell=True em Python", _t_command_injection_py)
test("detecta pickle.loads inseguro", _t_insecure_deserialization)
test("detecta debug=True no Flask", _t_debug_mode_flask)
test("detecta innerHTML com dado dinamico", _t_innerhtml)
test("detecta dangerouslySetInnerHTML no React", _t_dangerously_set_innerhtml)
test("nao gera falso positivo em codigo seguro", _t_no_false_positive)
test("ignora node_modules e .git", _t_ignores_ignored_dirs)


def _t_reports_incomplete_coverage():
    missing_dir = os.path.join(tempfile.gettempdir(), f"dimma-scan-missing-{os.getpid()}")
    result = scan_project(missing_dir)
    assert result["files_scanned"] == 0
    assert len(result["errors"]) == 1
    report = format_report(result)
    assert "Cobertura incompleta" in report
    assert "scan esta incompleto" in report


test("reporta erros de leitura como cobertura incompleta", _t_reports_incomplete_coverage)

print(f"\n{passed} passaram, {failed} falharam\n")
sys.exit(1 if failed else 0)
