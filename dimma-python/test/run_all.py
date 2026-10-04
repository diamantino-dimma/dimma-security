"""Run the complete Python test suite with the active interpreter."""
import os
import subprocess
import sys


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_SCRIPTS = (
    "run_tests.py",
    "run_scan_tests.py",
    "run_inject_tests.py",
    "run_security_parity_tests.py",
    "run_ide_tests.py",
    "run_webauthn_tests.py",
    "run_ai_tests.py",
)


def main() -> int:
    failed = []
    for script in TEST_SCRIPTS:
        print(f"\n=== {script} ===", flush=True)
        result = subprocess.run(
            [sys.executable, os.path.join(PROJECT_ROOT, "test", script)],
            cwd=PROJECT_ROOT,
            check=False,
        )
        if result.returncode:
            failed.append((script, result.returncode))

    if failed:
        print("\nSuites com falhas:")
        for script, returncode in failed:
            print(f"  {script}: exit code {returncode}")
        return 1

    print("\nTodas as suites Python passaram.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
