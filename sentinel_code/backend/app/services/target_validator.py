import ast
import os
import subprocess
import sys
import tempfile
from typing import Tuple


def validate_target_file(code_path: str) -> Tuple[bool, str]:
    """
    Perform a lightweight preflight validation before the sandbox boots.

    The target must:
    - exist and be a readable Python source file
    - parse successfully
    - import successfully in isolation
    - expose either a `handle` function or at least one module-defined function
    """
    if not code_path:
        return False, "Validation failed: No code path was provided."

    abs_path = os.path.abspath(code_path)

    if not os.path.exists(abs_path):
        return False, f"Validation failed: File not found: {abs_path}"

    if not os.path.isfile(abs_path):
        return False, f"Validation failed: Path is not a file: {abs_path}"

    if not abs_path.lower().endswith(".py"):
        return False, f"Validation failed: Unsupported file type. Expected a Python `.py` file, got: {abs_path}"

    try:
        with open(abs_path, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError as exc:
        return False, f"Validation failed: Could not read file: {exc}"

    try:
        ast.parse(source, filename=abs_path)
    except SyntaxError as exc:
        location = f"line {exc.lineno}" if exc.lineno else "unknown line"
        return False, f"Validation failed: Python syntax error at {location}: {exc.msg}"

    import_ok, import_error = _validate_import_and_entrypoint(abs_path)
    if not import_ok:
        return False, import_error

    return True, "Validation passed."


def _validate_import_and_entrypoint(code_path: str) -> Tuple[bool, str]:
    checker = """
import importlib.util
import inspect
import json
import sys

code_path = sys.argv[1]
spec = importlib.util.spec_from_file_location("sentinel_target_validation", code_path)
if spec is None or spec.loader is None:
    print(json.dumps({"ok": False, "error": "Validation failed: Could not build an import spec for the target file."}))
    raise SystemExit(0)

module = importlib.util.module_from_spec(spec)

try:
    spec.loader.exec_module(module)
except Exception as exc:
    print(json.dumps({"ok": False, "error": f"Validation failed: Target file could not be imported cleanly: {exc}"}))
    raise SystemExit(0)

if hasattr(module, "handle") and inspect.isfunction(module.handle):
    print(json.dumps({"ok": True}))
    raise SystemExit(0)

functions = [
    name for name, func in inspect.getmembers(module, inspect.isfunction)
    if getattr(func, "__module__", None) == module.__name__
]
if functions:
    print(json.dumps({"ok": True}))
else:
    print(json.dumps({"ok": False, "error": "Validation failed: Target file does not expose a callable handler. Define `handle(payload)` or at least one module-level function."}))
"""

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tmp:
            tmp.write(checker)
            tmp_path = tmp.name

        completed = subprocess.run(
            [sys.executable, tmp_path, code_path],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "Validation failed: Import preflight timed out while loading the target file."
    except Exception as exc:
        return False, f"Validation failed: Import preflight could not be executed: {exc}"
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    output = (completed.stdout or completed.stderr or "").strip()
    if not output:
        return False, "Validation failed: Import preflight produced no output."

    try:
        import json
        parsed = json.loads(output.splitlines()[-1])
    except Exception:
        return False, f"Validation failed: Import preflight returned an unexpected response: {output}"

    if parsed.get("ok"):
        return True, "Validation passed."

    return False, parsed.get("error", "Validation failed: Unknown import preflight error.")
