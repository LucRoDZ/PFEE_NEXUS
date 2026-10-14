"""End-to-end test: start the stack, run every scene, expect all checks to pass."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True, timeout=300)


def test_all_scenes_pass():
    run("demo/stack.py", "stop")
    started = run("demo/stack.py", "start", "--fresh")
    assert started.returncode == 0, started.stderr
    try:
        result = run("demo/scenes.py", "all")
        assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
        results = json.loads((ROOT / "var" / "results.json").read_text())
        checks = {k: v for s in ("scene1", "scene2", "scene3", "scene5") for k, v in results[s]["checks"].items()}
        assert len(checks) == 15 and all(checks.values()), checks
        assert results["scene2"]["allowed_after_revocation"] == 0
    finally:
        run("demo/stack.py", "stop")
