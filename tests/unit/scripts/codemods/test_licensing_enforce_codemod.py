"""Tests for scripts/codemods/licensing_enforce.py (RFC #244 PR-5).

Covers the extended shapes: single-line & multi-line ``async def run`` and
``async def execute``, idempotency across shapes, and the JSON summary
carrying per-shape counts.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
CODEMOD_PATH = REPO_ROOT / "scripts" / "codemods" / "licensing_enforce.py"


def _load_codemod():
    """Import the codemod as a module by path (it lives outside src/)."""
    spec = importlib.util.spec_from_file_location("_licensing_enforce_codemod", CODEMOD_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


codemod = _load_codemod()


# --- runner fixtures ------------------------------------------------------

RUNNER_SINGLE_RUN = '''"""Fake runner."""

from __future__ import annotations


class FakeRunner:
    def __init__(self) -> None:
        self._x = 1

    async def run(self, tenant_id: str = "") -> dict:
        return {"tenant_id": tenant_id}
'''

RUNNER_SINGLE_EXECUTE = '''"""Fake runner."""

from __future__ import annotations


class FakeRunner:
    def __init__(self) -> None:
        self._x = 1

    async def execute(self, tenant_id: str = "") -> dict:
        return {"tenant_id": tenant_id}
'''

RUNNER_MULTI_RUN = '''"""Fake runner."""

from __future__ import annotations

from typing import Any


class FakeRunner:
    def __init__(self) -> None:
        self._x = 1

    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> dict:
        return {"request_id": request_id}
'''

RUNNER_MULTI_EXECUTE = '''"""Fake runner."""

from __future__ import annotations

from typing import Any


class FakeRunner:
    def __init__(self) -> None:
        self._x = 1

    async def execute(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> dict:
        return {"request_id": request_id}
'''

RUNNER_NO_ENTRY_POINT = '''"""Fake runner with custom method name."""

from __future__ import annotations


class FakeRunner:
    async def certify(self, tenant_id: str = "") -> dict:
        return {"tenant_id": tenant_id}
'''


def _write_runner(tmp_path: Path, agent_name: str, source: str) -> Path:
    agent_dir = tmp_path / agent_name
    agent_dir.mkdir()
    runner = agent_dir / "runner.py"
    runner.write_text(source)
    return runner


# --- tests ----------------------------------------------------------------


def test_codemod_enforces_async_def_run_single_line(tmp_path: Path) -> None:
    runner = _write_runner(tmp_path, "alpha", RUNNER_SINGLE_RUN)

    result, shape = codemod.process_file(runner, apply=True)

    assert result == "enforced"
    assert shape == "run_single"
    text = runner.read_text()
    assert "from shieldops.licensing.enforce import enforced" in text
    assert '@enforced("alpha")\n    async def run(' in text
    ast.parse(text)  # still valid python


def test_codemod_enforces_async_def_execute_single_line(tmp_path: Path) -> None:
    runner = _write_runner(tmp_path, "beta", RUNNER_SINGLE_EXECUTE)

    result, shape = codemod.process_file(runner, apply=True)

    assert result == "enforced"
    assert shape == "execute_single"
    text = runner.read_text()
    assert "from shieldops.licensing.enforce import enforced" in text
    assert '@enforced("beta")\n    async def execute(' in text
    ast.parse(text)


def test_codemod_enforces_multi_line_def_signature(tmp_path: Path) -> None:
    runner_run = _write_runner(tmp_path, "gamma", RUNNER_MULTI_RUN)
    runner_exec = _write_runner(tmp_path, "delta", RUNNER_MULTI_EXECUTE)

    r1, s1 = codemod.process_file(runner_run, apply=True)
    r2, s2 = codemod.process_file(runner_exec, apply=True)

    assert (r1, s1) == ("enforced", "run_multi")
    assert (r2, s2) == ("enforced", "execute_multi")

    t1 = runner_run.read_text()
    t2 = runner_exec.read_text()
    assert '@enforced("gamma")\n    async def run(\n' in t1
    assert '@enforced("delta")\n    async def execute(\n' in t2
    ast.parse(t1)
    ast.parse(t2)


def test_codemod_is_idempotent_across_shapes(tmp_path: Path) -> None:
    shapes = {
        "alpha": RUNNER_SINGLE_RUN,
        "beta": RUNNER_SINGLE_EXECUTE,
        "gamma": RUNNER_MULTI_RUN,
        "delta": RUNNER_MULTI_EXECUTE,
    }
    runners = {name: _write_runner(tmp_path, name, src) for name, src in shapes.items()}

    # First pass: all enforced.
    for runner in runners.values():
        result, _ = codemod.process_file(runner, apply=True)
        assert result == "enforced"

    snapshots = {name: r.read_text() for name, r in runners.items()}

    # Second pass: all skipped_already_enforced, no textual change.
    for name, runner in runners.items():
        result, _ = codemod.process_file(runner, apply=True)
        assert result == "skipped_already_enforced"
        assert runner.read_text() == snapshots[name]


def test_codemod_skips_already_enforced(tmp_path: Path) -> None:
    runner = _write_runner(tmp_path, "epsilon", RUNNER_MULTI_EXECUTE)

    first, _ = codemod.process_file(runner, apply=True)
    assert first == "enforced"
    before = runner.read_text()
    # Explicitly verify @enforced(" is present on the line immediately
    # above the ``async def execute(`` line, regardless of paren shape.
    assert '@enforced("epsilon")' in before

    second, shape = codemod.process_file(runner, apply=True)
    assert second == "skipped_already_enforced"
    assert shape == "execute_multi"
    assert runner.read_text() == before


def test_codemod_skips_runner_without_entry_point(tmp_path: Path) -> None:
    runner = _write_runner(tmp_path, "zeta", RUNNER_NO_ENTRY_POINT)

    result, shape = codemod.process_file(runner, apply=False)

    assert result == "skipped_no_entry_point"
    assert shape is None
    # Not modified.
    assert "@enforced(" not in runner.read_text()


def test_codemod_reports_json_summary_with_per_shape_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Stage a miniature agents tree with all four shapes + a no-entry-point
    # file, then point the codemod at it via AGENTS monkeypatch.
    shapes = {
        "alpha": RUNNER_SINGLE_RUN,
        "beta": RUNNER_SINGLE_EXECUTE,
        "gamma": RUNNER_MULTI_RUN,
        "delta": RUNNER_MULTI_EXECUTE,
        "zeta": RUNNER_NO_ENTRY_POINT,
    }
    for name, src in shapes.items():
        _write_runner(tmp_path, name, src)

    # Exercise main() in-process with AGENTS + argv monkeypatched so we
    # hit the real JSON summary path.
    monkeypatch.setattr(codemod, "AGENTS", tmp_path)
    monkeypatch.setattr("sys.argv", ["licensing_enforce.py", "--apply"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = codemod.main()
    assert rc == 0
    payload = json.loads(buf.getvalue())

    # Legacy field names preserved for downstream-script compat.
    assert payload["enforced"] == 4
    assert payload["skipped_no_run"] == 1
    assert payload["skipped_already_enforced"] == 0

    # New per-shape breakdown present.
    per_shape = payload["per_shape"]
    assert per_shape["enforced_run_single"] == 1
    assert per_shape["enforced_run_multi"] == 1
    assert per_shape["enforced_execute_single"] == 1
    assert per_shape["enforced_execute_multi"] == 1
