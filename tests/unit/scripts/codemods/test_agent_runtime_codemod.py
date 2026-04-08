"""Tests for ``scripts/codemods/agent_runtime.py`` — RFC #247 PR-3."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
CODEMOD_PATH = REPO_ROOT / "scripts" / "codemods" / "agent_runtime.py"
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_codemod():
    spec = importlib.util.spec_from_file_location("agent_runtime_codemod", CODEMOD_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_runtime_codemod"] = module
    spec.loader.exec_module(module)
    return module


CODEMOD = _load_codemod()


@pytest.fixture
def fixtures_copy(tmp_path: Path) -> Path:
    """Copy the on-disk fixtures into a tmp_path so --apply mutations
    don't bleed across tests."""
    dst = tmp_path / "agents"
    shutil.copytree(FIXTURES_DIR, dst)
    return dst


def _run(root: Path, apply: bool = False) -> dict:
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        argv = ["--root", str(root)]
        if apply:
            argv.append("--apply")
        rc = CODEMOD.main(argv)
    assert rc == 0
    return json.loads(buf.getvalue())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_codemod_handles_canonical_async_run_shape(fixtures_copy: Path) -> None:
    """A linear graph with three nodes + ``async def run`` migrates cleanly."""
    summary = _run(fixtures_copy, apply=True)
    assert summary["mode"] == "apply"
    assert summary["migrated"] >= 1

    agent_py = fixtures_copy / "canonical_run" / "agent.py"
    assert agent_py.exists()
    text = agent_py.read_text()
    assert "_shieldops_runtime_migrated = True" in text
    assert 'name = "canonical_run"' in text
    assert "class CanonicalRunAgent(Agent):" in text
    # Three node names appear in the nodes dict.
    assert '"triage": triage,' in text
    assert '"investigate": investigate,' in text
    assert '"finalize": finalize,' in text
    # Three static edges + one to END.
    assert 'edge("triage", "investigate")' in text
    assert 'edge("investigate", "finalize")' in text
    assert 'edge("finalize", END)' in text
    assert 'entry = "triage"' in text
    # Header comment present.
    assert "RFC #247" in text


def test_codemod_handles_async_execute_shape(fixtures_copy: Path) -> None:
    """A runner exposing ``async def execute`` instead of ``run`` migrates."""
    summary = _run(fixtures_copy, apply=True)
    assert summary["migrated"] >= 1

    agent_py = fixtures_copy / "async_execute" / "agent.py"
    assert agent_py.exists()
    text = agent_py.read_text()
    assert "class AsyncExecuteAgent(Agent):" in text
    assert '"collect": collect,' in text
    assert '"summarize": summarize,' in text
    assert 'edge("collect", "summarize")' in text
    assert 'edge("summarize", END)' in text


def test_codemod_handles_conditional_edges(fixtures_copy: Path) -> None:
    """``add_conditional_edges`` calls land in a TODO marker (predicate
    semantics can't be safely guessed)."""
    _run(fixtures_copy, apply=True)
    text = (fixtures_copy / "conditional_edges" / "agent.py").read_text()
    assert "class ConditionalEdgesAgent(Agent):" in text
    # Linear edge before the conditional one is preserved.
    assert 'edge("detect", "evaluate")' in text
    # Conditional edge appears as a TODO referencing the predicate fn.
    assert "conditional edge" in text
    assert "_route" in text
    # Static edge after conditional is preserved too.
    assert 'edge("apply", END)' in text


def test_codemod_is_idempotent(fixtures_copy: Path) -> None:
    """Running the codemod twice produces zero diff on the second run."""
    first = _run(fixtures_copy, apply=True)
    snapshots = {
        path: path.read_text() for path in fixtures_copy.rglob("agent.py") if path.is_file()
    }
    second = _run(fixtures_copy, apply=True)
    # Second pass should not migrate anything new (already_migrated bucket grows).
    assert second["migrated"] == 0
    assert second["skipped_already_migrated"] >= first["migrated"]
    for path, content in snapshots.items():
        assert path.read_text() == content, f"agent.py mutated on second pass: {path}"


def test_codemod_skips_already_migrated(fixtures_copy: Path) -> None:
    """The pre-existing ``already_migrated`` fixture is reported as skipped."""
    summary = _run(fixtures_copy, apply=False)
    assert summary["skipped_already_migrated"] >= 1
    # Confirm by name.
    flat = " ".join(summary["samples"]["skipped_already_migrated"])
    assert "already_migrated" in flat


def test_codemod_reports_skipped_shapes(fixtures_copy: Path) -> None:
    """The weird-shape fixture lands in skipped_shape with a reason."""
    summary = _run(fixtures_copy, apply=False)
    assert summary["skipped_shape"] >= 1
    assert "no_runner_class" in summary["skip_reasons"] or any(
        "weird_shape" in s for s in summary["samples"]["skipped_shape"]
    )


def test_codemod_dry_run_does_not_write(fixtures_copy: Path) -> None:
    """Without --apply the codemod must not touch the filesystem."""
    summary = _run(fixtures_copy, apply=False)
    assert summary["mode"] == "dry-run"
    # canonical_run is a migration candidate but no agent.py should appear.
    assert not (fixtures_copy / "canonical_run" / "agent.py").exists()
