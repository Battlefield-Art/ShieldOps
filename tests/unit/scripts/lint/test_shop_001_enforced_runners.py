"""Contract tests for the SHOP-001 lint gate (RFC #244 PR-6).

The gate is a stand-in for a ruff custom rule (ruff has no native
plugin API). It fails the pre-commit hook if any agent runner's
``async def run`` / ``async def execute`` method lacks an
``@enforced(...)`` decorator or a ``_shieldops_enforced`` class marker.

These tests lock the contract on ephemeral fixture runner files so the
gate's behavior is verified without depending on the real 503 agents.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest

SCRIPT = Path(__file__).resolve().parents[4] / "scripts" / "lint" / "shop_001_enforced_runners.py"


ENFORCED_RUNNER = dedent(
    '''\
    """Fixture runner that SHOULD pass SHOP-001."""

    from shieldops.licensing.enforce import enforced


    class GoodRunner:
        @enforced("good")
        async def run(self, tenant_id: str = "") -> dict:
            return {}
    '''
)

UNENFORCED_RUN_RUNNER = dedent(
    '''\
    """Fixture runner that SHOULD fail SHOP-001 (missing @enforced on run)."""


    class BadRunRunner:
        async def run(self, tenant_id: str = "") -> dict:
            return {}
    '''
)

UNENFORCED_EXECUTE_RUNNER = dedent(
    '''\
    """Fixture runner that SHOULD fail SHOP-001 (missing @enforced on execute)."""


    class BadExecuteRunner:
        async def execute(self, tenant_id: str = "") -> dict:
            return {}
    '''
)

MARKER_RUNNER = dedent(
    '''\
    """Fixture runner that SHOULD pass via the class-level marker."""


    class MarkerRunner:
        _shieldops_enforced = True

        async def run(self, tenant_id: str = "") -> dict:
            return {}
    '''
)

NON_RUNNER_CLASS = dedent(
    '''\
    """Fixture runner whose entry-point-like class doesn't end in 'Runner'."""


    class SomeHelper:
        async def run(self, tenant_id: str = "") -> dict:
            return {}
    '''
)


def _write_fixture(tmp_path: Path, contents: str) -> Path:
    """Create a fake src/shieldops/agents/<name>/runner.py under tmp_path.

    The script treats ``src/shieldops/agents/*/runner.py`` as the canonical
    location, so we mirror that layout inside tmp_path before invoking it.
    """
    agent_dir = tmp_path / "src" / "shieldops" / "agents" / "fixture_agent"
    agent_dir.mkdir(parents=True)
    runner_path = agent_dir / "runner.py"
    runner_path.write_text(contents)
    return runner_path


def _run_gate(*files: Path) -> subprocess.CompletedProcess[str]:
    """Invoke the gate with the given explicit file list."""
    return subprocess.run(  # noqa: S603 — test harness invokes a trusted script
        [sys.executable, str(SCRIPT), "--files", *(str(f) for f in files)],
        capture_output=True,
        text=True,
        check=False,
    )


class TestShop001Gate:
    def test_enforced_runner_passes(self, tmp_path: Path) -> None:
        """A runner with @enforced on async def run must pass."""
        runner = _write_fixture(tmp_path, ENFORCED_RUNNER)
        result = _run_gate(runner)
        assert result.returncode == 0, f"expected pass, got stderr:\n{result.stderr}"

    def test_unenforced_run_fails(self, tmp_path: Path) -> None:
        """A runner with async def run but no @enforced must fail."""
        runner = _write_fixture(tmp_path, UNENFORCED_RUN_RUNNER)
        result = _run_gate(runner)
        assert result.returncode == 1
        assert "BadRunRunner.run" in result.stderr
        assert "SHOP-001" in result.stderr

    def test_unenforced_execute_fails(self, tmp_path: Path) -> None:
        """A runner with async def execute but no @enforced must fail."""
        runner = _write_fixture(tmp_path, UNENFORCED_EXECUTE_RUNNER)
        result = _run_gate(runner)
        assert result.returncode == 1
        assert "BadExecuteRunner.execute" in result.stderr

    def test_class_level_marker_passes(self, tmp_path: Path) -> None:
        """The _shieldops_enforced = True class attribute bypasses the check."""
        runner = _write_fixture(tmp_path, MARKER_RUNNER)
        result = _run_gate(runner)
        assert result.returncode == 0, f"expected pass via marker, got stderr:\n{result.stderr}"

    def test_non_runner_classes_are_ignored(self, tmp_path: Path) -> None:
        """Classes whose name doesn't end in 'Runner' are not checked.

        A helper class with an unrelated async ``run`` method should not
        trip the gate — it's not the license-admitted entry point.
        """
        runner = _write_fixture(tmp_path, NON_RUNNER_CLASS)
        result = _run_gate(runner)
        assert result.returncode == 0

    def test_gate_ignores_non_runner_files(self, tmp_path: Path) -> None:
        """Files not matching agents/*/runner.py must be silently skipped.

        Pre-commit hands the gate every touched file path — the gate
        must filter out unrelated ones itself.
        """
        # Create a random non-runner .py file outside the agents tree.
        unrelated = tmp_path / "src" / "shieldops" / "api" / "app.py"
        unrelated.parent.mkdir(parents=True)
        unrelated.write_text(UNENFORCED_RUN_RUNNER)
        result = _run_gate(unrelated)
        # Non-runner files should not cause the gate to report offenders.
        assert result.returncode == 0


@pytest.mark.integration
class TestFullRepoMode:
    """Full-repo mode (no --files) is what CI will eventually run.

    Today it exits 1 because ~147 existing runners still need @enforced
    (the #268 codemod batch hasn't fully landed yet). We assert only
    that the script runs cleanly and produces a well-formed report —
    not that it returns 0. When #268 lands the full-repo mode becomes
    mandatory and this test can flip to ``assert returncode == 0``.
    """

    def test_full_repo_runs_without_crashing(self) -> None:
        result = subprocess.run(  # noqa: S603 — test harness invokes a trusted script
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        # Exit 0 or 1 are both legal; exit 2 means the script itself crashed.
        assert result.returncode in (0, 1), (
            f"SHOP-001 script crashed with exit {result.returncode}:\nstderr:\n{result.stderr}"
        )
        if result.returncode == 1:
            assert "SHOP-001" in result.stderr
