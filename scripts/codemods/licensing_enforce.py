"""Codemod: apply ``@enforced("<agent_name>")`` to every agent runner's
``async def run`` method — RFC #244 PR-3 adoption surface fix.

Agents whose runner class has an ``async def run(self, ...)`` method get:

1. An import of ``enforced`` from ``shieldops.licensing.enforce`` added
   right above the class declaration (if not already present).
2. A ``@enforced("<agent_name>")`` decorator prepended to ``async def run``
   (where ``<agent_name>`` is the directory name of the runner file —
   e.g. ``session_manager/runner.py`` → ``"session_manager"``).

**Idempotency** — the codemod is safe to run twice. It skips:

- files that already import ``enforced``
- ``run`` methods that already have an ``@enforced(`` line directly above

**Skip list** — files that use ``async def execute`` (~148 runners) or
any method name other than ``run`` (~268 runners) are reported but not
touched. The RFC's ``SHOP-001`` lint-rule-as-error PR-3 catches those
via a separate mechanism once they migrate to ``async def run``.

Usage::

    python scripts/codemods/licensing_enforce.py           # dry-run (default)
    python scripts/codemods/licensing_enforce.py --apply    # write changes

The tool prints a JSON summary (``enforced``, ``skipped_no_run``,
``skipped_already_enforced``) to stdout. Expected counts for 2026-04-07:
~87 enforced, ~148 skipped_no_run (async def execute), ~268 skipped_no_run
(neither run nor execute).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGENTS = ROOT / "src" / "shieldops" / "agents"

IMPORT_LINE = "from shieldops.licensing.enforce import enforced\n"
# Pattern matches `    async def run(self` with any extra whitespace + args.
_ASYNC_RUN = re.compile(r"^(?P<indent>[ \t]+)async def run\(", re.MULTILINE)


def _already_enforced(source: str, run_match: re.Match[str]) -> bool:
    """True if the line immediately above ``run`` already has @enforced("."""
    start = run_match.start()
    if start == 0:
        return False
    # ``start - 1`` is the ``\n`` that ends the previous line (assuming the
    # match was anchored at ``^`` after that \n, which our MULTILINE regex
    # guarantees). Scan backward for the \n that begins that line.
    end_nl = start - 1
    prior_line_start = source.rfind("\n", 0, end_nl) + 1  # 0 if no earlier \n
    prior_line = source[prior_line_start:end_nl]
    return "@enforced(" in prior_line


def _has_import(source: str) -> bool:
    return IMPORT_LINE.strip() in source


def _add_import(source: str) -> str:
    """Insert the import after the last top-level ``import`` / ``from``.

    Uses :mod:`ast` to find the true end-line of the last top-level
    ``Import`` / ``ImportFrom`` statement, so multi-line parenthesized
    imports (``from X import (\\n  A,\\n  B,\\n)``) are handled correctly
    without landing the inserted line inside the paren group.
    """
    import ast  # local import to keep the top-level code-free on load

    lines = source.splitlines(keepends=True)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        tree = None

    last_import_end_lineno = -1
    if tree is not None:
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                last_import_end_lineno = max(
                    last_import_end_lineno,
                    (node.end_lineno or node.lineno),
                )

    if last_import_end_lineno == -1:
        # No imports at all — extremely unlikely for a runner file. Fall
        # back to inserting after the module docstring (if any) or at top.
        insert_at = 0
        if lines and lines[0].startswith(('"""', "'''")):
            for i in range(1, len(lines)):
                if lines[i].strip().endswith(('"""', "'''")):
                    insert_at = i + 1
                    break
        lines.insert(insert_at, IMPORT_LINE)
    else:
        # ast line numbers are 1-based; `last_import_end_lineno` is the
        # physical line where the final import statement ends. Insert the
        # new import on the following line.
        lines.insert(last_import_end_lineno, IMPORT_LINE)
    return "".join(lines)


def _add_decorator(source: str, run_match: re.Match[str], agent_name: str) -> str:
    """Insert ``@enforced("<agent_name>")`` above the matched ``run`` def."""
    indent = run_match.group("indent")
    decorator = f'{indent}@enforced("{agent_name}")\n'
    return source[: run_match.start()] + decorator + source[run_match.start() :]


def process_file(path: Path, apply: bool) -> str:
    """Return one of: 'enforced', 'skipped_no_run', 'skipped_already_enforced'.

    Only processes runner files whose class has ``async def run(self, ...)``.
    """
    source = path.read_text()
    m = _ASYNC_RUN.search(source)
    if m is None:
        return "skipped_no_run"
    if _already_enforced(source, m):
        return "skipped_already_enforced"

    agent_name = path.parent.name  # e.g. 'session_manager'
    new_source = source
    if not _has_import(new_source):
        new_source = _add_import(new_source)
        # Re-match because indices shifted.
        m = _ASYNC_RUN.search(new_source)
        assert m is not None, "run method disappeared after import insertion"
    new_source = _add_decorator(new_source, m, agent_name)

    if apply:
        path.write_text(new_source)
    return "enforced"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write changes to disk. Default is dry-run (report only).",
    )
    args = parser.parse_args()

    runners = sorted(AGENTS.glob("*/runner.py"))
    counts = {"enforced": 0, "skipped_no_run": 0, "skipped_already_enforced": 0}
    samples: dict[str, list[str]] = {k: [] for k in counts}
    for path in runners:
        result = process_file(path, apply=args.apply)
        counts[result] += 1
        if len(samples[result]) < 3:
            samples[result].append(str(path.relative_to(ROOT)))

    print(
        json.dumps(
            {
                "mode": "apply" if args.apply else "dry-run",
                "total_runners": len(runners),
                **counts,
                "samples": samples,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
