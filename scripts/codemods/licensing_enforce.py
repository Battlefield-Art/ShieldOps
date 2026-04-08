"""Codemod: apply ``@enforced("<agent_name>")`` to every agent runner's
async entry-point method — RFC #244 PR-3/PR-5 adoption surface fix.

Agents whose runner class has an ``async def run(...)`` or ``async def
execute(...)`` method get:

1. An import of ``enforced`` from ``shieldops.licensing.enforce`` added
   right after the last top-level import (if not already present).
2. A ``@enforced("<agent_name>")`` decorator prepended to the entry-point
   method (where ``<agent_name>`` is the directory name of the runner
   file — e.g. ``session_manager/runner.py`` → ``"session_manager"``).

**Shapes supported (PR-5):**

- ``async def run(self, ...)``              — single-line signature
- ``async def run(\\n    self, ...)``        — multi-line signature
- ``async def execute(self, ...)``          — single-line signature
- ``async def execute(\\n    self, ...)``    — multi-line signature

**Idempotency** — the codemod is safe to run twice. It skips:

- files that already import ``enforced`` (import dedup via string check)
- methods that already have an ``@enforced(`` line directly above the
  matched ``async def`` line

**Not touched** — files whose entry-point uses a domain-specific name
(``certify``, ``monitor``, ``remediate``, ``validate``, ...) are reported
as ``skipped_no_run`` (legacy field name retained). Those need a
separate pass once they standardize on ``run``/``execute``.

Usage::

    python scripts/codemods/licensing_enforce.py           # dry-run (default)
    python scripts/codemods/licensing_enforce.py --apply    # write changes

The tool prints a JSON summary to stdout with legacy fields
(``enforced``, ``skipped_no_run``, ``skipped_already_enforced``) plus a
new ``per_shape`` block with fine-grained counts.
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

# Pattern matches either ``async def run(`` or ``async def execute(``
# at the start of a line (plus leading indent). Works for both
# single-line signatures (``async def run(self, ...)``) and multi-line
# signatures (``async def run(\n    self, ...)``) because we only anchor
# on the opening paren — everything after it is the parameter list.
_ENTRY_POINT = re.compile(
    r"^(?P<indent>[ \t]+)async def (?P<name>run|execute)\(",
    re.MULTILINE,
)


def _already_enforced(source: str, match: re.Match[str]) -> bool:
    """True if the line immediately above the match has ``@enforced(``."""
    start = match.start()
    if start == 0:
        return False
    end_nl = start - 1
    prior_line_start = source.rfind("\n", 0, end_nl) + 1  # 0 if no earlier \n
    prior_line = source[prior_line_start:end_nl]
    return "@enforced(" in prior_line


def _has_import(source: str) -> bool:
    return IMPORT_LINE.strip() in source


def _add_import(source: str) -> str:
    """Insert the import after the last top-level ``import`` / ``from``."""
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
        insert_at = 0
        if lines and lines[0].startswith(('"""', "'''")):
            for i in range(1, len(lines)):
                if lines[i].strip().endswith(('"""', "'''")):
                    insert_at = i + 1
                    break
        lines.insert(insert_at, IMPORT_LINE)
    else:
        lines.insert(last_import_end_lineno, IMPORT_LINE)
    return "".join(lines)


def _add_decorator(source: str, match: re.Match[str], agent_name: str) -> str:
    """Insert ``@enforced("<agent_name>")`` above the matched def."""
    indent = match.group("indent")
    decorator = f'{indent}@enforced("{agent_name}")\n'
    return source[: match.start()] + decorator + source[match.start() :]


def _classify_shape(match: re.Match[str], source: str) -> str:
    """Return a fine-grained shape tag for reporting."""
    name = match.group("name")
    line_end = source.find("\n", match.end())
    if line_end == -1:
        line_end = len(source)
    rest = source[match.end() : line_end]
    # Heuristic: if ``)`` appears before the newline it's single-line.
    multi = ")" not in rest
    return f"{name}_{'multi' if multi else 'single'}"


def process_file(path: Path, apply: bool) -> tuple[str, str | None]:
    """Return ``(result, shape)``.

    ``result`` ∈ {'enforced', 'skipped_no_entry_point',
    'skipped_already_enforced'}. ``shape`` is the fine-grained tag
    (``run_single``, ``run_multi``, ``execute_single``, ``execute_multi``)
    when we matched an entry point; otherwise ``None``.
    """
    source = path.read_text()
    m = _ENTRY_POINT.search(source)
    if m is None:
        return "skipped_no_entry_point", None
    shape = _classify_shape(m, source)
    if _already_enforced(source, m):
        return "skipped_already_enforced", shape

    agent_name = path.parent.name  # e.g. 'session_manager'
    new_source = source
    if not _has_import(new_source):
        new_source = _add_import(new_source)
        # Re-match because indices shifted.
        m = _ENTRY_POINT.search(new_source)
        assert m is not None, "entry point disappeared after import insertion"
    new_source = _add_decorator(new_source, m, agent_name)

    if apply:
        path.write_text(new_source)
    return "enforced", shape


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write changes to disk. Default is dry-run (report only).",
    )
    args = parser.parse_args()

    runners = sorted(AGENTS.glob("*/runner.py"))
    # Legacy field names retained so downstream scripts don't break.
    counts = {
        "enforced": 0,
        "skipped_no_run": 0,
        "skipped_already_enforced": 0,
    }
    per_shape: dict[str, int] = {
        "enforced_run_single": 0,
        "enforced_run_multi": 0,
        "enforced_execute_single": 0,
        "enforced_execute_multi": 0,
        "already_enforced_run_single": 0,
        "already_enforced_run_multi": 0,
        "already_enforced_execute_single": 0,
        "already_enforced_execute_multi": 0,
    }
    samples: dict[str, list[str]] = {k: [] for k in counts}

    for path in runners:
        result, shape = process_file(path, apply=args.apply)
        if result == "skipped_no_entry_point":
            counts["skipped_no_run"] += 1
            bucket = "skipped_no_run"
        else:
            counts[result] += 1
            bucket = result
            if shape is not None:
                prefix = "enforced" if result == "enforced" else "already_enforced"
                per_shape[f"{prefix}_{shape}"] += 1
        if len(samples[bucket]) < 3:
            samples[bucket].append(_rel(path))

    print(
        json.dumps(
            {
                "mode": "apply" if args.apply else "dry-run",
                "total_runners": len(runners),
                **counts,
                "per_shape": per_shape,
                "samples": samples,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
