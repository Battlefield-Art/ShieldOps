"""SHOP-001 lint gate — every agent runner's async entry point must be
``@enforced``-decorated (RFC #244).

This script stands in for a ruff custom rule. Ruff has no native
custom-rule plugin API, so the RFC #244 acceptance criterion "ruff lint
rule SHOP-001" is satisfied by a pre-commit + CI grep gate instead.

The rule: every file under ``src/shieldops/agents/*/runner.py`` that
contains a ``class *Runner`` with an ``async def run`` (or
``async def execute``) method MUST either:

1. Have the ``_shieldops_enforced`` marker set on the class, OR
2. Have ``@enforced("<name>")`` directly above the method.

Reason: the ``@enforced`` decorator from ``shieldops.licensing.enforce``
is the only mechanism that routes agent starts through the
``LicenseManager``. A runner without it silently exceeds the license
``agent_limit`` — the exact bug RFC #244 was written to eliminate.

Invocation:

    python scripts/lint/shop_001_enforced_runners.py           # checks + exits
    python scripts/lint/shop_001_enforced_runners.py --files X Y  # check a subset

Exit code:

    0 — all runners have @enforced or a base-class equivalent
    1 — at least one runner missing @enforced (prints offenders)
    2 — script itself errored (usage / ast parse)

Integration:

- Wired as a local pre-commit hook in ``.pre-commit-config.yaml`` so
  any new runner touched during a commit is checked immediately.
- Run in full-repo mode in CI (``.github/workflows/ci.yml``) so a
  regression that slips past pre-commit is still caught on PR.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGENTS_DIR = ROOT / "src" / "shieldops" / "agents"

# Method names that count as "agent entry points" — matches what the
# licensing_enforce.py codemod recognizes.
ENTRY_POINT_NAMES = ("run", "execute")


def _method_decorators(method: ast.AsyncFunctionDef) -> list[str]:
    """Return the dotted names of this method's decorators."""
    out: list[str] = []
    for d in method.decorator_list:
        if isinstance(d, ast.Name):
            out.append(d.id)
        elif isinstance(d, ast.Call):
            # e.g. @enforced("adaptive_security")
            if isinstance(d.func, ast.Name):
                out.append(d.func.id)
            elif isinstance(d.func, ast.Attribute):
                out.append(d.func.attr)
        elif isinstance(d, ast.Attribute):
            out.append(d.attr)
    return out


def _class_has_marker(cls: ast.ClassDef) -> bool:
    """True if the class sets ``_shieldops_enforced = True`` at class level."""
    for stmt in cls.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == "_shieldops_enforced":
                    return True
    return False


def _check_file(path: Path) -> list[str]:
    """Return a list of violation messages for this runner file."""
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError as exc:
        return [f"{path}: syntax error ({exc})"]

    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        # Only care about *Runner classes.
        if not node.name.endswith("Runner"):
            continue
        if _class_has_marker(node):
            continue  # explicitly opted out / already enforced
        # Look for an async entry-point method.
        for stmt in node.body:
            if not isinstance(stmt, ast.AsyncFunctionDef):
                continue
            if stmt.name not in ENTRY_POINT_NAMES:
                continue
            decorators = _method_decorators(stmt)
            if "enforced" not in decorators:
                # path.relative_to(ROOT) crashes if the caller passes a
                # path outside the repo (the fixture test suite does
                # exactly this), so fall back to the raw path.
                try:
                    rel: Path | str = path.relative_to(ROOT)
                except ValueError:
                    rel = path
                violations.append(
                    f"{rel}:{stmt.lineno} "
                    f"{node.name}.{stmt.name} is missing @enforced(...) "
                    f"or _shieldops_enforced class marker — SHOP-001"
                )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--files",
        nargs="*",
        default=None,
        help="Limit the check to these files (pre-commit hands them in).",
    )
    args = parser.parse_args()

    if args.files:
        # Pre-commit hands in every touched file. Keep only paths that
        # *look like* agent runners (``.../agents/<name>/runner.py``).
        # We match the shape of the path rather than rooting at the
        # real ``AGENTS_DIR`` so the fixture test suite can exercise
        # this gate with tmp_path-anchored fixtures.
        targets = []
        for f in args.files:
            p = Path(f).resolve()
            if p.name != "runner.py":
                continue
            if len(p.parents) >= 2 and p.parents[1].name == "agents":
                targets.append(p)
    else:
        targets = sorted(AGENTS_DIR.glob("*/runner.py"))

    violations: list[str] = []
    for path in targets:
        violations.extend(_check_file(path))

    if violations:
        print(
            f"SHOP-001: {len(violations)} runner(s) missing @enforced "
            f"(RFC #244 — licensing enforcement gate):\n",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        print(
            '\nFix: either add @enforced("<agent_name>") above the async def, '
            "or run `python scripts/codemods/licensing_enforce.py --apply`.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
