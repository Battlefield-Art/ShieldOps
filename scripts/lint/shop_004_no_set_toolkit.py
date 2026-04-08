"""SHOP-004 lint gate — no new ``set_toolkit`` calls in
``src/shieldops/agents/`` (RFC #247).

RFC #247 replaced the ``set_toolkit(...)`` global-mutation idiom with
per-Agent declarative toolkit specs wired through the composition
root. The old pattern was:

    # nodes.py
    _TOOLKIT: FooToolkit | None = None

    def set_toolkit(tk: FooToolkit) -> None:  # noqa: PLW0603
        global _TOOLKIT
        _TOOLKIT = tk

    # runner.py
    def __init__(self, ...):
        self._toolkit = FooToolkit(...)
        set_toolkit(self._toolkit)

That pattern is a hidden global, breaks parallel tests, and was the
source of the 397 `set_toolkit` hot-spots RFC #247 set out to kill.

A full-repo sweep is still in progress (#285 PR-5 migrates the
remaining runners in 7 batches), so this gate is **scoped to the files
touched by the current commit** — same approach as SHOP-001. That way
the backlog doesn't block unrelated work, but no *new* `set_toolkit`
call can land.

The rule: a touched ``.py`` file under ``src/shieldops/agents/`` must
not contain any of:

    set_toolkit(           # function call
    def set_toolkit(       # function definition
    from ... import ... set_toolkit ...
    import set_toolkit

Full-repo mode (``--all``) runs in CI only *after* PR-5 lands. Until
then CI uses the --files mode.

Invocation:

    python scripts/lint/shop_004_no_set_toolkit.py --files X Y
    python scripts/lint/shop_004_no_set_toolkit.py --all

Exit code:

    0 — no new set_toolkit in touched files
    1 — at least one touched file reintroduces set_toolkit
    2 — script error
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGENTS_DIR = ROOT / "src" / "shieldops" / "agents"

# Ignore the runtime/ subpackage — RFC #247's new Agent spec machinery
# lives there and is explicitly allowed to reference the banned name in
# migration code comments / deprecation paths. If a real runtime file
# ever needs the symbol it gets reviewed manually.
ALLOWLIST_PREFIXES = (AGENTS_DIR / "runtime",)

# Matches: set_toolkit(, def set_toolkit(, ...set_toolkit,  (as an import)
# A plain substring search would false-positive on the string "set_toolkit"
# in docstrings, so we use a word-boundary regex.
PATTERN = re.compile(r"\bset_toolkit\b")


def _is_allowlisted(path: Path) -> bool:
    return any(path.is_relative_to(p) for p in ALLOWLIST_PREFIXES)


def _scan(path: Path) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"SHOP-004: {path}: could not read: {exc}", file=sys.stderr)
        return hits
    for i, line in enumerate(text.splitlines(), start=1):
        # Skip comments — we only care about executable uses.
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if PATTERN.search(line):
            hits.append((i, line.rstrip()))
    return hits


def _iter_targets(files: list[str] | None, all_mode: bool) -> list[Path]:
    if all_mode:
        return sorted(AGENTS_DIR.rglob("*.py"))
    if not files:
        return []
    return [
        Path(f).resolve()
        for f in files
        if Path(f).resolve().is_relative_to(AGENTS_DIR) and f.endswith(".py")
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", nargs="*", default=None)
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan the entire agents/ tree (enable after RFC #247 PR-5 lands)",
    )
    args = parser.parse_args()

    targets = _iter_targets(args.files, args.all)
    if not targets:
        return 0

    offenders: list[str] = []
    for path in targets:
        if _is_allowlisted(path):
            continue
        for lineno, snippet in _scan(path):
            rel = path.relative_to(ROOT)
            offenders.append(f"  {rel}:{lineno}: {snippet.strip()}")

    if offenders:
        print(
            "SHOP-004: `set_toolkit` is a deprecated global-mutation pattern "
            "(RFC #247). Declare tools on the Agent spec instead:\n"
            "  - nodes receive their toolkit via the Agent spec's `tools=` "
            "argument\n"
            "  - the composition root wires the real adapter in app.py\n"
            "  - tests use `use_test_toolkit(...)` context manager\n",
            file=sys.stderr,
        )
        print("\n".join(offenders), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover
        print(f"SHOP-004: script error: {exc}", file=sys.stderr)
        sys.exit(2)
