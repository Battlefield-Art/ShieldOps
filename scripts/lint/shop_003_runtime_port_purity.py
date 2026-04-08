"""SHOP-003 lint gate — AgentRuntime core must not import from
``shieldops.sdk`` (RFC #247).

The AgentRuntime core under ``src/shieldops/agents/runtime/`` is the
domain/ports side of RFC #247's ports-and-adapters split. It must stay
dependency-free of the SDK package, which is the outer-ring *adapter*.

Letting runtime import SDK would re-collapse the layering the RFC
just untangled (the old `framework.py` was a 4,000-LOC domain/adapter
tangle; the whole point of PR-1 was to cut that). A regression here
would be invisible until the next ``framework.py``-shaped mess grew on
top of it, so this gate catches it at commit time.

The rule: any file under ``src/shieldops/agents/runtime/`` that has

    from shieldops.sdk...
    import shieldops.sdk...

is a violation.

Invocation:

    python scripts/lint/shop_003_runtime_port_purity.py
    python scripts/lint/shop_003_runtime_port_purity.py --files X Y

Exit code:

    0 — runtime is SDK-free
    1 — at least one runtime file imports SDK (prints offenders)
    2 — script error
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_DIR = ROOT / "src" / "shieldops" / "agents" / "runtime"
FORBIDDEN_PREFIX = "shieldops.sdk"


def _imports_sdk(path: Path) -> list[tuple[int, str]]:
    """Return (lineno, module) tuples for any forbidden SDK imports."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        print(f"SHOP-003: {path}: could not parse: {exc}", file=sys.stderr)
        return []

    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == FORBIDDEN_PREFIX or mod.startswith(FORBIDDEN_PREFIX + "."):
                hits.append((node.lineno, f"from {mod} import ..."))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == FORBIDDEN_PREFIX or alias.name.startswith(FORBIDDEN_PREFIX + "."):
                    hits.append((node.lineno, f"import {alias.name}"))
    return hits


def _iter_targets(files: list[str] | None) -> list[Path]:
    if files:
        return [
            Path(f).resolve()
            for f in files
            if Path(f).resolve().is_relative_to(RUNTIME_DIR) and f.endswith(".py")
        ]
    return sorted(RUNTIME_DIR.rglob("*.py"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", nargs="*", default=None)
    args = parser.parse_args()

    targets = _iter_targets(args.files)
    if not targets:
        return 0

    offenders: list[str] = []
    for path in targets:
        for lineno, snippet in _imports_sdk(path):
            rel = path.relative_to(ROOT)
            offenders.append(f"  {rel}:{lineno}: {snippet}")

    if offenders:
        print(
            "SHOP-003: AgentRuntime core (src/shieldops/agents/runtime/) must not "
            "import from shieldops.sdk. The SDK is an outer-ring adapter; letting "
            "it leak into the domain recollapses the layering RFC #247 fixed.\n",
            file=sys.stderr,
        )
        print("\n".join(offenders), file=sys.stderr)
        print(
            "\nIf you genuinely need SDK-shaped data in the runtime, define a "
            "Port in runtime/ports.py and let the composition root wire the "
            "SDK adapter — do not import SDK directly.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover
        print(f"SHOP-003: script error: {exc}", file=sys.stderr)
        sys.exit(2)
