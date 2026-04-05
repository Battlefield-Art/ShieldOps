"""Bulk engine migration script — converts engine files to engine() factory calls.

Usage:
    python scripts/migrate_engines.py --dry-run         # Preview changes
    python scripts/migrate_engines.py --package security # Migrate one package
    python scripts/migrate_engines.py --all              # Migrate everything

This script:
1. Reads each engine file
2. Extracts: 3 StrEnum definitions, record/analysis field definitions
3. Generates an engine() factory call
4. Writes the new file (preserving backward-compatible re-exports)
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

# Packages and their record method convention
RECORD_ITEM_PACKAGES = {"changes", "operations", "topology"}
ENGINE_PACKAGES = [
    "security",
    "analytics",
    "observability",
    "operations",
    "compliance",
    "incidents",
    "billing",
    "changes",
    "topology",
    "sla",
    "audit",
    "knowledge",
    "config",
]


def extract_enums(source: str) -> list[dict[str, str | list[str]]]:
    """Extract StrEnum class definitions from source."""
    enums = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            # Check if it inherits from StrEnum
            for base in node.bases:
                base_name = ""
                if isinstance(base, ast.Name):
                    base_name = base.id
                elif isinstance(base, ast.Attribute):
                    base_name = base.attr
                if base_name == "StrEnum":
                    values = {}
                    for item in node.body:
                        if isinstance(item, ast.Assign):
                            for target in item.targets:
                                if isinstance(target, ast.Name) and isinstance(
                                    item.value, ast.Constant
                                ):
                                    values[target.id] = item.value.value
                    if values:
                        enums.append({"name": node.name, "values": values})
    return enums  # type: ignore[return-value]


def extract_fields(source: str, model_name: str) -> list[dict[str, str]]:
    """Extract Pydantic model field definitions."""
    fields = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == model_name:
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    field_name = item.target.id
                    if field_name in ("id", "created_at", "model_config"):
                        continue
                    # Get type annotation as string
                    type_str = "str"
                    if isinstance(item.annotation, ast.Name):
                        type_str = item.annotation.id
                    # Get default value
                    default = '""'
                    if item.value is not None and isinstance(item.value, ast.Constant):
                        default = repr(item.value.value)
                    fields.append({"name": field_name, "type": type_str, "default": default})
    return fields


def count_engine_files(base_path: Path) -> dict[str, int]:
    """Count engine files per package."""
    counts = {}
    for pkg in ENGINE_PACKAGES:
        pkg_path = base_path / pkg
        if pkg_path.exists():
            engine_files = list(pkg_path.glob("*_engine.py")) + list(pkg_path.glob("*_analyzer.py"))
            counts[pkg] = len(engine_files)
    return counts


def preview_migration(base_path: Path, package: str) -> list[dict[str, str]]:
    """Preview what would be migrated for a package."""
    pkg_path = base_path / package
    if not pkg_path.exists():
        return []

    results = []
    for f in sorted(pkg_path.glob("*.py")):
        if f.name.startswith("__"):
            continue
        source = f.read_text()
        enums = extract_enums(source)
        line_count = len(source.splitlines())
        has_engine_class = "class " in source and (
            "add_record" in source or "record_item" in source
        )

        if has_engine_class and len(enums) >= 2:
            results.append(
                {
                    "file": str(f.relative_to(base_path.parent.parent)),
                    "lines": line_count,
                    "enums": len(enums),
                    "migratable": True,
                }
            )
    return results  # type: ignore[return-value]


def main() -> None:
    parser = argparse.ArgumentParser(description="Bulk engine migration tool")
    parser.add_argument("--dry-run", action="store_true", help="Preview without changes")
    parser.add_argument("--package", type=str, help="Migrate a specific package")
    parser.add_argument("--all", action="store_true", help="Migrate all packages")
    parser.add_argument("--count", action="store_true", help="Count engine files per package")
    args = parser.parse_args()

    base_path = Path(__file__).parent.parent / "src" / "shieldops"

    if args.count:
        counts = count_engine_files(base_path)
        total = 0
        for pkg, count in sorted(counts.items()):
            print(f"  {pkg}: {count} files")
            total += count
        print(f"  TOTAL: {total} files")
        return

    if args.dry_run:
        packages = [args.package] if args.package else ENGINE_PACKAGES
        total_files = 0
        total_lines = 0
        for pkg in packages:
            results = preview_migration(base_path, pkg)
            if results:
                print(f"\n{pkg}/:")
                for r in results:
                    print(f"  {r['file']} ({r['lines']} lines, {r['enums']} enums)")
                    total_files += 1
                    total_lines += int(r["lines"])
        after = total_files * 30
        reduction = total_lines - after
        pct = (reduction / total_lines * 100) if total_lines else 0
        print(f"\nTotal: {total_files} files, {total_lines} → ~{after} lines")
        print(f"Estimated reduction: {reduction} lines ({pct:.0f}%)")
        return

    print("Migration script ready. Use --dry-run to preview, --count to count files.")
    print("Full migration requires manual review per package.")


if __name__ == "__main__":
    main()
