"""Bulk engine migration script -- converts engine files to engine() factory calls.

Usage:
    python scripts/migrate_engines.py --dry-run                    # Preview all packages
    python scripts/migrate_engines.py --dry-run --package security # Preview security
    python scripts/migrate_engines.py --package security           # Migrate security
    python scripts/migrate_engines.py --package security --limit 50 # First 50 only
    python scripts/migrate_engines.py --all                        # Migrate everything

This script:
1. Reads each engine file
2. Extracts: 3 StrEnum definitions, Record model fields, engine class name
3. Classifies as pure-template or custom-logic
4. For pure-template: generates engine() factory call with backward-compat re-exports
5. For custom: skips and logs reason
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

# Standard methods from engine() factory -- anything beyond these is custom logic
STANDARD_METHODS = {
    "add_record",
    "record_item",
    "get_record",
    "list_records",
    "add_analysis",
    "analyze_distribution",
    "identify_gaps",
    "rank_by_score",
    "detect_trends",
    "process",
    "generate_report",
    "get_stats",
    "clear_data",
    "__init__",
    "_ingest",
}


# --- AST extraction helpers ---


def _get_base_name(base: ast.expr) -> str:
    if isinstance(base, ast.Name):
        return base.id
    if isinstance(base, ast.Attribute):
        return base.attr
    return ""


def extract_enums(tree: ast.Module) -> list[dict]:
    """Extract StrEnum class definitions from AST."""
    enums = []
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        bases = [_get_base_name(b) for b in node.bases]
        if "StrEnum" not in bases:
            continue
        values: dict[str, str] = {}
        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name) and isinstance(item.value, ast.Constant):
                        values[target.id] = item.value.value
        if values:
            enums.append({"name": node.name, "values": values})
    return enums


def extract_record_fields(tree: ast.Module, model_name: str) -> list[dict]:
    """Extract Pydantic model field annotations from the Record model."""
    fields = []
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.ClassDef) or node.name != model_name:
            continue
        for item in node.body:
            if not isinstance(item, ast.AnnAssign) or not isinstance(item.target, ast.Name):
                continue
            field_name = item.target.id
            # Skip standard fields present on all engine() records
            if field_name in ("id", "created_at", "service", "team"):
                continue
            # Get type annotation as string
            type_str = ast.unparse(item.annotation) if item.annotation else "str"
            # Get default value
            default_str = None
            if item.value is not None:
                default_str = ast.unparse(item.value)
            fields.append({"name": field_name, "type_str": type_str, "default_str": default_str})
    return fields


def find_engine_class(tree: ast.Module) -> ast.ClassDef | None:
    """Find the engine class (not StrEnum, not BaseModel)."""
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        bases = [_get_base_name(b) for b in node.bases]
        if "StrEnum" not in bases and "BaseModel" not in bases:
            return node
    return None


def find_model_classes(tree: ast.Module) -> list[ast.ClassDef]:
    """Find Pydantic model classes."""
    models = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ClassDef):
            bases = [_get_base_name(b) for b in node.bases]
            if "BaseModel" in bases:
                models.append(node)
    return models


def get_engine_docstring(engine_class: ast.ClassDef) -> str:
    """Extract docstring from engine class."""
    if engine_class.body and isinstance(engine_class.body[0], ast.Expr):
        val = engine_class.body[0].value
        if isinstance(val, ast.Constant) and isinstance(val.value, str):
            return val.value
    return ""


def get_module_docstring(tree: ast.Module) -> str:
    """Extract module-level docstring."""
    if tree.body and isinstance(tree.body[0], ast.Expr):
        val = tree.body[0].value
        if isinstance(val, ast.Constant) and isinstance(val.value, str):
            return val.value
    return ""


def classify_engine(tree: ast.Module, engine_class: ast.ClassDef) -> dict:
    """Classify whether an engine is pure-template or custom.

    Returns dict with 'is_pure', 'reasons' (why not pure), 'methods', etc.
    """
    methods: set[str] = set()
    for item in engine_class.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            methods.add(item.name)

    # Private helper methods (custom logic)
    private_methods = {m for m in methods if m.startswith("_") and m != "__init__"}

    # Non-standard public methods
    public_methods = {m for m in methods if not m.startswith("_")}
    non_standard = public_methods - STANDARD_METHODS

    # Extra instance state beyond standard
    init_method = None
    for item in engine_class.body:
        if isinstance(item, ast.FunctionDef) and item.name == "__init__":
            init_method = item
            break

    extra_state_names: set[str] = set()
    standard_state = {
        "_max_records",
        "_threshold",
        "_records",
        "_analyses",
        "_logger",
    }
    if init_method:
        for stmt in ast.walk(init_method):
            if (
                isinstance(stmt, ast.Attribute)
                and isinstance(getattr(stmt, "ctx", None), ast.Store)
                and isinstance(stmt.value, ast.Name)
                and stmt.value.id == "self"
            ):
                if stmt.attr not in standard_state:
                    extra_state_names.add(stmt.attr)

    # Count enums
    enums = extract_enums(tree)

    reasons: list[str] = []
    if len(enums) != 3:
        reasons.append(f"enum_count={len(enums)} (expected 3)")
    if private_methods:
        reasons.append(f"private_methods={private_methods}")
    if len(non_standard) > 3:
        reasons.append(f"non_standard_methods={len(non_standard)}: {non_standard}")
    if len(extra_state_names) > 2:
        reasons.append(f"extra_state={extra_state_names}")

    return {
        "is_pure": len(reasons) == 0,
        "reasons": reasons,
        "methods": methods,
        "non_standard": non_standard,
        "private_methods": private_methods,
        "extra_state": extra_state_names,
        "enum_count": len(enums),
    }


# --- Determine engine parameters ---


def detect_ingest_method(engine_class: ast.ClassDef) -> str:
    """Detect if the engine uses add_record or record_item."""
    for item in engine_class.body:
        if isinstance(item, ast.FunctionDef):
            if item.name == "record_item":
                return "record_item"
            if item.name == "add_record":
                return "add_record"
    return "add_record"


def detect_score_field(record_fields: list[dict]) -> str:
    """Detect the primary score field name from record fields."""
    for f in record_fields:
        if f["type_str"] == "float" and "score" in f["name"]:
            return f["name"]
    return "score"


def detect_key_field(record_fields: list[dict]) -> str:
    """Detect the primary key field (first str field, usually 'name')."""
    for f in record_fields:
        if f["name"] in ("name", "entity_name", "trust_id", "user_id", "agent_id"):
            return f["name"]
    # First non-enum string field
    for f in record_fields:
        if f["type_str"] == "str" and f["name"] not in ("service", "team"):
            return f["name"]
    return "name"


# --- Code generation ---


def _repr_enum_values(values: dict[str, str]) -> str:
    """Format enum values dict for code output."""
    items = [f'        "{k}": "{v}",' for k, v in values.items()]
    return "{\n" + "\n".join(items) + "\n    }"


def _python_type_for(type_str: str) -> str:
    """Convert AST type string to FieldDef type= parameter."""
    mapping = {
        "str": "str",
        "float": "float",
        "int": "int",
        "bool": "bool",
        "list": "list",
        "dict": "dict",
    }
    # Handle list[X], dict[X,Y] etc
    base = type_str.split("[")[0]
    return mapping.get(base, "str")


def _default_for(field: dict) -> str:
    """Produce default= value for FieldDef."""
    if field["default_str"] is None:
        return '""'
    d = field["default_str"]
    # Skip Field(...) defaults, enum defaults
    if d.startswith("Field("):
        return '""'
    return d


def generate_migrated_code(
    *,
    module_docstring: str,
    engine_name: str,
    engine_docstring: str,
    enums: list[dict],
    record_fields: list[dict],
    score_field: str,
    key_field: str,
    ingest_method: str,
    record_model_name: str,
    analysis_model_name: str,
    report_model_name: str,
    enum_field_names: list[str],
) -> str:
    """Generate the migrated engine() factory call code."""
    lines: list[str] = []

    # Module docstring (collapse to single line, truncate to fit 100 char limit)
    if module_docstring:
        collapsed = " ".join(module_docstring.split())
        # Ensure line fits: 3 (""") + text + 3 (""") <= 100
        max_doc_len = 94
        if len(collapsed) > max_doc_len:
            collapsed = collapsed[: max_doc_len - 3].rstrip() + "..."
        lines.append(f'"""{collapsed}"""')
    else:
        lines.append(f'"""{engine_name} engine."""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")

    # Build record extra fields early to decide imports
    enum_names_set = {e["name"] for e in enums}
    skip_fields = {key_field, score_field, "service", "team", "id", "created_at"}
    skip_fields.update(enum_field_names)

    record_extra: list[str] = []
    for f in record_fields:
        if f["name"] in skip_fields:
            continue
        if f["type_str"] in enum_names_set:
            continue
        py_type = _python_type_for(f["type_str"])
        default = _default_for(f)
        record_extra.append(f'    FieldDef("{f["name"]}", {py_type}, {default}),')

    # Only import FieldDef if we need it
    if record_extra:
        lines.append("from shieldops.engine import EnumDef, FieldDef, engine")
    else:
        lines.append("from shieldops.engine import EnumDef, engine")
    lines.append("")

    # Build enum definitions
    enum_defs: list[str] = []
    for _i, (enum, field_name) in enumerate(zip(enums, enum_field_names, strict=True)):
        vals = _repr_enum_values(enum["values"])
        enum_defs.append(f'    "{field_name}": EnumDef("{enum["name"]}", {vals}),')

    # Determine module parameter for record_item vs add_record
    # security package normally uses add_record, but some use record_item
    module_param = ""
    if ingest_method == "record_item":
        module_param = '    module="operations",  # uses record_item\n'

    # Build the engine() call
    lines.append(f"{engine_name} = engine(")
    lines.append(f'    "{engine_name}",')
    if module_param:
        lines.append(module_param.rstrip())
    if engine_docstring:
        # Collapse multi-line docstrings to single line
        desc = " ".join(engine_docstring.replace('"', '\\"').split())
        # Truncate if description= line would exceed 100 chars
        # Line format: '    description="...",': 18 prefix + desc + 2 suffix = 20 + desc
        max_desc_len = 78
        if len(desc) > max_desc_len:
            desc = desc[: max_desc_len - 3].rstrip() + "..."
        lines.append(f'    description="{desc}",')

    # Enums
    if enum_defs:
        lines.append("    enums={")
        for ed in enum_defs:
            lines.append(ed)
        lines.append("    },")

    # Record fields
    if record_extra:
        lines.append("    record_fields=[")
        for rf in record_extra:
            lines.append(rf)
        lines.append("    ],")

    # Score field
    if score_field != "score":
        lines.append(f'    score_field="{score_field}",')

    # Key field
    if key_field != "name":
        lines.append(f'    key_field="{key_field}",')

    lines.append(")")
    lines.append("")

    # Backward-compatible re-exports
    lines.append("# Backward-compatible re-exports")
    # Enum classes
    for enum, _field_name in zip(enums, enum_field_names, strict=True):
        lines.append(f"{enum['name']} = {engine_name}.{enum['name']}")
    # Model classes
    lines.append(f"{record_model_name} = {engine_name}.Record")
    lines.append(f"{analysis_model_name} = {engine_name}.Analysis")
    lines.append(f"{report_model_name} = {engine_name}.Report")
    lines.append("")

    return "\n".join(lines)


# --- Main migration logic ---


def analyze_file(filepath: Path) -> dict | None:
    """Analyze a single engine file and return migration info."""
    source = filepath.read_text()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    engine_class = find_engine_class(tree)
    if engine_class is None:
        return None

    enums = extract_enums(tree)
    models = find_model_classes(tree)
    classification = classify_engine(tree, engine_class)

    # Get model names
    model_names = [m.name for m in models]
    record_model = model_names[0] if len(model_names) >= 1 else "Record"
    analysis_model = model_names[1] if len(model_names) >= 2 else "Analysis"
    report_model = model_names[2] if len(model_names) >= 3 else "Report"

    # Extract record fields
    record_fields = extract_record_fields(tree, record_model)

    # Map each enum class to its field name on the Record model.
    # We need exactly one field name per enum, in order.
    enum_field_names: list[str] = []
    used_fields: set[str] = set()
    for e in enums:
        ename = e["name"]
        # Try to find a Record field whose type matches this enum class
        found = False
        for f in record_fields:
            if f["name"] in used_fields:
                continue
            # Match exact type or Optional (e.g. "TamperIndicator | None")
            if f["type_str"] == ename or f["type_str"].startswith(ename + " |"):
                enum_field_names.append(f["name"])
                used_fields.add(f["name"])
                found = True
                break
        if not found:
            # Fall back: snake_case of enum class name
            cname = ename
            snake = ""
            for i, c in enumerate(cname):
                if c.isupper() and i > 0:
                    snake += "_"
                snake += c.lower()
            enum_field_names.append(snake)
            used_fields.add(snake)

    score_field = detect_score_field(record_fields)
    key_field = detect_key_field(record_fields)
    ingest_method = detect_ingest_method(engine_class)
    engine_docstring = get_engine_docstring(engine_class)
    module_docstring = get_module_docstring(tree)

    return {
        "filepath": filepath,
        "source": source,
        "line_count": len(source.splitlines()),
        "engine_name": engine_class.name,
        "engine_docstring": engine_docstring,
        "module_docstring": module_docstring,
        "enums": enums,
        "record_model": record_model,
        "analysis_model": analysis_model,
        "report_model": report_model,
        "record_fields": record_fields,
        "enum_field_names": enum_field_names,
        "score_field": score_field,
        "key_field": key_field,
        "ingest_method": ingest_method,
        "classification": classification,
    }


def migrate_file(info: dict) -> str:
    """Generate migrated code for a pure-template engine."""
    return generate_migrated_code(
        module_docstring=info["module_docstring"],
        engine_name=info["engine_name"],
        engine_docstring=info["engine_docstring"],
        enums=info["enums"],
        record_fields=info["record_fields"],
        score_field=info["score_field"],
        key_field=info["key_field"],
        ingest_method=info["ingest_method"],
        record_model_name=info["record_model"],
        analysis_model_name=info["analysis_model"],
        report_model_name=info["report_model"],
        enum_field_names=info["enum_field_names"],
    )


def verify_migrated_code(code: str) -> tuple[bool, str]:
    """Verify migrated code parses and is syntactically valid."""
    try:
        ast.parse(code)
        return True, ""
    except SyntaxError as e:
        return False, str(e)


def run_migration(
    base_path: Path,
    package: str,
    *,
    dry_run: bool = False,
    limit: int | None = None,
) -> dict:
    """Run migration on a package. Returns stats."""
    pkg_path = base_path / package
    if not pkg_path.exists():
        print(f"  Package {package} not found at {pkg_path}")
        return {}

    files = sorted(
        f for f in pkg_path.glob("*.py") if not f.name.startswith("__") and f.suffix == ".py"
    )
    if limit:
        files = files[:limit]

    stats = {
        "total": len(files),
        "pure_template": 0,
        "custom_logic": 0,
        "migrated": 0,
        "failed": 0,
        "skipped": 0,
        "original_lines": 0,
        "migrated_lines": 0,
        "custom_files": [],
        "failed_files": [],
        "migrated_files": [],
    }

    for f in files:
        info = analyze_file(f)
        if info is None:
            stats["skipped"] += 1
            continue

        stats["original_lines"] += info["line_count"]
        classification = info["classification"]

        if not classification["is_pure"]:
            stats["custom_logic"] += 1
            stats["custom_files"].append(
                {
                    "file": f.name,
                    "reasons": classification["reasons"],
                }
            )
            # Still count lines as-is
            stats["migrated_lines"] += info["line_count"]
            continue

        stats["pure_template"] += 1

        # Generate migrated code
        new_code = migrate_file(info)
        valid, err = verify_migrated_code(new_code)
        if not valid:
            stats["failed"] += 1
            stats["failed_files"].append({"file": f.name, "error": err})
            stats["migrated_lines"] += info["line_count"]
            continue

        new_lines = len(new_code.splitlines())
        stats["migrated_lines"] += new_lines
        stats["migrated_files"].append(
            {
                "file": f.name,
                "old_lines": info["line_count"],
                "new_lines": new_lines,
            }
        )

        if dry_run:
            stats["migrated"] += 1
        else:
            # Write the migrated file
            f.write_text(new_code)
            stats["migrated"] += 1

    return stats


def print_stats(stats: dict, package: str, dry_run: bool) -> None:
    prefix = "[DRY RUN] " if dry_run else ""
    print(f"\n{prefix}Migration results for {package}/:")
    print(f"  Total files scanned: {stats['total']}")
    print(f"  Pure-template (migratable): {stats['pure_template']}")
    print(f"  Custom-logic (skipped): {stats['custom_logic']}")
    print(f"  Successfully migrated: {stats['migrated']}")
    print(f"  Failed: {stats['failed']}")
    print(f"  Skipped (no engine): {stats['skipped']}")
    print()
    print(f"  Original lines: {stats['original_lines']:,}")
    print(f"  After migration lines: {stats['migrated_lines']:,}")
    reduction = stats["original_lines"] - stats["migrated_lines"]
    if stats["original_lines"] > 0:
        pct = reduction / stats["original_lines"] * 100
        print(f"  Line reduction: {reduction:,} ({pct:.1f}%)")

    if stats["failed_files"]:
        print(f"\n  Failed files ({len(stats['failed_files'])}):")
        for ff in stats["failed_files"]:
            print(f"    {ff['file']}: {ff['error']}")

    if stats["custom_files"]:
        print(f"\n  Custom-logic files ({len(stats['custom_files'])}):")
        for cf in stats["custom_files"][:20]:
            reasons = "; ".join(cf["reasons"])
            print(f"    {cf['file']}: {reasons}")
        if len(stats["custom_files"]) > 20:
            print(f"    ... and {len(stats['custom_files']) - 20} more")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bulk engine migration tool")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing files")
    parser.add_argument("--package", type=str, help="Migrate a specific package")
    parser.add_argument("--all", action="store_true", help="Migrate all packages")
    parser.add_argument("--limit", type=int, help="Limit number of files to process")
    parser.add_argument("--count", action="store_true", help="Count engine files per package")
    parser.add_argument(
        "--verify-imports",
        action="store_true",
        help="After migration, verify all migrated modules import correctly",
    )
    args = parser.parse_args()

    base_path = Path(__file__).parent.parent / "src" / "shieldops"

    if args.count:
        for pkg in ENGINE_PACKAGES:
            pkg_path = base_path / pkg
            if pkg_path.exists():
                count = len([f for f in pkg_path.glob("*.py") if not f.name.startswith("__")])
                print(f"  {pkg}: {count} files")
        return

    if args.package:
        packages = [args.package]
    elif args.all:
        packages = ENGINE_PACKAGES
    else:
        print("Usage: python scripts/migrate_engines.py --package security [--dry-run] [--limit N]")
        print("       python scripts/migrate_engines.py --all [--dry-run]")
        print("       python scripts/migrate_engines.py --count")
        return

    all_stats: dict[str, dict] = {}
    for pkg in packages:
        stats = run_migration(
            base_path,
            pkg,
            dry_run=args.dry_run,
            limit=args.limit,
        )
        if stats:
            all_stats[pkg] = stats
            print_stats(stats, pkg, args.dry_run)

    # Summary
    if len(all_stats) > 1:
        total_orig = sum(s["original_lines"] for s in all_stats.values())
        total_new = sum(s["migrated_lines"] for s in all_stats.values())
        total_migrated = sum(s["migrated"] for s in all_stats.values())
        total_custom = sum(s["custom_logic"] for s in all_stats.values())
        print(f"\n{'=' * 60}")
        print(f"TOTAL: {total_migrated} migrated, {total_custom} custom-logic")
        print(f"Lines: {total_orig:,} -> {total_new:,} (reduction: {total_orig - total_new:,})")

    if args.verify_imports:
        print("\n--- Verifying imports ---")
        failures = 0
        for pkg, stats in all_stats.items():
            for mf in stats.get("migrated_files", []):
                mod_name = mf["file"].replace(".py", "")
                fqn = f"shieldops.{pkg}.{mod_name}"
                try:
                    __import__(fqn)
                except Exception as e:
                    print(f"  FAIL: {fqn}: {e}")
                    failures += 1
        if failures == 0:
            print("  All migrated modules import successfully!")
        else:
            print(f"  {failures} import failure(s)")


if __name__ == "__main__":
    main()
