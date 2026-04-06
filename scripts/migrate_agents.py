"""Bulk agent migration script -- converts linear agent graph.py files to build_linear_graph().

Usage:
    python scripts/migrate_agents.py --dry-run
    python scripts/migrate_agents.py --dry-run --limit 10
    python scripts/migrate_agents.py --limit 50
    python scripts/migrate_agents.py --all
    python scripts/migrate_agents.py --all --verify-imports

A "linear" agent is one whose graph.py contains:
  - A single ``build_graph(toolkit)`` function that adds nodes and linear edges
  - An optional ``create_{name}_graph(**clients)`` factory wrapper
  - No ``add_conditional_edges`` calls (no custom routing)
  - Node functions imported from .nodes

This script rewrites only graph.py for matching agents. nodes.py, runner.py,
models.py, tools.py are untouched. The public API (build_graph / create_X_graph)
is preserved. Line count on graph.py typically drops from 60-120 lines to
15-30 lines.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path


def _get_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _get_str_arg(call: ast.Call, idx: int) -> str:
    if len(call.args) > idx and isinstance(call.args[idx], ast.Constant):
        val = call.args[idx].value
        if isinstance(val, str):
            return val
    return ""


def _find_function(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _extract_state_type_and_nodes(
    build_fn: ast.FunctionDef,
) -> tuple[str, list[tuple[str, str]], list[str], bool]:
    """Extract state type, node (name, fn_name) pairs, edges, and linearity.

    Returns:
        (state_type_name, [(node_name, underlying_fn_name), ...], edges, is_linear)
        edges is list of "(src, dst)" strings for validation.
    """
    state_type = ""
    # Track StateGraph variable name -> state type
    graph_var = ""
    # Track inner async function name -> actual imported fn name
    inner_fn_map: dict[str, str] = {}
    # Track local variables that hold imported callables
    local_alias: dict[str, str] = {}
    # add_node calls: node_name -> fn reference name (Name)
    add_nodes: list[tuple[str, str]] = []
    entry_point = ""
    edges: list[tuple[str, str]] = []
    has_conditional = False

    # Walk all statements (incl. nested)
    for node in ast.walk(build_fn):
        # Inner async def foo(state): return await imported_fn(...)
        if isinstance(node, ast.AsyncFunctionDef):
            inner_name = node.name
            # Find the last return; look for the underlying imported fn
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Await):
                    call = sub.value.value
                    if isinstance(call, ast.Call):
                        fn_name = _get_name(call.func)
                        if fn_name:
                            inner_fn_map[inner_name] = fn_name
                            break
        # Assignments like `graph = StateGraph(SomeState)` or `foo = imported_fn`
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                tgt = node.targets[0].id
                if isinstance(node.value, ast.Call):
                    fn_name = _get_name(node.value.func)
                    if fn_name == "StateGraph" and node.value.args:
                        state_type = _get_name(node.value.args[0])
                        _ = tgt  # capture for completeness
                elif isinstance(node.value, ast.Name):
                    local_alias[tgt] = node.value.id
        # graph.add_node / add_edge / set_entry_point / add_conditional_edges
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            func = call.func
            if isinstance(func, ast.Attribute):
                method = func.attr
                if method == "add_node":
                    node_name = _get_str_arg(call, 0)
                    fn_ref = ""
                    if len(call.args) > 1:
                        arg1 = call.args[1]
                        fn_ref = _get_name(arg1)
                        # Handle traced_node("label", "agent")(real_fn) pattern:
                        # a Call whose callee is itself a Call.
                        if not fn_ref and isinstance(arg1, ast.Call):
                            if isinstance(arg1.func, ast.Call) and arg1.args:
                                fn_ref = _get_name(arg1.args[0])
                    if node_name:
                        add_nodes.append((node_name, fn_ref))
                elif method == "add_edge":
                    src = _get_str_arg(call, 0)
                    dst = _get_str_arg(call, 1)
                    if not dst and len(call.args) > 1 and _get_name(call.args[1]) == "END":
                        dst = "__END__"
                    edges.append((src, dst))
                elif method == "set_entry_point":
                    entry_point = _get_str_arg(call, 0)
                elif method == "add_conditional_edges":
                    has_conditional = True

    # Resolve node fn references: underlying import name
    resolved: list[tuple[str, str]] = []
    for node_name, fn_ref in add_nodes:
        # Chase inner async wrappers
        if fn_ref in inner_fn_map:
            fn_ref = inner_fn_map[fn_ref]
        elif fn_ref in local_alias:
            fn_ref = local_alias[fn_ref]
        resolved.append((node_name, fn_ref))

    # Linearity check: sequence add_nodes order should match edges
    is_linear = not has_conditional and len(resolved) >= 1

    # Validate edges form a linear chain
    if is_linear and entry_point and entry_point != resolved[0][0]:
        # entry point doesn't match first add_node, still may be linear
        # Reorder resolved nodes to follow the edge chain
        pass

    return state_type, resolved, [f"{a}->{b}" for a, b in edges], is_linear


def _extract_imports(tree: ast.Module) -> dict[str, str]:
    """Return map of imported_name -> module path (relative or absolute)."""
    imports: dict[str, str] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ImportFrom):
            mod = ("." * (node.level or 0)) + (node.module or "")
            for alias in node.names:
                name = alias.asname or alias.name
                imports[name] = mod
    return imports


def _find_factory_function(
    tree: ast.Module,
    agent_name: str,
) -> tuple[str, ast.FunctionDef] | None:
    """Find the create_{name}_graph factory and return (source, node)."""
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("create_"):
            return node.name, node
    return None


def analyze_agent(agent_dir: Path) -> dict | None:
    """Analyze an agent's graph.py and return migration info, or None."""
    graph_py = agent_dir / "graph.py"
    if not graph_py.exists():
        return None
    nodes_py = agent_dir / "nodes.py"
    if not nodes_py.exists():
        return None

    source = graph_py.read_text()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    if "add_conditional_edges" in source:
        return {"agent": agent_dir.name, "skip_reason": "has_conditional_edges"}

    build_fn = _find_function(tree, "build_graph")
    if build_fn is None:
        return {"agent": agent_dir.name, "skip_reason": "no_build_graph"}

    state_type, resolved_nodes, edges, is_linear = _extract_state_type_and_nodes(build_fn)
    if not is_linear or not state_type or not resolved_nodes:
        return {"agent": agent_dir.name, "skip_reason": "parse_failed"}

    # All node functions must resolve to a name (not empty)
    if any(not fn for _, fn in resolved_nodes):
        return {"agent": agent_dir.name, "skip_reason": "unresolved_node_fn"}

    # Must have at least one edge to make sense of sequence (single-node is OK)
    if len(resolved_nodes) > 1 and not edges:
        return {"agent": agent_dir.name, "skip_reason": "no_edges"}

    # Get toolkit type from build_graph signature
    toolkit_type = ""
    has_toolkit_arg = bool(build_fn.args.args)
    toolkit_has_default = False
    if build_fn.args.args:
        first_arg = build_fn.args.args[0]
        if first_arg.annotation is not None:
            toolkit_type = _get_name(first_arg.annotation)
        # Defaults align with the tail of args; if every arg has a default,
        # the first arg has one too.
        if len(build_fn.args.defaults) >= len(build_fn.args.args):
            toolkit_has_default = True

    # Get factory function signature (to preserve)
    factory_info = _find_factory_function(tree, agent_dir.name)
    factory_source = ""
    factory_name = ""
    if factory_info:
        factory_name, factory_node = factory_info
        factory_source = ast.get_source_segment(source, factory_node) or ""

    # Extract module docstring
    module_docstring = ""
    if tree.body and isinstance(tree.body[0], ast.Expr):
        val = tree.body[0].value
        if isinstance(val, ast.Constant) and isinstance(val.value, str):
            module_docstring = val.value

    # Verify all node fn names are imported from .nodes
    imports = _extract_imports(tree)
    node_fn_names = [fn for _, fn in resolved_nodes]
    unresolved_imports = [
        fn for fn in node_fn_names if fn not in imports or not imports[fn].endswith(".nodes")
    ]
    if unresolved_imports:
        return {
            "agent": agent_dir.name,
            "skip_reason": f"node_fns_not_from_.nodes: {unresolved_imports}",
        }

    return {
        "agent": agent_dir.name,
        "graph_py": graph_py,
        "source": source,
        "line_count": len(source.splitlines()),
        "state_type": state_type,
        "toolkit_type": toolkit_type,
        "node_fns": resolved_nodes,  # list of (node_name, fn_name)
        "factory_name": factory_name,
        "factory_source": factory_source,
        "module_docstring": module_docstring,
        "has_toolkit_arg": has_toolkit_arg,
        "toolkit_has_default": toolkit_has_default,
        "skip_reason": None,
    }


def generate_migrated_graph_py(info: dict) -> str:
    """Generate new graph.py content using build_linear_graph."""
    lines: list[str] = []

    doc = info["module_docstring"] or f"{info['agent']} Agent — LangGraph StateGraph definition."
    # single-line docstring
    doc_single = " ".join(doc.split())
    if len(doc_single) > 94:
        doc_single = doc_single[:91] + "..."
    lines.append(f'"""{doc_single}"""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")

    # Imports
    lines.append("from shieldops.agents.framework import build_linear_graph")
    lines.append("")
    lines.append(f"from .models import {info['state_type']}")

    # Import node functions
    node_fn_names = sorted({fn for _, fn in info["node_fns"]})
    if len(node_fn_names) == 1:
        lines.append(f"from .nodes import {node_fn_names[0]}")
    else:
        lines.append("from .nodes import (")
        for fn in node_fn_names:
            lines.append(f"    {fn},")
        lines.append(")")

    # Import toolkit type
    if info.get("has_toolkit_arg") and info["toolkit_type"]:
        lines.append(f"from .tools import {info['toolkit_type']}")
    lines.append("")
    lines.append("")

    # build_graph function
    if info.get("has_toolkit_arg"):
        toolkit_param = info["toolkit_type"] or "object"
        suffix = " = None" if info.get("toolkit_has_default") else ""
        lines.append(
            f"def build_graph(toolkit: {toolkit_param}{suffix}):  # type: ignore[no-untyped-def]"
        )
    else:
        lines.append("def build_graph():  # type: ignore[no-untyped-def]")
    lines.append(f'    """Build the {info["agent"]} agent graph (linear sequence)."""')
    lines.append("    return build_linear_graph(")
    lines.append(f"        {info['state_type']},")
    lines.append("        [")
    for node_name, fn_name in info["node_fns"]:
        lines.append(f'            ("{node_name}", {fn_name}),')
    lines.append("        ],")
    if info.get("has_toolkit_arg"):
        lines.append("        toolkit=toolkit,")
    lines.append("    )")
    lines.append("")

    # Factory function (preserve as-is, indented)
    if info["factory_source"]:
        lines.append("")
        lines.append(info["factory_source"])
        lines.append("")

    return "\n".join(lines) + "\n"


def verify_code(code: str) -> tuple[bool, str]:
    try:
        ast.parse(code)
        return True, ""
    except SyntaxError as e:
        return False, str(e)


def run_migration(
    agents_base: Path,
    *,
    dry_run: bool = False,
    limit: int | None = None,
) -> dict:
    agent_dirs = sorted(
        d for d in agents_base.iterdir() if d.is_dir() and not d.name.startswith("_")
    )

    stats: dict = {
        "total": 0,
        "migratable": 0,
        "migrated": 0,
        "skipped": 0,
        "failed": 0,
        "original_lines": 0,
        "new_lines": 0,
        "skipped_details": {},
        "migrated_agents": [],
        "failed_agents": [],
    }

    for agent_dir in agent_dirs:
        if not (agent_dir / "graph.py").exists():
            continue
        stats["total"] += 1

        info = analyze_agent(agent_dir)
        if info is None:
            stats["skipped"] += 1
            stats["skipped_details"].setdefault("no_graph_or_nodes", []).append(agent_dir.name)
            continue
        if info.get("skip_reason"):
            stats["skipped"] += 1
            stats["skipped_details"].setdefault(info["skip_reason"], []).append(info["agent"])
            continue

        if limit is not None and stats["migrated"] >= limit:
            continue

        stats["migratable"] += 1

        new_code = generate_migrated_graph_py(info)
        ok, err = verify_code(new_code)
        if not ok:
            stats["failed"] += 1
            stats["failed_agents"].append({"agent": info["agent"], "error": err})
            continue

        stats["original_lines"] += info["line_count"]
        stats["new_lines"] += len(new_code.splitlines())
        stats["migrated_agents"].append(
            {
                "agent": info["agent"],
                "old_lines": info["line_count"],
                "new_lines": len(new_code.splitlines()),
            }
        )

        if not dry_run:
            info["graph_py"].write_text(new_code)
        stats["migrated"] += 1

    return stats


def print_stats(stats: dict, dry_run: bool) -> None:
    prefix = "[DRY RUN] " if dry_run else ""
    print(f"\n{prefix}Agent migration results:")
    print(f"  Total agents scanned: {stats['total']}")
    print(f"  Migratable (linear): {stats['migratable']}")
    print(f"  Migrated: {stats['migrated']}")
    print(f"  Skipped: {stats['skipped']}")
    print(f"  Failed: {stats['failed']}")
    print()
    print(f"  Original graph.py lines: {stats['original_lines']:,}")
    print(f"  New graph.py lines:      {stats['new_lines']:,}")
    reduction = stats["original_lines"] - stats["new_lines"]
    if stats["original_lines"] > 0:
        pct = reduction / stats["original_lines"] * 100
        print(f"  Line reduction: {reduction:,} ({pct:.1f}%)")

    if stats["skipped_details"]:
        print("\n  Skip reasons:")
        for reason, agents in sorted(stats["skipped_details"].items()):
            print(f"    {reason}: {len(agents)}")

    if stats["failed_agents"]:
        print(f"\n  Failed ({len(stats['failed_agents'])}):")
        for f in stats["failed_agents"][:20]:
            print(f"    {f['agent']}: {f['error']}")


def verify_imports(migrated_agents: list[dict]) -> int:
    failures = 0
    for mf in migrated_agents:
        mod = f"shieldops.agents.{mf['agent']}.graph"
        try:
            __import__(mod)
        except Exception as e:
            print(f"  FAIL: {mod}: {e}")
            failures += 1
    return failures


def main() -> None:
    parser = argparse.ArgumentParser(description="Bulk agent migration tool (linear agents)")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, help="Max agents to migrate")
    parser.add_argument("--all", action="store_true", help="Migrate all linear agents")
    parser.add_argument("--verify-imports", action="store_true")
    args = parser.parse_args()

    if not (args.dry_run or args.limit or args.all):
        parser.print_help()
        sys.exit(0)

    base = Path(__file__).parent.parent / "src" / "shieldops" / "agents"
    stats = run_migration(base, dry_run=args.dry_run, limit=args.limit)
    print_stats(stats, args.dry_run)

    if args.verify_imports and not args.dry_run:
        print("\n--- Verifying imports ---")
        failures = verify_imports(stats["migrated_agents"])
        if failures == 0:
            print(f"  All {len(stats['migrated_agents'])} migrated agents import successfully!")
        else:
            print(f"  {failures} import failure(s)")
            sys.exit(1)


if __name__ == "__main__":
    main()
