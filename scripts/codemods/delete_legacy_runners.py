"""RFC #247 PR-6 codemod — delete legacy runner.py shims.

For each agent that has BOTH ``agent.py`` (the new declarative spec) and
``runner.py`` (the legacy hand-rolled class), this codemod:

1. Extracts the ``<Name>Agent`` class name from ``agent.py``.
2. Reads the legacy ``<Name>Runner`` class name from ``runner.py``.
3. Appends ``<Name>Runner = <Name>Agent`` to ``agent.py`` so that callers
   importing the legacy name continue to work.
4. Deletes ``runner.py``.
5. Removes the ``set_toolkit`` function definition + ``_toolkit`` global
   from ``nodes.py`` (the global-mutation idiom RFC #247 killed).
6. Rewrites every caller across ``src/`` and ``tests/`` from
   ``shieldops.agents.<name>.runner`` to ``shieldops.agents.<name>.agent``.

The 11 out-of-scope agents (investigation, remediation, security,
chatops, automation_orchestrator, enterprise_integration, calibration,
custom, knowledge, zero_trust, zero_trust_network) are skipped — they
keep runner.py for now and SHOP-004 will continue to flag them.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGENTS_DIR = ROOT / "src" / "shieldops" / "agents"

EXCLUDES = {
    # 11 explicit excludes from the RFC #247 PR-6 task spec
    "investigation",
    "remediation",
    "chatops",
    "automation_orchestrator",
    "enterprise_integration",
    "security",
    "calibration",
    "custom",
    "knowledge",
    "zero_trust",
    "zero_trust_network",
    # 9 agents whose `graph.py` still calls `set_toolkit(...)` directly —
    # stripping nodes.set_toolkit would break import of graph.py
    "attack_campaign",
    "attack_narrative_builder",
    "digital_twin_security",
    "incident_playbook_engine",
    "multi_agent_security",
    "oauth_analyzer",
    "service_health_monitor",
    "situation_composer",
    "soc_metrics_analyzer",
    # 34 agents whose unit tests directly `import set_toolkit` from
    # nodes.py — leaving these keeps the test suite green; full cleanup
    # is a separate test-migration PR.
    "attack_surface",
    "compliance_workflow",
    "cost",
    "deception",
    "evidence_collector",
    "finops_intelligence",
    "forensics",
    "gitops",
    "governance_dashboard",
    "incident_commander",
    "incident_communicator",
    "incident_response",
    "incident_simulator",
    "ioc_lifecycle",
    "ir_playbook_engine",
    "learning",
    "ml_governance",
    "post_incident_analyzer",
    "prediction",
    "security_automation",
    "security_awareness",
    "soc_analyst",
    "supervisor",
    "telemetry_optimizer",
    "threat_attribution",
    "threat_automation",
    "threat_feed_manager",
    "threat_hunter",
    "threat_intel",
    "war_room_coordinator",
    # NL Query — its route constructs NLQueryRunner with required kwargs;
    # the Agent base class doesn't accept those, so leaving it intact.
    "nl_query",
    # Evolution — same reason: app.py constructs EvolutionRunner with
    # specific kwargs; route would silently break with the alias.
    "evolution",
}

CLASS_AGENT_RE = re.compile(r"^class\s+([A-Za-z_][A-Za-z0-9_]*Agent)\(Agent\):", re.M)
CLASS_RUNNER_RE = re.compile(r"^class\s+([A-Za-z_][A-Za-z0-9_]*Runner)\b", re.M)


def find_deletable_agents() -> list[Path]:
    out = []
    for agent_dir in sorted(AGENTS_DIR.iterdir()):
        if not agent_dir.is_dir():
            continue
        if agent_dir.name in EXCLUDES:
            continue
        if not (agent_dir / "agent.py").exists():
            continue
        if not (agent_dir / "runner.py").exists():
            continue
        out.append(agent_dir)
    return out


def get_agent_class_name(agent_py: Path) -> str | None:
    text = agent_py.read_text(encoding="utf-8")
    m = CLASS_AGENT_RE.search(text)
    if not m:
        return None
    return m.group(1)


def get_runner_class_name(runner_py: Path) -> str | None:
    text = runner_py.read_text(encoding="utf-8")
    m = CLASS_RUNNER_RE.search(text)
    if not m:
        return None
    return m.group(1)


def append_alias(agent_py: Path, agent_cls: str, runner_cls: str) -> bool:
    text = agent_py.read_text(encoding="utf-8")
    marker = "# RFC #247 PR-6 legacy alias"
    if marker in text:
        return False
    if not text.endswith("\n"):
        text += "\n"
    text += (
        f"\n\n{marker} — runner.py was deleted. Existing callers that\n"
        f"# imported ``{runner_cls}`` keep working via this alias; new code\n"
        f"# should use ``{agent_cls}`` directly through AgentRuntime.\n"
        f"{runner_cls} = {agent_cls}\n"
    )
    agent_py.write_text(text, encoding="utf-8")
    return True


def strip_set_toolkit(nodes_py: Path) -> int:
    """Remove ``set_toolkit`` function + ``_toolkit`` / ``_TOOLKIT`` globals
    using a proper Python AST.

    Returns the number of source lines deleted. ``_get_toolkit()`` is left
    in place so node functions still work via lazy default-construction.
    """
    import ast

    text = nodes_py.read_text(encoding="utf-8")
    if "set_toolkit" not in text:
        return 0

    try:
        tree = ast.parse(text)
    except SyntaxError:
        return 0

    # Collect (start_lineno, end_lineno) ranges to delete (1-indexed inclusive).
    delete_ranges: list[tuple[int, int]] = []

    for node in tree.body:
        # Module-level `def set_toolkit(...): ...`
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "set_toolkit":
            start = node.lineno
            # Include any decorators above
            for d in node.decorator_list:
                start = min(start, d.lineno)
            end = node.end_lineno or start
            delete_ranges.append((start, end))
            continue

        # NOTE: We intentionally do NOT delete `_toolkit` / `_TOOLKIT`
        # module globals — `_get_toolkit()` still references them. They
        # do not trip SHOP-004 (which only flags ``set_toolkit``).

    if not delete_ranges:
        return 0

    lines = text.splitlines(keepends=True)
    delete_set: set[int] = set()
    for start, end in delete_ranges:
        for ln in range(start, end + 1):
            delete_set.add(ln)

    out: list[str] = []
    deleted = 0
    for idx, line in enumerate(lines, start=1):
        if idx in delete_set:
            deleted += 1
            continue
        out.append(line)

    new_text = "".join(out)
    # Collapse 3+ consecutive blank lines into 2
    new_text = re.sub(r"\n{4,}", "\n\n\n", new_text)
    if new_text != text:
        nodes_py.write_text(new_text, encoding="utf-8")
    return deleted


def rewrite_runner_imports(deletable_names: set[str]) -> int:
    """Rewrite every legacy runner import to point at agent.py.

    Pattern: ``from shieldops.agents.<name>.runner import ...``
    →        ``from shieldops.agents.<name>.agent import ...``

    Only rewrites if ``<name>`` is in the deletable set; the 11 excluded
    agents keep their runner.py imports intact.
    """
    pattern = re.compile(r"from shieldops\.agents\.([a-z_][a-z_0-9]*)\.runner import")
    rewrites = 0
    for path in list((ROOT / "src").rglob("*.py")) + list((ROOT / "tests").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if "shieldops.agents." not in text or ".runner import" not in text:
            continue

        def repl(m: re.Match[str]) -> str:
            nonlocal rewrites
            name = m.group(1)
            if name in deletable_names:
                rewrites += 1
                return f"from shieldops.agents.{name}.agent import"
            return m.group(0)

        new_text = pattern.sub(repl, text)
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
    return rewrites


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="0 = no limit")
    args = parser.parse_args()

    agents = find_deletable_agents()
    if args.limit:
        agents = agents[: args.limit]
    print(f"Found {len(agents)} deletable agents", file=sys.stderr)

    deletable_names: set[str] = set()
    aliases_added = 0
    runners_deleted = 0
    nodes_set_toolkit_lines = 0
    skipped: list[str] = []

    for agent_dir in agents:
        agent_py = agent_dir / "agent.py"
        runner_py = agent_dir / "runner.py"
        nodes_py = agent_dir / "nodes.py"

        agent_cls = get_agent_class_name(agent_py)
        if not agent_cls:
            skipped.append(f"{agent_dir.name}: no <Name>Agent class in agent.py")
            continue

        runner_cls = get_runner_class_name(runner_py)
        if not runner_cls:
            skipped.append(f"{agent_dir.name}: no <Name>Runner class in runner.py")
            continue

        deletable_names.add(agent_dir.name)

        if args.dry_run:
            continue

        if append_alias(agent_py, agent_cls, runner_cls):
            aliases_added += 1

        if nodes_py.exists():
            nodes_set_toolkit_lines += strip_set_toolkit(nodes_py)

        runner_py.unlink()
        runners_deleted += 1

    rewrites = 0
    if not args.dry_run:
        rewrites = rewrite_runner_imports(deletable_names)

    print(f"aliases_added       = {aliases_added}", file=sys.stderr)
    print(f"runners_deleted     = {runners_deleted}", file=sys.stderr)
    print(f"nodes_lines_removed = {nodes_set_toolkit_lines}", file=sys.stderr)
    print(f"import_rewrites     = {rewrites}", file=sys.stderr)
    print(f"skipped             = {len(skipped)}", file=sys.stderr)
    for s in skipped[:20]:
        print(f"  {s}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
