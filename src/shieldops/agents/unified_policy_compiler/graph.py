"""LangGraph workflow for the Unified Policy Compiler."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.tracing import traced_node
from shieldops.agents.unified_policy_compiler.models import (
    UnifiedPolicyCompilerState,
)
from shieldops.agents.unified_policy_compiler.nodes import (
    compile_ruleset,
    generate_report,
    ingest_policies,
    parse_requirements,
    resolve_conflicts,
    validate_coverage,
)

_AGENT = "unified_policy_compiler"


def _should_resolve(
    state: UnifiedPolicyCompilerState,
) -> str:
    if state.error:
        return "generate_report"
    if state.parsed_requirements:
        return "resolve_conflicts"
    return "generate_report"


def _should_validate(
    state: UnifiedPolicyCompilerState,
) -> str:
    if state.compiled_rules:
        return "validate_coverage"
    return "generate_report"


def create_unified_policy_compiler_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the Unified Policy Compiler LangGraph.

    Workflow:
        ingest_policies -> parse_requirements
          -> [has_requirements?] -> resolve_conflicts
          -> compile_ruleset
          -> [has_rules?] -> validate_coverage
          -> generate_report
    """
    graph = StateGraph(UnifiedPolicyCompilerState)

    graph.add_node(
        "ingest_policies",
        traced_node(f"{_AGENT}.ingest_policies", _AGENT)(
            ingest_policies,
        ),
    )
    graph.add_node(
        "parse_requirements",
        traced_node(
            f"{_AGENT}.parse_requirements",
            _AGENT,
        )(parse_requirements),
    )
    graph.add_node(
        "resolve_conflicts",
        traced_node(f"{_AGENT}.resolve_conflicts", _AGENT)(
            resolve_conflicts,
        ),
    )
    graph.add_node(
        "compile_ruleset",
        traced_node(f"{_AGENT}.compile_ruleset", _AGENT)(
            compile_ruleset,
        ),
    )
    graph.add_node(
        "validate_coverage",
        traced_node(f"{_AGENT}.validate_coverage", _AGENT)(
            validate_coverage,
        ),
    )
    graph.add_node(
        "generate_report",
        traced_node(f"{_AGENT}.generate_report", _AGENT)(
            generate_report,
        ),
    )

    graph.set_entry_point("ingest_policies")
    graph.add_edge("ingest_policies", "parse_requirements")
    graph.add_conditional_edges(
        "parse_requirements",
        _should_resolve,
        {
            "resolve_conflicts": "resolve_conflicts",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("resolve_conflicts", "compile_ruleset")
    graph.add_conditional_edges(
        "compile_ruleset",
        _should_validate,
        {
            "validate_coverage": "validate_coverage",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("validate_coverage", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
