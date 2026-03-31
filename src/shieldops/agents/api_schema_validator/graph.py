"""LangGraph workflow for the API Schema Validator Agent."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from shieldops.agents.api_schema_validator.models import (
    APISchemaValidatorState,
)
from shieldops.agents.api_schema_validator.nodes import (
    assess_impact,
    detect_breaking,
    discover_schemas,
    generate_fixes,
    generate_report,
    validate_contracts,
)
from shieldops.agents.tracing import traced_node

_AGENT = "api_schema_validator"


def _should_validate(
    state: APISchemaValidatorState,
) -> str:
    """Route after discovery based on results."""
    if state.error:
        return "generate_report"
    if state.discovered_schemas:
        return "validate_contracts"
    return "generate_report"


def _should_fix(
    state: APISchemaValidatorState,
) -> str:
    """Route after impact assessment."""
    if state.breaking_changes or state.contract_violations:
        return "generate_fixes"
    return "generate_report"


def create_api_schema_validator_graph() -> StateGraph:  # type: ignore[type-arg]
    """Build the API Schema Validator LangGraph.

    Workflow:
        discover_schemas
          -> [has_schemas?] -> validate_contracts
          -> detect_breaking
          -> assess_impact
          -> [has_issues?] -> generate_fixes
          -> generate_report
    """
    graph = StateGraph(APISchemaValidatorState)

    graph.add_node(
        "discover_schemas",
        traced_node(
            f"{_AGENT}.discover_schemas",
            _AGENT,
        )(discover_schemas),
    )
    graph.add_node(
        "validate_contracts",
        traced_node(
            f"{_AGENT}.validate_contracts",
            _AGENT,
        )(validate_contracts),
    )
    graph.add_node(
        "detect_breaking",
        traced_node(
            f"{_AGENT}.detect_breaking",
            _AGENT,
        )(detect_breaking),
    )
    graph.add_node(
        "assess_impact",
        traced_node(
            f"{_AGENT}.assess_impact",
            _AGENT,
        )(assess_impact),
    )
    graph.add_node(
        "generate_fixes",
        traced_node(
            f"{_AGENT}.generate_fixes",
            _AGENT,
        )(generate_fixes),
    )
    graph.add_node(
        "generate_report",
        traced_node(
            f"{_AGENT}.generate_report",
            _AGENT,
        )(generate_report),
    )

    # Edges
    graph.set_entry_point("discover_schemas")
    graph.add_conditional_edges(
        "discover_schemas",
        _should_validate,
        {
            "validate_contracts": "validate_contracts",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("validate_contracts", "detect_breaking")
    graph.add_edge("detect_breaking", "assess_impact")
    graph.add_conditional_edges(
        "assess_impact",
        _should_fix,
        {
            "generate_fixes": "generate_fixes",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("generate_fixes", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
