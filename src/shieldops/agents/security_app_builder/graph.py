"""Security App Builder Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import SecurityAppBuilderState
from .nodes import (
    deploy_app,
    design_workflow,
    generate_code,
    parse_requirements,
    report,
    validate_security,
)
from .tools import SecurityAppBuilderToolkit


def _should_deploy(state: Any) -> str:
    """Route based on security validation results."""
    vals = state.validations if hasattr(state, "validations") else state.get("validations", [])

    if hasattr(state, "code_quality_score"):
        score = state.code_quality_score
    else:
        score = state.get("code_quality_score", 0.0)

    # Block deployment if critical checks failed
    for v in vals:
        severity = v.get("severity", "info") if isinstance(v, dict) else v.severity
        passed = v.get("passed", True) if isinstance(v, dict) else v.passed
        if severity == "critical" and not passed:
            return "report"

    # Deploy if quality score is acceptable
    if score >= 0.7:
        return "deploy"

    return "report"


def build_graph(
    toolkit: SecurityAppBuilderToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Security App Builder agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        return dict(state) if not isinstance(state, dict) else state

    async def _parse(
        state: Any,
    ) -> dict[str, Any]:
        return await parse_requirements(_to_dict(state), toolkit)

    async def _design(
        state: Any,
    ) -> dict[str, Any]:
        return await design_workflow(_to_dict(state), toolkit)

    async def _generate(
        state: Any,
    ) -> dict[str, Any]:
        return await generate_code(_to_dict(state), toolkit)

    async def _validate(
        state: Any,
    ) -> dict[str, Any]:
        return await validate_security(_to_dict(state), toolkit)

    async def _deploy(
        state: Any,
    ) -> dict[str, Any]:
        return await deploy_app(_to_dict(state), toolkit)

    async def _report(
        state: Any,
    ) -> dict[str, Any]:
        return await report(_to_dict(state), toolkit)

    graph = StateGraph(SecurityAppBuilderState)
    graph.add_node("parse_requirements", _parse)
    graph.add_node("design_workflow", _design)
    graph.add_node("generate_code", _generate)
    graph.add_node("validate_security", _validate)
    graph.add_node("deploy_app", _deploy)
    graph.add_node("report", _report)

    graph.set_entry_point("parse_requirements")
    graph.add_edge("parse_requirements", "design_workflow")
    graph.add_edge("design_workflow", "generate_code")
    graph.add_edge("generate_code", "validate_security")
    graph.add_conditional_edges(
        "validate_security",
        _should_deploy,
        {"deploy": "deploy_app", "report": "report"},
    )
    graph.add_edge("deploy_app", "report")
    graph.add_edge("report", END)

    return graph


def create_security_app_builder_graph(
    code_store: Any | None = None,
    registry_client: Any | None = None,
    opa_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Security App Builder graph with deps."""
    toolkit = SecurityAppBuilderToolkit(
        code_store=code_store,
        registry_client=registry_client,
        opa_client=opa_client,
    )
    return build_graph(toolkit)
