"""Data Pipeline Protector Agent — LangGraph StateGraph definition."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from .models import DataPipelineProtectorState
from .nodes import (
    detect_anomalies,
    discover_pipelines,
    enforce_access,
    generate_report,
    scan_inputs,
    validate_schemas,
)
from .tools import DataPipelineProtectorToolkit


def _has_critical_findings(state: Any) -> str:
    """Route based on whether critical findings exist."""
    if hasattr(state, "model_dump"):
        d = state.model_dump()
    elif isinstance(state, dict):
        d = state
    else:
        d = dict(state)

    critical_scans = [s for s in d.get("input_scans", []) if s.get("severity") == "critical"]
    critical_anomalies = [a for a in d.get("data_anomalies", []) if a.get("severity") == "critical"]
    breaking_schemas = [v for v in d.get("schema_validations", []) if v.get("is_breaking", False)]

    has_critical = (
        len(critical_scans) > 0 or len(critical_anomalies) > 0 or len(breaking_schemas) > 0
    )

    return "enforce_access" if has_critical else "report"


def build_graph(
    toolkit: DataPipelineProtectorToolkit,
) -> StateGraph:  # type: ignore[type-arg]
    """Build the Data Pipeline Protector agent graph."""

    def _to_dict(state: Any) -> dict[str, Any]:
        if hasattr(state, "model_dump"):
            return state.model_dump()  # type: ignore[no-any-return]
        if isinstance(state, dict):
            return state
        return dict(state)

    async def _discover(state: Any) -> dict[str, Any]:
        return await discover_pipelines(
            _to_dict(state),
            toolkit,
        )

    async def _scan(state: Any) -> dict[str, Any]:
        return await scan_inputs(
            _to_dict(state),
            toolkit,
        )

    async def _anomalies(state: Any) -> dict[str, Any]:
        return await detect_anomalies(
            _to_dict(state),
            toolkit,
        )

    async def _schemas(state: Any) -> dict[str, Any]:
        return await validate_schemas(
            _to_dict(state),
            toolkit,
        )

    async def _access(state: Any) -> dict[str, Any]:
        return await enforce_access(
            _to_dict(state),
            toolkit,
        )

    async def _report(state: Any) -> dict[str, Any]:
        return await generate_report(
            _to_dict(state),
            toolkit,
        )

    graph = StateGraph(DataPipelineProtectorState)

    graph.add_node("discover_pipelines", _discover)
    graph.add_node("scan_inputs", _scan)
    graph.add_node("detect_anomalies", _anomalies)
    graph.add_node("validate_schemas", _schemas)
    graph.add_node("enforce_access", _access)
    graph.add_node("generate_report", _report)

    # Linear pipeline: discover -> scan -> anomalies -> schemas
    graph.set_entry_point("discover_pipelines")
    graph.add_edge("discover_pipelines", "scan_inputs")
    graph.add_edge("scan_inputs", "detect_anomalies")
    graph.add_edge("detect_anomalies", "validate_schemas")

    # Conditional: enforce access if critical, else report
    graph.add_conditional_edges(
        "validate_schemas",
        _has_critical_findings,
        {
            "enforce_access": "enforce_access",
            "report": "generate_report",
        },
    )

    graph.add_edge("enforce_access", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


def create_data_pipeline_protector_graph(
    pipeline_client: Any | None = None,
    schema_registry: Any | None = None,
    iam_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Data Pipeline Protector graph with deps."""
    toolkit = DataPipelineProtectorToolkit(
        pipeline_client=pipeline_client,
        schema_registry=schema_registry,
        iam_client=iam_client,
    )
    return build_graph(toolkit)
