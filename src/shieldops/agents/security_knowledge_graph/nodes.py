"""Node implementations for the Security Knowledge Graph."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_knowledge_graph.models import (
    ReasoningStep,
    SecurityKnowledgeGraphState,
    SKGStage,
)
from shieldops.agents.security_knowledge_graph.prompts import (
    SYSTEM_BUILD_GRAPH,
    SYSTEM_DETECT_ANOMALIES,
    SYSTEM_EXTRACT_RELATIONSHIPS,
    SYSTEM_INGEST_ENTITIES,
    SYSTEM_QUERY_PATTERNS,
    AnomalyDetectionOutput,
    EntityIngestionOutput,
    GraphBuildOutput,
    PatternQueryOutput,
    RelationshipExtractionOutput,
)
from shieldops.agents.security_knowledge_graph.tools import (
    SecurityKnowledgeGraphToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityKnowledgeGraphToolkit | None = None


def set_toolkit(
    toolkit: SecurityKnowledgeGraphToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityKnowledgeGraphToolkit:
    if _toolkit is None:
        return SecurityKnowledgeGraphToolkit()
    return _toolkit


def _step(
    state: SecurityKnowledgeGraphState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def ingest_entities(
    state: SecurityKnowledgeGraphState,
) -> dict[str, Any]:
    """Ingest security entities from data sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.ingest_entities(state.config)
    types = {e.get("entity_type") for e in raw}

    try:
        ctx = _json.dumps(
            {"sources": state.config.get("sources", []), "entity_count": len(raw)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INGEST_ENTITIES,
            user_prompt=f"Entity ingestion context:\n{ctx}",
            schema=EntityIngestionOutput,
        )
        if hasattr(llm_result, "total_entities"):
            logger.info("llm_enhanced", node="ingest_entities")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="ingest_entities")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "ingest_entities",
        f"sources={state.config.get('sources', [])}",
        f"ingested {len(raw)} entities, {len(types)} types",
        elapsed,
        "asset_inventory",
    )
    await toolkit.record_metric("entities_ingested", float(len(raw)))

    return {
        "entities": raw,
        "stage": SKGStage.EXTRACT_RELATIONSHIPS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "ingest_entities",
        "session_start": start,
    }


async def extract_relationships(
    state: SecurityKnowledgeGraphState,
) -> dict[str, Any]:
    """Extract relationships between entities."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    rels = await toolkit.extract_relationships(state.entities)
    high_conf = sum(1 for r in rels if r.get("confidence", 0) >= 0.8)

    try:
        ctx = _json.dumps(
            {"entity_count": len(state.entities), "relationship_count": len(rels)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_EXTRACT_RELATIONSHIPS,
            user_prompt=f"Relationship extraction context:\n{ctx}",
            schema=RelationshipExtractionOutput,
        )
        if hasattr(llm_result, "total_relationships"):
            logger.info("llm_enhanced", node="extract_relationships")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="extract_relationships")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "extract_relationships",
        f"analyzing {len(state.entities)} entities",
        f"{len(rels)} relationships, {high_conf} high-confidence",
        elapsed,
        "graph_db_client",
    )

    return {
        "relationships": rels,
        "stage": SKGStage.BUILD_GRAPH,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "extract_relationships",
    }


async def build_graph(
    state: SecurityKnowledgeGraphState,
) -> dict[str, Any]:
    """Build the knowledge graph structure."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    graph_info = await toolkit.build_graph(state.entities, state.relationships)

    try:
        ctx = _json.dumps(
            {
                "entities": len(state.entities),
                "relationships": len(state.relationships),
                "graph_info": graph_info[:5],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_BUILD_GRAPH,
            user_prompt=f"Graph construction context:\n{ctx}",
            schema=GraphBuildOutput,
        )
        if hasattr(llm_result, "nodes"):
            logger.info("llm_enhanced", node="build_graph")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="build_graph")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "build_graph",
        f"building from {len(state.entities)} entities, {len(state.relationships)} relationships",
        f"graph built with {len(graph_info)} components",
        elapsed,
        "graph_db_client",
    )
    await toolkit.record_metric("graph_nodes", float(len(state.entities)))

    return {
        "patterns": graph_info,
        "stage": SKGStage.QUERY_PATTERNS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "build_graph",
    }


async def query_patterns(
    state: SecurityKnowledgeGraphState,
) -> dict[str, Any]:
    """Query the graph for known threat patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    patterns = await toolkit.query_patterns(state.entities, state.relationships)

    try:
        ctx = _json.dumps(
            {"entity_count": len(state.entities), "pattern_count": len(patterns)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_QUERY_PATTERNS,
            user_prompt=f"Pattern query context:\n{ctx}",
            schema=PatternQueryOutput,
        )
        if hasattr(llm_result, "patterns_found"):
            logger.info("llm_enhanced", node="query_patterns")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="query_patterns")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    critical = sum(1 for p in patterns if p.get("severity") == "critical")
    step = _step(
        state,
        "query_patterns",
        f"querying across {len(state.entities)} entities",
        f"{len(patterns)} patterns found, {critical} critical",
        elapsed,
        "graph_db_client",
    )

    return {
        "patterns": patterns,
        "stage": SKGStage.DETECT_ANOMALIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "query_patterns",
    }


async def detect_anomalies(
    state: SecurityKnowledgeGraphState,
) -> dict[str, Any]:
    """Detect anomalies in graph patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anomalies = await toolkit.detect_anomalies(state.patterns, state.entities)

    try:
        ctx = _json.dumps(
            {"pattern_count": len(state.patterns), "anomaly_count": len(anomalies)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DETECT_ANOMALIES,
            user_prompt=f"Anomaly detection context:\n{ctx}",
            schema=AnomalyDetectionOutput,
        )
        if hasattr(llm_result, "anomalies_detected"):
            logger.info("llm_enhanced", node="detect_anomalies")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="detect_anomalies")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "detect_anomalies",
        f"analyzing {len(state.patterns)} patterns",
        f"{len(anomalies)} anomalies detected",
        elapsed,
        "threat_intel_client",
    )
    await toolkit.record_metric("anomalies_detected", float(len(anomalies)))

    return {
        "anomalies": anomalies,
        "stage": SKGStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_anomalies",
    }


async def generate_report(
    state: SecurityKnowledgeGraphState,
) -> dict[str, Any]:
    """Generate final knowledge graph report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "entities": len(state.entities),
        "relationships": len(state.relationships),
        "patterns": len(state.patterns),
        "anomalies": len(state.anomalies),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("scan_duration_ms", float(duration_ms))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
