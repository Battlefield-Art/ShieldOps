"""Security Knowledge Graph Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AttackPath,
    GraphEntity,
    GraphPattern,
    GraphRelationship,
    ReasoningStep,
    SKGStage,
)
from .tools import SecurityKnowledgeGraphToolkit

logger = structlog.get_logger()

_toolkit: SecurityKnowledgeGraphToolkit | None = None  # noqa: PLW0603


def set_toolkit(tk: SecurityKnowledgeGraphToolkit) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = tk


def _get_toolkit() -> SecurityKnowledgeGraphToolkit:
    assert _toolkit is not None, "Toolkit not initialised"
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Ingest Entities
# ------------------------------------------------------------------


async def ingest_entities(
    state: dict[str, Any],
    toolkit: SecurityKnowledgeGraphToolkit,
) -> dict[str, Any]:
    """Ingest security entities into the knowledge graph."""
    logger.info("skg.node.ingest_entities")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    entities = await toolkit.ingest_entities(tenant_id)
    data = [e.model_dump() for e in entities]

    note = f"Ingested {len(entities)} entities into knowledge graph"

    return {
        "stage": SKGStage.BUILD_RELATIONSHIPS.value,
        "entities": data,
        "total_entities": len(entities),
        "current_step": "ingest_entities",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="ingest_entities",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Build Relationships
# ------------------------------------------------------------------


async def build_relationships(
    state: dict[str, Any],
    toolkit: SecurityKnowledgeGraphToolkit,
) -> dict[str, Any]:
    """Build relationships between entities."""
    logger.info("skg.node.build_relationships")
    state = _to_dict(state)

    entities = [GraphEntity(**e) for e in state.get("entities", [])]
    relationships = await toolkit.build_relationships(entities)
    data = [r.model_dump() for r in relationships]

    note = f"Built {len(relationships)} relationships across {len(entities)} entities"

    return {
        "stage": SKGStage.ANALYZE_PATHS.value,
        "relationships": data,
        "total_relationships": len(relationships),
        "current_step": "build_relationships",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="build_relationships",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Analyze Paths
# ------------------------------------------------------------------


async def analyze_paths(
    state: dict[str, Any],
    toolkit: SecurityKnowledgeGraphToolkit,
) -> dict[str, Any]:
    """Discover attack paths through the graph."""
    logger.info("skg.node.analyze_paths")
    state = _to_dict(state)

    entities = [GraphEntity(**e) for e in state.get("entities", [])]
    relationships = [GraphRelationship(**r) for r in state.get("relationships", [])]
    paths = await toolkit.analyze_paths(entities, relationships)
    data = [p.model_dump() for p in paths]

    note = f"Discovered {len(paths)} attack paths"

    try:
        from .prompts import SYSTEM_ANALYZE, PathInsight

        ctx = json.dumps(
            {
                "paths": [
                    {
                        "id": p.id,
                        "risk": p.total_risk,
                        "impact": p.impact,
                        "nodes": len(p.path_nodes),
                    }
                    for p in paths[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PathInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Attack paths:\n{ctx}",
                schema=PathInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="skg",
            node="analyze_paths",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="skg",
            node="analyze_paths",
        )

    return {
        "stage": SKGStage.DETECT_PATTERNS.value,
        "attack_paths": data,
        "attack_paths_found": len(paths),
        "current_step": "analyze_paths",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="analyze_paths",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Detect Patterns
# ------------------------------------------------------------------


async def detect_patterns(
    state: dict[str, Any],
    toolkit: SecurityKnowledgeGraphToolkit,
) -> dict[str, Any]:
    """Detect patterns in the knowledge graph."""
    logger.info("skg.node.detect_patterns")
    state = _to_dict(state)

    entities = [GraphEntity(**e) for e in state.get("entities", [])]
    relationships = [GraphRelationship(**r) for r in state.get("relationships", [])]
    patterns = await toolkit.detect_patterns(entities, relationships)
    data = [p.model_dump() for p in patterns]

    critical = sum(1 for p in patterns if p.severity == "critical")
    note = f"Detected {len(patterns)} patterns, {critical} critical"

    return {
        "stage": SKGStage.QUERY_INSIGHTS.value,
        "patterns": data,
        "current_step": "detect_patterns",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_patterns",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Query Insights
# ------------------------------------------------------------------


async def query_insights(
    state: dict[str, Any],
    toolkit: SecurityKnowledgeGraphToolkit,
) -> dict[str, Any]:
    """Query the knowledge graph for actionable insights."""
    logger.info("skg.node.query_insights")
    state = _to_dict(state)

    entities = [GraphEntity(**e) for e in state.get("entities", [])]
    paths = [AttackPath(**p) for p in state.get("attack_paths", [])]
    patterns = [GraphPattern(**p) for p in state.get("patterns", [])]
    results = await toolkit.query_insights(entities, paths, patterns)
    data = [r.model_dump() for r in results]

    total_insights = sum(len(r.insights) for r in results)
    note = f"Generated {total_insights} insights from {len(results)} queries"

    return {
        "stage": SKGStage.REPORT.value,
        "query_results": data,
        "current_step": "query_insights",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="query_insights",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: SecurityKnowledgeGraphToolkit,
) -> dict[str, Any]:
    """Compile the final knowledge graph analysis report."""
    logger.info("skg.node.report")
    state = _to_dict(state)

    total_entities = state.get("total_entities", 0)
    total_rels = state.get("total_relationships", 0)
    paths_found = state.get("attack_paths_found", 0)
    pattern_count = len(state.get("patterns", []))

    lines = [
        "# Security Knowledge Graph Report",
        "",
        f"**Entities ingested:** {total_entities}",
        f"**Relationships built:** {total_rels}",
        f"**Attack paths found:** {paths_found}",
        f"**Patterns detected:** {pattern_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_entities": total_entities,
                "relationships": total_rels,
                "attack_paths": paths_found,
                "patterns": pattern_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Knowledge graph report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="skg",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="skg",
            node="report",
        )

    return {
        "stage": SKGStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
