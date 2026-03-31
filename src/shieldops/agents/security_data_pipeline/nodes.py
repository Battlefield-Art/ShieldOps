"""Security Data Pipeline Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    IngestedRecord,
    ReasoningStep,
    SDPStage,
    TransformedRecord,
)
from .tools import SecurityDataPipelineToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Ingest Sources
# ------------------------------------------------------------------


async def ingest_sources(
    state: dict[str, Any],
    toolkit: SecurityDataPipelineToolkit,
) -> dict[str, Any]:
    """Ingest security data from multiple sources."""
    logger.info("sdp.node.ingest_sources")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    records = await toolkit.ingest_sources(tenant_id)
    data = [r.model_dump() for r in records]

    note = f"Ingested {len(records)} records from sources"

    return {
        "stage": SDPStage.TRANSFORM_DATA.value,
        "ingested_records": data,
        "total_records_processed": len(records),
        "current_step": "ingest_sources",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="ingest_sources",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Transform Data
# ------------------------------------------------------------------


async def transform_data(
    state: dict[str, Any],
    toolkit: SecurityDataPipelineToolkit,
) -> dict[str, Any]:
    """Normalize and transform ingested records."""
    logger.info("sdp.node.transform_data")
    state = _to_dict(state)

    records = [IngestedRecord(**r) for r in state.get("ingested_records", [])]
    transformed = await toolkit.transform_data(records)
    data = [t.model_dump() for t in transformed]

    note = f"Transformed {len(transformed)} records to OCSF"

    try:
        from .prompts import SYSTEM_TRANSFORM, TransformInsight

        ctx = json.dumps(
            {
                "records": [
                    {
                        "source": t.source.value,
                        "event_type": t.event_type,
                        "severity": t.severity,
                        "schema": t.normalized_schema,
                    }
                    for t in transformed[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            TransformInsight,
            await llm_structured(
                system_prompt=SYSTEM_TRANSFORM,
                user_prompt=f"Transform results:\n{ctx}",
                schema=TransformInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sdp",
            node="transform_data",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sdp",
            node="transform_data",
        )

    return {
        "stage": SDPStage.ENRICH.value,
        "transformed_records": data,
        "current_step": "transform_data",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="transform_data",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Enrich
# ------------------------------------------------------------------


async def enrich_records(
    state: dict[str, Any],
    toolkit: SecurityDataPipelineToolkit,
) -> dict[str, Any]:
    """Enrich records with IOC and threat intelligence."""
    logger.info("sdp.node.enrich")
    state = _to_dict(state)

    records = [TransformedRecord(**r) for r in state.get("transformed_records", [])]
    enrichments = await toolkit.enrich_records(records)
    data = [e.model_dump() for e in enrichments]

    matched = sum(1 for e in enrichments if e.matched)
    total = len(enrichments) if enrichments else 1
    hit_rate = round(matched / total, 2)
    note = f"Enriched {len(enrichments)} records, {matched} IOC matches ({hit_rate})"

    return {
        "stage": SDPStage.VALIDATE_QUALITY.value,
        "enrichments": data,
        "enrichment_hit_rate": hit_rate,
        "current_step": "enrich",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="enrich",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Validate Quality
# ------------------------------------------------------------------


async def validate_quality(
    state: dict[str, Any],
    toolkit: SecurityDataPipelineToolkit,
) -> dict[str, Any]:
    """Validate data quality of transformed records."""
    logger.info("sdp.node.validate_quality")
    state = _to_dict(state)

    records = [TransformedRecord(**r) for r in state.get("transformed_records", [])]
    checks = await toolkit.validate_quality(records)
    data = [c.model_dump() for c in checks]

    passed = sum(1 for c in checks if c.passed)
    note = f"Quality validation: {passed}/{len(checks)} checks passed"

    return {
        "stage": SDPStage.LOAD_DESTINATION.value,
        "quality_checks": data,
        "current_step": "validate_quality",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="validate_quality",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Load Destination
# ------------------------------------------------------------------


async def load_destination(
    state: dict[str, Any],
    toolkit: SecurityDataPipelineToolkit,
) -> dict[str, Any]:
    """Load transformed records to destinations."""
    logger.info("sdp.node.load_destination")
    state = _to_dict(state)

    records = [TransformedRecord(**r) for r in state.get("transformed_records", [])]
    results = await toolkit.load_destination(records)
    data = [r.model_dump() for r in results]

    loaded = sum(r.records_loaded for r in results)
    note = f"Loaded {loaded} records across {len(results)} destinations"

    return {
        "stage": SDPStage.REPORT.value,
        "load_results": data,
        "current_step": "load_destination",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="load_destination",
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
    toolkit: SecurityDataPipelineToolkit,
) -> dict[str, Any]:
    """Compile the final pipeline execution report."""
    logger.info("sdp.node.report")
    state = _to_dict(state)

    total = state.get("total_records_processed", 0)
    hit_rate = state.get("enrichment_hit_rate", 0.0)
    quality_count = len(state.get("quality_checks", []))
    load_count = len(state.get("load_results", []))

    lines = [
        "# Security Data Pipeline Report",
        "",
        f"**Records processed:** {total}",
        f"**Enrichment hit rate:** {hit_rate}",
        f"**Quality checks:** {quality_count}",
        f"**Destinations loaded:** {load_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_records": total,
                "enrichment_hit_rate": hit_rate,
                "quality_checks": quality_count,
                "destinations": load_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Pipeline report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sdp",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sdp",
            node="report",
        )

    return {
        "stage": SDPStage.REPORT.value,
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
