"""Node implementations for the Threat Feed Orchestrator
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.threat_feed_orchestrator.models import (
    ReasoningStep,
    TFOStage,
    ThreatFeedOrchestratorState,
)
from shieldops.agents.threat_feed_orchestrator.prompts import (
    SYSTEM_DEDUP,
    SYSTEM_ENRICH,
    SYSTEM_NORMALIZE,
    SYSTEM_REPORT,
    DeduplicationOutput,
    EnrichmentOutput,
    NormalizationOutput,
    PipelineReportOutput,
)
from shieldops.agents.threat_feed_orchestrator.tools import (
    ThreatFeedOrchestratorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ThreatFeedOrchestratorToolkit | None = None


def set_toolkit(
    toolkit: ThreatFeedOrchestratorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ThreatFeedOrchestratorToolkit:
    if _toolkit is None:
        return ThreatFeedOrchestratorToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: connect_feeds
# ------------------------------------------------------------------


async def connect_feeds(
    state: ThreatFeedOrchestratorState,
) -> dict[str, Any]:
    """Connect to configured threat intelligence feed
    sources and poll for indicators."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    connections = await toolkit.connect_feeds(
        feed_urls=state.feed_urls,
        feed_configs=state.feed_configs,
    )

    step = _step(
        state.reasoning_chain,
        "connect_feeds",
        f"Connecting to {len(state.feed_urls)} feeds",
        f"Connected {len(connections)} feeds",
        start,
        "feed_connector",
    )

    return {
        "feed_connections": connections,
        "stage": TFOStage.CONNECT_FEEDS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "connect_feeds",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: normalize
# ------------------------------------------------------------------


async def normalize(
    state: ThreatFeedOrchestratorState,
) -> dict[str, Any]:
    """Normalize raw indicators from all feeds into
    common STIX 2.1 format."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    normalized = await toolkit.normalize_indicators(
        feed_connections=state.feed_connections,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "feed_count": len(state.feed_connections),
                "raw_count": sum(c.get("indicator_count", 0) for c in state.feed_connections),
                "sample": state.feed_connections[:3],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_NORMALIZE,
            user_prompt=f"Normalize indicators:\n{ctx}",
            schema=NormalizationOutput,
        )
        if llm_out.format_issues:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            normalized.append(
                {
                    "meta_id": f"llm-{rand_id}",
                    "normalized_count": llm_out.normalized_count,  # type: ignore[union-attr]
                    "format_issues": llm_out.format_issues,  # type: ignore[union-attr]
                    "type_distribution": llm_out.type_distribution,  # type: ignore[union-attr]
                    "quality_score": llm_out.quality_score,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="normalize",
            issues=len(llm_out.format_issues),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="normalize",
        )

    step = _step(
        state.reasoning_chain,
        "normalize",
        f"Normalizing from {len(state.feed_connections)} feeds",
        f"Normalized {len(normalized)} indicators",
        start,
        "normalizer",
    )

    return {
        "normalized_indicators": normalized,
        "total_indicators": len(normalized),
        "stage": TFOStage.NORMALIZE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "normalize",
    }


# ------------------------------------------------------------------
# Node: deduplicate
# ------------------------------------------------------------------


async def deduplicate(
    state: ThreatFeedOrchestratorState,
) -> dict[str, Any]:
    """Deduplicate normalized indicators across feeds
    using exact and fuzzy matching."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    deduped = await toolkit.deduplicate(
        indicators=state.normalized_indicators,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "total": state.total_indicators,
                "deduped_count": len(deduped),
                "sample": state.normalized_indicators[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DEDUP,
            user_prompt=f"Deduplicate indicators:\n{ctx}",
            schema=DeduplicationOutput,
        )
        logger.info(
            "llm_enhanced",
            node="deduplicate",
            unique=llm_out.unique_count,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="deduplicate",
        )

    total = state.total_indicators
    unique = len(deduped)
    ratio = 1.0 - (unique / total) if total > 0 else 0.0

    step = _step(
        state.reasoning_chain,
        "deduplicate",
        f"Deduplicating {total} indicators",
        f"{unique} unique, ratio={ratio:.2f}",
        start,
        "dedup_engine",
    )

    return {
        "deduplicated_indicators": deduped,
        "unique_indicators": unique,
        "dedup_ratio": ratio,
        "stage": TFOStage.DEDUPLICATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "deduplicate",
    }


# ------------------------------------------------------------------
# Node: enrich
# ------------------------------------------------------------------


async def enrich(
    state: ThreatFeedOrchestratorState,
) -> dict[str, Any]:
    """Enrich deduplicated indicators with threat actor
    attribution and context."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    enriched = await toolkit.enrich_indicators(
        indicators=state.deduplicated_indicators,
        enrichment_sources=state.enrichment_sources,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "indicator_count": len(state.deduplicated_indicators),
                "sources": state.enrichment_sources,
                "sample": state.deduplicated_indicators[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ENRICH,
            user_prompt=f"Enrich indicators:\n{ctx}",
            schema=EnrichmentOutput,
        )
        if llm_out.threat_actors:  # type: ignore[union-attr]
            enriched.append(
                {
                    "source": "llm_enrichment",
                    "enriched_count": llm_out.enriched_count,  # type: ignore[union-attr]
                    "threat_actors": llm_out.threat_actors,  # type: ignore[union-attr]
                    "campaigns": llm_out.campaigns,  # type: ignore[union-attr]
                    "avg_risk_score": llm_out.avg_risk_score,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="enrich",
            actors=len(llm_out.threat_actors),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enrich",
        )

    step = _step(
        state.reasoning_chain,
        "enrich",
        f"Enriching {len(state.deduplicated_indicators)} indicators",
        f"Enriched {len(enriched)} indicators",
        start,
        "enrichment_service",
    )

    return {
        "enriched_indicators": enriched,
        "enriched_count": len(enriched),
        "stage": TFOStage.ENRICH,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enrich",
    }


# ------------------------------------------------------------------
# Node: distribute
# ------------------------------------------------------------------


async def distribute(
    state: ThreatFeedOrchestratorState,
) -> dict[str, Any]:
    """Distribute enriched indicators to configured
    consumers (SIEM, EDR, firewall, SOAR)."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.distribute_to_consumers(
        indicators=state.enriched_indicators,
        consumer_configs=state.consumer_configs,
    )

    distributed = sum(r.get("indicators_sent", 0) for r in results)

    step = _step(
        state.reasoning_chain,
        "distribute",
        f"Distributing to {len(state.consumer_configs)} consumers",
        f"Distributed {distributed} indicators",
        start,
        "distribution_engine",
    )

    return {
        "distribution_results": results,
        "distributed_count": distributed,
        "stage": TFOStage.DISTRIBUTE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "distribute",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: ThreatFeedOrchestratorState,
) -> dict[str, Any]:
    """Generate the final pipeline report with feed health
    and top threats."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_indicators": state.total_indicators,
        "unique_indicators": state.unique_indicators,
        "enriched_count": state.enriched_count,
        "distributed_count": state.distributed_count,
        "dedup_ratio": state.dedup_ratio,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "feed_count": len(state.feed_connections),
                "total_indicators": state.total_indicators,
                "unique_indicators": state.unique_indicators,
                "enriched_count": state.enriched_count,
                "distributed_count": state.distributed_count,
                "dedup_ratio": state.dedup_ratio,
                "enriched_sample": state.enriched_indicators[:5],
                "distribution_results": state.distribution_results[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate pipeline report:\n{ctx}",
            schema=PipelineReportOutput,
        )
        if isinstance(llm_out, PipelineReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "feed_health": llm_out.feed_health,
                    "top_threats": llm_out.top_threats,
                    "recommendations": llm_out.recommendations,
                    "effectiveness_rating": llm_out.effectiveness_rating,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                threats=len(llm_out.top_threats),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "total_indicators": state.total_indicators,
            "unique_indicators": state.unique_indicators,
            "enriched_count": state.enriched_count,
            "distributed_count": state.distributed_count,
            "dedup_ratio": state.dedup_ratio,
        },
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_indicators} indicators",
        f"Report generated, {state.unique_indicators} unique",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": TFOStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
