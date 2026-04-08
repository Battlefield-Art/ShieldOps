"""Node implementations for the Threat Intelligence Fusion."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.threat_intelligence_fusion.models import (
    ReasoningStep,
    ThreatIntelligenceFusionState,
    TIFStage,
)
from shieldops.agents.threat_intelligence_fusion.prompts import (
    SYSTEM_COLLECT,
    SYSTEM_CORRELATE,
    SYSTEM_ENRICH,
    SYSTEM_NORMALIZE,
    SYSTEM_SCORE,
    CorrelationOutput,
    EnrichmentOutput,
    FeedCollectionOutput,
    NormalizationOutput,
    ThreatScoringOutput,
)
from shieldops.agents.threat_intelligence_fusion.tools import (
    ThreatIntelligenceFusionToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ThreatIntelligenceFusionToolkit | None = None


def _get_toolkit() -> ThreatIntelligenceFusionToolkit:
    if _toolkit is None:
        return ThreatIntelligenceFusionToolkit()
    return _toolkit


def _step(
    state: ThreatIntelligenceFusionState,
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


async def collect_feeds(
    state: ThreatIntelligenceFusionState,
) -> dict[str, Any]:
    """Collect IOCs from configured threat feeds."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    feeds = await toolkit.collect_feeds(state.fusion_config)
    total_raw = sum(f.get("ioc_count", 0) for f in feeds)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "sources": state.fusion_config.get("sources", [])[:10],
                "feed_count": len(feeds),
                "total_raw_iocs": total_raw,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COLLECT,
            user_prompt=(f"Feed collection context:\n{ctx}"),
            schema=FeedCollectionOutput,
        )
        if hasattr(llm_result, "total_raw_iocs"):
            logger.info(
                "llm_enhanced",
                node="collect_feeds",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_feeds",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "collect_feeds",
        f"sources={len(state.fusion_config.get('sources', []))}",
        f"collected {len(feeds)} feeds, {total_raw} raw IOCs",
        elapsed,
        "feed_client",
    )
    await toolkit.record_metric("feeds_collected", float(len(feeds)))

    return {
        "collected_feeds": feeds,
        "total_raw_iocs": total_raw,
        "stage": TIFStage.NORMALIZE_IOCS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "collect_feeds",
        "session_start": start,
    }


async def normalize_iocs(
    state: ThreatIntelligenceFusionState,
) -> dict[str, Any]:
    """Normalize IOCs to STIX 2.1 format."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    normalized = await toolkit.normalize_iocs(
        state.collected_feeds,
    )
    unique_count = len(normalized)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "feed_count": len(state.collected_feeds),
                "normalized_count": len(normalized),
                "raw_total": state.total_raw_iocs,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_NORMALIZE,
            user_prompt=(f"IOC normalization:\n{ctx}"),
            schema=NormalizationOutput,
        )
        if hasattr(llm_result, "unique_iocs"):
            logger.info(
                "llm_enhanced",
                node="normalize_iocs",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="normalize_iocs",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "normalize_iocs",
        f"normalizing from {len(state.collected_feeds)} feeds",
        f"{unique_count} unique IOCs",
        elapsed,
        "stix_parser",
    )

    return {
        "normalized_iocs": normalized,
        "unique_ioc_count": unique_count,
        "stage": TIFStage.CORRELATE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "normalize_iocs",
    }


async def correlate_indicators(
    state: ThreatIntelligenceFusionState,
) -> dict[str, Any]:
    """Correlate indicators across multiple sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    correlations = await toolkit.correlate_indicators(
        state.normalized_iocs,
    )
    campaigns = len(
        {c.get("campaign_name") for c in correlations if c.get("campaign_name")},
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "ioc_count": len(state.normalized_iocs),
                "correlations": len(correlations),
                "campaigns": campaigns,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CORRELATE,
            user_prompt=(f"IOC correlation:\n{ctx}"),
            schema=CorrelationOutput,
        )
        if (
            hasattr(llm_result, "campaigns_identified")
            and llm_result.campaigns_identified > campaigns
        ):
            campaigns = llm_result.campaigns_identified
        logger.info(
            "llm_enhanced",
            node="correlate_indicators",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="correlate_indicators",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "correlate_indicators",
        f"correlating {len(state.normalized_iocs)} IOCs",
        f"{len(correlations)} correlations, {campaigns} campaigns",
        elapsed,
        "correlation_engine",
    )

    return {
        "correlations": correlations,
        "campaign_count": campaigns,
        "stage": TIFStage.ENRICH,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "correlate_indicators",
    }


async def enrich_context(
    state: ThreatIntelligenceFusionState,
) -> dict[str, Any]:
    """Enrich indicators with additional context."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    enriched = await toolkit.enrich_context(
        state.normalized_iocs,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "ioc_count": len(state.normalized_iocs),
                "enriched_count": len(enriched),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ENRICH,
            user_prompt=(f"Indicator enrichment:\n{ctx}"),
            schema=EnrichmentOutput,
        )
        if hasattr(llm_result, "enriched_count"):
            logger.info(
                "llm_enhanced",
                node="enrich_context",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enrich_context",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "enrich_context",
        f"enriching {len(state.normalized_iocs)} IOCs",
        f"enriched {len(enriched)} indicators",
        elapsed,
        "enrichment_service",
    )

    return {
        "enriched_indicators": enriched,
        "stage": TIFStage.SCORE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "enrich_context",
    }


async def score_threats(
    state: ThreatIntelligenceFusionState,
) -> dict[str, Any]:
    """Score threat indicators."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scores = await toolkit.score_threats(
        state.enriched_indicators,
        state.correlations,
    )
    critical = sum(1 for s in scores if s.get("threat_level") == "critical")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "enriched_count": len(state.enriched_indicators),
                "correlation_count": len(state.correlations),
                "score_count": len(scores),
                "critical": critical,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SCORE,
            user_prompt=(f"Threat scoring:\n{ctx}"),
            schema=ThreatScoringOutput,
        )
        if hasattr(llm_result, "critical_count") and llm_result.critical_count > critical:
            critical = llm_result.critical_count
        logger.info(
            "llm_enhanced",
            node="score_threats",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="score_threats",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "score_threats",
        f"scoring {len(state.enriched_indicators)} indicators",
        f"{len(scores)} scored, {critical} critical",
        elapsed,
        "scoring_engine",
    )
    await toolkit.record_metric("critical_threats", float(critical))

    return {
        "threat_scores": scores,
        "critical_threat_count": critical,
        "stage": TIFStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "score_threats",
    }


async def generate_report(
    state: ThreatIntelligenceFusionState,
) -> dict[str, Any]:
    """Generate final threat intelligence fusion report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "total_feeds": len(state.collected_feeds),
        "total_raw_iocs": state.total_raw_iocs,
        "unique_iocs": state.unique_ioc_count,
        "correlations": len(state.correlations),
        "campaigns": state.campaign_count,
        "enriched": len(state.enriched_indicators),
        "critical_threats": state.critical_threat_count,
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("scan_duration_ms", float(duration_ms))
    await toolkit.record_metric(
        "unique_iocs",
        float(state.unique_ioc_count),
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing fusion {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
