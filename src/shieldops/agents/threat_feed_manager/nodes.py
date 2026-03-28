"""Node implementations for the Threat Feed Manager Agent."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.agents.threat_feed_manager.models import (
    FeedStage,
    ThreatFeedManagerState,
)
from shieldops.agents.threat_feed_manager.prompts import (
    SYSTEM_ENRICH,
    SYSTEM_NORMALIZE,
    SYSTEM_REPORT,
    SYSTEM_SCORE,
    EnrichOutput,
    NormalizeOutput,
    ReportOutput,
    ScoreOutput,
)
from shieldops.agents.threat_feed_manager.tools import ThreatFeedManagerToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ThreatFeedManagerToolkit | None = None


def set_toolkit(toolkit: ThreatFeedManagerToolkit) -> None:
    """Set the shared toolkit instance for all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ThreatFeedManagerToolkit:
    if _toolkit is None:
        return ThreatFeedManagerToolkit()
    return _toolkit


async def ingest_feeds(
    state: ThreatFeedManagerState,
) -> dict[str, Any]:
    """Poll all configured threat feeds."""
    start = time.time()
    toolkit = _get_toolkit()

    feeds = await toolkit.ingest_feeds()
    healthy = sum(1 for f in feeds if f.health.value == "healthy")
    total_iocs = sum(f.ioc_count for f in feeds)

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "threat_feed.ingest_done",
        request_id=state.request_id,
        feeds=len(feeds),
        healthy=healthy,
    )

    return {
        "feeds": feeds,
        "stage": FeedStage.NORMALIZE,
        "current_step": "ingest_feeds",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Ingested {len(feeds)} feeds ({healthy} healthy, {total_iocs} raw IOCs)",
        ],
        "session_start": (start if state.session_start == 0.0 else state.session_start),
        "stats": {**state.stats, "ingest_ms": elapsed},
    }


async def normalize(
    state: ThreatFeedManagerState,
) -> dict[str, Any]:
    """Normalize raw IOC data into standard format."""
    start = time.time()
    toolkit = _get_toolkit()

    iocs = await toolkit.normalize_iocs(state.feeds)

    # LLM enhancement
    try:
        sample = iocs[:5] if iocs else []
        context = _json.dumps(
            [{"type": i.ioc_type, "value": i.value, "tags": i.tags} for i in sample],
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_NORMALIZE,
            user_prompt=f"Validate IOC normalization:\n{context}",
            schema=NormalizeOutput,
        )
        if hasattr(llm_result, "severity"):
            llm_sev = getattr(llm_result, "severity", "")
            if llm_sev and sample:
                sample[0].severity = llm_sev
            llm_tags = getattr(llm_result, "tags", [])
            if llm_tags and sample:
                sample[0].tags = list(set(sample[0].tags + llm_tags))
        logger.info("llm_enhanced", node="normalize")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="normalize")

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "threat_feed.normalize_done",
        request_id=state.request_id,
        iocs=len(iocs),
    )

    return {
        "normalized_iocs": iocs,
        "stage": FeedStage.DEDUPLICATE,
        "current_step": "normalize",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Normalized {len(iocs)} IOCs from {len(state.feeds)} feeds",
        ],
        "stats": {**state.stats, "normalize_ms": elapsed},
    }


async def deduplicate(
    state: ThreatFeedManagerState,
) -> dict[str, Any]:
    """Deduplicate normalized IOCs."""
    start = time.time()
    toolkit = _get_toolkit()

    deduped = await toolkit.deduplicate(state.normalized_iocs)
    removed = len(state.normalized_iocs) - len(deduped)

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "threat_feed.dedup_done",
        request_id=state.request_id,
        input=len(state.normalized_iocs),
        output=len(deduped),
    )

    return {
        "normalized_iocs": deduped,
        "stage": FeedStage.SCORE,
        "current_step": "deduplicate",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Deduplicated: {len(state.normalized_iocs)} -> {len(deduped)} "
            f"({removed} duplicates removed)",
        ],
        "stats": {**state.stats, "dedup_ms": elapsed, "duplicates_removed": removed},
    }


async def score(
    state: ThreatFeedManagerState,
) -> dict[str, Any]:
    """Score each feed on quality metrics."""
    start = time.time()
    toolkit = _get_toolkit()

    scores = await toolkit.score_feeds(state.feeds, state.normalized_iocs)

    # LLM enhancement
    try:
        context = _json.dumps(
            [
                {
                    "feed": s.feed_name,
                    "reliability": s.reliability,
                    "freshness": s.freshness,
                    "coverage": s.coverage,
                    "overall": s.overall_score,
                }
                for s in scores
            ],
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SCORE,
            user_prompt=f"Validate feed scores:\n{context}",
            schema=ScoreOutput,
        )
        if hasattr(llm_result, "recommendation") and scores:
            llm_rec = getattr(llm_result, "recommendation", "")
            if llm_rec:
                scores[0].recommendation = f"{scores[0].recommendation} | LLM: {llm_rec}"
        logger.info("llm_enhanced", node="score")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="score")

    elapsed = int((time.time() - start) * 1000)

    keep = sum(1 for s in scores if s.recommendation.startswith("keep"))

    logger.info(
        "threat_feed.score_done",
        request_id=state.request_id,
        feeds_scored=len(scores),
        keep=keep,
    )

    return {
        "feed_scores": scores,
        "stage": FeedStage.ENRICH,
        "current_step": "score",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Scored {len(scores)} feeds: {keep} keep, {len(scores) - keep} deprioritize/remove",
        ],
        "stats": {**state.stats, "score_ms": elapsed, "feeds_keep": keep},
    }


async def enrich(
    state: ThreatFeedManagerState,
) -> dict[str, Any]:
    """Enrich IOCs with additional context."""
    start = time.time()
    toolkit = _get_toolkit()

    enriched = await toolkit.enrich_iocs(state.normalized_iocs)

    # LLM enhancement
    try:
        sample = enriched[:3] if enriched else []
        context = _json.dumps(
            [
                {
                    "type": i.ioc_type,
                    "value": i.value,
                    "tags": i.tags,
                    "enrichment": i.enrichment,
                }
                for i in sample
            ],
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ENRICH,
            user_prompt=f"Enrich these IOCs:\n{context}",
            schema=EnrichOutput,
        )
        if hasattr(llm_result, "threat_actor") and sample:
            actor = getattr(llm_result, "threat_actor", "")
            if actor:
                sample[0].enrichment["threat_actor"] = actor
            campaign = getattr(llm_result, "campaign", "")
            if campaign:
                sample[0].enrichment["campaign"] = campaign
            tactics = getattr(llm_result, "mitre_tactics", [])
            if tactics:
                sample[0].enrichment["mitre_tactics"] = tactics
        logger.info("llm_enhanced", node="enrich")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="enrich")

    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "threat_feed.enrich_done",
        request_id=state.request_id,
        iocs_enriched=len(enriched),
    )

    return {
        "normalized_iocs": enriched,
        "stage": FeedStage.REPORT,
        "current_step": "enrich",
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Enriched {len(enriched)} IOCs with contextual data",
        ],
        "stats": {**state.stats, "enrich_ms": elapsed},
    }


async def report(
    state: ThreatFeedManagerState,
) -> dict[str, Any]:
    """Generate final threat feed management report."""
    start = time.time()
    total_elapsed = int((time.time() - state.session_start) * 1000)

    healthy = sum(1 for f in state.feeds if f.health.value == "healthy")
    total_iocs = len(state.normalized_iocs)
    keep = sum(1 for s in state.feed_scores if s.recommendation.startswith("keep"))

    report_stats: dict[str, Any] = {
        "total_feeds": len(state.feeds),
        "healthy_feeds": healthy,
        "total_iocs": total_iocs,
        "feeds_scored": len(state.feed_scores),
        "feeds_keep": keep,
        "feeds_deprioritize": len(state.feed_scores) - keep,
    }

    # LLM-generated summary
    try:
        context = _json.dumps(
            {
                **report_stats,
                "feed_scores": [s.model_dump() for s in state.feed_scores],
                "top_iocs": [
                    i.model_dump()
                    for i in sorted(
                        state.normalized_iocs,
                        key=lambda x: x.confidence,
                        reverse=True,
                    )[:10]
                ],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate feed management report:\n{context}",
            schema=ReportOutput,
        )
        if hasattr(llm_result, "executive_summary"):
            report_stats["executive_summary"] = getattr(llm_result, "executive_summary", "")
            report_stats["top_iocs_summary"] = getattr(llm_result, "top_iocs", [])
            report_stats["feed_health_summary"] = getattr(llm_result, "feed_health_summary", "")
            report_stats["recommendations"] = getattr(llm_result, "recommendations", [])
        logger.info("llm_enhanced", node="report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="report")

    elapsed = int((time.time() - start) * 1000)

    return {
        "stage": FeedStage.REPORT,
        "current_step": "report",
        "stats": {**state.stats, **report_stats, "report_ms": elapsed},
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report: {len(state.feeds)} feeds, {total_iocs} IOCs, "
            f"{keep}/{len(state.feed_scores)} feeds recommended to keep",
        ],
        "session_duration_ms": total_elapsed,
    }
