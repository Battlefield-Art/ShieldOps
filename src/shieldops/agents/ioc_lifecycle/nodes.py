"""Node implementations for the IOC Lifecycle Agent."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.agents.ioc_lifecycle.models import (
    IOCLifecycleState,
    IOCStage,
    IOCStatus,
)
from shieldops.agents.ioc_lifecycle.prompts import (
    SYSTEM_CLASSIFY,
    SYSTEM_ENRICH,
    SYSTEM_REPORT,
    SYSTEM_VALIDATE,
    ClassificationOutput,
    EnrichmentOutput,
    ReportOutput,
    ValidationOutput,
)
from shieldops.agents.ioc_lifecycle.tools import (
    IOCLifecycleToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IOCLifecycleToolkit | None = None


def set_toolkit(
    toolkit: IOCLifecycleToolkit,
) -> None:
    """Set the toolkit instance for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> IOCLifecycleToolkit:
    if _toolkit is None:
        return IOCLifecycleToolkit()
    return _toolkit


async def collect(
    state: IOCLifecycleState,
) -> dict[str, Any]:
    """Collect IOCs from configured sources."""
    toolkit = _get_toolkit()

    sources = state.sources or ["default"]
    iocs = await toolkit.collect_iocs(sources)

    reasoning = [
        *state.reasoning_chain,
        f"Collected {len(iocs)} IOCs from {len(sources)} sources",
    ]

    return {
        "iocs": iocs,
        "stage": IOCStage.VALIDATE,
        "reasoning_chain": reasoning,
        "session_start": state.session_start or time.time(),
    }


async def validate(
    state: IOCLifecycleState,
) -> dict[str, Any]:
    """Validate collected IOCs for format and duplicates."""
    toolkit = _get_toolkit()

    validated = await toolkit.validate_iocs(state.iocs)

    # LLM-enhanced validation
    try:
        context = _json.dumps(
            {
                "original_count": len(state.iocs),
                "validated_count": len(validated),
                "removed": len(state.iocs) - len(validated),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATE,
            user_prompt=("Validate these IOCs:\n" + context),
            schema=ValidationOutput,
        )
        logger.info(
            "llm_enhanced",
            node="validate",
            reasoning=llm_result.reasoning[:80],
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="validate",
        )

    reasoning = [
        *state.reasoning_chain,
        f"Validated {len(validated)}/{len(state.iocs)} IOCs passed checks",
    ]

    return {
        "iocs": validated,
        "stage": IOCStage.ENRICH,
        "reasoning_chain": reasoning,
    }


async def enrich(
    state: IOCLifecycleState,
) -> dict[str, Any]:
    """Enrich validated IOCs with threat intelligence."""
    toolkit = _get_toolkit()

    enrichments = []
    for ioc in state.iocs:
        enrichment = await toolkit.enrich_ioc(ioc)
        enrichments.append(enrichment)

    # LLM-enhanced enrichment analysis
    try:
        context = _json.dumps(
            {
                "ioc_count": len(state.iocs),
                "avg_threat_score": (
                    sum(e.threat_score for e in enrichments) / max(len(enrichments), 1)
                ),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ENRICH,
            user_prompt=("Analyze enrichment results:\n" + context),
            schema=EnrichmentOutput,
        )
        logger.info(
            "llm_enhanced",
            node="enrich",
            category=llm_result.category,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enrich",
        )

    reasoning = [
        *state.reasoning_chain,
        f"Enriched {len(enrichments)} IOCs with threat intelligence",
    ]

    return {
        "enrichments": enrichments,
        "stage": IOCStage.CLASSIFY,
        "reasoning_chain": reasoning,
    }


async def classify(
    state: IOCLifecycleState,
) -> dict[str, Any]:
    """Classify IOCs based on enrichment data."""
    toolkit = _get_toolkit()

    # Build enrichment lookup
    enrich_map = {e.ioc_id: e for e in state.enrichments}

    classifications = []
    fp_count = 0
    for ioc in state.iocs:
        enrichment = enrich_map.get(ioc.id)
        if enrichment is None:
            continue
        classification = await toolkit.classify_ioc(ioc, enrichment)
        classifications.append(classification)
        if classification.is_false_positive:
            fp_count += 1

    # LLM-enhanced classification
    try:
        context = _json.dumps(
            {
                "total_iocs": len(state.iocs),
                "classified": len(classifications),
                "false_positives": fp_count,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=("Classify these IOCs:\n" + context),
            schema=ClassificationOutput,
        )
        logger.info(
            "llm_enhanced",
            node="classify",
            severity=llm_result.severity,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify",
        )

    reasoning = [
        *state.reasoning_chain,
        f"Classified {len(classifications)} IOCs, {fp_count} false positives detected",
    ]

    return {
        "classifications": classifications,
        "false_positive_count": fp_count,
        "stage": IOCStage.AGE_CHECK,
        "reasoning_chain": reasoning,
    }


async def age_check(
    state: IOCLifecycleState,
) -> dict[str, Any]:
    """Check IOC ages and update statuses."""
    toolkit = _get_toolkit()

    # Mark false positives before age check
    fp_ids = {c.ioc_id for c in state.classifications if c.is_false_positive}
    iocs_to_check = []
    for ioc in state.iocs:
        if ioc.id in fp_ids:
            updated = ioc.model_copy(
                update={"status": IOCStatus.FALSE_POSITIVE},
            )
            iocs_to_check.append(updated)
        else:
            iocs_to_check.append(ioc)

    aged_iocs = await toolkit.check_age(iocs_to_check)

    # Compute stats
    by_status: dict[str, int] = {}
    for ioc in aged_iocs:
        key = ioc.status.value
        by_status[key] = by_status.get(key, 0) + 1

    stats = {
        "total_iocs": len(aged_iocs),
        "by_status": by_status,
        "false_positives": state.false_positive_count,
    }

    reasoning = [
        *state.reasoning_chain,
        f"Age-checked {len(aged_iocs)} IOCs: "
        + ", ".join(f"{k}={v}" for k, v in by_status.items()),
    ]

    return {
        "iocs": aged_iocs,
        "stats": stats,
        "stage": IOCStage.REPORT,
        "reasoning_chain": reasoning,
    }


async def report(
    state: IOCLifecycleState,
) -> dict[str, Any]:
    """Generate the final IOC lifecycle report."""
    duration_ms = 0
    if state.session_start:
        duration_ms = int((time.time() - state.session_start) * 1000)

    report_data: dict[str, Any] = {
        "tenant_id": state.tenant_id,
        "total_iocs": len(state.iocs),
        "enriched": len(state.enrichments),
        "classified": len(state.classifications),
        "false_positive_count": state.false_positive_count,
        "stats": state.stats,
        "duration_ms": duration_ms,
        "status": "complete",
    }

    # LLM-enhanced report summary
    try:
        context = _json.dumps(report_data, default=str)
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=("Generate the IOC lifecycle report:\n" + context),
            schema=ReportOutput,
        )
        report_data["executive_summary"] = llm_result.executive_summary
        report_data["recommendations"] = llm_result.recommendations
        logger.info(
            "llm_enhanced",
            node="report",
            active_iocs=llm_result.active_iocs,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="report",
        )

    reasoning = [
        *state.reasoning_chain,
        f"Generated report: {len(state.iocs)} IOCs, "
        f"{state.false_positive_count} FPs, "
        f"duration={duration_ms}ms",
    ]

    return {
        "report": report_data,
        "stage": "complete",
        "reasoning_chain": reasoning,
    }
