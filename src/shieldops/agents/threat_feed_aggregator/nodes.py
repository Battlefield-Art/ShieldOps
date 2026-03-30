"""Threat Feed Aggregator Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    EnrichedThreat,
    NormalizedIOC,
    ReasoningStep,
    TFAStage,
    ThreatFeed,
)
from .tools import ThreatFeedAggregatorToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# --------------------------------------------------------
# Node 1: Collect Feeds
# --------------------------------------------------------


async def collect_feeds(
    state: dict[str, Any],
    toolkit: ThreatFeedAggregatorToolkit,
) -> dict[str, Any]:
    """Collect IOCs from all threat intel feeds."""
    logger.info("tfa.node.collect_feeds")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    feeds = await toolkit.collect_feeds(tenant_id)
    data = [f.model_dump() for f in feeds]

    src_count = len({f.source for f in feeds})
    note = f"Collected {len(feeds)} IOCs from {src_count} feeds"

    return {
        "stage": TFAStage.NORMALIZE_IOCS.value,
        "feeds": data,
        "total_iocs": len(feeds),
        "current_step": "collect_feeds",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_feeds",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# --------------------------------------------------------
# Node 2: Normalize IOCs
# --------------------------------------------------------


async def normalize_iocs(
    state: dict[str, Any],
    toolkit: ThreatFeedAggregatorToolkit,
) -> dict[str, Any]:
    """Normalize and deduplicate IOCs."""
    logger.info("tfa.node.normalize_iocs")
    state = _to_dict(state)

    feeds = [ThreatFeed(**f) for f in state.get("feeds", [])]
    normalized = await toolkit.normalize_iocs(feeds)
    data = [n.model_dump() for n in normalized]

    high = sum(1 for n in normalized if n.severity in ("high", "critical"))
    note = f"Normalized {len(normalized)} unique IOCs, {high} high/critical severity"

    return {
        "stage": TFAStage.CORRELATE_THREATS.value,
        "normalized_iocs": data,
        "total_iocs": len(normalized),
        "high_severity_count": high,
        "current_step": "normalize_iocs",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="normalize_iocs",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# --------------------------------------------------------
# Node 3: Correlate Threats
# --------------------------------------------------------


async def correlate_threats(
    state: dict[str, Any],
    toolkit: ThreatFeedAggregatorToolkit,
) -> dict[str, Any]:
    """Correlate IOCs into threat campaigns."""
    logger.info("tfa.node.correlate_threats")
    state = _to_dict(state)

    iocs = [NormalizedIOC(**n) for n in state.get("normalized_iocs", [])]
    correlations = await toolkit.correlate_threats(
        iocs,
    )
    data = [c.model_dump() for c in correlations]

    note = f"Identified {len(correlations)} campaigns across {len(iocs)} IOCs"

    try:
        from .prompts import (
            SYSTEM_CORRELATE,
            CorrelationInsight,
        )

        ctx = json.dumps(
            {
                "campaigns": [
                    {
                        "name": c.campaign_name,
                        "actor": c.threat_actor,
                        "iocs": len(c.ioc_ids),
                        "mitre": (c.mitre_techniques),
                    }
                    for c in correlations[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            CorrelationInsight,
            await llm_structured(
                system_prompt=SYSTEM_CORRELATE,
                user_prompt=(f"Threat correlation:\n{ctx}"),
                schema=CorrelationInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="tfa",
            node="correlate_threats",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="tfa",
            node="correlate_threats",
        )

    return {
        "stage": TFAStage.ENRICH_CONTEXT.value,
        "correlations": data,
        "current_step": "correlate_threats",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="correlate_threats",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# --------------------------------------------------------
# Node 4: Enrich Context
# --------------------------------------------------------


async def enrich_context(
    state: dict[str, Any],
    toolkit: ThreatFeedAggregatorToolkit,
) -> dict[str, Any]:
    """Enrich IOCs with geo, ASN, and context."""
    logger.info("tfa.node.enrich_context")
    state = _to_dict(state)

    iocs = [NormalizedIOC(**n) for n in state.get("normalized_iocs", [])]
    enriched = await toolkit.enrich_context(iocs)
    data = [e.model_dump() for e in enriched]

    high_risk = sum(1 for e in enriched if e.risk_score >= 80.0)
    note = f"Enriched {len(enriched)} IOCs, {high_risk} high-risk (>=80)"

    return {
        "stage": TFAStage.DISTRIBUTE_INTEL.value,
        "enriched_threats": data,
        "current_step": "enrich_context",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="enrich_context",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# --------------------------------------------------------
# Node 5: Distribute Intel
# --------------------------------------------------------


async def distribute_intel(
    state: dict[str, Any],
    toolkit: ThreatFeedAggregatorToolkit,
) -> dict[str, Any]:
    """Distribute enriched threat intel to targets."""
    logger.info("tfa.node.distribute_intel")
    state = _to_dict(state)

    enriched = [EnrichedThreat(**e) for e in state.get("enriched_threats", [])]
    distributions = await toolkit.distribute_intel(
        enriched,
    )
    data = [d.model_dump() for d in distributions]

    delivered = sum(1 for d in distributions if d.status == "delivered")
    note = f"Distributed to {delivered}/{len(distributions)} targets"

    return {
        "stage": TFAStage.REPORT.value,
        "distributions": data,
        "current_step": "distribute_intel",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="distribute_intel",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# --------------------------------------------------------
# Node 6: Report
# --------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: ThreatFeedAggregatorToolkit,
) -> dict[str, Any]:
    """Compile the final threat intel report."""
    logger.info("tfa.node.report")
    state = _to_dict(state)

    total_iocs = state.get("total_iocs", 0)
    high_sev = state.get(
        "high_severity_count",
        0,
    )
    corr_count = len(
        state.get("correlations", []),
    )
    enr_count = len(
        state.get("enriched_threats", []),
    )
    dist_count = len(
        state.get("distributions", []),
    )

    lines = [
        "# Threat Intelligence Report",
        "",
        f"**Total IOCs:** {total_iocs}",
        f"**High/critical:** {high_sev}",
        f"**Campaigns:** {corr_count}",
        f"**IOCs enriched:** {enr_count}",
        f"**Distributions:** {dist_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import (
            SYSTEM_REPORT,
            ReportInsight,
        )

        ctx = json.dumps(
            {
                "total_iocs": total_iocs,
                "high_severity": high_sev,
                "campaigns": corr_count,
                "enriched": enr_count,
                "distributions": dist_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Threat intel report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="tfa",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="tfa",
            node="report",
        )

    return {
        "stage": TFAStage.REPORT.value,
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
