"""Incident Timeline Builder Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CorrelatedEvent,
    ITBStage,
    RawEvent,
    ReasoningStep,
    RootCauseAnalysis,
    TimelineEntry,
)
from .tools import IncidentTimelineBuilderToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Collect Events
# ------------------------------------------------------------------


async def collect_events(
    state: dict[str, Any],
    toolkit: IncidentTimelineBuilderToolkit,
) -> dict[str, Any]:
    """Collect raw events from all sources."""
    logger.info("itb.node.collect_events")
    state = _to_dict(state)

    incident_id = state.get("incident_id", "INC-001")
    tenant_id = state.get("tenant_id", "default")
    events = await toolkit.collect_events(
        incident_id,
        tenant_id,
    )
    data = [e.model_dump() for e in events]

    note = f"Collected {len(events)} raw events"

    return {
        "stage": ITBStage.CORRELATE_SOURCES.value,
        "raw_events": data,
        "total_events": len(events),
        "current_step": "collect_events",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_events",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Correlate Sources
# ------------------------------------------------------------------


async def correlate_sources(
    state: dict[str, Any],
    toolkit: IncidentTimelineBuilderToolkit,
) -> dict[str, Any]:
    """Correlate events across multiple sources."""
    logger.info("itb.node.correlate_sources")
    state = _to_dict(state)

    events = [RawEvent(**e) for e in state.get("raw_events", [])]
    correlated = await toolkit.correlate_events(events)
    data = [c.model_dump() for c in correlated]

    note = f"Correlated into {len(correlated)} clusters from {len(events)} events"

    try:
        from .prompts import (
            SYSTEM_CORRELATE,
            CorrelationInsight,
        )

        ctx = json.dumps(
            {
                "clusters": [
                    {
                        "host": c.host,
                        "sources": [s.value for s in c.sources],
                        "event_count": len(c.event_ids),
                        "score": c.correlation_score,
                    }
                    for c in correlated[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            CorrelationInsight,
            await llm_structured(
                system_prompt=SYSTEM_CORRELATE,
                user_prompt=(f"Event correlation:\n{ctx}"),
                schema=CorrelationInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="itb",
            node="correlate_sources",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="itb",
            node="correlate_sources",
        )

    return {
        "stage": ITBStage.BUILD_TIMELINE.value,
        "correlated_events": data,
        "total_correlated": len(correlated),
        "current_step": "correlate_sources",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="correlate_sources",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Build Timeline
# ------------------------------------------------------------------


async def build_timeline(
    state: dict[str, Any],
    toolkit: IncidentTimelineBuilderToolkit,
) -> dict[str, Any]:
    """Build chronological timeline from correlated events."""
    logger.info("itb.node.build_timeline")
    state = _to_dict(state)

    correlated = [CorrelatedEvent(**c) for c in state.get("correlated_events", [])]
    raw_events = [RawEvent(**e) for e in state.get("raw_events", [])]
    timeline = await toolkit.build_timeline(
        correlated,
        raw_events,
    )
    data = [t.model_dump() for t in timeline]

    span = 0.0
    if len(timeline) >= 2:
        first_ts = timeline[0].timestamp
        last_ts = timeline[-1].timestamp
        span = _approx_span_minutes(
            first_ts,
            last_ts,
        )

    note = f"Built timeline with {len(timeline)} entries spanning ~{span:.1f} minutes"

    return {
        "stage": ITBStage.IDENTIFY_ROOT_CAUSE.value,
        "timeline_entries": data,
        "timeline_span_minutes": round(span, 1),
        "current_step": "build_timeline",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="build_timeline",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Identify Root Cause
# ------------------------------------------------------------------


async def identify_root_cause(
    state: dict[str, Any],
    toolkit: IncidentTimelineBuilderToolkit,
) -> dict[str, Any]:
    """Identify the probable root cause."""
    logger.info("itb.node.identify_root_cause")
    state = _to_dict(state)

    timeline = [TimelineEntry(**t) for t in state.get("timeline_entries", [])]
    correlated = [CorrelatedEvent(**c) for c in state.get("correlated_events", [])]
    rca = await toolkit.identify_root_cause(
        timeline,
        correlated,
    )
    data = rca.model_dump()

    note = f"Root cause: {rca.attack_vector} (confidence {rca.confidence:.0%})"

    try:
        from .prompts import (
            SYSTEM_ROOT_CAUSE,
            RootCauseInsight,
        )

        ctx = json.dumps(
            {
                "attack_vector": rca.attack_vector,
                "initial_host": rca.initial_access_host,
                "techniques": rca.mitre_techniques[:5],
                "factors": rca.contributing_factors[:5],
            },
            default=str,
        )
        llm_result = cast(
            RootCauseInsight,
            await llm_structured(
                system_prompt=SYSTEM_ROOT_CAUSE,
                user_prompt=(f"Root cause analysis:\n{ctx}"),
                schema=RootCauseInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="itb",
            node="identify_root_cause",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="itb",
            node="identify_root_cause",
        )

    return {
        "stage": ITBStage.GENERATE_NARRATIVE.value,
        "root_cause": data,
        "current_step": "identify_root_cause",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="identify_root_cause",
                detail=note,
                confidence=rca.confidence,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Generate Narrative
# ------------------------------------------------------------------


async def generate_narrative(
    state: dict[str, Any],
    toolkit: IncidentTimelineBuilderToolkit,
) -> dict[str, Any]:
    """Generate a human-readable incident narrative."""
    logger.info("itb.node.generate_narrative")
    state = _to_dict(state)

    timeline = [TimelineEntry(**t) for t in state.get("timeline_entries", [])]
    rca = RootCauseAnalysis(
        **state.get("root_cause", {}),
    )
    narrative = await toolkit.generate_narrative(
        timeline,
        rca,
    )
    data = narrative.model_dump()

    note = f"Generated narrative: {len(narrative.recommendations)} recommendations"

    try:
        from .prompts import (
            SYSTEM_NARRATIVE,
            NarrativeInsight,
        )

        ctx = json.dumps(
            {
                "summary": narrative.executive_summary,
                "impact": narrative.impact_assessment,
                "entry_count": len(timeline),
            },
            default=str,
        )
        llm_result = cast(
            NarrativeInsight,
            await llm_structured(
                system_prompt=SYSTEM_NARRATIVE,
                user_prompt=(f"Incident narrative:\n{ctx}"),
                schema=NarrativeInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="itb",
            node="generate_narrative",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="itb",
            node="generate_narrative",
        )

    return {
        "stage": ITBStage.REPORT.value,
        "narrative": data,
        "current_step": "generate_narrative",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="generate_narrative",
                detail=note,
                confidence=0.87,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: IncidentTimelineBuilderToolkit,
) -> dict[str, Any]:
    """Compile the final incident timeline report."""
    logger.info("itb.node.report")
    state = _to_dict(state)

    total_events = state.get("total_events", 0)
    total_correlated = state.get(
        "total_correlated",
        0,
    )
    span = state.get("timeline_span_minutes", 0.0)
    entry_count = len(
        state.get("timeline_entries", []),
    )
    narrative = state.get("narrative", {})
    rca = state.get("root_cause", {})

    lines = [
        "# Incident Timeline Report",
        "",
        f"**Total events collected:** {total_events}",
        f"**Correlated clusters:** {total_correlated}",
        f"**Timeline entries:** {entry_count}",
        f"**Timeline span:** {span:.1f} minutes",
        "",
        "## Root Cause",
        f"**Vector:** {rca.get('attack_vector', 'N/A')}",
        (f"**Confidence:** {rca.get('confidence', 0):.0%}"),
        f"**Cause:** {rca.get('probable_cause', 'N/A')}",
        "",
        "## Executive Summary",
        narrative.get("executive_summary", "N/A"),
        "",
        "## Impact",
        narrative.get("impact_assessment", "N/A"),
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_events": total_events,
                "correlated": total_correlated,
                "span_minutes": span,
                "attack_vector": rca.get(
                    "attack_vector",
                    "",
                ),
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Incident timeline report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="itb",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="itb",
            node="report",
        )

    return {
        "stage": ITBStage.REPORT.value,
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


def _approx_span_minutes(
    first: str,
    last: str,
) -> float:
    """Approximate time span between ISO timestamps."""
    try:
        from datetime import datetime

        fmt = "%Y-%m-%dT%H:%M:%SZ"
        t1 = datetime.strptime(first, fmt)
        t2 = datetime.strptime(last, fmt)
        delta = (t2 - t1).total_seconds()
        return max(0.0, delta / 60.0)
    except Exception:
        return 0.0
