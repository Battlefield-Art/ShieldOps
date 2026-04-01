"""Node implementations for the Intelligence Fusion Center LangGraph workflow.

Each node is an async function that:
1. Queries external systems via the toolkit
2. Uses the LLM to analyze and reason about data
3. Updates the IFC state with findings
4. Records its reasoning step in the audit trail
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.intelligence_fusion_center.models import (
    IFCStage,
    IntelligenceFusionCenterState,
    ReasoningStep,
)
from shieldops.agents.intelligence_fusion_center.prompts import (
    SYSTEM_ASSESS_THREATS,
    SYSTEM_COLLECT_FEEDS,
    SYSTEM_CORRELATE_THREATS,
    SYSTEM_FUSE_INTELLIGENCE,
    SYSTEM_GENERATE_ASSESSMENT,
    AssessmentAnalysis,
    CorrelationAnalysis,
    FeedCollectionAnalysis,
    FusionAnalysis,
    ReportAnalysis,
)
from shieldops.agents.intelligence_fusion_center.tools import (
    IntelligenceFusionCenterToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by runner at startup.
_toolkit: IntelligenceFusionCenterToolkit | None = None


def set_toolkit(
    toolkit: IntelligenceFusionCenterToolkit,
) -> None:
    """Configure toolkit used by all nodes."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> IntelligenceFusionCenterToolkit:
    if _toolkit is None:
        return IntelligenceFusionCenterToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# ---- Node: collect_feeds ----


async def collect_feeds(
    state: IntelligenceFusionCenterState,
) -> dict[str, Any]:
    """Collect raw intelligence feeds from all configured sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "ifc_collecting_feeds",
        request_id=state.request_id,
    )

    feeds = await toolkit.collect_feeds(tenant_id=state.tenant_id)

    output_summary = f"Collected {len(feeds)} feeds from configured sources."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "feeds_collected": len(feeds),
                "sources": list({f.source.value for f in feeds}),
                "indicator_types": list({f.indicator_type for f in feeds[:20]}),
            },
            default=str,
        )
        llm_result = cast(
            FeedCollectionAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_COLLECT_FEEDS,
                user_prompt=f"Feed collection results:\n{ctx}",
                schema=FeedCollectionAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(feeds)} feeds collected."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_feeds",
        )

    step = ReasoningStep(
        step_number=1,
        action="collect_feeds",
        input_summary="Collecting feeds from all configured sources",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="multi_source_feed_collector",
    )

    return {
        "feeds_collected": [f.model_dump() for f in feeds],
        "stage": IFCStage.CORRELATE_THREATS,
        "session_start": start,
        "reasoning_chain": [step],
        "current_step": "collect_feeds",
    }


# ---- Node: correlate_threats ----


async def correlate_threats(
    state: IntelligenceFusionCenterState,
) -> dict[str, Any]:
    """Correlate indicators across sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    from shieldops.agents.intelligence_fusion_center.models import IntelFeed

    feeds = [IntelFeed.model_validate(f) for f in state.feeds_collected]

    logger.info(
        "ifc_correlating_threats",
        request_id=state.request_id,
        feed_count=len(feeds),
    )

    correlations = await toolkit.correlate_threats(feeds)

    matched = sum(1 for c in correlations if c.match_count > 1)
    output_summary = (
        f"Correlated {len(feeds)} feeds into "
        f"{len(correlations)} threat groups. "
        f"{matched} had multi-source matches."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "feeds": len(feeds),
                "correlations": len(correlations),
                "multi_source": matched,
                "avg_risk": round(
                    sum(c.risk_score for c in correlations) / max(len(correlations), 1),
                    2,
                ),
            },
            default=str,
        )
        llm_result = cast(
            CorrelationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_CORRELATE_THREATS,
                user_prompt=f"Correlation results:\n{ctx}",
                schema=CorrelationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {matched} multi-source matches."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="correlate_threats",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="correlate_threats",
        input_summary=f"Correlating {len(feeds)} feeds across sources",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="cross_source_correlator",
    )

    return {
        "correlated_threats": [c.model_dump() for c in correlations],
        "stage": IFCStage.FUSE_INTELLIGENCE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "correlate_threats",
    }


# ---- Node: fuse_intelligence ----


async def fuse_intelligence(
    state: IntelligenceFusionCenterState,
) -> dict[str, Any]:
    """Fuse correlated threats into unified intelligence."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    from shieldops.agents.intelligence_fusion_center.models import (
        CorrelatedThreat,
        IntelFeed,
    )

    correlations = [CorrelatedThreat.model_validate(c) for c in state.correlated_threats]
    feeds = [IntelFeed.model_validate(f) for f in state.feeds_collected]

    logger.info(
        "ifc_fusing_intelligence",
        request_id=state.request_id,
        correlation_count=len(correlations),
    )

    fusions = await toolkit.fuse_intelligence(correlations, feeds)

    avg_conf = round(
        sum(f.unified_confidence for f in fusions) / max(len(fusions), 1),
        3,
    )
    output_summary = (
        f"Fused {len(correlations)} correlations into "
        f"{len(fusions)} unified assessments. "
        f"Avg confidence: {avg_conf}."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "correlations": len(correlations),
                "fusions": len(fusions),
                "avg_confidence": avg_conf,
                "gaps": [g for f in fusions for g in f.intelligence_gaps],
            },
            default=str,
        )
        llm_result = cast(
            FusionAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_FUSE_INTELLIGENCE,
                user_prompt=f"Fusion results:\n{ctx}",
                schema=FusionAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Quality: {llm_result.fusion_quality}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="fuse_intelligence",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="fuse_intelligence",
        input_summary=(f"Fusing {len(correlations)} correlations with {len(feeds)} feeds"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="intelligence_fuser",
    )

    return {
        "fusion_results": [f.model_dump() for f in fusions],
        "confidence_score": avg_conf,
        "stage": IFCStage.ASSESS_THREATS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "fuse_intelligence",
    }


# ---- Node: assess_threats ----


async def assess_threats(
    state: IntelligenceFusionCenterState,
) -> dict[str, Any]:
    """Assess fused threats against the environment."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    from shieldops.agents.intelligence_fusion_center.models import FusionResult

    fusions = [FusionResult.model_validate(f) for f in state.fusion_results]

    logger.info(
        "ifc_assessing_threats",
        request_id=state.request_id,
        fusion_count=len(fusions),
    )

    assessments = await toolkit.assess_threats(fusions)

    actionable_count = sum(1 for a in assessments if a.actionable)
    high_priority = sum(1 for a in assessments if a.overall_score >= 0.7)

    output_summary = (
        f"Assessed {len(assessments)} fused threats. "
        f"{actionable_count} actionable, "
        f"{high_priority} high-priority."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "total": len(assessments),
                "actionable": actionable_count,
                "high_priority": high_priority,
                "threat_levels": [a.threat_level.value for a in assessments],
                "top_scores": sorted(
                    [a.overall_score for a in assessments],
                    reverse=True,
                )[:5],
            },
            default=str,
        )
        llm_result = cast(
            AssessmentAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_ASSESS_THREATS,
                user_prompt=f"Threat assessment:\n{ctx}",
                schema=AssessmentAnalysis,
            ),
        )
        output_summary = (
            f"{llm_result.summary} {actionable_count} actionable. Risk: {llm_result.overall_risk}."
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_threats",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_threats",
        input_summary=f"Assessing {len(fusions)} fused threats",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="threat_assessor",
    )

    return {
        "threat_assessments": [a.model_dump() for a in assessments],
        "actionable_count": actionable_count,
        "high_priority_count": high_priority,
        "stage": IFCStage.GENERATE_ASSESSMENT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "assess_threats",
    }


# ---- Node: generate_assessment ----


async def generate_assessment(
    state: IntelligenceFusionCenterState,
) -> dict[str, Any]:
    """Generate unified assessment reports from threat assessments."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    from shieldops.agents.intelligence_fusion_center.models import (
        FusionResult,
        ThreatAssessment,
    )

    assessments = [ThreatAssessment.model_validate(a) for a in state.threat_assessments]
    fusions = [FusionResult.model_validate(f) for f in state.fusion_results]

    logger.info(
        "ifc_generating_assessment",
        request_id=state.request_id,
        assessment_count=len(assessments),
    )

    reports = await toolkit.generate_assessment(assessments, fusions)

    output_summary = (
        f"Generated {len(reports)} assessment reports "
        f"from {state.actionable_count} actionable threats."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "reports": len(reports),
                "actionable": state.actionable_count,
                "threat_levels": [r.threat_level.value for r in reports],
            },
            default=str,
        )
        llm_result = cast(
            ReportAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_GENERATE_ASSESSMENT,
                user_prompt=f"Assessment generation:\n{ctx}",
                schema=ReportAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(reports)} reports."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_assessment",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_assessment",
        input_summary=(f"Generating assessments from {len(assessments)} threat assessments"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="assessment_generator",
    )

    return {
        "assessment_output": [r.model_dump() for r in reports],
        "stage": IFCStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "generate_assessment",
    }


# ---- Node: generate_report ----


async def generate_report(
    state: IntelligenceFusionCenterState,
) -> dict[str, Any]:
    """Final reporting node — summarize the fusion cycle."""
    start = datetime.now(UTC)

    session_duration_ms = 0
    if state.session_start:
        session_duration_ms = _elapsed_ms(state.session_start)

    output_summary = (
        f"IFC cycle complete. "
        f"{len(state.feeds_collected)} feeds collected, "
        f"{len(state.correlated_threats)} correlated, "
        f"{len(state.fusion_results)} fused, "
        f"{state.actionable_count} actionable, "
        f"{len(state.assessment_output)} reports. "
        f"Duration: {session_duration_ms}ms."
    )

    logger.info(
        "ifc_report",
        request_id=state.request_id,
        summary=output_summary,
    )

    report = {
        "request_id": state.request_id,
        "tenant_id": state.tenant_id,
        "feeds_collected": len(state.feeds_collected),
        "threats_correlated": len(state.correlated_threats),
        "fusions_completed": len(state.fusion_results),
        "assessments_generated": len(state.threat_assessments),
        "reports_generated": len(state.assessment_output),
        "actionable_count": state.actionable_count,
        "high_priority_count": state.high_priority_count,
        "confidence_score": state.confidence_score,
        "duration_ms": session_duration_ms,
        "summary": output_summary,
    }

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary="Generating final fusion report",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": session_duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
