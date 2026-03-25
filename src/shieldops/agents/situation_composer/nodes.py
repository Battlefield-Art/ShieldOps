"""Node implementations for the Situation Composer Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.situation_composer.models import (
    ComposerStage,
    ReasoningStep,
    SituationComposerState,
)
from shieldops.agents.situation_composer.prompts import (
    SYSTEM_ACTION_RECOMMENDATION,
    SYSTEM_ALERT_CORRELATION,
    SYSTEM_NARRATIVE_BUILDER,
    SYSTEM_SITUATION_SUMMARY,
    ActionRecommendationOutput,
    CorrelationOutput,
    NarrativeOutput,
    SituationSummaryOutput,
)
from shieldops.agents.situation_composer.tools import SituationComposerToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SituationComposerToolkit | None = None


def set_toolkit(toolkit: SituationComposerToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SituationComposerToolkit:
    if _toolkit is None:
        return SituationComposerToolkit()
    return _toolkit


# ------------------------------------------------------------------
# 1. Collect alerts
# ------------------------------------------------------------------


async def collect_alerts(state: SituationComposerState) -> dict[str, Any]:
    """Pull recent alerts from all connected vendors."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    time_window = state.stats.get("time_window_minutes", 60)
    vendors = state.stats.get("vendors")

    raw_alerts = await toolkit.collect_alerts(
        time_window_minutes=time_window,
        vendors=vendors,
    )

    step = ReasoningStep(
        step="collect_alerts",
        detail=f"Collected {len(raw_alerts)} alerts (window={time_window}m)",
        confidence=1.0,
        metadata={"alert_count": len(raw_alerts), "vendors": vendors},
    )

    return {
        "raw_alerts": raw_alerts,
        "stage": ComposerStage.COLLECT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_alerts",
        "session_start": start,
    }


# ------------------------------------------------------------------
# 2. Deduplicate
# ------------------------------------------------------------------


async def deduplicate(state: SituationComposerState) -> dict[str, Any]:
    """Merge duplicate/related alerts."""
    toolkit = _get_toolkit()

    deduped = await toolkit.deduplicate_alerts(state.raw_alerts)

    step = ReasoningStep(
        step="deduplicate",
        detail=(
            f"Deduplicated {len(state.raw_alerts)} alerts into {len(deduped)} canonical alerts"
        ),
        confidence=1.0,
        metadata={
            "input_count": len(state.raw_alerts),
            "output_count": len(deduped),
        },
    )

    return {
        "deduplicated_alerts": deduped,
        "stage": ComposerStage.DEDUPLICATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "deduplicate",
    }


# ------------------------------------------------------------------
# 3. Correlate signals
# ------------------------------------------------------------------


async def correlate_signals(state: SituationComposerState) -> dict[str, Any]:
    """Identify correlations across alerts with LLM enhancement."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    correlations = await toolkit.correlate_signals(state.raw_alerts)

    # LLM-enhanced correlation
    try:
        context = _json.dumps(
            {
                "alert_count": len(state.raw_alerts),
                "vendors": list({a.vendor for a in state.raw_alerts}),
                "alerts_summary": [
                    {
                        "id": a.id,
                        "vendor": a.vendor,
                        "type": a.alert_type,
                        "severity": a.severity.value if a.severity else "",
                        "hostname": a.hostname,
                        "source_ip": a.source_ip,
                        "dest_ip": a.dest_ip,
                        "user": a.user,
                        "title": a.title[:100],
                    }
                    for a in state.raw_alerts[:30]
                ],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ALERT_CORRELATION,
            user_prompt=f"Alerts to correlate:\n{context}",
            schema=CorrelationOutput,
        )
        if hasattr(llm_result, "cross_vendor_insights"):
            logger.info(
                "llm_enhanced",
                node="correlate_signals",
                confidence=getattr(llm_result, "correlation_confidence", 0),
            )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="correlate_signals")

    duration_ms = int((datetime.now(UTC) - start).total_seconds() * 1000)

    step = ReasoningStep(
        step="correlate_signals",
        detail=f"Found {len(correlations)} correlation links",
        confidence=0.8,
        metadata={
            "correlation_count": len(correlations),
            "duration_ms": duration_ms,
        },
    )

    return {
        "correlations": correlations,
        "stage": ComposerStage.CORRELATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "correlate_signals",
    }


# ------------------------------------------------------------------
# 4. Build narrative
# ------------------------------------------------------------------


async def build_narrative(state: SituationComposerState) -> dict[str, Any]:
    """Construct a kill-chain narrative from correlated alerts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    narrative = await toolkit.build_narrative(
        alerts=state.raw_alerts,
        correlations=state.correlations,
    )

    # LLM-enhanced narrative
    try:
        context = _json.dumps(
            {
                "alert_count": len(state.raw_alerts),
                "correlation_count": len(state.correlations),
                "kill_chain_phases": list(narrative.kill_chain_mapping.keys()),
                "affected_assets": narrative.affected_assets[:15],
                "iocs": narrative.ioc_list[:10],
                "timeline_events": narrative.timeline[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_NARRATIVE_BUILDER,
            user_prompt=f"Build narrative from:\n{context}",
            schema=NarrativeOutput,
        )
        # Merge LLM-generated fields into narrative
        if hasattr(llm_result, "title"):
            narrative.title = llm_result.title
        if hasattr(llm_result, "executive_summary"):
            narrative.executive_summary = llm_result.executive_summary
        if hasattr(llm_result, "mitre_techniques"):
            narrative.mitre_techniques = list(
                set(narrative.mitre_techniques + llm_result.mitre_techniques)
            )
        if hasattr(llm_result, "ioc_list"):
            narrative.ioc_list = list(set(narrative.ioc_list + llm_result.ioc_list))
        if hasattr(llm_result, "confidence"):
            narrative.confidence = llm_result.confidence

        logger.info(
            "llm_enhanced",
            node="build_narrative",
            narrative_id=narrative.id,
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="build_narrative")

    duration_ms = int((datetime.now(UTC) - start).total_seconds() * 1000)

    step = ReasoningStep(
        step="build_narrative",
        detail=(
            f"Built narrative: {narrative.title} "
            f"({len(narrative.kill_chain_mapping)} phases, "
            f"{len(narrative.affected_assets)} assets)"
        ),
        confidence=narrative.confidence,
        metadata={
            "narrative_id": narrative.id,
            "duration_ms": duration_ms,
        },
    )

    return {
        "narrative": narrative,
        "stage": ComposerStage.BUILD_NARRATIVE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "build_narrative",
    }


# ------------------------------------------------------------------
# 5. Recommend actions
# ------------------------------------------------------------------


async def recommend_actions(state: SituationComposerState) -> dict[str, Any]:
    """Generate response recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if state.narrative is None:
        return {
            "recommended_actions": [],
            "stage": ComposerStage.RECOMMEND_ACTIONS,
            "reasoning_chain": [
                *state.reasoning_chain,
                ReasoningStep(
                    step="recommend_actions",
                    detail="Skipped — no narrative available",
                    confidence=0.0,
                ),
            ],
            "current_step": "recommend_actions",
        }

    actions = await toolkit.recommend_actions(state.narrative)

    # LLM-enhanced recommendations
    try:
        context = _json.dumps(
            {
                "narrative_title": state.narrative.title,
                "executive_summary": state.narrative.executive_summary,
                "kill_chain_phases": list(state.narrative.kill_chain_mapping.keys()),
                "affected_assets": state.narrative.affected_assets[:10],
                "iocs": state.narrative.ioc_list[:10],
                "mitre_techniques": state.narrative.mitre_techniques,
                "confidence": state.narrative.confidence,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ACTION_RECOMMENDATION,
            user_prompt=f"Recommend actions for:\n{context}",
            schema=ActionRecommendationOutput,
        )
        logger.info(
            "llm_enhanced",
            node="recommend_actions",
            action_count=len(getattr(llm_result, "actions", [])),
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="recommend_actions")

    duration_ms = int((datetime.now(UTC) - start).total_seconds() * 1000)

    step = ReasoningStep(
        step="recommend_actions",
        detail=f"Recommended {len(actions)} actions",
        confidence=state.narrative.confidence,
        metadata={
            "action_count": len(actions),
            "auto_executable": sum(1 for a in actions if a.auto_executable),
            "duration_ms": duration_ms,
        },
    )

    return {
        "recommended_actions": actions,
        "stage": ComposerStage.RECOMMEND_ACTIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_actions",
    }


# ------------------------------------------------------------------
# 6. Publish situation
# ------------------------------------------------------------------


async def publish_situation(state: SituationComposerState) -> dict[str, Any]:
    """Create and publish the composed situation."""
    toolkit = _get_toolkit()

    situation = await toolkit.publish_situation(
        narrative=state.narrative,
        actions=state.recommended_actions,
    )

    # LLM-enhanced summary
    try:
        context = _json.dumps(
            {
                "has_narrative": state.narrative is not None,
                "narrative_title": state.narrative.title if state.narrative else "",
                "alert_count": len(state.raw_alerts),
                "correlation_count": len(state.correlations),
                "action_count": len(state.recommended_actions),
                "confidence": state.narrative.confidence if state.narrative else 0.0,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SITUATION_SUMMARY,
            user_prompt=f"Summarize situation:\n{context}",
            schema=SituationSummaryOutput,
        )
        if hasattr(llm_result, "severity"):
            import contextlib

            from shieldops.agents.situation_composer.models import AlertSeverity

            with contextlib.suppress(ValueError):
                situation.severity = AlertSeverity(llm_result.severity)
        if hasattr(llm_result, "assigned_team"):
            situation.assigned_to = llm_result.assigned_team

        logger.info(
            "llm_enhanced",
            node="publish_situation",
            situation_id=situation.id,
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="publish_situation")

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    step = ReasoningStep(
        step="publish_situation",
        detail=f"Published situation {situation.id} ({situation.severity.value})",
        confidence=state.narrative.confidence if state.narrative else 0.0,
        metadata={
            "situation_id": situation.id,
            "severity": situation.severity.value,
            "duration_ms": duration_ms,
        },
    )

    stats = {
        **state.stats,
        "total_alerts": len(state.raw_alerts),
        "deduplicated_alerts": len(state.deduplicated_alerts),
        "correlations": len(state.correlations),
        "actions": len(state.recommended_actions),
        "situation_severity": situation.severity.value,
    }

    return {
        "situation": situation,
        "stage": ComposerStage.PUBLISH,
        "stats": stats,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
        "session_duration_ms": duration_ms,
    }
