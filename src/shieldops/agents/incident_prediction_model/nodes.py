"""Node implementations for the Incident Prediction Model."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.incident_prediction_model.models import (
    IncidentPredictionModelState,
    IPMStage,
    ReasoningStep,
)
from shieldops.agents.incident_prediction_model.prompts import (
    SYSTEM_ANALYZE_PATTERNS,
    SYSTEM_ASSESS_CONFIDENCE,
    SYSTEM_BUILD_PREDICTIONS,
    SYSTEM_COLLECT_SIGNALS,
    SYSTEM_RECOMMEND_PREVENTIONS,
    ConfidenceAssessOutput,
    PatternAnalysisOutput,
    PredictionBuildOutput,
    PreventionOutput,
    SignalCollectionOutput,
)
from shieldops.agents.incident_prediction_model.tools import (
    IncidentPredictionModelToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IncidentPredictionModelToolkit | None = None


def set_toolkit(
    toolkit: IncidentPredictionModelToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> IncidentPredictionModelToolkit:
    if _toolkit is None:
        return IncidentPredictionModelToolkit()
    return _toolkit


def _step(
    state: IncidentPredictionModelState,
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


async def collect_signals(
    state: IncidentPredictionModelState,
) -> dict[str, Any]:
    """Collect security signals from configured sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.collect_signals(state.config)
    high_sev = sum(1 for s in raw if s.get("severity") in ("critical", "high"))

    try:
        ctx = _json.dumps(
            {
                "time_window": state.config.get("time_window_hours", 24),
                "signal_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COLLECT_SIGNALS,
            user_prompt=f"Signal collection context:\n{ctx}",
            schema=SignalCollectionOutput,
        )
        if hasattr(llm_result, "total_signals"):
            logger.info("llm_enhanced", node="collect_signals")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="collect_signals")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "collect_signals",
        f"window={state.config.get('time_window_hours', 24)}h",
        f"collected {len(raw)} signals, {high_sev} high-severity",
        elapsed,
        "siem_client",
    )
    await toolkit.record_metric("signals_collected", float(len(raw)))

    return {
        "signals": raw,
        "stage": IPMStage.ANALYZE_PATTERNS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_signals",
        "session_start": start,
    }


async def analyze_patterns(
    state: IncidentPredictionModelState,
) -> dict[str, Any]:
    """Analyze signals against historical incident patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    patterns = await toolkit.analyze_patterns(state.signals)

    try:
        ctx = _json.dumps(
            {"signal_count": len(state.signals), "pattern_count": len(patterns)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE_PATTERNS,
            user_prompt=f"Pattern analysis context:\n{ctx}",
            schema=PatternAnalysisOutput,
        )
        if hasattr(llm_result, "patterns_found"):
            logger.info("llm_enhanced", node="analyze_patterns")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="analyze_patterns")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "analyze_patterns",
        f"analyzing {len(state.signals)} signals",
        f"{len(patterns)} patterns identified",
        elapsed,
        "incident_db",
    )

    return {
        "patterns": patterns,
        "stage": IPMStage.BUILD_PREDICTIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_patterns",
    }


async def build_predictions(
    state: IncidentPredictionModelState,
) -> dict[str, Any]:
    """Build incident predictions from patterns and signals."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    predictions = await toolkit.build_predictions(state.patterns, state.signals)

    try:
        ctx = _json.dumps(
            {
                "pattern_count": len(state.patterns),
                "prediction_count": len(predictions),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_BUILD_PREDICTIONS,
            user_prompt=f"Prediction building context:\n{ctx}",
            schema=PredictionBuildOutput,
        )
        if hasattr(llm_result, "predictions_made"):
            logger.info("llm_enhanced", node="build_predictions")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="build_predictions")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    high_prob = sum(1 for p in predictions if p.get("probability", 0) >= 0.7)
    step = _step(
        state,
        "build_predictions",
        f"building from {len(state.patterns)} patterns",
        f"{len(predictions)} predictions, {high_prob} high-probability",
        elapsed,
        "incident_db",
    )
    await toolkit.record_metric("predictions_built", float(len(predictions)))

    return {
        "predictions": predictions,
        "stage": IPMStage.ASSESS_CONFIDENCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "build_predictions",
    }


async def assess_confidence(
    state: IncidentPredictionModelState,
) -> dict[str, Any]:
    """Assess confidence for each prediction."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scores = await toolkit.assess_confidence(state.predictions)

    try:
        ctx = _json.dumps(
            {"prediction_count": len(state.predictions), "scores": scores[:5]},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ASSESS_CONFIDENCE,
            user_prompt=f"Confidence assessment context:\n{ctx}",
            schema=ConfidenceAssessOutput,
        )
        if hasattr(llm_result, "avg_confidence"):
            logger.info("llm_enhanced", node="assess_confidence")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="assess_confidence")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "assess_confidence",
        f"assessing {len(state.predictions)} predictions",
        f"{len(scores)} confidence scores generated",
        elapsed,
        "incident_db",
    )

    return {
        "confidence_scores": scores,
        "stage": IPMStage.RECOMMEND_PREVENTIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_confidence",
    }


async def recommend_preventions(
    state: IncidentPredictionModelState,
) -> dict[str, Any]:
    """Recommend prevention plans for predictions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    plans = await toolkit.recommend_preventions(state.predictions, state.confidence_scores)

    try:
        ctx = _json.dumps(
            {"prediction_count": len(state.predictions), "plan_count": len(plans)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RECOMMEND_PREVENTIONS,
            user_prompt=f"Prevention recommendation context:\n{ctx}",
            schema=PreventionOutput,
        )
        if hasattr(llm_result, "plans_created"):
            logger.info("llm_enhanced", node="recommend_preventions")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="recommend_preventions")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "recommend_preventions",
        f"planning for {len(state.predictions)} predictions",
        f"{len(plans)} prevention plans created",
        elapsed,
        "threat_intel_client",
    )
    await toolkit.record_metric("prevention_plans", float(len(plans)))

    return {
        "prevention_plans": plans,
        "stage": IPMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_preventions",
    }


async def generate_report(
    state: IncidentPredictionModelState,
) -> dict[str, Any]:
    """Generate final prediction model report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "signals": len(state.signals),
        "patterns": len(state.patterns),
        "predictions": len(state.predictions),
        "confidence_scores": len(state.confidence_scores),
        "prevention_plans": len(state.prevention_plans),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("scan_duration_ms", float(duration_ms))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
