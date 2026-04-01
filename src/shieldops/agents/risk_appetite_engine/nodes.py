"""Node implementations for the Risk Appetite Engine Agent."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.risk_appetite_engine.models import (
    RAEStage,
    ReasoningStep,
    RiskAppetiteEngineState,
)
from shieldops.agents.risk_appetite_engine.prompts import (
    SYSTEM_COMPARE_THRESHOLDS,
    SYSTEM_DEFINE_APPETITE,
    SYSTEM_IDENTIFY_BREACHES,
    SYSTEM_MEASURE_EXPOSURE,
    SYSTEM_RECOMMEND,
    AdjustmentOutput,
    AppetiteDefinitionOutput,
    BreachIdentifyOutput,
    ExposureMeasureOutput,
    ThresholdCompareOutput,
)
from shieldops.agents.risk_appetite_engine.tools import (
    RiskAppetiteEngineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: RiskAppetiteEngineToolkit | None = None


def set_toolkit(
    toolkit: RiskAppetiteEngineToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> RiskAppetiteEngineToolkit:
    if _toolkit is None:
        return RiskAppetiteEngineToolkit()
    return _toolkit


def _step(
    state: RiskAppetiteEngineState,
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


async def define_appetite(
    state: RiskAppetiteEngineState,
) -> dict[str, Any]:
    """Define risk appetite per category."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    defs = await toolkit.define_appetite(state.config)

    try:
        ctx = _json.dumps(
            {
                "categories": state.config.get("categories", []),
                "definition_count": len(defs),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DEFINE_APPETITE,
            user_prompt=f"Appetite definition context:\n{ctx}",
            schema=AppetiteDefinitionOutput,
        )
        if hasattr(llm_result, "categories_defined"):
            logger.info("llm_enhanced", node="define_appetite")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="define_appetite",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "define_appetite",
        f"config={state.config.get('categories', [])}",
        f"defined {len(defs)} categories",
        elapsed,
        "risk_data_source",
    )
    await toolkit.record_metric(
        "categories_defined",
        float(len(defs)),
    )

    return {
        "appetite_definitions": defs,
        "stage": RAEStage.MEASURE_EXPOSURE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "define_appetite",
        "session_start": start,
    }


async def measure_exposure(
    state: RiskAppetiteEngineState,
) -> dict[str, Any]:
    """Measure current risk exposure per category."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    measurements = await toolkit.measure_exposure(
        state.appetite_definitions,
    )

    try:
        ctx = _json.dumps(
            {
                "definition_count": len(state.appetite_definitions),
                "measurement_count": len(measurements),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MEASURE_EXPOSURE,
            user_prompt=f"Exposure measurement context:\n{ctx}",
            schema=ExposureMeasureOutput,
        )
        if hasattr(llm_result, "categories_measured"):
            logger.info("llm_enhanced", node="measure_exposure")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="measure_exposure",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "measure_exposure",
        f"measuring {len(state.appetite_definitions)} categories",
        f"{len(measurements)} measurements",
        elapsed,
        "risk_data_source",
    )

    return {
        "exposure_measurements": measurements,
        "stage": RAEStage.COMPARE_THRESHOLDS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "measure_exposure",
    }


async def compare_thresholds(
    state: RiskAppetiteEngineState,
) -> dict[str, Any]:
    """Compare exposure against appetite thresholds."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    comparisons = await toolkit.compare_thresholds(
        state.appetite_definitions,
        state.exposure_measurements,
    )
    exceeding = sum(1 for c in comparisons if not c.get("within_tolerance"))

    try:
        ctx = _json.dumps(
            {
                "definition_count": len(state.appetite_definitions),
                "exceeding": exceeding,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COMPARE_THRESHOLDS,
            user_prompt=f"Threshold comparison context:\n{ctx}",
            schema=ThresholdCompareOutput,
        )
        if hasattr(llm_result, "within_tolerance"):
            logger.info(
                "llm_enhanced",
                node="compare_thresholds",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="compare_thresholds",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "compare_thresholds",
        f"comparing {len(state.appetite_definitions)} thresholds",
        f"{len(comparisons)} compared, {exceeding} exceeding",
        elapsed,
        "policy_engine",
    )
    await toolkit.record_metric("thresholds_exceeded", float(exceeding))

    return {
        "threshold_comparisons": comparisons,
        "stage": RAEStage.IDENTIFY_BREACHES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "compare_thresholds",
    }


async def identify_breaches(
    state: RiskAppetiteEngineState,
) -> dict[str, Any]:
    """Identify threshold breaches requiring action."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    breaches = await toolkit.identify_breaches(
        state.threshold_comparisons,
    )
    critical = sum(1 for b in breaches if b.get("severity") == "critical")

    try:
        ctx = _json.dumps(
            {
                "comparison_count": len(state.threshold_comparisons),
                "breach_count": len(breaches),
                "critical": critical,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_IDENTIFY_BREACHES,
            user_prompt=f"Breach identification context:\n{ctx}",
            schema=BreachIdentifyOutput,
        )
        if hasattr(llm_result, "breaches_found"):
            logger.info(
                "llm_enhanced",
                node="identify_breaches",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="identify_breaches",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "identify_breaches",
        f"analyzing {len(state.threshold_comparisons)} comparisons",
        f"{len(breaches)} breaches, {critical} critical",
        elapsed,
        "risk_data_source",
    )

    return {
        "breach_records": breaches,
        "stage": RAEStage.RECOMMEND_ADJUSTMENTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_breaches",
    }


async def recommend_adjustments(
    state: RiskAppetiteEngineState,
) -> dict[str, Any]:
    """Recommend adjustments to reduce risk exposure."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    recs = await toolkit.recommend_adjustments(
        state.breach_records,
        state.config,
    )

    try:
        ctx = _json.dumps(
            {
                "breach_count": len(state.breach_records),
                "recommendation_count": len(recs),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RECOMMEND,
            user_prompt=f"Adjustment context:\n{ctx}",
            schema=AdjustmentOutput,
        )
        if hasattr(llm_result, "recommendations_count"):
            logger.info(
                "llm_enhanced",
                node="recommend_adjustments",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend_adjustments",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "recommend_adjustments",
        f"addressing {len(state.breach_records)} breaches",
        f"{len(recs)} recommendations",
        elapsed,
        "policy_engine",
    )
    await toolkit.record_metric(
        "recommendations",
        float(len(recs)),
    )

    return {
        "adjustment_recommendations": recs,
        "stage": RAEStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_adjustments",
    }


async def generate_report(
    state: RiskAppetiteEngineState,
) -> dict[str, Any]:
    """Generate final risk appetite report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "appetite_definitions": len(state.appetite_definitions),
        "exposures_measured": len(state.exposure_measurements),
        "thresholds_compared": len(state.threshold_comparisons),
        "breaches_found": len(state.breach_records),
        "recommendations": len(state.adjustment_recommendations),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
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
