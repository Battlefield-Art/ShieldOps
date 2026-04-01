"""Node implementations for the Cloud Entitlement Optimizer."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cloud_entitlement_optimizer.models import (
    CEOStage,
    CloudEntitlementOptimizerState,
    ReasoningStep,
)
from shieldops.agents.cloud_entitlement_optimizer.prompts import (
    SYSTEM_EXCESS,
    SYSTEM_INVENTORY,
    SYSTEM_RECOMMEND,
    SYSTEM_RISK,
    SYSTEM_USAGE,
    ExcessOutput,
    InventoryOutput,
    RecommendationOutput,
    RiskOutput,
    UsageOutput,
)
from shieldops.agents.cloud_entitlement_optimizer.tools import (
    CloudEntitlementOptimizerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CloudEntitlementOptimizerToolkit | None = None


def set_toolkit(
    toolkit: CloudEntitlementOptimizerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> CloudEntitlementOptimizerToolkit:
    if _toolkit is None:
        return CloudEntitlementOptimizerToolkit()
    return _toolkit


def _step(
    state: CloudEntitlementOptimizerState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def inventory_entitlements(
    state: CloudEntitlementOptimizerState,
) -> dict[str, Any]:
    """Inventory cloud entitlements."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    ents = await toolkit.inventory_entitlements(state.config)

    try:
        ctx = _json.dumps(
            {"count": len(ents)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INVENTORY,
            user_prompt=f"Inventory context:\n{ctx}",
            schema=InventoryOutput,
        )
        if hasattr(llm_result, "total_entitlements"):
            logger.info(
                "llm_enhanced",
                node="inventory_entitlements",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="inventory_entitlements",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "inventory_entitlements",
        f"config={state.config}",
        f"inventoried {len(ents)} entitlements",
        elapsed,
        "cloud_client",
    )
    await toolkit.record_metric(
        "entitlements_inventoried",
        float(len(ents)),
    )

    return {
        "entitlements": ents,
        "stage": CEOStage.ANALYZE_USAGE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "inventory_entitlements",
        "session_start": start,
    }


async def analyze_usage(
    state: CloudEntitlementOptimizerState,
) -> dict[str, Any]:
    """Analyze entitlement usage patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_usage(
        state.entitlements,
    )

    try:
        ctx = _json.dumps(
            {
                "entitlements": len(state.entitlements),
                "analyzed": len(analyses),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_USAGE,
            user_prompt=f"Usage analysis context:\n{ctx}",
            schema=UsageOutput,
        )
        if hasattr(llm_result, "analyzed_count"):
            logger.info(
                "llm_enhanced",
                node="analyze_usage",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_usage",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "analyze_usage",
        f"analyzing {len(state.entitlements)} entitlements",
        f"{len(analyses)} usage analyses",
        elapsed,
        "iam_analyzer",
    )

    return {
        "usage_analyses": analyses,
        "stage": CEOStage.IDENTIFY_EXCESS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_usage",
    }


async def identify_excess(
    state: CloudEntitlementOptimizerState,
) -> dict[str, Any]:
    """Identify excess entitlements."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    excess = await toolkit.identify_excess(
        state.usage_analyses,
        state.entitlements,
    )

    try:
        ctx = _json.dumps(
            {
                "analyses": len(state.usage_analyses),
                "excess": len(excess),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_EXCESS,
            user_prompt=f"Excess identification context:\n{ctx}",
            schema=ExcessOutput,
        )
        if hasattr(llm_result, "excess_count"):
            logger.info(
                "llm_enhanced",
                node="identify_excess",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="identify_excess",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "identify_excess",
        f"checking {len(state.usage_analyses)} analyses",
        f"{len(excess)} excess entitlements",
        elapsed,
        "iam_analyzer",
    )
    await toolkit.record_metric(
        "excess_found",
        float(len(excess)),
    )

    return {
        "excess_entitlements": excess,
        "stage": CEOStage.CALCULATE_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_excess",
    }


async def calculate_risk(
    state: CloudEntitlementOptimizerState,
) -> dict[str, Any]:
    """Calculate risk for excess entitlements."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.calculate_risk(
        state.excess_entitlements,
    )
    critical = sum(1 for a in assessments if a.get("risk_level") == "critical")

    try:
        ctx = _json.dumps(
            {
                "excess": len(state.excess_entitlements),
                "assessed": len(assessments),
                "critical": critical,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=f"Risk calculation context:\n{ctx}",
            schema=RiskOutput,
        )
        if hasattr(llm_result, "assessed_count"):
            logger.info(
                "llm_enhanced",
                node="calculate_risk",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="calculate_risk",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "calculate_risk",
        f"assessing {len(state.excess_entitlements)} excess",
        f"{len(assessments)} assessed, {critical} critical",
        elapsed,
        "risk_engine",
    )

    return {
        "risk_assessments": assessments,
        "stage": CEOStage.RECOMMEND_CHANGES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "calculate_risk",
    }


async def recommend_changes(
    state: CloudEntitlementOptimizerState,
) -> dict[str, Any]:
    """Recommend entitlement changes."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    recs = await toolkit.recommend_changes(
        state.risk_assessments,
        state.excess_entitlements,
    )

    try:
        ctx = _json.dumps(
            {
                "assessments": len(state.risk_assessments),
                "recommendations": len(recs),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RECOMMEND,
            user_prompt=f"Recommendation context:\n{ctx}",
            schema=RecommendationOutput,
        )
        if hasattr(llm_result, "recommendations_count"):
            logger.info(
                "llm_enhanced",
                node="recommend_changes",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend_changes",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "recommend_changes",
        f"generating for {len(state.risk_assessments)} risks",
        f"{len(recs)} recommendations",
        elapsed,
        "iam_analyzer",
    )
    await toolkit.record_metric(
        "recommendations",
        float(len(recs)),
    )

    return {
        "recommendations": recs,
        "stage": CEOStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_changes",
    }


async def generate_report(
    state: CloudEntitlementOptimizerState,
) -> dict[str, Any]:
    """Generate final optimization report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "entitlements_inventoried": len(state.entitlements),
        "usage_analyzed": len(state.usage_analyses),
        "excess_found": len(state.excess_entitlements),
        "risks_assessed": len(state.risk_assessments),
        "recommendations": len(state.recommendations),
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
