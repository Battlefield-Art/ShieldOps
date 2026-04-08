"""Node implementations for the Security Telemetry
Optimizer Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_telemetry_optimizer.models import (
    ReasoningStep,
    SecurityTelemetryOptimizerState,
    STOStage,
)
from shieldops.agents.security_telemetry_optimizer.prompts import (
    SYSTEM_REPORT,
    SYSTEM_ROUTING,
    SYSTEM_VOLUME_ANALYSIS,
    SYSTEM_WASTE_DETECTION,
    OptimizationReportOutput,
    RoutingOptimizationOutput,
    VolumeAnalysisOutput,
    WasteDetectionOutput,
)
from shieldops.agents.security_telemetry_optimizer.tools import (
    SecurityTelemetryOptimizerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityTelemetryOptimizerToolkit | None = None


def _get_toolkit() -> SecurityTelemetryOptimizerToolkit:
    if _toolkit is None:
        return SecurityTelemetryOptimizerToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: inventory_sources
# ------------------------------------------------------------------


async def inventory_sources(
    state: SecurityTelemetryOptimizerState,
) -> dict[str, Any]:
    """Inventory all telemetry sources in the pipeline."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sources = await toolkit.inventory_sources(
        target_sources=state.target_sources,
        pipeline_name=state.pipeline_name,
    )

    step = _step(
        state.reasoning_chain,
        "inventory_sources",
        f"Targets: {len(state.target_sources)}",
        f"Discovered {len(sources)} sources",
        start,
        "pipeline_manager",
    )

    return {
        "sources": sources,
        "stage": STOStage.INVENTORY_SOURCES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "inventory_sources",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_volume
# ------------------------------------------------------------------


async def analyze_volume(
    state: SecurityTelemetryOptimizerState,
) -> dict[str, Any]:
    """Analyze volume and cardinality across sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_volume(
        sources=state.sources,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "source_count": len(state.sources),
                "sources_sample": state.sources[:5],
                "pipeline": state.pipeline_name,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_VOLUME_ANALYSIS,
            user_prompt=f"Analyze telemetry volume:\n{ctx}",
            schema=VolumeAnalysisOutput,
        )
        if llm_out.high_volume_sources:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            analyses.append(
                {
                    "analysis_id": f"llm-{rand_id}",
                    "high_volume": llm_out.high_volume_sources,  # type: ignore[union-attr]
                    "duplicates": llm_out.duplicate_sources,  # type: ignore[union-attr]
                    "total_waste_gb": llm_out.total_waste_gb,  # type: ignore[union-attr]
                    "cardinality_hotspots": llm_out.cardinality_hotspots,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_volume",
            hotspots=len(llm_out.cardinality_hotspots),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_volume",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_volume",
        f"Analyzing {len(state.sources)} sources",
        f"Produced {len(analyses)} volume analyses",
        start,
        "volume_analyzer",
    )

    return {
        "volume_analyses": analyses,
        "stage": STOStage.ANALYZE_VOLUME,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_volume",
    }


# ------------------------------------------------------------------
# Node: detect_waste
# ------------------------------------------------------------------


async def detect_waste(
    state: SecurityTelemetryOptimizerState,
) -> dict[str, Any]:
    """Detect telemetry waste and inefficiency."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    detections = await toolkit.detect_waste(
        volume_analyses=state.volume_analyses,
        sources=state.sources,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "volume_analyses": state.volume_analyses[:5],
                "source_count": len(state.sources),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_WASTE_DETECTION,
            user_prompt=f"Detect telemetry waste:\n{ctx}",
            schema=WasteDetectionOutput,
        )
        if llm_out.waste_items:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            detections.append(
                {
                    "waste_id": f"llm-{rand_id}",
                    "items": llm_out.waste_items,  # type: ignore[union-attr]
                    "total_cost_impact": llm_out.total_cost_impact,  # type: ignore[union-attr]
                    "priority_actions": llm_out.priority_actions,  # type: ignore[union-attr]
                    "severity": llm_out.severity,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="detect_waste",
            items=len(llm_out.waste_items),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_waste",
        )

    step = _step(
        state.reasoning_chain,
        "detect_waste",
        f"Scanning {len(state.volume_analyses)} analyses",
        f"Found {len(detections)} waste items",
        start,
        "waste_detector",
    )

    return {
        "waste_detections": detections,
        "stage": STOStage.DETECT_WASTE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_waste",
    }


# ------------------------------------------------------------------
# Node: optimize_routing
# ------------------------------------------------------------------


async def optimize_routing(
    state: SecurityTelemetryOptimizerState,
) -> dict[str, Any]:
    """Generate routing optimizations to reduce waste."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    optimizations = await toolkit.optimize_routing(
        waste_detections=state.waste_detections,
        sources=state.sources,
        budget_limit=state.budget_limit,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "waste_detections": state.waste_detections[:5],
                "sources": state.sources[:5],
                "budget_limit": state.budget_limit,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ROUTING,
            user_prompt=(f"Optimize telemetry routing:\n{ctx}"),
            schema=RoutingOptimizationOutput,
        )
        if llm_out.optimizations:  # type: ignore[union-attr]
            optimizations = [
                *optimizations,
                *llm_out.optimizations,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="optimize_routing",
            count=len(llm_out.optimizations),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="optimize_routing",
        )

    total_savings_gb = sum(
        float(o.get("savings_gb", 0)) for o in optimizations if isinstance(o, dict)
    )
    total_savings_cost = sum(
        float(o.get("savings_cost", 0)) for o in optimizations if isinstance(o, dict)
    )

    step = _step(
        state.reasoning_chain,
        "optimize_routing",
        f"Processing {len(state.waste_detections)} waste items",
        f"Generated {len(optimizations)} optimizations",
        start,
        "routing_engine",
    )

    return {
        "optimizations": optimizations,
        "total_savings_gb": total_savings_gb,
        "total_savings_cost": total_savings_cost,
        "stage": STOStage.OPTIMIZE_ROUTING,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "optimize_routing",
    }


# ------------------------------------------------------------------
# Node: validate_quality
# ------------------------------------------------------------------


async def validate_quality(
    state: SecurityTelemetryOptimizerState,
) -> dict[str, Any]:
    """Validate optimizations maintain data quality."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    validations = await toolkit.validate_quality(
        optimizations=state.optimizations,
        quality_threshold=state.quality_threshold,
    )

    all_passed = (
        all(v.get("passed", False) for v in validations if isinstance(v, dict))
        if validations
        else True
    )

    sources_optimized = len(
        {o.get("source_id", "") for o in state.optimizations if isinstance(o, dict)}
    )

    step = _step(
        state.reasoning_chain,
        "validate_quality",
        f"Validating {len(state.optimizations)} optimizations",
        f"Quality {'maintained' if all_passed else 'degraded'}",
        start,
        "quality_validator",
    )

    return {
        "validations": validations,
        "quality_maintained": all_passed,
        "sources_optimized": sources_optimized,
        "stage": STOStage.VALIDATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_quality",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityTelemetryOptimizerState,
) -> dict[str, Any]:
    """Generate the final telemetry optimization report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    report: dict[str, Any] = {
        "pipeline": state.pipeline_name,
        "sources_optimized": state.sources_optimized,
        "total_savings_gb": state.total_savings_gb,
        "total_savings_cost": state.total_savings_cost,
        "quality_maintained": state.quality_maintained,
        "duration_ms": duration_ms,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "pipeline": state.pipeline_name,
                "sources_count": len(state.sources),
                "waste_count": len(state.waste_detections),
                "optimizations_count": len(state.optimizations),
                "savings_gb": state.total_savings_gb,
                "savings_cost": state.total_savings_cost,
                "quality_maintained": state.quality_maintained,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate optimization report:\n{ctx}",
            schema=OptimizationReportOutput,
        )
        if isinstance(llm_out, OptimizationReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "quality_assessment": llm_out.quality_assessment,
                    "roi_estimate": llm_out.roi_estimate,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recs=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record final metric
    await toolkit.record_metric(
        metric_name="optimization_savings",
        value=state.total_savings_cost,
        tags={"pipeline": state.pipeline_name},
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.sources_optimized} sources",
        (f"Report generated, savings=${state.total_savings_cost:.2f}/mo"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": STOStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
