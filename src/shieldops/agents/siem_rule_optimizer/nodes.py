"""Node implementations for the SIEM Rule Optimizer
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.siem_rule_optimizer.models import (
    ReasoningStep,
    SIEMRuleOptimizerState,
    SROStage,
)
from shieldops.agents.siem_rule_optimizer.prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_COLLECT,
    SYSTEM_OVERLAP,
    SYSTEM_REPORT,
    OptimizationReportOutput,
    OverlapDetectionOutput,
    PerformanceAnalysisOutput,
    RuleCollectionOutput,
)
from shieldops.agents.siem_rule_optimizer.tools import (
    SIEMRuleOptimizerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SIEMRuleOptimizerToolkit | None = None


def _get_toolkit() -> SIEMRuleOptimizerToolkit:
    if _toolkit is None:
        return SIEMRuleOptimizerToolkit()
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
# Node: collect_rules
# ------------------------------------------------------------------


async def collect_rules(
    state: SIEMRuleOptimizerState,
) -> dict[str, Any]:
    """Collect detection rules from the SIEM platform."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    rules = await toolkit.collect_rules(
        siem_source=state.siem_source,
        rule_filters=state.rule_filters,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "siem": state.siem_source,
                "filters": state.rule_filters,
                "rule_count": len(rules),
                "time_range": state.time_range,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_COLLECT,
            user_prompt=f"Analyze rule inventory:\n{ctx}",
            schema=RuleCollectionOutput,
        )
        if llm_out.risk_areas:  # type: ignore[union-attr]
            rules.append(
                {
                    "collection_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "categories": llm_out.categories,  # type: ignore[union-attr]
                    "risk_areas": llm_out.risk_areas,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="collect_rules",
            risks=len(llm_out.risk_areas),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_rules",
        )

    step = _step(
        state.reasoning_chain,
        "collect_rules",
        f"SIEM: {state.siem_source}, range={state.time_range}",
        f"Collected {len(rules)} rules",
        start,
        "siem_connector",
    )

    return {
        "rules": rules,
        "total_rules": len(rules),
        "stage": SROStage.COLLECT_RULES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_rules",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_performance
# ------------------------------------------------------------------


async def analyze_performance(
    state: SIEMRuleOptimizerState,
) -> dict[str, Any]:
    """Analyze detection rule performance metrics."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    performance_data = await toolkit.analyze_performance(
        rules=state.rules,
        time_range=state.time_range,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "rule_count": len(state.rules),
                "rules_sample": state.rules[:5],
                "time_range": state.time_range,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Analyze rule performance:\n{ctx}",
            schema=PerformanceAnalysisOutput,
        )
        if llm_out.recommendations:  # type: ignore[union-attr]
            performance_data.append(
                {
                    "analysis_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "noisy_rules": llm_out.noisy_rules,  # type: ignore[union-attr]
                    "underperforming": llm_out.underperforming_rules,  # type: ignore[union-attr]
                    "avg_precision": llm_out.avg_precision,  # type: ignore[union-attr]
                    "recommendations": llm_out.recommendations,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_performance",
            noisy=len(llm_out.noisy_rules),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_performance",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_performance",
        f"Analyzing {len(state.rules)} rules over {state.time_range}",
        f"Produced {len(performance_data)} performance records",
        start,
        "performance_analyzer",
    )

    return {
        "performance_data": performance_data,
        "stage": SROStage.ANALYZE_PERFORMANCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_performance",
    }


# ------------------------------------------------------------------
# Node: detect_overlap
# ------------------------------------------------------------------


async def detect_overlap(
    state: SIEMRuleOptimizerState,
) -> dict[str, Any]:
    """Detect overlapping and redundant detection rules."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    overlaps = await toolkit.detect_overlap(
        rules=state.rules,
        performance_data=state.performance_data,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "rule_count": len(state.rules),
                "performance_count": len(state.performance_data),
                "rules_sample": state.rules[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_OVERLAP,
            user_prompt=f"Detect rule overlaps:\n{ctx}",
            schema=OverlapDetectionOutput,
        )
        if llm_out.redundant_rules:  # type: ignore[union-attr]
            overlaps.append(
                {
                    "overlap_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "pairs": llm_out.overlap_pairs,  # type: ignore[union-attr]
                    "redundant": llm_out.redundant_rules,  # type: ignore[union-attr]
                    "savings": llm_out.alert_savings,  # type: ignore[union-attr]
                    "plan": llm_out.consolidation_plan,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="detect_overlap",
            redundant=len(llm_out.redundant_rules),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_overlap",
        )

    step = _step(
        state.reasoning_chain,
        "detect_overlap",
        f"Checking {len(state.rules)} rules for overlaps",
        f"Found {len(overlaps)} overlap groups",
        start,
        "overlap_detector",
    )

    return {
        "overlaps": overlaps,
        "overlap_count": len(overlaps),
        "stage": SROStage.DETECT_OVERLAP,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_overlap",
    }


# ------------------------------------------------------------------
# Node: tune_thresholds
# ------------------------------------------------------------------


async def tune_thresholds(
    state: SIEMRuleOptimizerState,
) -> dict[str, Any]:
    """Generate threshold tuning recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    tuning_suggestions = await toolkit.tune_thresholds(
        performance_data=state.performance_data,
        overlaps=state.overlaps,
        config=state.optimization_config,
    )

    step = _step(
        state.reasoning_chain,
        "tune_thresholds",
        (f"Tuning from {len(state.performance_data)} perf records, {len(state.overlaps)} overlaps"),
        f"Generated {len(tuning_suggestions)} tuning suggestions",
        start,
        "threshold_tuner",
    )

    return {
        "tuning_suggestions": tuning_suggestions,
        "rules_optimized": len(tuning_suggestions),
        "stage": SROStage.TUNE_THRESHOLDS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "tune_thresholds",
    }


# ------------------------------------------------------------------
# Node: validate_rules
# ------------------------------------------------------------------


async def validate_rules(
    state: SIEMRuleOptimizerState,
) -> dict[str, Any]:
    """Validate tuning suggestions against historical
    data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    validation_results = await toolkit.validate_rules(
        tuning_suggestions=state.tuning_suggestions,
        rules=state.rules,
    )

    step = _step(
        state.reasoning_chain,
        "validate_rules",
        f"Validating {len(state.tuning_suggestions)} suggestions",
        f"Validated {len(validation_results)} results",
        start,
        "rule_validator",
    )

    return {
        "validation_results": validation_results,
        "stage": SROStage.VALIDATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_rules",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SIEMRuleOptimizerState,
) -> dict[str, Any]:
    """Generate the final optimization report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Compute FP reduction estimate
    fp_reduction = 0.0
    if state.rules_optimized > 0:
        fp_reduction = min(80.0, state.rules_optimized * 3.5)

    report: dict[str, Any] = {
        "siem_source": state.siem_source,
        "total_rules": state.total_rules,
        "rules_optimized": state.rules_optimized,
        "overlap_count": state.overlap_count,
        "fp_reduction_pct": round(fp_reduction, 2),
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "siem": state.siem_source,
                "total_rules": state.total_rules,
                "performance_sample": state.performance_data[:5],
                "overlaps": state.overlaps[:5],
                "tuning": state.tuning_suggestions[:5],
                "validation": state.validation_results[:5],
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
                    "risk_assessment": llm_out.risk_assessment,
                    "fp_reduction_pct": llm_out.fp_reduction_pct,
                }
            )
            fp_reduction = llm_out.fp_reduction_pct
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recommendations=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metric
    await toolkit.record_metric(
        metric_name="sro.fp_reduction",
        value=fp_reduction,
        labels={"siem": state.siem_source},
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.rules_optimized} optimized rules",
        f"Report generated, FP reduction={fp_reduction:.1f}%",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "fp_reduction_pct": fp_reduction,
        "session_duration_ms": duration_ms,
        "stage": SROStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
