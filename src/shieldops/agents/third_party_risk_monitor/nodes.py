"""Node implementations for the Third Party Risk Monitor
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.third_party_risk_monitor.models import (
    ReasoningStep,
    ThirdPartyRiskMonitorState,
    TPRMStage,
)
from shieldops.agents.third_party_risk_monitor.prompts import (
    SYSTEM_ASSESS,
    SYSTEM_EVALUATE,
    SYSTEM_INVENTORY,
    SYSTEM_REPORT,
    PostureAssessmentOutput,
    RiskEvaluationOutput,
    RiskReportOutput,
    VendorInventoryOutput,
)
from shieldops.agents.third_party_risk_monitor.tools import (
    ThirdPartyRiskMonitorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ThirdPartyRiskMonitorToolkit | None = None


def _get_toolkit() -> ThirdPartyRiskMonitorToolkit:
    if _toolkit is None:
        return ThirdPartyRiskMonitorToolkit()
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
# Node: inventory_vendors
# ------------------------------------------------------------------


async def inventory_vendors(
    state: ThirdPartyRiskMonitorState,
) -> dict[str, Any]:
    """Inventory third-party vendors for risk monitoring."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    vendors = await toolkit.inventory_vendors(
        filters=state.vendor_filters,
        config=state.monitoring_config,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "filters": state.vendor_filters,
                "config": state.monitoring_config,
                "vendor_count": len(vendors),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_INVENTORY,
            user_prompt=f"Analyze vendor inventory:\n{ctx}",
            schema=VendorInventoryOutput,
        )
        if llm_out.critical_vendors:  # type: ignore[union-attr]
            vendors.append(
                {
                    "inventory_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "critical": llm_out.critical_vendors,  # type: ignore[union-attr]
                    "data_risk": llm_out.data_risk_vendors,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="inventory_vendors",
            critical=len(llm_out.critical_vendors),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="inventory_vendors",
        )

    step = _step(
        state.reasoning_chain,
        "inventory_vendors",
        f"Filters: {len(state.vendor_filters)} criteria",
        f"Inventoried {len(vendors)} vendors",
        start,
        "vendor_registry",
    )

    return {
        "vendors": vendors,
        "total_vendors": len(vendors),
        "stage": TPRMStage.INVENTORY_VENDORS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "inventory_vendors",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: assess_posture
# ------------------------------------------------------------------


async def assess_posture(
    state: ThirdPartyRiskMonitorState,
) -> dict[str, Any]:
    """Assess security posture for each vendor."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    domains = [d.value for d in state.risk_domains]
    posture_assessments = await toolkit.assess_posture(
        vendors=state.vendors,
        risk_domains=domains,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "vendor_count": len(state.vendors),
                "vendors_sample": state.vendors[:5],
                "risk_domains": domains,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ASSESS,
            user_prompt=f"Assess vendor posture:\n{ctx}",
            schema=PostureAssessmentOutput,
        )
        if llm_out.gaps:  # type: ignore[union-attr]
            posture_assessments.append(
                {
                    "assessment_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "weak_posture": llm_out.weak_posture,  # type: ignore[union-attr]
                    "avg_score": llm_out.avg_score,  # type: ignore[union-attr]
                    "gaps": llm_out.gaps,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="assess_posture",
            gaps=len(llm_out.gaps),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_posture",
        )

    step = _step(
        state.reasoning_chain,
        "assess_posture",
        (f"Assessing {len(state.vendors)} vendors across {len(domains)} domains"),
        f"Produced {len(posture_assessments)} assessments",
        start,
        "posture_scanner",
    )

    return {
        "posture_assessments": posture_assessments,
        "stage": TPRMStage.ASSESS_POSTURE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_posture",
    }


# ------------------------------------------------------------------
# Node: monitor_changes
# ------------------------------------------------------------------


async def monitor_changes(
    state: ThirdPartyRiskMonitorState,
) -> dict[str, Any]:
    """Monitor for changes in vendor security posture."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    posture_changes = await toolkit.monitor_changes(
        vendors=state.vendors,
        posture_assessments=state.posture_assessments,
    )

    step = _step(
        state.reasoning_chain,
        "monitor_changes",
        (
            f"Monitoring {len(state.vendors)} vendors "
            f"with {len(state.posture_assessments)} assessments"
        ),
        f"Detected {len(posture_changes)} posture changes",
        start,
        "change_monitor",
    )

    return {
        "posture_changes": posture_changes,
        "posture_changes_count": len(posture_changes),
        "stage": TPRMStage.MONITOR_CHANGES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "monitor_changes",
    }


# ------------------------------------------------------------------
# Node: evaluate_risk
# ------------------------------------------------------------------


async def evaluate_risk(
    state: ThirdPartyRiskMonitorState,
) -> dict[str, Any]:
    """Evaluate composite risk for each vendor."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    risk_evaluations = await toolkit.evaluate_risk(
        posture_assessments=state.posture_assessments,
        posture_changes=state.posture_changes,
        threshold_config=state.threshold_config,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "assessment_count": len(state.posture_assessments),
                "changes_count": len(state.posture_changes),
                "assessments_sample": state.posture_assessments[:5],
                "changes_sample": state.posture_changes[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_EVALUATE,
            user_prompt=f"Evaluate vendor risk:\n{ctx}",
            schema=RiskEvaluationOutput,
        )
        if llm_out.risk_factors:  # type: ignore[union-attr]
            risk_evaluations.append(
                {
                    "eval_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "high_risk": llm_out.high_risk_count,  # type: ignore[union-attr]
                    "factors": llm_out.risk_factors,  # type: ignore[union-attr]
                    "recommendations": llm_out.recommendations,  # type: ignore[union-attr]
                    "exposure": llm_out.overall_exposure,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="evaluate_risk",
            factors=len(llm_out.risk_factors),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="evaluate_risk",
        )

    high_risk = sum(1 for e in risk_evaluations if e.get("overall_risk", 0) > 70)

    step = _step(
        state.reasoning_chain,
        "evaluate_risk",
        (f"Evaluating risk from {len(state.posture_assessments)} assessments"),
        f"Evaluated {len(risk_evaluations)} vendors, {high_risk} high-risk",
        start,
        "risk_scorer",
    )

    return {
        "risk_evaluations": risk_evaluations,
        "high_risk_vendors": high_risk,
        "stage": TPRMStage.EVALUATE_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "evaluate_risk",
    }


# ------------------------------------------------------------------
# Node: generate_alerts
# ------------------------------------------------------------------


async def generate_alerts(
    state: ThirdPartyRiskMonitorState,
) -> dict[str, Any]:
    """Generate alerts for vendors exceeding risk
    thresholds."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    alerts = await toolkit.generate_alerts(
        risk_evaluations=state.risk_evaluations,
        threshold_config=state.threshold_config,
    )

    step = _step(
        state.reasoning_chain,
        "generate_alerts",
        f"Alerting on {len(state.risk_evaluations)} evaluations",
        f"Generated {len(alerts)} alerts",
        start,
        "alert_engine",
    )

    return {
        "alerts": alerts,
        "alerts_generated": len(alerts),
        "stage": TPRMStage.GENERATE_ALERTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_alerts",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: ThirdPartyRiskMonitorState,
) -> dict[str, Any]:
    """Generate the final risk monitoring report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_vendors": state.total_vendors,
        "high_risk_vendors": state.high_risk_vendors,
        "posture_changes": state.posture_changes_count,
        "alerts_generated": state.alerts_generated,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "total_vendors": state.total_vendors,
                "high_risk": state.high_risk_vendors,
                "posture_changes": state.posture_changes[:5],
                "risk_evaluations": state.risk_evaluations[:5],
                "alerts": state.alerts[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate risk report:\n{ctx}",
            schema=RiskReportOutput,
        )
        if isinstance(llm_out, RiskReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "trend": llm_out.trend,
                }
            )
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
        metric_name="tprm.high_risk_vendors",
        value=float(state.high_risk_vendors),
        labels={"tenant": state.tenant_id},
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_vendors} vendors",
        (f"Report generated, {state.high_risk_vendors} high-risk"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": TPRMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
