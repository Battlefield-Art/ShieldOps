"""Node implementations for the Cross-Cloud Posture Manager."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cross_cloud_posture_manager.models import (
    CCPMStage,
    CrossCloudPostureManagerState,
    ReasoningStep,
)
from shieldops.agents.cross_cloud_posture_manager.prompts import (
    SYSTEM_ASSESS_COMPLIANCE,
    SYSTEM_COMPARE_BASELINES,
    SYSTEM_DETECT_DRIFT,
    SYSTEM_PLAN_REMEDIATION,
    SYSTEM_SCAN_POSTURE,
    BaselineCompareOutput,
    ComplianceAssessOutput,
    DriftDetectOutput,
    PostureScanOutput,
    RemediationPlanOutput,
)
from shieldops.agents.cross_cloud_posture_manager.tools import (
    CrossCloudPostureManagerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CrossCloudPostureManagerToolkit | None = None


def _get_toolkit() -> CrossCloudPostureManagerToolkit:
    if _toolkit is None:
        return CrossCloudPostureManagerToolkit()
    return _toolkit


def _step(
    state: CrossCloudPostureManagerState,
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


async def scan_posture(
    state: CrossCloudPostureManagerState,
) -> dict[str, Any]:
    """Scan security posture across cloud providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.scan_posture(state.config)
    providers = {f.get("provider") for f in raw}

    try:
        ctx = _json.dumps(
            {
                "providers": state.config.get("providers", []),
                "finding_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SCAN_POSTURE,
            user_prompt=f"Posture scan context:\n{ctx}",
            schema=PostureScanOutput,
        )
        if hasattr(llm_result, "total_findings"):
            logger.info("llm_enhanced", node="scan_posture")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="scan_posture")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "scan_posture",
        f"providers={state.config.get('providers', [])}",
        f"found {len(raw)} findings across {len(providers)} providers",
        elapsed,
        "cloud_client",
    )
    await toolkit.record_metric("findings_scanned", float(len(raw)))

    return {
        "findings": raw,
        "stage": CCPMStage.COMPARE_BASELINES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_posture",
        "session_start": start,
    }


async def compare_baselines(
    state: CrossCloudPostureManagerState,
) -> dict[str, Any]:
    """Compare findings against baseline posture."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    comparisons = await toolkit.compare_baselines(state.findings, state.config)
    total_devs = sum(c.get("deviations", 0) for c in comparisons)

    try:
        ctx = _json.dumps(
            {
                "finding_count": len(state.findings),
                "comparison_count": len(comparisons),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COMPARE_BASELINES,
            user_prompt=f"Baseline comparison context:\n{ctx}",
            schema=BaselineCompareOutput,
        )
        if hasattr(llm_result, "total_deviations"):
            logger.info("llm_enhanced", node="compare_baselines")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="compare_baselines")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "compare_baselines",
        f"comparing {len(state.findings)} findings",
        f"{len(comparisons)} comparisons, {total_devs} deviations",
        elapsed,
        "cloud_client",
    )

    return {
        "comparisons": comparisons,
        "stage": CCPMStage.DETECT_DRIFT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "compare_baselines",
    }


async def detect_drift(
    state: CrossCloudPostureManagerState,
) -> dict[str, Any]:
    """Detect configuration drift from baseline."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    drifts = await toolkit.detect_drift(state.comparisons, state.findings)

    try:
        ctx = _json.dumps(
            {
                "comparison_count": len(state.comparisons),
                "drift_count": len(drifts),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DETECT_DRIFT,
            user_prompt=f"Drift detection context:\n{ctx}",
            schema=DriftDetectOutput,
        )
        if hasattr(llm_result, "drifts_detected"):
            logger.info("llm_enhanced", node="detect_drift")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="detect_drift")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    critical = sum(1 for d in drifts if d.get("severity") == "critical")
    step = _step(
        state,
        "detect_drift",
        f"analyzing {len(state.comparisons)} comparisons",
        f"{len(drifts)} drifts detected, {critical} critical",
        elapsed,
        "cloud_client",
    )
    await toolkit.record_metric("drifts_detected", float(len(drifts)))

    return {
        "drifts": drifts,
        "stage": CCPMStage.ASSESS_COMPLIANCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_drift",
    }


async def assess_compliance(
    state: CrossCloudPostureManagerState,
) -> dict[str, Any]:
    """Assess compliance against standard frameworks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    gaps = await toolkit.assess_compliance(state.findings, state.drifts)

    try:
        ctx = _json.dumps(
            {"finding_count": len(state.findings), "gap_count": len(gaps)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ASSESS_COMPLIANCE,
            user_prompt=f"Compliance assessment context:\n{ctx}",
            schema=ComplianceAssessOutput,
        )
        if hasattr(llm_result, "gaps_found"):
            logger.info("llm_enhanced", node="assess_compliance")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="assess_compliance")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "assess_compliance",
        f"assessing {len(state.findings)} findings, {len(state.drifts)} drifts",
        f"{len(gaps)} compliance gaps identified",
        elapsed,
        "cloud_client",
    )

    return {
        "compliance_gaps": gaps,
        "stage": CCPMStage.PLAN_REMEDIATION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_compliance",
    }


async def plan_remediation(
    state: CrossCloudPostureManagerState,
) -> dict[str, Any]:
    """Create remediation plans for drifts and compliance gaps."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    plans = await toolkit.plan_remediation(state.drifts, state.compliance_gaps)

    try:
        ctx = _json.dumps(
            {
                "drift_count": len(state.drifts),
                "gap_count": len(state.compliance_gaps),
                "plan_count": len(plans),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PLAN_REMEDIATION,
            user_prompt=f"Remediation planning context:\n{ctx}",
            schema=RemediationPlanOutput,
        )
        if hasattr(llm_result, "plans_created"):
            logger.info("llm_enhanced", node="plan_remediation")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="plan_remediation")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    automated = sum(1 for p in plans if p.get("automated"))
    step = _step(
        state,
        "plan_remediation",
        f"planning for {len(state.drifts)} drifts, {len(state.compliance_gaps)} gaps",
        f"{len(plans)} plans created, {automated} automated",
        elapsed,
        "cloud_client",
    )
    await toolkit.record_metric("remediation_plans", float(len(plans)))

    return {
        "remediation_plans": plans,
        "stage": CCPMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "plan_remediation",
    }


async def generate_report(
    state: CrossCloudPostureManagerState,
) -> dict[str, Any]:
    """Generate final posture management report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "findings": len(state.findings),
        "comparisons": len(state.comparisons),
        "drifts": len(state.drifts),
        "compliance_gaps": len(state.compliance_gaps),
        "remediation_plans": len(state.remediation_plans),
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
