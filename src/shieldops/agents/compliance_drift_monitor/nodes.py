"""Node implementations for the Compliance Drift Monitor."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.compliance_drift_monitor.models import (
    CDMStage,
    ComplianceDriftMonitorState,
    ReasoningStep,
)
from shieldops.agents.compliance_drift_monitor.prompts import (
    SYSTEM_ASSESS_IMPACT,
    SYSTEM_DETECT_DRIFT,
    SYSTEM_LOAD_BASELINES,
    SYSTEM_PLAN_REMEDIATION,
    SYSTEM_SCAN_STATE,
    BaselineLoadOutput,
    DriftDetectionOutput,
    ImpactOutput,
    RemediationOutput,
    StateScanOutput,
)
from shieldops.agents.compliance_drift_monitor.tools import (
    ComplianceDriftMonitorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ComplianceDriftMonitorToolkit | None = None


def set_toolkit(
    toolkit: ComplianceDriftMonitorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ComplianceDriftMonitorToolkit:
    if _toolkit is None:
        return ComplianceDriftMonitorToolkit()
    return _toolkit


def _step(
    state: ComplianceDriftMonitorState,
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


async def load_baselines(
    state: ComplianceDriftMonitorState,
) -> dict[str, Any]:
    """Load compliance baselines for configured frameworks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.load_baselines(state.config)
    frameworks = list({b.get("framework", "") for b in raw})

    try:
        ctx = _json.dumps(
            {
                "frameworks": state.config.get("frameworks", []),
                "baseline_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_LOAD_BASELINES,
            user_prompt=f"Baseline loading context:\n{ctx}",
            schema=BaselineLoadOutput,
        )
        if hasattr(llm_result, "total_baselines"):
            logger.info("llm_enhanced", node="load_baselines")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="load_baselines",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "load_baselines",
        f"frameworks={frameworks}",
        f"loaded {len(raw)} baselines",
        elapsed,
        "compliance_client",
    )
    await toolkit.record_metric("baselines_loaded", float(len(raw)))

    return {
        "baselines": raw,
        "stage": CDMStage.SCAN_CURRENT_STATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "load_baselines",
        "session_start": start,
    }


async def scan_current_state(
    state: ComplianceDriftMonitorState,
) -> dict[str, Any]:
    """Scan current infrastructure state."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    records = await toolkit.scan_current_state(state.baselines)
    compliant = sum(1 for r in records if r.get("actual_value") == "compliant")

    try:
        ctx = _json.dumps(
            {
                "baseline_count": len(state.baselines),
                "records_scanned": len(records),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SCAN_STATE,
            user_prompt=f"State scan context:\n{ctx}",
            schema=StateScanOutput,
        )
        if hasattr(llm_result, "resources_scanned"):
            logger.info("llm_enhanced", node="scan_current_state")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_current_state",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "scan_current_state",
        f"scanning {len(state.baselines)} baselines",
        f"{len(records)} records, {compliant} compliant",
        elapsed,
        "scanner_client",
    )

    return {
        "current_state": records,
        "stage": CDMStage.DETECT_DRIFT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_current_state",
    }


async def detect_drift(
    state: ComplianceDriftMonitorState,
) -> dict[str, Any]:
    """Detect drift between baselines and current state."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    findings = await toolkit.detect_drift(state.baselines, state.current_state)
    critical = sum(1 for f in findings if f.get("severity") == "critical")

    try:
        ctx = _json.dumps(
            {
                "baseline_count": len(state.baselines),
                "drift_count": len(findings),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DETECT_DRIFT,
            user_prompt=f"Drift detection context:\n{ctx}",
            schema=DriftDetectionOutput,
        )
        if hasattr(llm_result, "drifts_found"):
            logger.info("llm_enhanced", node="detect_drift")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_drift",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "detect_drift",
        f"comparing {len(state.current_state)} records",
        f"{len(findings)} drifts, {critical} critical",
        elapsed,
        "policy_engine",
    )
    await toolkit.record_metric("drifts_detected", float(len(findings)))

    return {
        "drift_findings": findings,
        "stage": CDMStage.ASSESS_IMPACT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_drift",
    }


async def assess_impact(
    state: ComplianceDriftMonitorState,
) -> dict[str, Any]:
    """Assess impact of detected drift findings."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_impact(state.drift_findings)

    try:
        ctx = _json.dumps(
            {
                "finding_count": len(state.drift_findings),
                "assessments": assessments[:5],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ASSESS_IMPACT,
            user_prompt=f"Impact assessment context:\n{ctx}",
            schema=ImpactOutput,
        )
        if hasattr(llm_result, "risk_score"):
            logger.info("llm_enhanced", node="assess_impact")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_impact",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "assess_impact",
        f"assessing {len(state.drift_findings)} findings",
        f"{len(assessments)} impact assessments",
        elapsed,
        "compliance_client",
    )

    return {
        "impact_assessments": assessments,
        "stage": CDMStage.PLAN_REMEDIATION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_impact",
    }


async def plan_remediation(
    state: ComplianceDriftMonitorState,
) -> dict[str, Any]:
    """Generate remediation plans for drift findings."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    plans = await toolkit.plan_remediation(state.drift_findings)
    automated = sum(1 for p in plans if p.get("automated"))

    try:
        ctx = _json.dumps(
            {
                "finding_count": len(state.drift_findings),
                "plan_count": len(plans),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PLAN_REMEDIATION,
            user_prompt=(f"Remediation planning context:\n{ctx}"),
            schema=RemediationOutput,
        )
        if hasattr(llm_result, "plans_generated"):
            logger.info("llm_enhanced", node="plan_remediation")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="plan_remediation",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "plan_remediation",
        f"planning for {len(state.drift_findings)} findings",
        f"{len(plans)} plans, {automated} automated",
        elapsed,
        "policy_engine",
    )
    await toolkit.record_metric("plans_generated", float(len(plans)))

    return {
        "remediation_plans": plans,
        "stage": CDMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "plan_remediation",
    }


async def generate_report(
    state: ComplianceDriftMonitorState,
) -> dict[str, Any]:
    """Generate final compliance drift report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "baselines": len(state.baselines),
        "current_state_records": len(state.current_state),
        "drift_findings": len(state.drift_findings),
        "impact_assessments": len(state.impact_assessments),
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
