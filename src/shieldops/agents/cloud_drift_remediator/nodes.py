"""Node implementations for the Cloud Drift Remediator."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cloud_drift_remediator.models import (
    CDRStage,
    CloudDriftRemediatorState,
    ReasoningStep,
)
from shieldops.agents.cloud_drift_remediator.prompts import (
    SYSTEM_BASELINE,
    SYSTEM_CLASSIFY,
    SYSTEM_DETECT,
    SYSTEM_EXECUTE,
    SYSTEM_PLAN,
    BaselineScanOutput,
    DriftDetectionOutput,
    ExecutionOutput,
    RemediationPlanOutput,
    RiskClassificationOutput,
)
from shieldops.agents.cloud_drift_remediator.tools import (
    CloudDriftRemediatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CloudDriftRemediatorToolkit | None = None


def _get_toolkit() -> CloudDriftRemediatorToolkit:
    if _toolkit is None:
        return CloudDriftRemediatorToolkit()
    return _toolkit


def _step(
    state: CloudDriftRemediatorState,
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


async def scan_baseline(
    state: CloudDriftRemediatorState,
) -> dict[str, Any]:
    """Scan IaC baseline for managed resources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.scan_baseline(state.scan_config)
    count = len(raw)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "provider": state.scan_config.get("provider", ""),
                "region": state.scan_config.get("region", ""),
                "resource_count": count,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_BASELINE,
            user_prompt=(f"Baseline scan context:\n{ctx}"),
            schema=BaselineScanOutput,
        )
        if hasattr(llm_result, "total_resources") and llm_result.total_resources > count:
            count = llm_result.total_resources
        logger.info(
            "llm_enhanced",
            node="scan_baseline",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_baseline",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "scan_baseline",
        f"provider={state.scan_config.get('provider', '')}",
        f"found {count} managed resources",
        elapsed,
        "iac_parser",
    )
    await toolkit.record_metric("resource_count", float(count))

    return {
        "baseline_resources": raw,
        "resource_count": count,
        "stage": CDRStage.DETECT_DRIFT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "scan_baseline",
        "session_start": start,
    }


async def detect_drift(
    state: CloudDriftRemediatorState,
) -> dict[str, Any]:
    """Detect drift between baseline and live state."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    drifts = await toolkit.detect_drift(
        state.baseline_resources,
    )
    drift_count = len(drifts)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "resource_count": len(state.baseline_resources),
                "drifts": drifts[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DETECT,
            user_prompt=(f"Drift detection context:\n{ctx}"),
            schema=DriftDetectionOutput,
        )
        if hasattr(llm_result, "total_drifts") and llm_result.total_drifts > drift_count:
            drift_count = llm_result.total_drifts
        logger.info(
            "llm_enhanced",
            node="detect_drift",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_drift",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "detect_drift",
        f"scanning {len(state.baseline_resources)} resources",
        f"detected {drift_count} drifts",
        elapsed,
        "drift_detector",
    )

    return {
        "detected_drifts": drifts,
        "drift_count": drift_count,
        "stage": CDRStage.CLASSIFY_RISK,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_drift",
    }


async def classify_risk(
    state: CloudDriftRemediatorState,
) -> dict[str, Any]:
    """Classify risk for detected drifts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_risk(
        state.detected_drifts,
    )
    critical = sum(1 for c in classifications if c.get("risk") == "critical")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "drift_count": len(state.detected_drifts),
                "classifications": classifications[:10],
                "critical": critical,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=(f"Risk classification context:\n{ctx}"),
            schema=RiskClassificationOutput,
        )
        if hasattr(llm_result, "critical_count") and llm_result.critical_count > critical:
            critical = llm_result.critical_count
        logger.info(
            "llm_enhanced",
            node="classify_risk",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_risk",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "classify_risk",
        f"classifying {len(state.detected_drifts)} drifts",
        f"{critical} critical drifts",
        elapsed,
        "risk_classifier",
    )
    await toolkit.record_metric("critical_drifts", float(critical))

    return {
        "drift_classifications": classifications,
        "critical_drift_count": critical,
        "stage": CDRStage.PLAN_REMEDIATION,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "classify_risk",
    }


async def plan_remediation(
    state: CloudDriftRemediatorState,
) -> dict[str, Any]:
    """Plan remediation for classified drifts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    plans = await toolkit.plan_remediation(
        state.detected_drifts,
        state.drift_classifications,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "drift_count": len(state.detected_drifts),
                "classification_count": len(state.drift_classifications),
                "plan_count": len(plans),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PLAN,
            user_prompt=(f"Remediation planning context:\n{ctx}"),
            schema=RemediationPlanOutput,
        )
        if hasattr(llm_result, "plans"):
            logger.info(
                "llm_enhanced",
                node="plan_remediation",
                llm_plans=len(llm_result.plans),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="plan_remediation",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "plan_remediation",
        f"planning for {len(state.detected_drifts)} drifts",
        f"created {len(plans)} plans",
        elapsed,
        "remediation_engine",
    )

    return {
        "remediation_plans": plans,
        "stage": CDRStage.EXECUTE_FIX,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "plan_remediation",
    }


async def execute_fix(
    state: CloudDriftRemediatorState,
) -> dict[str, Any]:
    """Execute remediation plans."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.execute_fix(
        state.remediation_plans,
    )

    # LLM enhancement
    try:
        success_count = sum(1 for r in results if r.get("success"))
        ctx = _json.dumps(
            {
                "plan_count": len(state.remediation_plans),
                "executed": success_count,
                "failed": len(results) - success_count,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_EXECUTE,
            user_prompt=(f"Execution context:\n{ctx}"),
            schema=ExecutionOutput,
        )
        if hasattr(llm_result, "executed"):
            logger.info(
                "llm_enhanced",
                node="execute_fix",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="execute_fix",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "execute_fix",
        f"executing {len(state.remediation_plans)} plans",
        f"completed {len(results)} executions",
        elapsed,
        "cloud_api",
    )

    return {
        "execution_results": results,
        "stage": CDRStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "execute_fix",
    }


async def generate_report(
    state: CloudDriftRemediatorState,
) -> dict[str, Any]:
    """Generate final drift remediation report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    success_count = sum(1 for r in state.execution_results if r.get("success"))
    report = {
        "request_id": state.request_id,
        "resources_scanned": state.resource_count,
        "drifts_detected": state.drift_count,
        "critical_drifts": state.critical_drift_count,
        "plans_created": len(state.remediation_plans),
        "fixes_applied": success_count,
        "fixes_pending": len(state.execution_results) - success_count,
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "remediation_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_metric(
        "fixes_applied",
        float(success_count),
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing remediation {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
