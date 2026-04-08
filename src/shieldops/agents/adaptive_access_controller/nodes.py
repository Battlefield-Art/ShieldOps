"""Node implementations for the Adaptive Access Controller."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.adaptive_access_controller.models import (
    AACStage,
    AdaptiveAccessControllerState,
    ReasoningStep,
)
from shieldops.agents.adaptive_access_controller.prompts import (
    SYSTEM_ADJUST_PERMISSIONS,
    SYSTEM_ASSESS_CONTEXT,
    SYSTEM_AUDIT_DECISIONS,
    SYSTEM_ENFORCE_ACCESS,
    SYSTEM_EVALUATE_RISK,
    AuditOutput,
    ContextAssessmentOutput,
    EnforcementOutput,
    PermissionAdjustmentOutput,
    RiskEvaluationOutput,
)
from shieldops.agents.adaptive_access_controller.tools import (
    AdaptiveAccessControllerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AdaptiveAccessControllerToolkit | None = None


def _get_toolkit() -> AdaptiveAccessControllerToolkit:
    if _toolkit is None:
        return AdaptiveAccessControllerToolkit()
    return _toolkit


def _step(
    state: AdaptiveAccessControllerState,
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


async def assess_context(
    state: AdaptiveAccessControllerState,
) -> dict[str, Any]:
    """Assess access request contexts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.assess_context(state.config)
    high_risk = sum(1 for c in raw if c.get("session_risk", 0) > 0.7)

    try:
        ctx = _json.dumps(
            {
                "request_count": len(raw),
                "high_risk": high_risk,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ASSESS_CONTEXT,
            user_prompt=f"Access context assessment:\n{ctx}",
            schema=ContextAssessmentOutput,
        )
        if hasattr(llm_result, "total_requests"):
            logger.info("llm_enhanced", node="assess_context")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_context",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "assess_context",
        f"config={state.config}",
        f"assessed {len(raw)} requests, {high_risk} high-risk",
        elapsed,
        "identity_client",
    )
    await toolkit.record_metric(
        "contexts_assessed",
        float(len(raw)),
    )

    return {
        "access_contexts": raw,
        "stage": AACStage.EVALUATE_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_context",
        "session_start": start,
    }


async def evaluate_risk(
    state: AdaptiveAccessControllerState,
) -> dict[str, Any]:
    """Evaluate risk for each access context."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.evaluate_risk(
        state.access_contexts,
    )
    denied = sum(1 for a in assessments if a.get("recommendation") == "deny")

    try:
        ctx = _json.dumps(
            {
                "context_count": len(state.access_contexts),
                "assessment_count": len(assessments),
                "denied": denied,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_EVALUATE_RISK,
            user_prompt=f"Risk evaluation context:\n{ctx}",
            schema=RiskEvaluationOutput,
        )
        if hasattr(llm_result, "avg_risk_score"):
            logger.info("llm_enhanced", node="evaluate_risk")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="evaluate_risk",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "evaluate_risk",
        f"evaluating {len(state.access_contexts)} contexts",
        f"{len(assessments)} assessments, {denied} denied",
        elapsed,
        "risk_engine",
    )

    return {
        "risk_assessments": assessments,
        "stage": AACStage.ADJUST_PERMISSIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "evaluate_risk",
    }


async def adjust_permissions(
    state: AdaptiveAccessControllerState,
) -> dict[str, Any]:
    """Adjust permissions based on risk assessments."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    adjustments = await toolkit.adjust_permissions(
        state.risk_assessments,
        state.access_contexts,
    )

    try:
        ctx = _json.dumps(
            {
                "assessment_count": len(state.risk_assessments),
                "adjustment_count": len(adjustments),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ADJUST_PERMISSIONS,
            user_prompt=f"Permission adjustment context:\n{ctx}",
            schema=PermissionAdjustmentOutput,
        )
        if hasattr(llm_result, "adjustments_made"):
            logger.info(
                "llm_enhanced",
                node="adjust_permissions",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="adjust_permissions",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "adjust_permissions",
        f"adjusting for {len(state.risk_assessments)} assessments",
        f"{len(adjustments)} adjustments applied",
        elapsed,
        "policy_engine",
    )

    return {
        "permission_adjustments": adjustments,
        "stage": AACStage.ENFORCE_ACCESS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "adjust_permissions",
    }


async def enforce_access(
    state: AdaptiveAccessControllerState,
) -> dict[str, Any]:
    """Enforce access decisions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.enforce_access(
        state.permission_adjustments,
    )
    denied = sum(1 for r in results if r.get("decision") == "deny")

    try:
        ctx = _json.dumps(
            {
                "adjustment_count": len(
                    state.permission_adjustments,
                ),
                "enforcement_count": len(results),
                "denied": denied,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ENFORCE_ACCESS,
            user_prompt=f"Enforcement context:\n{ctx}",
            schema=EnforcementOutput,
        )
        if hasattr(llm_result, "allowed"):
            logger.info("llm_enhanced", node="enforce_access")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enforce_access",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "enforce_access",
        f"enforcing {len(state.permission_adjustments)} adjustments",
        f"{len(results)} enforced, {denied} denied",
        elapsed,
        "enforcement_engine",
    )
    await toolkit.record_metric("decisions_enforced", float(len(results)))

    return {
        "enforcement_results": results,
        "stage": AACStage.AUDIT_DECISIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enforce_access",
    }


async def audit_decisions(
    state: AdaptiveAccessControllerState,
) -> dict[str, Any]:
    """Generate audit entries for access decisions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    entries = await toolkit.audit_decisions(
        state.enforcement_results,
        state.risk_assessments,
    )

    try:
        ctx = _json.dumps(
            {
                "enforcement_count": len(
                    state.enforcement_results,
                ),
                "audit_count": len(entries),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_AUDIT_DECISIONS,
            user_prompt=f"Audit context:\n{ctx}",
            schema=AuditOutput,
        )
        if hasattr(llm_result, "total_entries"):
            logger.info(
                "llm_enhanced",
                node="audit_decisions",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="audit_decisions",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "audit_decisions",
        f"auditing {len(state.enforcement_results)} enforcements",
        f"{len(entries)} audit entries created",
        elapsed,
        "audit_logger",
    )

    return {
        "audit_entries": entries,
        "stage": AACStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "audit_decisions",
    }


async def generate_report(
    state: AdaptiveAccessControllerState,
) -> dict[str, Any]:
    """Generate final access control report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    denied = sum(1 for r in state.enforcement_results if r.get("decision") == "deny")
    allowed = sum(1 for r in state.enforcement_results if r.get("decision") == "allow")
    report = {
        "request_id": state.request_id,
        "contexts_assessed": len(state.access_contexts),
        "risk_assessments": len(state.risk_assessments),
        "adjustments": len(state.permission_adjustments),
        "enforcements": len(state.enforcement_results),
        "audit_entries": len(state.audit_entries),
        "decisions_allowed": allowed,
        "decisions_denied": denied,
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
