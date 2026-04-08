"""Node implementations for the Policy Compliance
Enforcer Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.policy_compliance_enforcer.models import (
    PCEStage,
    PolicyComplianceEnforcerState,
    ReasoningStep,
)
from shieldops.agents.policy_compliance_enforcer.prompts import (
    SYSTEM_COMPLIANCE,
    SYSTEM_ENFORCE,
    SYSTEM_EVALUATE,
    SYSTEM_REPORT,
    ComplianceCheckOutput,
    EnforcementDecisionOutput,
    EnforcerReportOutput,
    PolicyEvaluationOutput,
)
from shieldops.agents.policy_compliance_enforcer.tools import (
    PolicyComplianceEnforcerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: PolicyComplianceEnforcerToolkit | None = None


def _get_toolkit() -> PolicyComplianceEnforcerToolkit:
    if _toolkit is None:
        return PolicyComplianceEnforcerToolkit()
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
# Node: load_policies
# ------------------------------------------------------------------


async def load_policies(
    state: PolicyComplianceEnforcerState,
) -> dict[str, Any]:
    """Load applicable policies from OPA and compliance
    stores."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    policies = await toolkit.load_policies(
        frameworks=state.frameworks,
        resource_type=state.request_type,
    )

    step = _step(
        state.reasoning_chain,
        "load_policies",
        (f"Frameworks: {len(state.frameworks)}, type={state.request_type}"),
        f"Loaded {len(policies)} policies",
        start,
        "opa_client",
    )

    return {
        "policies": policies,
        "stage": PCEStage.LOAD_POLICIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "load_policies",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: evaluate_request
# ------------------------------------------------------------------


async def evaluate_request(
    state: PolicyComplianceEnforcerState,
) -> dict[str, Any]:
    """Evaluate the request against loaded policies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    request_context = {
        "type": state.request_type,
        "resource": state.resource,
        "actor": state.actor,
        "context": state.context,
    }

    evaluations = await toolkit.evaluate_request(
        request_context=request_context,
        policies=state.policies,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "request_type": state.request_type,
                "resource": state.resource,
                "actor": state.actor,
                "context": state.context,
                "policy_count": len(state.policies),
                "policies_sample": state.policies[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_EVALUATE,
            user_prompt=(f"Evaluate request against policies:\n{ctx}"),
            schema=PolicyEvaluationOutput,
        )
        if llm_out.violations:  # type: ignore[union-attr]
            evaluations.append(
                {
                    "evaluation_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "violations": llm_out.violations,  # type: ignore[union-attr]
                    "warnings": llm_out.warnings,  # type: ignore[union-attr]
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "compliant": llm_out.compliant,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="evaluate_request",
            violations=len(llm_out.violations),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="evaluate_request",
        )

    violation_count = sum(len(e.get("violations", [])) for e in evaluations)
    compliant = violation_count == 0

    step = _step(
        state.reasoning_chain,
        "evaluate_request",
        (f"Evaluating {len(state.policies)} policies"),
        (f"{violation_count} violations, compliant={compliant}"),
        start,
        "opa_evaluator",
    )

    return {
        "evaluations": evaluations,
        "violation_count": violation_count,
        "compliant": compliant,
        "stage": PCEStage.EVALUATE_REQUEST,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "evaluate_request",
    }


# ------------------------------------------------------------------
# Node: check_compliance
# ------------------------------------------------------------------


async def check_compliance(
    state: PolicyComplianceEnforcerState,
) -> dict[str, Any]:
    """Check evaluations against compliance frameworks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    checks = await toolkit.check_compliance(
        evaluations=state.evaluations,
        frameworks=state.frameworks,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "evaluations": state.evaluations[:5],
                "frameworks": state.frameworks,
                "violation_count": state.violation_count,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_COMPLIANCE,
            user_prompt=(f"Check compliance status:\n{ctx}"),
            schema=ComplianceCheckOutput,
        )
        if llm_out.framework_results:  # type: ignore[union-attr]
            checks = [
                *checks,
                *llm_out.framework_results,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="check_compliance",
            results=len(llm_out.framework_results),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_compliance",
        )

    step = _step(
        state.reasoning_chain,
        "check_compliance",
        (f"Checking {len(state.frameworks)} frameworks"),
        f"Produced {len(checks)} compliance checks",
        start,
        "compliance_checker",
    )

    return {
        "compliance_checks": checks,
        "stage": PCEStage.CHECK_COMPLIANCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "check_compliance",
    }


# ------------------------------------------------------------------
# Node: enforce_decision
# ------------------------------------------------------------------


async def enforce_decision(
    state: PolicyComplianceEnforcerState,
) -> dict[str, Any]:
    """Make enforcement decision based on policy
    evaluations and compliance checks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    decision = await toolkit.enforce_decision(
        evaluations=state.evaluations,
        compliance_checks=state.compliance_checks,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "violation_count": state.violation_count,
                "compliant": state.compliant,
                "evaluations_sample": state.evaluations[:5],
                "compliance_checks": (state.compliance_checks[:5]),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ENFORCE,
            user_prompt=(f"Make enforcement decision:\n{ctx}"),
            schema=EnforcementDecisionOutput,
        )
        if isinstance(llm_out, EnforcementDecisionOutput):
            decision.update(
                {
                    "action": llm_out.action,
                    "reason": llm_out.reason,
                    "policy_references": (llm_out.policy_references),
                    "exemption_applicable": (llm_out.exemption_applicable),
                }
            )
        logger.info(
            "llm_enhanced",
            node="enforce_decision",
            action=llm_out.action,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enforce_decision",
        )

    enforcement_action = decision.get("action", "allow")
    exemptions = 1 if decision.get("exemption_applicable") else 0

    decisions = [decision]

    step = _step(
        state.reasoning_chain,
        "enforce_decision",
        (f"Violations: {state.violation_count}, compliant={state.compliant}"),
        f"Decision: {enforcement_action}",
        start,
        "policy_enforcer",
    )

    return {
        "decisions": decisions,
        "enforcement_action": enforcement_action,
        "exemptions_applied": exemptions,
        "stage": PCEStage.ENFORCE_DECISION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enforce_decision",
    }


# ------------------------------------------------------------------
# Node: audit_log
# ------------------------------------------------------------------


async def audit_log(
    state: PolicyComplianceEnforcerState,
) -> dict[str, Any]:
    """Write immutable audit log entries for the
    enforcement decision."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    decision = state.decisions[0] if state.decisions else {}
    context = {
        "request_type": state.request_type,
        "resource": state.resource,
        "actor": state.actor,
        "tenant_id": state.tenant_id,
    }

    _result = await toolkit.write_audit_log(
        decision=decision,
        context=context,
    )

    audit_entry = {
        "request_id": state.request_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "action": state.enforcement_action,
        "resource": state.resource,
        "actor": state.actor,
        "violations": state.violation_count,
        "compliant": state.compliant,
    }

    step = _step(
        state.reasoning_chain,
        "audit_log",
        (f"Logging {state.enforcement_action} for {state.resource}"),
        "Audit entry written",
        start,
        "audit_store",
    )

    return {
        "audit_entries": [
            *state.audit_entries,
            audit_entry,
        ],
        "stage": PCEStage.AUDIT_LOG,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "audit_log",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: PolicyComplianceEnforcerState,
) -> dict[str, Any]:
    """Generate enforcement report with compliance
    summary and recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "request_id": state.request_id,
        "resource": state.resource,
        "enforcement_action": state.enforcement_action,
        "violation_count": state.violation_count,
        "compliant": state.compliant,
        "exemptions": state.exemptions_applied,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "request_type": state.request_type,
                "resource": state.resource,
                "enforcement_action": (state.enforcement_action),
                "violation_count": state.violation_count,
                "compliant": state.compliant,
                "evaluations_sample": (state.evaluations[:5]),
                "compliance_checks": (state.compliance_checks[:5]),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate enforcement report:\n{ctx}"),
            schema=EnforcerReportOutput,
        )
        if isinstance(llm_out, EnforcerReportOutput):
            report.update(
                {
                    "executive_summary": (llm_out.executive_summary),
                    "recommendations": (llm_out.recommendations),
                    "compliance_score": (llm_out.compliance_score),
                    "risk_rating": llm_out.risk_rating,
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

    # Record metrics
    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "action": state.enforcement_action,
            "violations": state.violation_count,
            "compliant": state.compliant,
            "exemptions": state.exemptions_applied,
        },
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.enforcement_action} decision"),
        (f"Report generated, violations={state.violation_count}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": PCEStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
