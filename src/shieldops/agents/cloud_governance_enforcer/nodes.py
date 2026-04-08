"""Node implementations for the Cloud Governance
Enforcer Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cloud_governance_enforcer.models import (
    CGEStage,
    CloudGovernanceEnforcerState,
    ReasoningStep,
)
from shieldops.agents.cloud_governance_enforcer.prompts import (
    SYSTEM_POLICY_EVALUATION,
    SYSTEM_REPORT,
    SYSTEM_TAG_COMPLIANCE,
    SYSTEM_VIOLATION_ANALYSIS,
    GovernanceReportOutput,
    PolicyEvaluationOutput,
    TagComplianceOutput,
    ViolationAnalysisOutput,
)
from shieldops.agents.cloud_governance_enforcer.tools import (
    CloudGovernanceEnforcerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CloudGovernanceEnforcerToolkit | None = None


def _get_toolkit() -> CloudGovernanceEnforcerToolkit:
    if _toolkit is None:
        return CloudGovernanceEnforcerToolkit()
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
# Node: scan_resources
# ------------------------------------------------------------------


async def scan_resources(
    state: CloudGovernanceEnforcerState,
) -> dict[str, Any]:
    """Scan cloud resources across providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    resources = await toolkit.scan_resources(
        cloud_providers=state.cloud_providers,
        scan_scope=state.scan_scope,
    )

    step = _step(
        state.reasoning_chain,
        "scan_resources",
        f"Providers: {len(state.cloud_providers)}",
        f"Discovered {len(resources)} resources",
        start,
        "cloud_scanner",
    )

    return {
        "resources": resources,
        "total_resources": len(resources),
        "stage": CGEStage.SCAN_RESOURCES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_resources",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: check_tags
# ------------------------------------------------------------------


async def check_tags(
    state: CloudGovernanceEnforcerState,
) -> dict[str, Any]:
    """Check tag compliance across discovered resources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    tag_results = await toolkit.check_tag_compliance(
        resources=state.resources,
        required_tags=state.required_tags,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "resource_count": len(state.resources),
                "required_tags": state.required_tags,
                "resources_sample": state.resources[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_TAG_COMPLIANCE,
            user_prompt=f"Analyze tag compliance:\n{ctx}",
            schema=TagComplianceOutput,
        )
        if llm_out.non_compliant_resources:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            tag_results.append(
                {
                    "result_id": f"llm-{rand_id}",
                    "non_compliant": llm_out.non_compliant_resources,  # type: ignore[union-attr]
                    "common_missing": llm_out.common_missing_tags,  # type: ignore[union-attr]
                    "naming_violations": llm_out.naming_violations_count,  # type: ignore[union-attr]
                    "compliance_score": llm_out.compliance_score,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="check_tags",
            non_compliant=len(llm_out.non_compliant_resources),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_tags",
        )

    compliant_count = sum(
        1 for r in tag_results if isinstance(r, dict) and r.get("compliant", False)
    )

    step = _step(
        state.reasoning_chain,
        "check_tags",
        f"Checking {len(state.resources)} resources",
        f"{compliant_count} compliant of {len(tag_results)}",
        start,
        "tag_engine",
    )

    return {
        "tag_results": tag_results,
        "compliant_resources": compliant_count,
        "stage": CGEStage.CHECK_TAGS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "check_tags",
    }


# ------------------------------------------------------------------
# Node: evaluate_policies
# ------------------------------------------------------------------


async def evaluate_policies(
    state: CloudGovernanceEnforcerState,
) -> dict[str, Any]:
    """Evaluate resources against governance policies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    evaluations = await toolkit.evaluate_policies(
        resources=state.resources,
        tag_results=state.tag_results,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "resource_count": len(state.resources),
                "tag_results_sample": state.tag_results[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_POLICY_EVALUATION,
            user_prompt=f"Evaluate governance policies:\n{ctx}",
            schema=PolicyEvaluationOutput,
        )
        if hasattr(llm_out, "violations_found") and llm_out.violations_found > 0:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            evaluations.append(
                {
                    "eval_id": f"llm-{rand_id}",
                    "violations_found": llm_out.violations_found,  # type: ignore[union-attr]
                    "critical": llm_out.critical_violations,  # type: ignore[union-attr]
                    "cost_gaps": llm_out.cost_attribution_gaps,  # type: ignore[union-attr]
                    "lifecycle_issues": llm_out.lifecycle_issues,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="evaluate_policies",
            violations=llm_out.violations_found,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="evaluate_policies",
        )

    step = _step(
        state.reasoning_chain,
        "evaluate_policies",
        f"Evaluating {len(state.resources)} resources",
        f"Produced {len(evaluations)} evaluations",
        start,
        "policy_evaluator",
    )

    return {
        "policy_evaluations": evaluations,
        "stage": CGEStage.EVALUATE_POLICIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "evaluate_policies",
    }


# ------------------------------------------------------------------
# Node: detect_violations
# ------------------------------------------------------------------


async def detect_violations(
    state: CloudGovernanceEnforcerState,
) -> dict[str, Any]:
    """Detect and classify governance violations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    violations = await toolkit.detect_violations(
        policy_evaluations=state.policy_evaluations,
        tag_results=state.tag_results,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "policy_evaluations": state.policy_evaluations[:5],
                "tag_results": state.tag_results[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_VIOLATION_ANALYSIS,
            user_prompt=f"Analyze violations:\n{ctx}",
            schema=ViolationAnalysisOutput,
        )
        if llm_out.priority_actions:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            violations.append(
                {
                    "violation_id": f"llm-{rand_id}",
                    "total": llm_out.total_violations,  # type: ignore[union-attr]
                    "by_severity": llm_out.by_severity,  # type: ignore[union-attr]
                    "auto_remediable": llm_out.auto_remediable_count,  # type: ignore[union-attr]
                    "cost_impact": llm_out.estimated_cost_impact,  # type: ignore[union-attr]
                    "priority_actions": llm_out.priority_actions,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="detect_violations",
            total=llm_out.total_violations,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_violations",
        )

    total_score = 0.0
    if state.total_resources > 0:
        compliant = state.total_resources - len(violations)
        total_score = max(0.0, compliant / state.total_resources)

    step = _step(
        state.reasoning_chain,
        "detect_violations",
        f"Analyzing {len(state.policy_evaluations)} evals",
        f"Found {len(violations)} violations",
        start,
        "violation_detector",
    )

    return {
        "violations": violations,
        "total_violations": len(violations),
        "compliance_score": total_score,
        "stage": CGEStage.DETECT_VIOLATIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_violations",
    }


# ------------------------------------------------------------------
# Node: remediate
# ------------------------------------------------------------------


async def remediate(
    state: CloudGovernanceEnforcerState,
) -> dict[str, Any]:
    """Auto-remediate violations where permitted."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    remediations = await toolkit.auto_remediate(
        violations=state.violations,
        auto_remediate=state.auto_remediate,
    )

    applied = sum(1 for r in remediations if isinstance(r, dict) and r.get("status") == "applied")

    step = _step(
        state.reasoning_chain,
        "remediate",
        f"Processing {len(state.violations)} violations",
        f"Applied {applied} remediations",
        start,
        "remediation_engine",
    )

    return {
        "remediations": remediations,
        "remediations_applied": applied,
        "stage": CGEStage.REMEDIATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "remediate",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: CloudGovernanceEnforcerState,
) -> dict[str, Any]:
    """Generate the final governance enforcement report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    report: dict[str, Any] = {
        "scan_scope": state.scan_scope,
        "total_resources": state.total_resources,
        "compliant_resources": state.compliant_resources,
        "total_violations": state.total_violations,
        "remediations_applied": state.remediations_applied,
        "compliance_score": state.compliance_score,
        "duration_ms": duration_ms,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scope": state.scan_scope,
                "providers": state.cloud_providers,
                "total_resources": state.total_resources,
                "compliant": state.compliant_resources,
                "violations": state.total_violations,
                "remediations": state.remediations_applied,
                "compliance_score": state.compliance_score,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate governance report:\n{ctx}",
            schema=GovernanceReportOutput,
        )
        if isinstance(llm_out, GovernanceReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "risk_assessment": llm_out.risk_assessment,
                    "cost_opportunities": llm_out.cost_optimization_opportunities,
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
        metric_name="compliance_score",
        value=state.compliance_score,
        tags={"scope": state.scan_scope},
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_resources} resources",
        (f"Report generated, score={state.compliance_score:.2f}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": CGEStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
