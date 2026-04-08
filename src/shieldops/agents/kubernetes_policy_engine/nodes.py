"""Node implementations for the Kubernetes Policy Engine
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.kubernetes_policy_engine.models import (
    KPEStage,
    KubernetesPolicyEngineState,
    ReasoningStep,
)
from shieldops.agents.kubernetes_policy_engine.prompts import (
    SYSTEM_EVALUATE,
    SYSTEM_REPORT,
    SYSTEM_SCAN,
    SYSTEM_STANDARDS,
    EnforcementReportOutput,
    PolicyEvaluationOutput,
    ResourceScanOutput,
    StandardsCheckOutput,
)
from shieldops.agents.kubernetes_policy_engine.tools import (
    KubernetesPolicyEngineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: KubernetesPolicyEngineToolkit | None = None


def _get_toolkit() -> KubernetesPolicyEngineToolkit:
    if _toolkit is None:
        return KubernetesPolicyEngineToolkit()
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
    state: KubernetesPolicyEngineState,
) -> dict[str, Any]:
    """Scan Kubernetes cluster resources for policy
    evaluation."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    resources = await toolkit.scan_resources(
        cluster_name=state.cluster_name,
        namespaces=state.namespaces,
        config=state.config,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "cluster": state.cluster_name,
                "namespaces": state.namespaces,
                "config": state.config,
                "resource_count": len(resources),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_SCAN,
            user_prompt=f"Scan cluster resources:\n{ctx}",
            schema=ResourceScanOutput,
        )
        if llm_out.risk_areas:  # type: ignore[union-attr]
            resources.append(
                {
                    "scan_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "risk_areas": llm_out.risk_areas,  # type: ignore[union-attr]
                    "recommendations": llm_out.recommendations,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="scan_resources",
            risks=len(llm_out.risk_areas),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_resources",
        )

    step = _step(
        state.reasoning_chain,
        "scan_resources",
        f"Cluster: {state.cluster_name}, NS: {len(state.namespaces)}",
        f"Scanned {len(resources)} resources",
        start,
        "k8s_api",
    )

    return {
        "resources": resources,
        "total_resources": len(resources),
        "stage": KPEStage.SCAN_RESOURCES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_resources",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: evaluate_policies
# ------------------------------------------------------------------


async def evaluate_policies(
    state: KubernetesPolicyEngineState,
) -> dict[str, Any]:
    """Evaluate scanned resources against OPA policy
    rules."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scopes = [s.value for s in state.policy_scopes]
    policy_results = await toolkit.evaluate_policies(
        resources=state.resources,
        scopes=scopes,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "resource_count": len(state.resources),
                "resources_sample": state.resources[:5],
                "scopes": scopes,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_EVALUATE,
            user_prompt=f"Evaluate policies:\n{ctx}",
            schema=PolicyEvaluationOutput,
        )
        if llm_out.summary:  # type: ignore[union-attr]
            policy_results.append(
                {
                    "eval_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "violations_found": llm_out.violations_found,  # type: ignore[union-attr]
                    "critical_count": llm_out.critical_count,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
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
        f"Produced {len(policy_results)} results",
        start,
        "opa_engine",
    )

    return {
        "policy_results": policy_results,
        "stage": KPEStage.EVALUATE_POLICIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "evaluate_policies",
    }


# ------------------------------------------------------------------
# Node: check_standards
# ------------------------------------------------------------------


async def check_standards(
    state: KubernetesPolicyEngineState,
) -> dict[str, Any]:
    """Check resources against Pod Security Standards
    and CIS benchmarks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    standards_results = await toolkit.check_standards(
        resources=state.resources,
        policy_results=state.policy_results,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "resource_count": len(state.resources),
                "policy_results_count": len(state.policy_results),
                "policy_sample": state.policy_results[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_STANDARDS,
            user_prompt=f"Check standards:\n{ctx}",
            schema=StandardsCheckOutput,
        )
        if llm_out.gaps:  # type: ignore[union-attr]
            standards_results.append(
                {
                    "check_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "compliant": llm_out.compliant,  # type: ignore[union-attr]
                    "standards": llm_out.standards_checked,  # type: ignore[union-attr]
                    "gaps": llm_out.gaps,  # type: ignore[union-attr]
                    "score": llm_out.score,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="check_standards",
            gaps=len(llm_out.gaps),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_standards",
        )

    step = _step(
        state.reasoning_chain,
        "check_standards",
        (f"Checking {len(state.resources)} resources against {len(state.policy_results)} policies"),
        f"Produced {len(standards_results)} standards results",
        start,
        "standards_checker",
    )

    return {
        "standards_results": standards_results,
        "stage": KPEStage.CHECK_STANDARDS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "check_standards",
    }


# ------------------------------------------------------------------
# Node: detect_violations
# ------------------------------------------------------------------


async def detect_violations(
    state: KubernetesPolicyEngineState,
) -> dict[str, Any]:
    """Detect and classify violations from evaluation
    results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    violations = await toolkit.detect_violations(
        policy_results=state.policy_results,
        standards_results=state.standards_results,
    )

    critical_count = sum(1 for v in violations if v.get("severity") == "critical")

    step = _step(
        state.reasoning_chain,
        "detect_violations",
        (
            f"Analyzing {len(state.policy_results)} policy "
            f"and {len(state.standards_results)} standards results"
        ),
        f"Detected {len(violations)} violations, {critical_count} critical",
        start,
        "violation_detector",
    )

    return {
        "violations": violations,
        "total_violations": len(violations),
        "critical_violations": critical_count,
        "stage": KPEStage.DETECT_VIOLATIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_violations",
    }


# ------------------------------------------------------------------
# Node: enforce_policies
# ------------------------------------------------------------------


async def enforce_policies(
    state: KubernetesPolicyEngineState,
) -> dict[str, Any]:
    """Enforce policies by remediating auto-fixable
    violations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.enforce_policies(
        violations=state.violations,
        config=state.config,
    )

    step = _step(
        state.reasoning_chain,
        "enforce_policies",
        f"Enforcing on {len(state.violations)} violations",
        f"Applied {len(actions)} enforcement actions",
        start,
        "enforcement_engine",
    )

    return {
        "enforcement_actions": actions,
        "stage": KPEStage.ENFORCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enforce_policies",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: KubernetesPolicyEngineState,
) -> dict[str, Any]:
    """Generate the final policy engine report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Compute compliance score
    if state.total_resources > 0:
        _ratio = state.total_violations / max(state.total_resources, 1)
        compliance_score = max(0.0, 100.0 * (1.0 - _ratio))
    else:
        compliance_score = 100.0

    report: dict[str, Any] = {
        "cluster": state.cluster_name,
        "total_resources": state.total_resources,
        "total_violations": state.total_violations,
        "critical_violations": state.critical_violations,
        "enforcement_actions": len(state.enforcement_actions),
        "compliance_score": round(compliance_score, 2),
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "cluster": state.cluster_name,
                "total_resources": state.total_resources,
                "violations": state.violations[:10],
                "enforcement_actions": state.enforcement_actions[:5],
                "standards_results": state.standards_results[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate policy report:\n{ctx}",
            schema=EnforcementReportOutput,
        )
        if isinstance(llm_out, EnforcementReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "compliance_score": llm_out.compliance_score,
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
        metric_name="kpe.compliance_score",
        value=compliance_score,
        labels={"cluster": state.cluster_name},
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_violations} violations",
        f"Report generated, compliance={compliance_score:.1f}%",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "compliance_score": compliance_score,
        "session_duration_ms": duration_ms,
        "stage": KPEStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
