"""Node implementations for the Cloud Workload Inspector."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cloud_workload_inspector.models import (
    CloudWorkloadInspectorState,
    CWIStage,
    ReasoningStep,
)
from shieldops.agents.cloud_workload_inspector.prompts import (
    SYSTEM_ANALYZE_CONFIG,
    SYSTEM_COMPLIANCE,
    SYSTEM_DISCOVER,
    SYSTEM_RECOMMEND,
    SYSTEM_RISK,
    ComplianceCheckOutput,
    ConfigAnalysisOutput,
    RecommendationOutput,
    RiskAssessmentOutput,
    WorkloadDiscoveryOutput,
)
from shieldops.agents.cloud_workload_inspector.tools import (
    CloudWorkloadInspectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CloudWorkloadInspectorToolkit | None = None


def set_toolkit(
    toolkit: CloudWorkloadInspectorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> CloudWorkloadInspectorToolkit:
    if _toolkit is None:
        return CloudWorkloadInspectorToolkit()
    return _toolkit


def _step(
    state: CloudWorkloadInspectorState,
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


async def discover_workloads(
    state: CloudWorkloadInspectorState,
) -> dict[str, Any]:
    """Discover cloud workloads across providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.discover_workloads(state.inspect_config)
    public_count = sum(1 for w in raw if w.get("is_public"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "provider": state.inspect_config.get("provider", ""),
                "regions": state.inspect_config.get("regions", [])[:10],
                "workload_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DISCOVER,
            user_prompt=(f"Workload discovery context:\n{ctx}"),
            schema=WorkloadDiscoveryOutput,
        )
        if hasattr(llm_result, "public_count") and llm_result.public_count > public_count:
            public_count = llm_result.public_count
        logger.info(
            "llm_enhanced",
            node="discover_workloads",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="discover_workloads",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "discover_workloads",
        f"provider={state.inspect_config.get('provider', '')}",
        f"found {len(raw)} workloads, {public_count} public",
        elapsed,
        "cloud_client",
    )
    await toolkit.record_metric("discovery", float(len(raw)))

    return {
        "discovered_workloads": raw,
        "public_workload_count": public_count,
        "stage": CWIStage.ANALYZE_CONFIG,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "discover_workloads",
        "session_start": start,
    }


async def analyze_config(
    state: CloudWorkloadInspectorState,
) -> dict[str, Any]:
    """Analyze configuration of discovered workloads."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    findings = await toolkit.analyze_config(
        state.discovered_workloads,
    )
    critical_count = sum(1 for f in findings if f.get("severity") == "critical")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "workload_count": len(state.discovered_workloads),
                "findings": findings[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE_CONFIG,
            user_prompt=(f"Config analysis context:\n{ctx}"),
            schema=ConfigAnalysisOutput,
        )
        if (
            hasattr(llm_result, "critical_findings")
            and llm_result.critical_findings > critical_count
        ):
            critical_count = llm_result.critical_findings
        logger.info(
            "llm_enhanced",
            node="analyze_config",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_config",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "analyze_config",
        f"analyzing {len(state.discovered_workloads)} workloads",
        f"{len(findings)} findings, {critical_count} critical",
        elapsed,
        "config_scanner",
    )

    return {
        "config_findings": findings,
        "critical_finding_count": critical_count,
        "stage": CWIStage.CHECK_COMPLIANCE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_config",
    }


async def check_compliance(
    state: CloudWorkloadInspectorState,
) -> dict[str, Any]:
    """Check compliance posture for workloads."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    checks = await toolkit.check_compliance(
        state.discovered_workloads,
        state.config_findings,
    )
    compliant = sum(1 for c in checks if c.get("status") == "compliant")
    pass_rate = round(compliant / len(checks) * 100, 1) if checks else 0.0

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "workload_count": len(state.discovered_workloads),
                "checks": checks[:10],
                "pass_rate": pass_rate,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COMPLIANCE,
            user_prompt=(f"Compliance check context:\n{ctx}"),
            schema=ComplianceCheckOutput,
        )
        if hasattr(llm_result, "pass_rate"):
            pass_rate = round(
                (pass_rate + llm_result.pass_rate) / 2,
                1,
            )
        logger.info(
            "llm_enhanced",
            node="check_compliance",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_compliance",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "check_compliance",
        f"checking {len(state.discovered_workloads)} workloads",
        f"pass_rate={pass_rate}%",
        elapsed,
        "compliance_engine",
    )

    return {
        "compliance_checks": checks,
        "compliance_pass_rate": pass_rate,
        "stage": CWIStage.ASSESS_RISK,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "check_compliance",
    }


async def assess_risk(
    state: CloudWorkloadInspectorState,
) -> dict[str, Any]:
    """Assess risk for inspected workloads."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_risk(
        state.discovered_workloads,
        state.config_findings,
    )
    max_score = max(
        (a.get("risk_score", 0.0) for a in assessments),
        default=0.0,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "workload_count": len(state.discovered_workloads),
                "assessments": assessments[:10],
                "max_score": max_score,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=(f"Risk assessment context:\n{ctx}"),
            schema=RiskAssessmentOutput,
        )
        if hasattr(llm_result, "max_risk_score") and llm_result.max_risk_score > max_score:
            max_score = round(
                (max_score + llm_result.max_risk_score) / 2,
                1,
            )
        logger.info(
            "llm_enhanced",
            node="assess_risk",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "assess_risk",
        f"assessing {len(state.discovered_workloads)} workloads",
        f"max_risk={max_score}",
        elapsed,
        "risk_engine",
    )
    await toolkit.record_metric("max_risk", max_score)

    return {
        "risk_assessments": assessments,
        "max_risk_score": max_score,
        "stage": CWIStage.RECOMMEND,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "assess_risk",
    }


async def recommend(
    state: CloudWorkloadInspectorState,
) -> dict[str, Any]:
    """Generate remediation recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    recs = await toolkit.recommend_fixes(
        state.risk_assessments,
        state.config_findings,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "risk_count": len(state.risk_assessments),
                "finding_count": len(state.config_findings),
                "rec_count": len(recs),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RECOMMEND,
            user_prompt=(f"Recommendation context:\n{ctx}"),
            schema=RecommendationOutput,
        )
        if hasattr(llm_result, "actions"):
            logger.info(
                "llm_enhanced",
                node="recommend",
                llm_actions=len(llm_result.actions),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "recommend",
        f"generating recs for {len(state.risk_assessments)} risks",
        f"created {len(recs)} recommendations",
        elapsed,
        "recommendation_engine",
    )

    return {
        "recommendations": recs,
        "stage": CWIStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "recommend",
    }


async def generate_report(
    state: CloudWorkloadInspectorState,
) -> dict[str, Any]:
    """Generate final workload inspection report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "total_workloads": len(state.discovered_workloads),
        "public_workloads": state.public_workload_count,
        "critical_findings": state.critical_finding_count,
        "compliance_pass_rate": state.compliance_pass_rate,
        "max_risk_score": state.max_risk_score,
        "recommendations": len(state.recommendations),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_metric(
        "total_workloads",
        float(len(state.discovered_workloads)),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "generate_report",
        f"finalizing inspection {state.request_id}",
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
