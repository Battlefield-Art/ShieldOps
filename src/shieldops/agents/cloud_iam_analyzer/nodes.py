"""Node implementations for the Cloud IAM Analyzer
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cloud_iam_analyzer.models import (
    CIAStage,
    CloudIAMAnalyzerState,
    ReasoningStep,
)
from shieldops.agents.cloud_iam_analyzer.prompts import (
    SYSTEM_COMPARISON,
    SYSTEM_PERMISSIONS,
    SYSTEM_REPORT,
    SYSTEM_RISKS,
    CloudComparisonOutput,
    IAMReportOutput,
    PermissionAnalysisOutput,
    RiskDetectionOutput,
)
from shieldops.agents.cloud_iam_analyzer.tools import (
    CloudIAMAnalyzerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CloudIAMAnalyzerToolkit | None = None


def _get_toolkit() -> CloudIAMAnalyzerToolkit:
    if _toolkit is None:
        return CloudIAMAnalyzerToolkit()
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
# Node: collect_policies
# ------------------------------------------------------------------


async def collect_policies(
    state: CloudIAMAnalyzerState,
) -> dict[str, Any]:
    """Collect IAM policies from target cloud providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.collect_policies(
        providers=state.target_providers,
        scope=state.scope,
    )

    policies: list[dict[str, Any]] = list(results)

    step = _step(
        state.reasoning_chain,
        "collect_policies",
        f"Providers: {len(state.target_providers)}",
        f"Collected {len(policies)} policies",
        start,
        "iam_collector",
    )

    return {
        "policies": policies,
        "total_policies": len(policies),
        "stage": CIAStage.COLLECT_POLICIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_policies",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_permissions
# ------------------------------------------------------------------


async def analyze_permissions(
    state: CloudIAMAnalyzerState,
) -> dict[str, Any]:
    """Analyze IAM permissions for least-privilege
    adherence."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_permissions(
        policies=state.policies,
        scope=state.scope,
    )

    analyses = list(analyses)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "policy_count": len(state.policies),
                "sample": state.policies[:5],
                "providers": state.target_providers,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_PERMISSIONS,
            user_prompt=f"Analyze permissions:\n{ctx}",
            schema=PermissionAnalysisOutput,
        )
        rand_id = random.randint(1000, 9999)  # noqa: S311
        if llm_out.summary:  # type: ignore[union-attr]
            analyses.append(
                {
                    "analysis_id": f"llm-{rand_id}",
                    "overprivileged": llm_out.overprivileged_principals,  # type: ignore[union-attr]
                    "unused_count": llm_out.unused_permission_count,  # type: ignore[union-attr]
                    "admin_access": llm_out.admin_access_principals,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_permissions",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_permissions",
        )

    overprivileged = sum(
        1
        for a in analyses
        if a.get("overprivileged")
        and a.get("overprivileged") is not True
        or a.get("overprivileged") is True
    )

    step = _step(
        state.reasoning_chain,
        "analyze_permissions",
        f"Analyzing {len(state.policies)} policies",
        f"{len(analyses)} analyses, {overprivileged} overprivileged",
        start,
        "permission_analyzer",
    )

    return {
        "permission_analyses": analyses,
        "overprivileged_count": overprivileged,
        "stage": CIAStage.ANALYZE_PERMISSIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_permissions",
    }


# ------------------------------------------------------------------
# Node: detect_risks
# ------------------------------------------------------------------


async def detect_risks(
    state: CloudIAMAnalyzerState,
) -> dict[str, Any]:
    """Detect IAM-related security risks across
    cloud providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    findings = await toolkit.detect_iam_risks(
        analyses=state.permission_analyses,
        compliance_frameworks=state.compliance_frameworks,
    )

    findings = list(findings)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "analyses": state.permission_analyses[:5],
                "frameworks": state.compliance_frameworks,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_RISKS,
            user_prompt=f"Detect IAM risks:\n{ctx}",
            schema=RiskDetectionOutput,
        )
        if llm_out.findings:  # type: ignore[union-attr]
            findings.extend(llm_out.findings)  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="detect_risks",
            count=len(llm_out.findings),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_risks",
        )

    critical = sum(
        1 for f in findings if f.get("risk_level") == "critical" or f.get("level") == "critical"
    )

    step = _step(
        state.reasoning_chain,
        "detect_risks",
        f"Scanning {len(state.permission_analyses)} analyses",
        f"{len(findings)} risks, {critical} critical",
        start,
        "risk_detector",
    )

    return {
        "risk_findings": findings,
        "critical_risks": critical,
        "stage": CIAStage.DETECT_RISKS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_risks",
    }


# ------------------------------------------------------------------
# Node: compare_clouds
# ------------------------------------------------------------------


async def compare_clouds(
    state: CloudIAMAnalyzerState,
) -> dict[str, Any]:
    """Compare IAM policies across cloud providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    comparisons = await toolkit.compare_clouds(
        policies=state.policies,
        providers=state.target_providers,
    )

    comparisons = list(comparisons)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "providers": state.target_providers,
                "policy_count": len(state.policies),
                "risk_findings": state.risk_findings[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_COMPARISON,
            user_prompt=f"Compare cloud IAM:\n{ctx}",
            schema=CloudComparisonOutput,
        )
        if llm_out.gaps:  # type: ignore[union-attr]
            comparisons.append(
                {
                    "consistency_score": llm_out.consistency_score,  # type: ignore[union-attr]
                    "gaps": llm_out.gaps,  # type: ignore[union-attr]
                    "recommendations": llm_out.recommendations,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="compare_clouds",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="compare_clouds",
        )

    step = _step(
        state.reasoning_chain,
        "compare_clouds",
        f"Comparing across {len(state.target_providers)} providers",
        f"Produced {len(comparisons)} comparisons",
        start,
        "cloud_comparator",
    )

    return {
        "cloud_comparisons": comparisons,
        "stage": CIAStage.COMPARE_CLOUDS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "compare_clouds",
    }


# ------------------------------------------------------------------
# Node: optimize
# ------------------------------------------------------------------


async def optimize(
    state: CloudIAMAnalyzerState,
) -> dict[str, Any]:
    """Generate IAM optimization recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    optimizations = await toolkit.optimize_policies(
        risk_findings=state.risk_findings,
        comparisons=state.cloud_comparisons,
    )

    step = _step(
        state.reasoning_chain,
        "optimize",
        f"Optimizing from {len(state.risk_findings)} findings",
        f"Produced {len(optimizations)} actions",
        start,
        "optimizer",
    )

    return {
        "optimizations": optimizations,
        "optimization_count": len(optimizations),
        "stage": CIAStage.OPTIMIZE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "optimize",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: CloudIAMAnalyzerState,
) -> dict[str, Any]:
    """Generate the final IAM analysis report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_policies": state.total_policies,
        "overprivileged": state.overprivileged_count,
        "critical_risks": state.critical_risks,
        "optimizations": state.optimization_count,
        "providers": state.target_providers,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "total_policies": state.total_policies,
                "overprivileged": state.overprivileged_count,
                "critical_risks": state.critical_risks,
                "optimizations": state.optimization_count,
                "findings_sample": state.risk_findings[:5],
                "comparisons": state.cloud_comparisons[:3],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate IAM report:\n{ctx}",
            schema=IAMReportOutput,
        )
        if isinstance(llm_out, IAMReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "risk_score": llm_out.risk_score,
                    "recommendations": llm_out.recommendations,
                    "compliance_gaps": llm_out.compliance_gaps,
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

    await toolkit.record_metric("cia_total_policies", float(state.total_policies))
    await toolkit.record_metric("cia_critical_risks", float(state.critical_risks))

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_policies} policies",
        f"Report generated, critical={state.critical_risks}",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": CIAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
