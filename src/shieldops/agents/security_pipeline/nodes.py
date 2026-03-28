"""Node implementations for the Security Pipeline Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_pipeline.models import (
    PipelineStage,
    SecurityPipelineState,
)
from shieldops.agents.security_pipeline.prompts import (
    SYSTEM_PLAN,
    SYSTEM_REMEDIATE,
    SYSTEM_REPORT,
    PipelinePlanOutput,
    PipelineReportOutput,
    RemediationDecisionOutput,
)
from shieldops.agents.security_pipeline.tools import (
    SecurityPipelineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityPipelineToolkit | None = None


def set_toolkit(
    toolkit: SecurityPipelineToolkit,
) -> None:
    """Set the global toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SecurityPipelineToolkit:
    if _toolkit is None:
        return SecurityPipelineToolkit()
    return _toolkit


async def plan_pipeline(
    state: SecurityPipelineState,
) -> dict[str, Any]:
    """Plan the security pipeline run."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    plan = await toolkit.plan_pipeline(
        tenant_id=state.tenant_id,
    )

    try:
        result = await llm_structured(
            system_prompt=SYSTEM_PLAN,
            user_prompt=(
                f"Tenant: {state.tenant_id}\nDefault agents: {', '.join(plan.agents_to_dispatch)}"
            ),
            output_schema=PipelinePlanOutput,
        )
        plan.phases = result.phases
        plan.agents_to_dispatch = result.agents_to_dispatch
        plan.estimated_duration_minutes = result.estimated_duration_minutes
    except Exception:
        logger.warning("security_pipeline.plan_llm_fallback")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "pipeline_plan": plan,
        "current_stage": PipelineStage.PLAN_PIPELINE,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Planned pipeline with {len(plan.agents_to_dispatch)} agents ({elapsed}ms)",
        ],
    }


async def dispatch_discovery(
    state: SecurityPipelineState,
) -> dict[str, Any]:
    """Dispatch discovery agents."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.dispatch_discovery(
        tenant_id=state.tenant_id,
        agents=state.pipeline_plan.agents_to_dispatch[:3],
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "discovery_results": results,
        "agents_dispatched": (state.agents_dispatched + len(results)),
        "current_stage": (PipelineStage.DISPATCH_DISCOVERY),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Dispatched {len(results)} discovery agents ({elapsed}ms)",
        ],
    }


async def dispatch_pentest(
    state: SecurityPipelineState,
) -> dict[str, Any]:
    """Dispatch pentest agents."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.dispatch_pentest(
        tenant_id=state.tenant_id,
        agents=state.pipeline_plan.agents_to_dispatch[3:],
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "pentest_results": results,
        "agents_dispatched": (state.agents_dispatched + len(results)),
        "current_stage": (PipelineStage.DISPATCH_PENTEST),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Dispatched {len(results)} pentest agents ({elapsed}ms)",
        ],
    }


async def collect_findings(
    state: SecurityPipelineState,
) -> dict[str, Any]:
    """Collect findings from all agents."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    findings = await toolkit.collect_findings(
        discovery_results=state.discovery_results,
        pentest_results=state.pentest_results,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "findings": findings,
        "current_stage": (PipelineStage.COLLECT_FINDINGS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Collected {len(findings)} findings ({elapsed}ms)",
        ],
    }


async def dispatch_remediation(
    state: SecurityPipelineState,
) -> dict[str, Any]:
    """Dispatch remediations for findings."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # LLM decides which findings to auto-remediate
    safe_findings = []
    for finding in state.findings:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_REMEDIATE,
                user_prompt=(
                    f"Finding: {finding.title}\n"
                    f"Severity: {finding.severity}\n"
                    f"Asset: {finding.asset}\n"
                    f"CVSS: {finding.cvss_score}"
                ),
                output_schema=(RemediationDecisionOutput),
            )
            if result.should_remediate:
                safe_findings.append(finding)
        except Exception:
            logger.warning(
                "security_pipeline.remediate_fallback",
                finding_id=finding.id,
            )
            if finding.severity in (
                "low",
                "medium",
            ):
                safe_findings.append(finding)

    remediations = await toolkit.dispatch_remediation(
        safe_findings,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "remediations": remediations,
        "current_stage": (PipelineStage.DISPATCH_REMEDIATION),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Dispatched {len(remediations)} remediations ({elapsed}ms)",
        ],
    }


async def verify_results(
    state: SecurityPipelineState,
) -> dict[str, Any]:
    """Verify remediations were effective."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    verifications = await toolkit.verify_results(
        state.remediations,
    )
    resolved = sum(1 for v in verifications if v.retest_passed)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "verifications": verifications,
        "findings_resolved": resolved,
        "cycle_count": state.cycle_count + 1,
        "current_stage": (PipelineStage.VERIFY_RESULTS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Verified {len(verifications)} remediations, {resolved} resolved ({elapsed}ms)",
        ],
    }


async def generate_report(
    state: SecurityPipelineState,
) -> dict[str, Any]:
    """Generate the pipeline report."""
    start = datetime.now(UTC)

    try:
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(
                f"Findings: {len(state.findings)}\n"
                f"Remediations: "
                f"{len(state.remediations)}\n"
                f"Verified: "
                f"{len(state.verifications)}\n"
                f"Resolved: {state.findings_resolved}\n"
                f"Agents dispatched: "
                f"{state.agents_dispatched}"
            ),
            output_schema=PipelineReportOutput,
        )
        summary = result.executive_summary
    except Exception:
        logger.warning("security_pipeline.report_llm_fallback")
        summary = (
            f"Pipeline completed: "
            f"{len(state.findings)} findings, "
            f"{state.findings_resolved} resolved"
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    total_ms = (
        sum(int(r.split("(")[-1].rstrip("ms)")) for r in state.reasoning_chain if "ms)" in r)
        + elapsed
    )

    return {
        "current_stage": PipelineStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report: {summary[:100]} ({elapsed}ms)",
        ],
        "session_duration_ms": total_ms,
    }
