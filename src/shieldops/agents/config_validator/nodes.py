"""Node implementations for the Config Validator Agent LangGraph workflow.

Each node is an async function that:
1. Calls tools to collect or compare configuration data
2. Uses the LLM to analyze and reason about findings
3. Updates the validation state
4. Records its reasoning step in the audit trail
"""

import time
from typing import Any, cast

import structlog

from shieldops.agents.config_validator.models import (
    ConfigValidatorState,
    ReasoningStep,
    ValidatorStage,
)
from shieldops.agents.config_validator.prompts import (
    SYSTEM_DRIFT_ANALYSIS,
    SYSTEM_IMPACT_ANALYSIS,
    SYSTEM_VALIDATION_REPORT,
    DriftAnalysisResult,
    ImpactAnalysisResult,
    ValidationReportResult,
)
from shieldops.agents.config_validator.tools import ConfigValidatorToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit reference, set by the runner at graph construction time.
_toolkit: ConfigValidatorToolkit | None = None


def _get_toolkit() -> ConfigValidatorToolkit:
    if _toolkit is None:
        return ConfigValidatorToolkit()
    return _toolkit


def _elapsed_ms(start: float) -> int:
    return int((time.time() - start) * 1000)


async def collect_configs(state: ConfigValidatorState) -> dict[str, Any]:
    """Collect configuration snapshots from all infrastructure sources."""
    start = time.time()
    toolkit = _get_toolkit()

    logger.info("config_validator_collecting", tenant_id=state.tenant_id)

    snapshots = await toolkit.collect_configs(state.tenant_id)

    step = ReasoningStep(
        step_number=1,
        action="collect_configs",
        input_summary=f"Collecting configs for tenant {state.tenant_id}",
        output_summary=f"Collected {len(snapshots)} config snapshots across all sources",
        duration_ms=_elapsed_ms(start),
        tool_used="config_collector",
    )

    return {
        "snapshots": snapshots,
        "total_configs": len(snapshots),
        "stage": ValidatorStage.COMPARE_BASELINES,
        "reasoning_chain": [step],
        "started_at": start,
    }


async def compare_baselines(state: ConfigValidatorState) -> dict[str, Any]:
    """Compare collected snapshots against golden baselines."""
    start = time.time()
    toolkit = _get_toolkit()

    logger.info("config_validator_comparing", snapshot_count=len(state.snapshots))

    updated_snapshots = await toolkit.compare_baselines(state.snapshots)
    compliant_count = sum(1 for s in updated_snapshots if s.compliant)
    non_compliant = len(updated_snapshots) - compliant_count

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="compare_baselines",
        input_summary=f"Comparing {len(updated_snapshots)} snapshots against golden baselines",
        output_summary=(
            f"{compliant_count} compliant, {non_compliant} non-compliant "
            f"out of {len(updated_snapshots)} configs"
        ),
        duration_ms=_elapsed_ms(start),
        tool_used="baseline_comparator",
    )

    return {
        "snapshots": updated_snapshots,
        "compliant_count": compliant_count,
        "stage": ValidatorStage.DETECT_DRIFT,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def detect_drift(state: ConfigValidatorState) -> dict[str, Any]:
    """Detect configuration drift for non-compliant resources using LLM analysis."""
    start = time.time()
    toolkit = _get_toolkit()

    logger.info("config_validator_detecting_drift", tenant_id=state.tenant_id)

    drifts = await toolkit.detect_drift(state.snapshots)

    output_summary = f"Detected {len(drifts)} configuration drifts"

    # Use LLM to analyze drift patterns
    if drifts:
        drift_context = _format_drift_context(state, drifts)
        try:
            analysis = cast(
                DriftAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_DRIFT_ANALYSIS,
                    user_prompt=drift_context,
                    schema=DriftAnalysisResult,
                ),
            )
            output_summary = analysis.summary
        except Exception as e:
            logger.error("llm_drift_analysis_failed", error=str(e))
            output_summary = f"Detected {len(drifts)} drifts (LLM analysis failed: {e})"

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_drift",
        input_summary=(
            f"Analyzing {sum(1 for s in state.snapshots if not s.compliant)} "
            f"non-compliant snapshots for drift"
        ),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="drift_detector + llm",
    )

    return {
        "drifts": drifts,
        "drift_count": len(drifts),
        "stage": ValidatorStage.ASSESS_IMPACT,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def assess_impact(state: ConfigValidatorState) -> dict[str, Any]:
    """Assess the impact of detected drifts using LLM reasoning."""
    start = time.time()
    toolkit = _get_toolkit()

    logger.info("config_validator_assessing_impact", drift_count=len(state.drifts))

    assessments = await toolkit.assess_impact(state.drifts, state.snapshots)

    output_summary = f"Assessed impact for {len(assessments)} drifts"

    if assessments:
        impact_context = _format_impact_context(state, assessments)
        try:
            analysis = cast(
                ImpactAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_IMPACT_ANALYSIS,
                    user_prompt=impact_context,
                    schema=ImpactAnalysisResult,
                ),
            )
            output_summary = (
                f"{analysis.summary}. Blast radius: {analysis.blast_radius}. "
                f"Security concerns: {len(analysis.security_concerns)}"
            )
        except Exception as e:
            logger.error("llm_impact_analysis_failed", error=str(e))
            output_summary = f"Impact assessed for {len(assessments)} drifts (LLM failed: {e})"

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_impact",
        input_summary=f"Assessing impact for {len(state.drifts)} drifts",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="impact_assessor + llm",
    )

    return {
        "impact_assessments": assessments,
        "stage": ValidatorStage.REMEDIATE,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def remediate(state: ConfigValidatorState) -> dict[str, Any]:
    """Attempt auto-remediation for fixable drifts."""
    start = time.time()
    toolkit = _get_toolkit()

    logger.info("config_validator_remediating", drift_count=len(state.drifts))

    actions = await toolkit.remediate_drift(state.drifts)
    applied = sum(1 for a in actions if a.applied)
    succeeded = sum(1 for a in actions if a.success)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="remediate",
        input_summary=f"Attempting remediation for {len(state.drifts)} drifts",
        output_summary=(f"Applied {applied}/{len(actions)} remediations, {succeeded} succeeded"),
        duration_ms=_elapsed_ms(start),
        tool_used="drift_remediator",
    )

    return {
        "remediations": actions,
        "stage": ValidatorStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def generate_report(state: ConfigValidatorState) -> dict[str, Any]:
    """Generate the final validation report using LLM synthesis."""
    start = time.time()

    logger.info(
        "config_validator_reporting",
        total=state.total_configs,
        drifts=state.drift_count,
    )

    report_context = _format_report_context(state)
    report_summary = (
        f"Validated {state.total_configs} configs: "
        f"{state.compliant_count} compliant, {state.drift_count} drifts found, "
        f"{sum(1 for r in state.remediations if r.success)} auto-fixed"
    )

    try:
        result = cast(
            ValidationReportResult,
            await llm_structured(
                system_prompt=SYSTEM_VALIDATION_REPORT,
                user_prompt=report_context,
                schema=ValidationReportResult,
            ),
        )
        report_summary = (
            f"[{result.risk_level.upper()}] {result.executive_summary} "
            f"Key findings: {'; '.join(result.key_findings[:3])}"
        )
    except Exception as e:
        logger.error("llm_report_generation_failed", error=str(e))

    elapsed = _elapsed_ms(state.started_at) if state.started_at else _elapsed_ms(start)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary="Synthesizing all findings into final validation report",
        output_summary=report_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm",
    )

    return {
        "report_summary": report_summary,
        "stage": ValidatorStage.REPORT,
        "duration_ms": elapsed,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


# --- Context formatting helpers ---


def _format_drift_context(
    state: ConfigValidatorState,
    drifts: list,
) -> str:
    """Format drift data for LLM analysis."""
    lines = [
        "## Validation Context",
        f"Tenant: {state.tenant_id}",
        f"Total configs: {state.total_configs}",
        f"Compliant: {state.compliant_count}",
        "",
        f"## Detected Drifts ({len(drifts)})",
    ]
    for d in drifts:
        lines.append(
            f"- [{d.severity}] {d.source}:{d.field_path} "
            f"expected='{d.expected_value}' actual='{d.actual_value}' "
            f"auto_fixable={d.auto_fixable}"
        )
    return "\n".join(lines)


def _format_impact_context(
    state: ConfigValidatorState,
    assessments: list,
) -> str:
    """Format impact assessment data for LLM analysis."""
    lines = [
        "## Drift Summary",
        f"Total drifts: {len(state.drifts)}",
        "",
        "## Impact Assessments",
    ]
    for a in assessments:
        lines.append(f"- Drift {a.drift_id}:")
        lines.append(f"  Affected services: {', '.join(a.affected_services)}")
        lines.append(f"  Security: {a.security_impact}")
        lines.append(f"  Availability: {a.availability_impact}")
        lines.append(f"  Compliance: {a.compliance_impact}")
    return "\n".join(lines)


def _format_report_context(state: ConfigValidatorState) -> str:
    """Format the full validation context for report generation."""
    lines = [
        "## Validation Summary",
        f"Tenant: {state.tenant_id}",
        f"Total configs checked: {state.total_configs}",
        f"Compliant: {state.compliant_count}",
        f"Drifts detected: {state.drift_count}",
        "",
        "## Drifts",
    ]
    for d in state.drifts:
        lines.append(
            f"- [{d.severity}] {d.source}:{d.field_path} "
            f"expected='{d.expected_value}' actual='{d.actual_value}'"
        )

    lines.append("")
    lines.append("## Impact Assessments")
    for a in state.impact_assessments:
        lines.append(
            f"- {a.drift_id}: security={a.security_impact}, "
            f"availability={a.availability_impact}, "
            f"compliance={a.compliance_impact}"
        )

    lines.append("")
    lines.append("## Remediations")
    for r in state.remediations:
        status = "success" if r.success else ("applied" if r.applied else "pending")
        lines.append(f"- {r.action} ({status}): {r.description}")

    lines.append("")
    lines.append("## Reasoning Chain")
    for step in state.reasoning_chain:
        lines.append(f"Step {step.step_number} ({step.action}): {step.output_summary}")

    return "\n".join(lines)
