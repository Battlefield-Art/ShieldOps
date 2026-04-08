"""Node implementations for the File Integrity Monitor Agent.

Each node is an async function that:
1. Calls tools to scan or compare file integrity data
2. Uses the LLM to classify and reason about changes
3. Updates the FIM state
4. Records its reasoning step in the audit trail
"""

import time
from typing import Any, cast

import structlog

from shieldops.agents.file_integrity_monitor.models import (
    ChangeClassification,
    FileIntegrityMonitorState,
    FIMStage,
    ImpactLevel,
    ReasoningStep,
)
from shieldops.agents.file_integrity_monitor.prompts import (
    SYSTEM_CHANGE_CLASSIFICATION,
    SYSTEM_FIM_REPORT,
    SYSTEM_IMPACT_ANALYSIS,
    ChangeClassificationResult,
    FIMReportResult,
    ImpactAnalysisResult,
)
from shieldops.agents.file_integrity_monitor.tools import (
    FileIntegrityMonitorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by runner at startup.
_toolkit: FileIntegrityMonitorToolkit | None = None


def _get_toolkit() -> FileIntegrityMonitorToolkit:
    if _toolkit is None:
        return FileIntegrityMonitorToolkit()
    return _toolkit


def _elapsed_ms(start: float) -> int:
    return int((time.time() - start) * 1000)


async def scan_baseline(
    state: FileIntegrityMonitorState,
) -> dict[str, Any]:
    """Scan monitored paths and build file baselines."""
    start = time.time()
    toolkit = _get_toolkit()

    logger.info(
        "fim_scanning_baseline",
        tenant_id=state.tenant_id,
    )

    paths = state.monitored_paths or None
    baselines = await toolkit.scan_baselines(state.tenant_id, paths)

    step = ReasoningStep(
        step_number=1,
        action="scan_baseline",
        input_summary=(f"Scanning baselines for tenant {state.tenant_id}"),
        output_summary=(f"Scanned {len(baselines)} file baselines across monitored paths"),
        duration_ms=_elapsed_ms(start),
        tool_used="baseline_scanner",
    )

    return {
        "baselines": baselines,
        "baselines_scanned": len(baselines),
        "stage": FIMStage.DETECT_CHANGES,
        "reasoning_chain": [step],
        "started_at": start,
    }


async def detect_changes(
    state: FileIntegrityMonitorState,
) -> dict[str, Any]:
    """Detect file changes by comparing against baselines."""
    start = time.time()
    toolkit = _get_toolkit()

    logger.info(
        "fim_detecting_changes",
        baseline_count=len(state.baselines),
    )

    changes = await toolkit.detect_changes(state.baselines)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_changes",
        input_summary=(f"Comparing {len(state.baselines)} baselines against current file state"),
        output_summary=(f"Detected {len(changes)} file changes via hash comparison"),
        duration_ms=_elapsed_ms(start),
        tool_used="change_detector",
    )

    return {
        "changes": changes,
        "changes_detected": len(changes),
        "stage": FIMStage.CLASSIFY_CHANGES,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def classify_changes(
    state: FileIntegrityMonitorState,
) -> dict[str, Any]:
    """Classify detected changes using LLM reasoning."""
    start = time.time()

    logger.info(
        "fim_classifying_changes",
        change_count=len(state.changes),
    )

    output_summary = f"Classified {len(state.changes)} changes"

    # Build classifications from tool data + LLM
    toolkit = _get_toolkit()
    classifications = []
    critical_count = 0

    for change in state.changes:
        impact = toolkit._classify_path(change.path)
        is_critical = impact in (
            ImpactLevel.CRITICAL_SYSTEM,
            ImpactLevel.SECURITY_CONFIG,
        )
        if is_critical:
            critical_count += 1

        from uuid import uuid4

        classifications.append(
            ChangeClassification(
                id=f"cls-{uuid4().hex[:12]}",
                change_id=change.id,
                impact_level=impact,
                category=toolkit._category_for_path(change.path),
                explanation=change.diff_summary,
                is_authorized=False,
                confidence=0.85,
            )
        )

    # Enrich with LLM analysis
    if state.changes:
        context = _format_classification_context(state)
        try:
            analysis = cast(
                ChangeClassificationResult,
                await llm_structured(
                    system_prompt=SYSTEM_CHANGE_CLASSIFICATION,
                    user_prompt=context,
                    schema=ChangeClassificationResult,
                ),
            )
            output_summary = analysis.summary
        except Exception as e:
            logger.error(
                "llm_classification_failed",
                error=str(e),
            )
            output_summary = (
                f"Classified {len(state.changes)} changes "
                f"({critical_count} critical) "
                f"(LLM failed: {e})"
            )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="classify_changes",
        input_summary=(f"Classifying {len(state.changes)} detected file changes via LLM"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="change_classifier + llm",
    )

    return {
        "classifications": classifications,
        "critical_changes": critical_count,
        "stage": FIMStage.ASSESS_IMPACT,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def assess_impact(
    state: FileIntegrityMonitorState,
) -> dict[str, Any]:
    """Assess impact of classified changes using LLM."""
    start = time.time()
    toolkit = _get_toolkit()

    logger.info(
        "fim_assessing_impact",
        change_count=len(state.changes),
    )

    assessments = await toolkit.assess_impact(state.changes, state.baselines)

    output_summary = f"Assessed impact for {len(assessments)} changes"
    compliance_count = sum(1 for a in assessments if a.compliance_impact != "none")

    if assessments:
        context = _format_impact_context(state, assessments)
        try:
            analysis = cast(
                ImpactAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_IMPACT_ANALYSIS,
                    user_prompt=context,
                    schema=ImpactAnalysisResult,
                ),
            )
            output_summary = (
                f"{analysis.summary}. "
                f"Blast radius: {analysis.blast_radius}. "
                f"Security concerns: "
                f"{len(analysis.security_concerns)}"
            )
            compliance_count = len(analysis.compliance_violations)
        except Exception as e:
            logger.error(
                "llm_impact_analysis_failed",
                error=str(e),
            )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_impact",
        input_summary=(f"Assessing impact for {len(state.changes)} changes"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="impact_assessor + llm",
    )

    return {
        "impact_assessments": assessments,
        "compliance_violations": compliance_count,
        "stage": FIMStage.RESPOND,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def respond(
    state: FileIntegrityMonitorState,
) -> dict[str, Any]:
    """Execute automated responses for critical changes."""
    start = time.time()
    toolkit = _get_toolkit()

    logger.info(
        "fim_responding",
        change_count=len(state.changes),
    )

    responses = await toolkit.execute_responses(state.changes, state.impact_assessments)
    executed = sum(1 for r in responses if r.executed)
    succeeded = sum(1 for r in responses if r.success)
    rollbacks = sum(1 for r in responses if r.action == "rollback")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="respond",
        input_summary=(f"Executing responses for {len(state.changes)} changes"),
        output_summary=(
            f"Executed {executed}/{len(responses)} "
            f"responses, {succeeded} succeeded, "
            f"{rollbacks} rollbacks"
        ),
        duration_ms=_elapsed_ms(start),
        tool_used="response_executor",
    )

    return {
        "responses": responses,
        "stage": FIMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


async def generate_report(
    state: FileIntegrityMonitorState,
) -> dict[str, Any]:
    """Generate the final FIM report using LLM synthesis."""
    start = time.time()

    logger.info(
        "fim_reporting",
        baselines=state.baselines_scanned,
        changes=state.changes_detected,
    )

    report_context = _format_report_context(state)
    rollback_count = sum(1 for r in state.responses if r.action == "rollback")
    report_summary = (
        f"Scanned {state.baselines_scanned} files: "
        f"{state.changes_detected} changes detected, "
        f"{state.critical_changes} critical, "
        f"{rollback_count} rolled back"
    )

    try:
        result = cast(
            FIMReportResult,
            await llm_structured(
                system_prompt=SYSTEM_FIM_REPORT,
                user_prompt=report_context,
                schema=FIMReportResult,
            ),
        )
        findings = "; ".join(result.key_findings[:3])
        report_summary = (
            f"[{result.risk_level.upper()}] {result.executive_summary} Key findings: {findings}"
        )
    except Exception as e:
        logger.error(
            "llm_report_generation_failed",
            error=str(e),
        )

    elapsed = _elapsed_ms(state.started_at) if state.started_at else _elapsed_ms(start)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=("Synthesizing all findings into final FIM report"),
        output_summary=report_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm",
    )

    return {
        "report_summary": report_summary,
        "stage": FIMStage.REPORT,
        "duration_ms": elapsed,
        "reasoning_chain": [*state.reasoning_chain, step],
    }


# --- Context formatting helpers ---


def _format_classification_context(
    state: FileIntegrityMonitorState,
) -> str:
    """Format change data for LLM classification."""
    lines = [
        "## FIM Context",
        f"Tenant: {state.tenant_id}",
        f"Baselines scanned: {state.baselines_scanned}",
        "",
        f"## Detected Changes ({len(state.changes)})",
    ]
    for c in state.changes:
        lines.append(f"- [{c.change_type}] {c.path} diff='{c.diff_summary}'")
    return "\n".join(lines)


def _format_impact_context(
    state: FileIntegrityMonitorState,
    assessments: list,
) -> str:
    """Format impact data for LLM analysis."""
    lines = [
        "## Change Summary",
        f"Total changes: {len(state.changes)}",
        f"Critical: {state.critical_changes}",
        "",
        "## Impact Assessments",
    ]
    for a in assessments:
        lines.append(f"- Change {a.change_id}:")
        lines.append(f"  Affected: {', '.join(a.affected_services)}")
        lines.append(f"  Security: {a.security_impact}")
        lines.append(f"  Compliance: {a.compliance_impact}")
        lines.append(f"  Blast radius: {a.blast_radius}")
    return "\n".join(lines)


def _format_report_context(
    state: FileIntegrityMonitorState,
) -> str:
    """Format full FIM context for report generation."""
    lines = [
        "## FIM Summary",
        f"Tenant: {state.tenant_id}",
        f"Files scanned: {state.baselines_scanned}",
        f"Changes detected: {state.changes_detected}",
        f"Critical changes: {state.critical_changes}",
        f"Compliance violations: {state.compliance_violations}",
        "",
        "## Changes",
    ]
    for c in state.changes:
        lines.append(f"- [{c.change_type}] {c.path}: {c.diff_summary}")

    lines.append("")
    lines.append("## Classifications")
    for cl in state.classifications:
        lines.append(
            f"- {cl.change_id}: "
            f"impact={cl.impact_level} "
            f"authorized={cl.is_authorized} "
            f"confidence={cl.confidence}"
        )

    lines.append("")
    lines.append("## Impact Assessments")
    for a in state.impact_assessments:
        lines.append(
            f"- {a.change_id}: "
            f"security={a.security_impact}, "
            f"compliance={a.compliance_impact}, "
            f"blast_radius={a.blast_radius}"
        )

    lines.append("")
    lines.append("## Responses")
    for r in state.responses:
        status = "success" if r.success else ("executed" if r.executed else "pending")
        lines.append(f"- {r.action} ({status}): {r.description}")

    lines.append("")
    lines.append("## Reasoning Chain")
    for step in state.reasoning_chain:
        lines.append(f"Step {step.step_number} ({step.action}): {step.output_summary}")

    return "\n".join(lines)
