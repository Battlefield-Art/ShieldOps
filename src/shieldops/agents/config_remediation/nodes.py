"""Node implementations for the Config Remediation Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.config_remediation.models import (
    ConfigRemediationState,
    FixStatus,
    ReasoningStep,
    RemediationStage,
)
from shieldops.agents.config_remediation.prompts import (
    SYSTEM_GENERATE_FIX,
    SYSTEM_REPORT,
    FixGenerationResult,
    RemediationReportResult,
)
from shieldops.agents.config_remediation.tools import (
    ConfigRemediationToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ConfigRemediationToolkit | None = None


def _get_toolkit() -> ConfigRemediationToolkit:
    if _toolkit is None:
        return ConfigRemediationToolkit()
    return _toolkit


async def scan_configurations(
    state: ConfigRemediationState,
) -> dict[str, Any]:
    """Scan cloud configurations."""
    start = datetime.now(UTC)
    tk = _get_toolkit()

    scans = await tk.scan_configurations(state.target_cloud)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="scan_configurations",
        input_summary=f"cloud={state.target_cloud}",
        output_summary=f"Scanned {len(scans)} resources",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="cloud_api",
    )
    return {
        "configs_scanned": scans,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": (RemediationStage.SCAN_CONFIGURATIONS),
    }


async def identify_misconfigs(
    state: ConfigRemediationState,
) -> dict[str, Any]:
    """Identify misconfigurations from scans."""
    start = datetime.now(UTC)
    tk = _get_toolkit()

    misconfigs = await tk.identify_misconfigs(state.configs_scanned)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="identify_misconfigs",
        input_summary=(f"{len(state.configs_scanned)} scans"),
        output_summary=(f"Found {len(misconfigs)} misconfigs"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="policy_engine",
    )
    return {
        "misconfigs_found": misconfigs,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": (RemediationStage.IDENTIFY_MISCONFIGS),
    }


async def generate_fixes(
    state: ConfigRemediationState,
) -> dict[str, Any]:
    """Generate fix plans for each misconfiguration."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    fixes = []

    for mc in state.misconfigs_found:
        fix = await tk.generate_fix(mc)

        # LLM-enhanced fix generation
        ctx = (
            f"Type: {mc.misconfig_type}\n"
            f"Resource: {mc.resource_id}\n"
            f"Current: {mc.current_value}\n"
            f"Expected: {mc.expected_value}"
        )
        try:
            result = cast(
                FixGenerationResult,
                await llm_structured(
                    system_prompt=SYSTEM_GENERATE_FIX,
                    user_prompt=ctx,
                    schema=FixGenerationResult,
                ),
            )
            fix.fix_description = result.fix_description
            fix.api_call = result.api_call
            fix.rollback_command = result.rollback_command
        except Exception as e:
            logger.error("llm_fix_gen_failed", error=str(e))

        # OPA approval check
        approved = await tk.check_opa_approval(fix)
        if approved:
            fix.status = FixStatus.APPROVED
        fixes.append(fix)

    manual = sum(1 for f in fixes if f.status != FixStatus.APPROVED)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_fixes",
        input_summary=(f"{len(state.misconfigs_found)} misconfigs"),
        output_summary=(f"Generated {len(fixes)} fixes, {manual} need manual approval"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )
    return {
        "fixes_planned": fixes,
        "manual_required": manual,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": RemediationStage.GENERATE_FIXES,
    }


async def apply_fixes(
    state: ConfigRemediationState,
) -> dict[str, Any]:
    """Apply approved fixes."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    applications = []

    for fix in state.fixes_planned:
        if fix.status != FixStatus.APPROVED:
            continue
        if state.dry_run:
            logger.info("dry_run_skip", fix_id=fix.id)
            continue
        app = await tk.apply_fix(fix)
        applications.append(app)

    auto_fixed = sum(1 for a in applications if a.success)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="apply_fixes",
        input_summary=(f"{len(state.fixes_planned)} planned, dry_run={state.dry_run}"),
        output_summary=(f"Applied {len(applications)} fixes, {auto_fixed} succeeded"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="cloud_api",
    )
    return {
        "fixes_applied": applications,
        "auto_fixed_count": auto_fixed,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": RemediationStage.APPLY_FIXES,
    }


async def verify_fixes(
    state: ConfigRemediationState,
) -> dict[str, Any]:
    """Verify applied fixes by re-scanning."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    verifications = []

    for fix in state.fixes_planned:
        if fix.status == FixStatus.APPROVED:
            ver = await tk.verify_fix(fix)
            verifications.append(ver)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="verify_fixes",
        input_summary=(f"{len(state.fixes_applied)} applied"),
        output_summary=(f"Verified {len(verifications)} fixes"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="cloud_api",
    )
    return {
        "fixes_verified": verifications,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": RemediationStage.VERIFY_FIXES,
    }


async def generate_report(
    state: ConfigRemediationState,
) -> dict[str, Any]:
    """Generate remediation report."""
    start = datetime.now(UTC)

    ctx = (
        f"Scanned: {len(state.configs_scanned)}\n"
        f"Misconfigs: {len(state.misconfigs_found)}\n"
        f"Auto-fixed: {state.auto_fixed_count}\n"
        f"Manual required: {state.manual_required}\n"
        f"Dry run: {state.dry_run}"
    )

    report = (
        f"Config remediation: "
        f"{state.auto_fixed_count} auto-fixed, "
        f"{state.manual_required} manual required."
    )

    try:
        result = cast(
            RemediationReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=ctx,
                schema=RemediationReportResult,
            ),
        )
        report = f"{result.title}\n\n{result.executive_summary}\nRisk: {result.risk_assessment}"
    except Exception as e:
        logger.error("llm_report_failed", error=str(e))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=ctx[:100],
        output_summary=report[:200],
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    total = sum(s.duration_ms for s in [*state.reasoning_chain, step])
    return {
        "report_summary": report,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": RemediationStage.REPORT,
        "duration_ms": total,
    }
