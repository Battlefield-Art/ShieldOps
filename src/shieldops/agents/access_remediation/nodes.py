"""Node implementations for the Access Remediation Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.access_remediation.models import (
    AccessRemediationState,
    AccessStage,
    ReasoningStep,
)
from shieldops.agents.access_remediation.prompts import (
    SYSTEM_ANALYZE_ACCESS,
    SYSTEM_REPORT,
    AccessAnalysisResult,
    AccessReportResult,
)
from shieldops.agents.access_remediation.tools import (
    AccessRemediationToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AccessRemediationToolkit | None = None


def _get_toolkit() -> AccessRemediationToolkit:
    if _toolkit is None:
        return AccessRemediationToolkit()
    return _toolkit


async def audit_access(
    state: AccessRemediationState,
) -> dict[str, Any]:
    """Audit all accounts in the target provider."""
    start = datetime.now(UTC)
    tk = _get_toolkit()

    audits = await tk.audit_access(state.target_provider)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="audit_access",
        input_summary=(f"provider={state.target_provider}"),
        output_summary=(f"Audited {len(audits)} accounts"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="idp_api",
    )
    return {
        "accounts_audited": audits,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": AccessStage.AUDIT_ACCESS,
    }


async def identify_excess(
    state: AccessRemediationState,
) -> dict[str, Any]:
    """Identify excess access from audits."""
    start = datetime.now(UTC)
    tk = _get_toolkit()

    excess = await tk.identify_excess(state.accounts_audited)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="identify_excess",
        input_summary=(f"{len(state.accounts_audited)} accounts"),
        output_summary=(f"Found {len(excess)} excess access issues"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="policy_engine",
    )
    return {
        "excess_found": excess,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": AccessStage.IDENTIFY_EXCESS,
    }


async def plan_remediation(
    state: AccessRemediationState,
) -> dict[str, Any]:
    """Plan remediation for each excess access issue."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    plans = []

    for exc in state.excess_found:
        plan = await tk.plan_change(exc)

        # LLM-enhanced analysis
        ctx = (
            f"Account: {exc.account_id}\n"
            f"Issue: {exc.issue_type}\n"
            f"Severity: {exc.severity}\n"
            f"Description: {exc.description}"
        )
        try:
            result = cast(
                AccessAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_ANALYZE_ACCESS,
                    user_prompt=ctx,
                    schema=AccessAnalysisResult,
                ),
            )
            plan.description = result.justification
        except Exception as e:
            logger.error(
                "llm_access_analysis_failed",
                error=str(e),
            )

        # Notify owner before changes
        await tk.notify_owner(plan)
        plan.owner_notified = True
        plans.append(plan)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="plan_remediation",
        input_summary=(f"{len(state.excess_found)} excess issues"),
        output_summary=(f"Planned {len(plans)} remediations"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )
    return {
        "changes_planned": plans,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": AccessStage.PLAN_REMEDIATION,
    }


async def execute_changes(
    state: AccessRemediationState,
) -> dict[str, Any]:
    """Execute planned access changes."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    changes = []

    for plan in state.changes_planned:
        if plan.approval_required:
            logger.info(
                "access_change_pending_approval",
                account=plan.account_id,
            )
            continue
        change = await tk.execute_change(plan)
        changes.append(change)

    remediated = sum(1 for c in changes if c.success)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_changes",
        input_summary=(f"{len(state.changes_planned)} planned"),
        output_summary=(f"Executed {len(changes)}, {remediated} succeeded"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="idp_api",
    )
    return {
        "changes_executed": changes,
        "accounts_remediated": remediated,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": AccessStage.EXECUTE_CHANGES,
    }


async def verify_access(
    state: AccessRemediationState,
) -> dict[str, Any]:
    """Verify access changes were applied."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    verifications = []

    for change in state.changes_executed:
        ver = await tk.verify_change(change)
        verifications.append(ver)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="verify_access",
        input_summary=(f"{len(state.changes_executed)} changes"),
        output_summary=(f"Verified {len(verifications)} changes"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="idp_api",
    )
    return {
        "changes_verified": verifications,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": AccessStage.VERIFY_ACCESS,
    }


async def generate_report(
    state: AccessRemediationState,
) -> dict[str, Any]:
    """Generate access remediation report."""
    start = datetime.now(UTC)

    ctx = (
        f"Audited: {len(state.accounts_audited)}\n"
        f"Excess found: {len(state.excess_found)}\n"
        f"Remediated: {state.accounts_remediated}\n"
        f"Verified: {len(state.changes_verified)}"
    )

    report = (
        f"Access remediation: "
        f"{state.accounts_remediated} remediated "
        f"of {len(state.excess_found)} issues."
    )

    try:
        result = cast(
            AccessReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=ctx,
                schema=AccessReportResult,
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
        "current_stage": AccessStage.REPORT,
        "duration_ms": total,
    }
