"""Node implementations for the Service Account Guardian
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.service_account_guardian.models import (
    ReasoningStep,
    SAGStage,
    ServiceAccountGuardianState,
)
from shieldops.agents.service_account_guardian.prompts import (
    SYSTEM_AUDIT,
    SYSTEM_ORPHAN,
    SYSTEM_REPORT,
    SYSTEM_RISK,
    GuardianReportOutput,
    OrphanDetectionOutput,
    PermissionAuditOutput,
    RiskAssessmentOutput,
)
from shieldops.agents.service_account_guardian.tools import (
    ServiceAccountGuardianToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ServiceAccountGuardianToolkit | None = None


def set_toolkit(
    toolkit: ServiceAccountGuardianToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ServiceAccountGuardianToolkit:
    if _toolkit is None:
        return ServiceAccountGuardianToolkit()
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
    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: discover_accounts
# ------------------------------------------------------------------


async def discover_accounts(
    state: ServiceAccountGuardianState,
) -> dict[str, Any]:
    """Discover service accounts across cloud providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    accounts = await toolkit.discover_accounts(
        target_providers=state.target_providers,
        scope=state.scope,
    )

    step = _step(
        state.reasoning_chain,
        "discover_accounts",
        (f"Providers: {len(state.target_providers)}"),
        f"Discovered {len(accounts)} accounts",
        start,
        "identity_provider",
    )

    return {
        "discovered_accounts": accounts,
        "total_accounts": len(accounts),
        "stage": SAGStage.DISCOVER_ACCOUNTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_accounts",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: audit_permissions
# ------------------------------------------------------------------


async def audit_permissions(
    state: ServiceAccountGuardianState,
) -> dict[str, Any]:
    """Audit permissions for discovered service accounts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    audits = await toolkit.audit_permissions(
        discovered_accounts=state.discovered_accounts,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "account_count": state.total_accounts,
                "accounts_sample": state.discovered_accounts[:5],
                "providers": state.target_providers,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_AUDIT,
            user_prompt=f"Audit permissions for:\n{ctx}",
            schema=PermissionAuditOutput,
        )
        if llm_out.excessive_permissions:  # type: ignore[union-attr]
            rid = random.randint(1000, 9999)  # noqa: S311
            audits.append(
                {
                    "audit_id": f"llm-{rid}",
                    "excessive": llm_out.excessive_permissions,  # type: ignore[union-attr]
                    "escalation_paths": llm_out.escalation_paths,  # type: ignore[union-attr]
                    "compliance_issues": llm_out.compliance_issues,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="audit_permissions",
            issues=len(llm_out.excessive_permissions),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="audit_permissions",
        )

    step = _step(
        state.reasoning_chain,
        "audit_permissions",
        f"Auditing {state.total_accounts} accounts",
        f"Produced {len(audits)} audit results",
        start,
        "permission_analyzer",
    )

    return {
        "permission_audits": audits,
        "stage": SAGStage.AUDIT_PERMISSIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "audit_permissions",
    }


# ------------------------------------------------------------------
# Node: detect_orphans
# ------------------------------------------------------------------


async def detect_orphans(
    state: ServiceAccountGuardianState,
) -> dict[str, Any]:
    """Detect orphaned service accounts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    orphans = await toolkit.detect_orphans(
        discovered_accounts=state.discovered_accounts,
        permission_audits=state.permission_audits,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "total_accounts": state.total_accounts,
                "accounts_sample": state.discovered_accounts[:5],
                "audit_sample": state.permission_audits[:3],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ORPHAN,
            user_prompt=f"Detect orphans:\n{ctx}",
            schema=OrphanDetectionOutput,
        )
        if llm_out.orphans:  # type: ignore[union-attr]
            orphans = [
                *orphans,
                *llm_out.orphans,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="detect_orphans",
            count=len(llm_out.orphans),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_orphans",
        )

    step = _step(
        state.reasoning_chain,
        "detect_orphans",
        f"Scanning {state.total_accounts} accounts",
        f"Found {len(orphans)} orphans",
        start,
        "orphan_detector",
    )

    return {
        "orphan_detections": orphans,
        "orphan_count": len(orphans),
        "stage": SAGStage.DETECT_ORPHANS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_orphans",
    }


# ------------------------------------------------------------------
# Node: assess_risk
# ------------------------------------------------------------------


async def assess_risk(
    state: ServiceAccountGuardianState,
) -> dict[str, Any]:
    """Assess risk for each service account."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_risk(
        permission_audits=state.permission_audits,
        orphan_detections=state.orphan_detections,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "audit_count": len(state.permission_audits),
                "orphan_count": state.orphan_count,
                "audits_sample": state.permission_audits[:5],
                "orphans_sample": state.orphan_detections[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=f"Assess risk:\n{ctx}",
            schema=RiskAssessmentOutput,
        )
        if llm_out.high_risk_accounts:  # type: ignore[union-attr]
            rid = random.randint(1000, 9999)  # noqa: S311
            assessments.append(
                {
                    "assessment_id": f"llm-{rid}",
                    "risk_factors": llm_out.risk_factors,  # type: ignore[union-attr]
                    "high_risk": llm_out.high_risk_accounts,  # type: ignore[union-attr]
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "recommendations": llm_out.recommendations,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="assess_risk",
            high_risk=len(llm_out.high_risk_accounts),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk",
        )

    high_risk = sum(1 for a in assessments if a.get("risk_level") in ("critical", "high"))

    step = _step(
        state.reasoning_chain,
        "assess_risk",
        (f"Assessing {len(state.permission_audits)} audits"),
        f"{high_risk} high-risk accounts found",
        start,
        "risk_engine",
    )

    return {
        "risk_assessments": assessments,
        "high_risk_count": high_risk,
        "stage": SAGStage.ASSESS_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_risk",
    }


# ------------------------------------------------------------------
# Node: remediate
# ------------------------------------------------------------------


async def remediate(
    state: ServiceAccountGuardianState,
) -> dict[str, Any]:
    """Apply remediation actions to high-risk accounts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.remediate_accounts(
        risk_assessments=state.risk_assessments,
        auto_remediate=state.auto_remediate,
    )

    remediated = sum(1 for a in actions if a.get("status") == "applied")

    step = _step(
        state.reasoning_chain,
        "remediate",
        (f"Remediating {state.high_risk_count} high-risk accounts"),
        f"{remediated} actions applied",
        start,
        "remediation_engine",
    )

    return {
        "remediation_actions": actions,
        "remediated_count": remediated,
        "stage": SAGStage.REMEDIATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "remediate",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: ServiceAccountGuardianState,
) -> dict[str, Any]:
    """Generate the final service account guardian report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    await toolkit.record_metric(
        metric_name="orphan_rate",
        value=(state.orphan_count / state.total_accounts if state.total_accounts > 0 else 0.0),
        metadata={
            "total_accounts": state.total_accounts,
            "providers": state.target_providers,
        },
    )

    report: dict[str, Any] = {
        "scan_name": state.scan_name,
        "total_accounts": state.total_accounts,
        "orphan_count": state.orphan_count,
        "high_risk_count": state.high_risk_count,
        "remediated_count": state.remediated_count,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scan_name": state.scan_name,
                "total_accounts": state.total_accounts,
                "orphan_count": state.orphan_count,
                "high_risk_count": state.high_risk_count,
                "remediated_count": state.remediated_count,
                "risk_sample": state.risk_assessments[:5],
                "orphans_sample": state.orphan_detections[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate guardian report:\n{ctx}"),
            schema=GuardianReportOutput,
        )
        if isinstance(llm_out, GuardianReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "compliance_status": llm_out.compliance_status,
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

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_accounts} accounts"),
        (f"Report generated, {state.high_risk_count} high-risk"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": SAGStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
