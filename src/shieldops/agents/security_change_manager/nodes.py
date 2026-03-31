"""Security Change Manager Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    ChangeRequest,
    DependencyCheck,
    ReasoningStep,
    RiskAssessment,
    SCMStage,
)
from .tools import SecurityChangeManagerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Receive Change
# ------------------------------------------------------------------


async def receive_change(
    state: dict[str, Any],
    toolkit: SecurityChangeManagerToolkit,
) -> dict[str, Any]:
    """Receive and ingest change requests."""
    logger.info("scm.node.receive_change")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    changes = await toolkit.receive_change(tenant_id)
    data = [c.model_dump() for c in changes]

    note = f"Received {len(changes)} change requests"

    return {
        "stage": SCMStage.ASSESS_RISK.value,
        "changes": data,
        "total_changes_processed": len(changes),
        "current_step": "receive_change",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="receive_change",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Assess Risk
# ------------------------------------------------------------------


async def assess_risk(
    state: dict[str, Any],
    toolkit: SecurityChangeManagerToolkit,
) -> dict[str, Any]:
    """Assess security risk for each change."""
    logger.info("scm.node.assess_risk")
    state = _to_dict(state)

    changes = [ChangeRequest(**c) for c in state.get("changes", [])]
    assessments = await toolkit.assess_change_risk(changes)
    data = [a.model_dump() for a in assessments]

    high_risk = sum(1 for a in assessments if a.risk_score > 0.7)
    note = f"Assessed {len(assessments)} changes, {high_risk} high-risk"

    try:
        from .prompts import SYSTEM_RISK, RiskInsight

        ctx = json.dumps(
            {
                "assessments": [
                    {
                        "change_id": a.change_id,
                        "risk_level": a.risk_level.value,
                        "score": a.risk_score,
                        "blast_radius": a.blast_radius,
                    }
                    for a in assessments[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RiskInsight,
            await llm_structured(
                system_prompt=SYSTEM_RISK,
                user_prompt=f"Change risk assessments:\n{ctx}",
                schema=RiskInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="scm",
            node="assess_risk",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="scm",
            node="assess_risk",
        )

    return {
        "stage": SCMStage.CHECK_DEPENDENCIES.value,
        "risk_assessments": data,
        "current_step": "assess_risk",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="assess_risk",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Check Dependencies
# ------------------------------------------------------------------


async def check_dependencies(
    state: dict[str, Any],
    toolkit: SecurityChangeManagerToolkit,
) -> dict[str, Any]:
    """Analyze dependency impact of changes."""
    logger.info("scm.node.check_dependencies")
    state = _to_dict(state)

    changes = [ChangeRequest(**c) for c in state.get("changes", [])]
    dep_checks = await toolkit.check_dependencies(changes)
    data = [d.model_dump() for d in dep_checks]

    conflicts = sum(1 for d in dep_checks if d.conflicting_changes)
    note = f"Checked {len(dep_checks)} dependencies, {conflicts} conflicts"

    return {
        "stage": SCMStage.APPROVE_OR_REJECT.value,
        "dependency_checks": data,
        "current_step": "check_dependencies",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="check_dependencies",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Approve or Reject
# ------------------------------------------------------------------


async def approve_or_reject(
    state: dict[str, Any],
    toolkit: SecurityChangeManagerToolkit,
) -> dict[str, Any]:
    """Process approval decisions for changes."""
    logger.info("scm.node.approve_or_reject")
    state = _to_dict(state)

    assessments = [RiskAssessment(**a) for a in state.get("risk_assessments", [])]
    dep_checks = [DependencyCheck(**d) for d in state.get("dependency_checks", [])]
    decisions = await toolkit.process_approval(assessments, dep_checks)
    data = [d.model_dump() for d in decisions]

    approved = sum(1 for d in decisions if d.status.value in ("approved", "auto_approved"))
    note = f"Processed {len(decisions)} decisions, {approved} approved"

    return {
        "stage": SCMStage.MONITOR_ROLLOUT.value,
        "approval_decisions": data,
        "changes_approved": approved,
        "current_step": "approve_or_reject",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="approve_or_reject",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Monitor Rollout
# ------------------------------------------------------------------


async def monitor_rollout(
    state: dict[str, Any],
    toolkit: SecurityChangeManagerToolkit,
) -> dict[str, Any]:
    """Monitor post-change rollout health."""
    logger.info("scm.node.monitor_rollout")
    state = _to_dict(state)

    from .models import ApprovalDecision

    decisions = [ApprovalDecision(**d) for d in state.get("approval_decisions", [])]
    metrics = await toolkit.monitor_rollout(decisions)
    data = [m.model_dump() for m in metrics]

    breached = sum(1 for m in metrics if m.breached)
    note = f"Monitored {len(metrics)} metrics, {breached} breached"

    return {
        "stage": SCMStage.REPORT.value,
        "rollout_metrics": data,
        "current_step": "monitor_rollout",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="monitor_rollout",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: SecurityChangeManagerToolkit,
) -> dict[str, Any]:
    """Compile the final change management report."""
    logger.info("scm.node.report")
    state = _to_dict(state)

    total_changes = state.get("total_changes_processed", 0)
    approved_count = state.get("changes_approved", 0)
    metric_count = len(state.get("rollout_metrics", []))
    breached_count = sum(1 for m in state.get("rollout_metrics", []) if m.get("breached", False))

    lines = [
        "# Security Change Management Report",
        "",
        f"**Changes processed:** {total_changes}",
        f"**Changes approved:** {approved_count}",
        f"**Rollout metrics:** {metric_count}",
        f"**Thresholds breached:** {breached_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_changes": total_changes,
                "approved": approved_count,
                "metrics": metric_count,
                "breached": breached_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Change management report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="scm",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="scm",
            node="report",
        )

    return {
        "stage": SCMStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
