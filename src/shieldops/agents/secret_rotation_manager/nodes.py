"""Secret Rotation Manager Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    ReasoningStep,
    RotationAssessment,
    RotationExecution,
    RotationPlan,
    RotationStatus,
    SecretInventory,
    SRMStage,
)
from .tools import SecretRotationManagerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Inventory Secrets
# ------------------------------------------------------------------


async def inventory_secrets(
    state: dict[str, Any],
    toolkit: SecretRotationManagerToolkit,
) -> dict[str, Any]:
    """Discover secrets across vaults and providers."""
    logger.info("srm.node.inventory_secrets")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    secrets = await toolkit.inventory_secrets(tenant_id)
    data = [s.model_dump() for s in secrets]

    note = f"Discovered {len(secrets)} secrets across vaults"

    return {
        "stage": SRMStage.ASSESS_ROTATION.value,
        "inventory": data,
        "total_secrets": len(secrets),
        "current_step": "inventory_secrets",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="inventory_secrets",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Assess Rotation
# ------------------------------------------------------------------


async def assess_rotation(
    state: dict[str, Any],
    toolkit: SecretRotationManagerToolkit,
) -> dict[str, Any]:
    """Assess rotation risk and urgency for each secret."""
    logger.info("srm.node.assess_rotation")
    state = _to_dict(state)

    secrets = [SecretInventory(**s) for s in state.get("inventory", [])]
    assessments = await toolkit.assess_rotation(secrets)
    data = [a.model_dump() for a in assessments]

    critical = sum(1 for a in assessments if a.rotation_urgency in ("critical", "high"))
    note = f"Assessed {len(assessments)} secrets, {critical} need urgent rotation"

    try:
        from .prompts import SYSTEM_ASSESS, RotationRiskInsight

        ctx = json.dumps(
            {
                "assessments": [
                    {
                        "name": a.secret_name,
                        "type": a.secret_type.value,
                        "risk": a.risk_score,
                        "urgency": a.rotation_urgency,
                        "age_days": a.age_days,
                        "compliant": a.policy_compliant,
                    }
                    for a in assessments[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RotationRiskInsight,
            await llm_structured(
                system_prompt=SYSTEM_ASSESS,
                user_prompt=(f"Rotation risk assessment:\n{ctx}"),
                schema=RotationRiskInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="srm",
            node="assess_rotation",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="srm",
            node="assess_rotation",
        )

    return {
        "stage": SRMStage.PLAN_ROTATION.value,
        "assessments": data,
        "current_step": "assess_rotation",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="assess_rotation",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Plan Rotation
# ------------------------------------------------------------------


async def plan_rotation(
    state: dict[str, Any],
    toolkit: SecretRotationManagerToolkit,
) -> dict[str, Any]:
    """Generate zero-downtime rotation plans."""
    logger.info("srm.node.plan_rotation")
    state = _to_dict(state)

    assessments = [RotationAssessment(**a) for a in state.get("assessments", [])]
    plans = await toolkit.plan_rotation(assessments)
    data = [p.model_dump() for p in plans]

    approval_needed = sum(1 for p in plans if p.requires_approval)
    note = f"Created {len(plans)} rotation plans, {approval_needed} require approval"

    try:
        from .prompts import SYSTEM_PLAN, RotationPlanInsight

        ctx = json.dumps(
            {
                "plans": [
                    {
                        "name": p.secret_name,
                        "strategy": p.strategy,
                        "steps": len(p.steps),
                        "approval": p.requires_approval,
                        "downtime_s": (p.estimated_downtime_seconds),
                    }
                    for p in plans[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RotationPlanInsight,
            await llm_structured(
                system_prompt=SYSTEM_PLAN,
                user_prompt=(f"Rotation planning:\n{ctx}"),
                schema=RotationPlanInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="srm",
            node="plan_rotation",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="srm",
            node="plan_rotation",
        )

    return {
        "stage": SRMStage.EXECUTE_ROTATION.value,
        "rotation_plans": data,
        "current_step": "plan_rotation",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="plan_rotation",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Execute Rotation
# ------------------------------------------------------------------


async def execute_rotation(
    state: dict[str, Any],
    toolkit: SecretRotationManagerToolkit,
) -> dict[str, Any]:
    """Execute rotation plans with rollback support."""
    logger.info("srm.node.execute_rotation")
    state = _to_dict(state)

    plans = [RotationPlan(**p) for p in state.get("rotation_plans", [])]
    executions = await toolkit.execute_rotation(plans)
    data = [e.model_dump() for e in executions]

    completed = sum(1 for e in executions if e.status == RotationStatus.COMPLETED)
    failed = sum(1 for e in executions if e.status == RotationStatus.FAILED)
    note = f"Executed {len(executions)} rotations: {completed} completed, {failed} failed"

    return {
        "stage": SRMStage.VERIFY_HEALTH.value,
        "executions": data,
        "secrets_rotated": completed,
        "secrets_failed": failed,
        "current_step": "execute_rotation",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="execute_rotation",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Verify Health
# ------------------------------------------------------------------


async def verify_health(
    state: dict[str, Any],
    toolkit: SecretRotationManagerToolkit,
) -> dict[str, Any]:
    """Verify consumer health post-rotation."""
    logger.info("srm.node.verify_health")
    state = _to_dict(state)

    executions = [RotationExecution(**e) for e in state.get("executions", [])]
    secrets = [SecretInventory(**s) for s in state.get("inventory", [])]
    checks = await toolkit.verify_health(
        executions,
        secrets,
    )
    data = [c.model_dump() for c in checks]

    healthy = sum(1 for c in checks if c.healthy)
    unhealthy = len(checks) - healthy
    note = f"Verified {len(checks)} services: {healthy} healthy, {unhealthy} unhealthy"

    try:
        from .prompts import HealthInsight

        system = "You are a reliability engineer verifying service health after secret rotation."
        ctx = json.dumps(
            {
                "checks": [
                    {
                        "service": c.service_name,
                        "healthy": c.healthy,
                        "latency_ms": c.latency_ms,
                        "error_rate": c.error_rate_pct,
                    }
                    for c in checks[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            HealthInsight,
            await llm_structured(
                system_prompt=system,
                user_prompt=(f"Post-rotation health:\n{ctx}"),
                schema=HealthInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="srm",
            node="verify_health",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="srm",
            node="verify_health",
        )

    return {
        "stage": SRMStage.REPORT.value,
        "health_checks": data,
        "current_step": "verify_health",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="verify_health",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: SecretRotationManagerToolkit,
) -> dict[str, Any]:
    """Compile the final secret rotation report."""
    logger.info("srm.node.report")
    state = _to_dict(state)

    total = state.get("total_secrets", 0)
    rotated = state.get("secrets_rotated", 0)
    failed = state.get("secrets_failed", 0)
    plans = len(state.get("rotation_plans", []))
    checks = state.get("health_checks", [])
    healthy = sum(1 for c in checks if c.get("healthy"))
    unhealthy = len(checks) - healthy

    lines = [
        "# Secret Rotation Manager Report",
        "",
        f"**Total secrets inventoried:** {total}",
        f"**Rotation plans created:** {plans}",
        f"**Rotations completed:** {rotated}",
        f"**Rotations failed:** {failed}",
        f"**Health checks passed:** {healthy}",
        f"**Health checks failed:** {unhealthy}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_secrets": total,
                "rotated": rotated,
                "failed": failed,
                "healthy_services": healthy,
                "unhealthy_services": unhealthy,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Rotation cycle report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="srm",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="srm",
            node="report",
        )

    return {
        "stage": SRMStage.REPORT.value,
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
