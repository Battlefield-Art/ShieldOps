"""Policy evaluation engine — three-tier decision logic for all agent actions.

Every agent action must pass through this engine before execution.
Decision tiers:
    - risk_score < 0.5  → APPROVED (auto-approve, log decision)
    - 0.5 <= risk_score <= 0.85 → REQUIRES_APPROVAL (create approval request)
    - risk_score > 0.85 → DENIED (hard deny, escalate to human)
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.policy.blast_radius import BlastRadiusResult, check_blast_radius
from shieldops.policy.opa_client import query_opa

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Threshold constants
# ---------------------------------------------------------------------------
RISK_THRESHOLD_AUTO_APPROVE = 0.5
RISK_THRESHOLD_DENY = 0.85


class Decision(StrEnum):
    """Three-tier decision outcome."""

    APPROVED = "approved"
    DENIED = "denied"
    REQUIRES_APPROVAL = "requires_approval"


class PolicyContext(BaseModel):
    """Context provided by an agent when requesting a policy evaluation."""

    agent_name: str
    action_type: str
    target_resources: list[str] = Field(default_factory=list)
    environment: str = "dev"  # dev | staging | prod
    risk_score: float = Field(ge=0.0, le=1.0, default=0.0)
    org_id: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


class PolicyDecision(BaseModel):
    """Result returned after evaluating a policy gate."""

    allowed: bool
    decision: Decision
    reason: str
    matched_policies: list[str] = Field(default_factory=list)
    blast_radius: int = 0
    approval_request_id: str | None = None

    model_config = {"extra": "forbid"}


async def evaluate(action: str, context: PolicyContext) -> PolicyDecision:
    """Evaluate an agent action against policy rules.

    Steps:
        1. Check blast-radius limits for the target environment.
        2. Query OPA for any policy matches (fail-closed on error).
        3. Apply three-tier risk thresholds.
        4. Log the decision to the audit trail.

    Args:
        action: Human-readable description of the action being taken.
        context: Rich context about the agent, environment, and targets.

    Returns:
        A ``PolicyDecision`` with the outcome.
    """
    # ---- 1. Blast-radius check ----
    br_result: BlastRadiusResult = check_blast_radius(
        environment=context.environment,
        target_resources=context.target_resources,
    )
    if not br_result.allowed:
        decision = PolicyDecision(
            allowed=False,
            decision=Decision.DENIED,
            reason=br_result.reason,
            blast_radius=br_result.resource_count,
        )
        _audit_log(action, context, decision)
        return decision

    # ---- 2. OPA evaluation (fail-closed) ----
    opa_matched: list[str] = []
    opa_denied = False
    opa_reason = ""
    try:
        opa_result = await query_opa(
            policy_path="shieldops/agent_action",
            input_data={
                "action": action,
                "agent_name": context.agent_name,
                "action_type": context.action_type,
                "target_resources": context.target_resources,
                "environment": context.environment,
                "risk_score": context.risk_score,
                "org_id": context.org_id,
                "metadata": context.metadata,
            },
        )
        opa_denied = opa_result.get("deny", False)
        opa_matched = opa_result.get("matched_policies", [])
        opa_reason = opa_result.get("reason", "")
    except Exception:
        # query_opa already logs and returns deny on failure — but guard here
        opa_denied = True
        opa_reason = "OPA unreachable — fail-closed deny."

    if opa_denied:
        decision = PolicyDecision(
            allowed=False,
            decision=Decision.DENIED,
            reason=opa_reason or "Denied by OPA policy.",
            matched_policies=opa_matched,
            blast_radius=br_result.resource_count,
        )
        _audit_log(action, context, decision)
        return decision

    # ---- 3. Three-tier risk threshold ----
    risk = context.risk_score

    if risk < RISK_THRESHOLD_AUTO_APPROVE:
        decision = PolicyDecision(
            allowed=True,
            decision=Decision.APPROVED,
            reason="Auto-approved: risk score below threshold.",
            matched_policies=opa_matched,
            blast_radius=br_result.resource_count,
        )
    elif risk <= RISK_THRESHOLD_DENY:
        decision = PolicyDecision(
            allowed=False,
            decision=Decision.REQUIRES_APPROVAL,
            reason=(
                f"Risk score {risk:.2f} requires human approval "
                f"(threshold {RISK_THRESHOLD_AUTO_APPROVE}–{RISK_THRESHOLD_DENY})."
            ),
            matched_policies=opa_matched,
            blast_radius=br_result.resource_count,
        )
    else:
        decision = PolicyDecision(
            allowed=False,
            decision=Decision.DENIED,
            reason=(
                f"Risk score {risk:.2f} exceeds maximum threshold "
                f"({RISK_THRESHOLD_DENY}). Escalated to human."
            ),
            matched_policies=opa_matched,
            blast_radius=br_result.resource_count,
        )

    _audit_log(action, context, decision)
    return decision


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------


def _audit_log(action: str, context: PolicyContext, decision: PolicyDecision) -> None:
    """Emit a structured audit log entry for every policy evaluation."""
    logger.info(
        "policy_evaluation",
        action=action,
        agent_name=context.agent_name,
        action_type=context.action_type,
        environment=context.environment,
        risk_score=context.risk_score,
        target_resources=context.target_resources,
        decision=decision.decision.value,
        allowed=decision.allowed,
        reason=decision.reason,
        matched_policies=decision.matched_policies,
        blast_radius=decision.blast_radius,
        org_id=context.org_id,
        timestamp=datetime.now(UTC).isoformat(),
    )
