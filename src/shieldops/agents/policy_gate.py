"""Shared OPA policy gate for agent actions."""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger()

# Actions that modify infrastructure — fail-closed on policy error
WRITE_ACTIONS = frozenset(
    {
        "contain",
        "remediate",
        "delete",
        "modify",
        "block",
        "isolate",
        "quarantine",
        "terminate",
        "restart",
        "scale",
        "deploy",
        "rollback",
        "rotate_credentials",
        "update_policy",
        "create_ticket",
    }
)


async def check_policy(
    policy_engine: Any,
    agent_type: str,
    action: str,
    target_resource: str = "",
    environment: str = "development",
    risk_score: float = 0.0,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate OPA policy for an agent action.

    Returns:
        {"allowed": bool, "reasons": list[str], "approval_required": bool}
    """
    if policy_engine is None:
        return {"allowed": True, "reasons": ["no_policy_engine"], "approval_required": False}

    try:
        input_data = {
            "agent_type": agent_type,
            "action": action,
            "target_resource": target_resource,
            "environment": environment,
            "risk_score": risk_score,
            **(metadata or {}),
        }
        result = await policy_engine.evaluate(input_data)

        if hasattr(result, "allowed"):
            allowed = result.allowed
            reasons = getattr(result, "reasons", [])
        elif isinstance(result, dict):
            allowed = result.get("allowed", True)
            reasons = result.get("reasons", [])
        else:
            allowed = True
            reasons = []

        approval_required = 0.5 <= risk_score <= 0.85

        logger.info(
            "policy_gate.evaluated",
            agent=agent_type,
            action=action,
            allowed=allowed,
            risk_score=risk_score,
            environment=environment,
            approval_required=approval_required,
        )

        return {
            "allowed": allowed,
            "reasons": list(reasons),
            "approval_required": approval_required,
        }
    except Exception as e:
        logger.warning("policy_gate.error", agent=agent_type, action=action, error=str(e))
        is_write = action in WRITE_ACTIONS
        return {
            "allowed": not is_write,
            "reasons": [f"policy_error: {e}"],
            "approval_required": is_write,
        }
