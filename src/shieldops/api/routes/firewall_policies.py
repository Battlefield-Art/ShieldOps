"""Agent Firewall policy CRUD + evaluation API routes."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse
from shieldops.firewall.evaluator import PolicyEvaluator, get_default_policies
from shieldops.firewall.models import (
    PolicyAction,
    PolicyCondition,
    PolicyEvaluation,
    PolicyRule,
    ToolCallContext,
)
from shieldops.utils.persistence import write_audit_log

logger = structlog.get_logger()
router = APIRouter(prefix="/firewall/policies", tags=["Firewall Policies"])


def _org_id_from_user(user: UserResponse) -> str:
    """Extract org_id from the authenticated user (falls back to user.id)."""
    return getattr(user, "org_id", None) or user.id


# ---------------------------------------------------------------------------
# Singleton evaluator (injected at startup or lazily created)
# ---------------------------------------------------------------------------
_evaluator: PolicyEvaluator | None = None


def set_evaluator(ev: PolicyEvaluator) -> None:
    """Allow ``app.py`` lifespan to inject a shared evaluator."""
    global _evaluator
    _evaluator = ev


def _get_evaluator() -> PolicyEvaluator:
    global _evaluator
    if _evaluator is None:
        _evaluator = PolicyEvaluator()
    return _evaluator


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class CreatePolicyRequest(BaseModel):
    name: str
    description: str = ""
    condition: PolicyCondition = Field(default_factory=PolicyCondition)
    action: PolicyAction = PolicyAction.ALLOW
    priority: int = Field(default=100, ge=0)
    enabled: bool = True

    model_config = {"extra": "forbid"}


class UpdatePolicyRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    condition: PolicyCondition | None = None
    action: PolicyAction | None = None
    priority: int | None = Field(default=None, ge=0)
    enabled: bool | None = None

    model_config = {"extra": "forbid"}


class EvaluateRequest(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    caller_identity: str = ""

    model_config = {"extra": "forbid"}


class PolicyRuleResponse(BaseModel):
    id: str
    name: str
    description: str
    condition: PolicyCondition
    action: PolicyAction
    priority: int
    enabled: bool
    org_id: str
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=PolicyRuleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_policy(
    body: CreatePolicyRequest,
    user: UserResponse = Depends(get_current_user),
) -> PolicyRuleResponse:
    """Create a new firewall policy rule (scoped to the caller's org)."""
    evaluator = _get_evaluator()
    rule = PolicyRule(
        name=body.name,
        description=body.description,
        condition=body.condition,
        action=body.action,
        priority=body.priority,
        enabled=body.enabled,
        org_id=_org_id_from_user(user),
    )
    evaluator.add_rule(rule)
    org_id = _org_id_from_user(user)
    logger.info("firewall_policy_created", rule_id=rule.id, org_id=org_id, name=rule.name)
    return PolicyRuleResponse(**rule.model_dump())


@router.get("", response_model=list[PolicyRuleResponse])
async def list_policies(
    user: UserResponse = Depends(get_current_user),
) -> list[PolicyRuleResponse]:
    """List all firewall policy rules for the caller's org."""
    evaluator = _get_evaluator()
    rules = evaluator.list_rules(_org_id_from_user(user))
    return [PolicyRuleResponse(**r.model_dump()) for r in rules]


@router.get("/defaults", response_model=list[PolicyRuleResponse])
async def list_default_policies() -> list[PolicyRuleResponse]:
    """List the built-in default policies applied to all organisations."""
    return [PolicyRuleResponse(**r.model_dump()) for r in get_default_policies()]


@router.get("/{rule_id}", response_model=PolicyRuleResponse)
async def get_policy(
    rule_id: str,
    user: UserResponse = Depends(get_current_user),
) -> PolicyRuleResponse:
    """Get a single firewall policy rule by id."""
    evaluator = _get_evaluator()
    rule = evaluator.get_rule(rule_id, _org_id_from_user(user))
    if rule is None:
        raise HTTPException(status_code=404, detail="Policy rule not found.")
    return PolicyRuleResponse(**rule.model_dump())


@router.put("/{rule_id}", response_model=PolicyRuleResponse)
async def update_policy(
    rule_id: str,
    body: UpdatePolicyRequest,
    user: UserResponse = Depends(get_current_user),
) -> PolicyRuleResponse:
    """Update an existing firewall policy rule."""
    evaluator = _get_evaluator()
    updates = body.model_dump(exclude_none=True)
    if "condition" in updates:
        updates["condition"] = PolicyCondition(**updates["condition"])
    updates["updated_at"] = datetime.now(UTC)
    updated = evaluator.update_rule(rule_id, _org_id_from_user(user), updates)
    if updated is None:
        raise HTTPException(status_code=404, detail="Policy rule not found.")
    logger.info("firewall_policy_updated", rule_id=rule_id, org_id=_org_id_from_user(user))
    return PolicyRuleResponse(**updated.model_dump())


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_policy(
    rule_id: str,
    user: UserResponse = Depends(get_current_user),
) -> None:
    """Delete a firewall policy rule."""
    evaluator = _get_evaluator()
    removed = evaluator.remove_rule(rule_id, _org_id_from_user(user))
    if not removed:
        raise HTTPException(status_code=404, detail="Policy rule not found.")
    logger.info("firewall_policy_deleted", rule_id=rule_id, org_id=_org_id_from_user(user))


@router.post("/evaluate", response_model=PolicyEvaluation)
async def evaluate_tool_call(
    body: EvaluateRequest,
    user: UserResponse = Depends(get_current_user),
) -> PolicyEvaluation:
    """Evaluate a tool call against the policy engine (used by the SDK)."""
    evaluator = _get_evaluator()
    org_id = _org_id_from_user(user)
    ctx = ToolCallContext(
        tool_name=body.tool_name,
        arguments=body.arguments,
        caller_identity=body.caller_identity or user.email,
        org_id=org_id,
    )
    result = evaluator.evaluate(ctx)

    # Persist immutable audit log for every evaluation (allowed AND denied)
    await write_audit_log(
        action="firewall.evaluate",
        actor=body.caller_identity or user.email,
        target=body.tool_name,
        result=result.decision.value,
        org_id=org_id,
        metadata={
            "risk_score": result.risk_score,
            "tool_name": body.tool_name,
            "evaluation_ms": result.evaluation_ms,
            "matched_rule": (result.matching_rules[0].id if result.matching_rules else None),
        },
    )

    # Notify the in-memory dashboard tracker
    from shieldops.api.routes.firewall_dashboard import record_evaluation

    record_evaluation(
        org_id=org_id,
        tool_name=body.tool_name,
        decision=result.decision.value,
        risk_score=result.risk_score,
        caller=body.caller_identity or user.email,
    )

    return result
