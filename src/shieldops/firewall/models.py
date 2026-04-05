"""Pydantic models for the Agent Firewall policy engine."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PolicyAction(StrEnum):
    """Decision an evaluated rule can produce."""

    ALLOW = "allow"
    DENY = "deny"
    REVIEW = "review"


class PolicyCondition(BaseModel):
    """Matching criteria for a policy rule.

    All non-None fields must match for the rule to fire.
    ``tool_name_pattern`` supports Unix shell-style globs (``fnmatch``).
    """

    tool_name_pattern: str = "*"
    argument_patterns: dict[str, str] = Field(default_factory=dict)
    caller_identity: str | None = None
    min_risk_score: float | None = None
    max_risk_score: float | None = None

    model_config = {"extra": "forbid"}


class PolicyRule(BaseModel):
    """A single policy rule belonging to an organisation."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    condition: PolicyCondition = Field(default_factory=PolicyCondition)
    action: PolicyAction = PolicyAction.ALLOW
    priority: int = Field(default=100, ge=0, description="Lower number = higher priority")
    enabled: bool = True
    org_id: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    model_config = {"extra": "forbid"}


class ToolCallContext(BaseModel):
    """Context describing an intercepted tool call submitted for evaluation."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    caller_identity: str = ""
    org_id: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


class PolicyEvaluation(BaseModel):
    """Result returned after evaluating a tool call against the policy engine."""

    decision: PolicyAction
    risk_score: float = Field(ge=0.0, le=1.0)
    matching_rules: list[PolicyRule] = Field(default_factory=list)
    explanation: str = ""
    evaluation_ms: float = 0.0

    model_config = {"extra": "forbid"}
