"""State models for the Security Copilot Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SCAStage(StrEnum):
    """Stages in the security copilot lifecycle."""

    RECEIVE_QUERY = "receive_query"
    GATHER_CONTEXT = "gather_context"
    ANALYZE = "analyze"
    RECOMMEND = "recommend"
    EXECUTE_ACTION = "execute_action"
    REPORT = "report"


class QueryCategory(StrEnum):
    """Category of the analyst's security query."""

    THREAT_INVESTIGATION = "threat_investigation"
    VULNERABILITY_TRIAGE = "vulnerability_triage"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE_CHECK = "compliance_check"
    CONFIGURATION_REVIEW = "configuration_review"
    GENERAL = "general"


class ActionType(StrEnum):
    """Types of actions the copilot can execute."""

    INVESTIGATE = "investigate"
    REMEDIATE = "remediate"
    ESCALATE = "escalate"
    BLOCK = "block"
    ISOLATE = "isolate"
    REPORT = "report"


# --- Domain models ---


class AnalystQuery(BaseModel):
    """A natural language security query from an analyst."""

    query_id: str = ""
    raw_query: str = ""
    category: QueryCategory = QueryCategory.GENERAL
    intent: str = ""
    entities: list[str] = Field(default_factory=list)
    urgency: str = "medium"


class SecurityContext(BaseModel):
    """Context gathered from security data sources."""

    context_id: str = ""
    sources_queried: list[str] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    related_incidents: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    asset_info: dict[str, Any] = Field(default_factory=dict)
    threat_intel: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    relevance_score: float = 0.0


class Recommendation(BaseModel):
    """A recommended action for the analyst."""

    recommendation_id: str = ""
    action_type: ActionType = ActionType.INVESTIGATE
    title: str = ""
    description: str = ""
    confidence: float = 0.0
    risk_level: str = "medium"
    automated: bool = False
    steps: list[str] = Field(default_factory=list)


class ActionResult(BaseModel):
    """Result of executing a recommended action."""

    action_id: str = ""
    action_type: ActionType = ActionType.INVESTIGATE
    success: bool = False
    output: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    duration_ms: int = 0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the copilot workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityCopilotAgentState(BaseModel):
    """Full state for a security copilot agent run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SCAStage = SCAStage.RECEIVE_QUERY

    # Inputs
    raw_query: str = ""
    analyst_id: str = ""
    session_history: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Pipeline fields
    parsed_query: dict[str, Any] = Field(default_factory=dict)
    context: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    analysis: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    action_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    query_resolved: bool = False
    actions_taken: int = 0
    confidence_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
