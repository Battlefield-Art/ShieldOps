"""State models for the AI SOC Assistant Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AssistantStage(StrEnum):
    """Stages of the AI SOC assistant workflow."""

    PARSE_QUERY = "parse_query"
    GATHER_CONTEXT = "gather_context"
    REASON = "reason_about_findings"
    GENERATE_ACTIONS = "generate_actions"
    PRESENT_RESULTS = "present_results"
    REPORT = "report"


class QueryType(StrEnum):
    """Types of analyst queries the assistant handles."""

    INVESTIGATION = "investigation"
    THREAT_HUNT = "threat_hunt"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE_CHECK = "compliance_check"
    SYSTEM_STATUS = "system_status"
    EXPLAINER = "explainer"


class ActionType(StrEnum):
    """Types of actions the assistant can suggest."""

    SEARCH_SIEM = "search_siem"
    QUERY_EDR = "query_edr"
    CHECK_IDENTITY = "check_identity"
    SCAN_CLOUD = "scan_cloud"
    RUN_PLAYBOOK = "run_playbook"
    GENERATE_REPORT = "generate_report"


class AnalystQuery(BaseModel):
    """Parsed representation of an analyst's NL query."""

    raw_query: str = ""
    query_type: str = QueryType.INVESTIGATION
    entities: list[str] = Field(default_factory=list)
    time_range: str = "24h"
    intent: str = ""
    follow_up_of: str | None = None


class ContextGathering(BaseModel):
    """Cross-vendor context gathered for a query."""

    siem_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    edr_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    identity_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    cloud_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    vendor_sources: list[str] = Field(
        default_factory=list,
    )
    total_events: int = 0


class ReasoningResult(BaseModel):
    """LLM-produced reasoning about gathered findings."""

    summary: str = ""
    key_findings: list[str] = Field(
        default_factory=list,
    )
    risk_level: str = "low"
    confidence: float = 0.0
    evidence_chain: list[str] = Field(
        default_factory=list,
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
    )


class SuggestedAction(BaseModel):
    """An action the assistant suggests to the analyst."""

    action_type: str = ActionType.SEARCH_SIEM
    description: str = ""
    target: str = ""
    confidence: float = 0.0
    auto_executable: bool = False
    parameters: dict[str, Any] = Field(
        default_factory=dict,
    )


class AssistantResponse(BaseModel):
    """Formatted response to the analyst."""

    answer: str = ""
    evidence: list[str] = Field(
        default_factory=list,
    )
    follow_up_suggestions: list[str] = Field(
        default_factory=list,
    )
    sources: list[str] = Field(
        default_factory=list,
    )


class AISOCAssistantState(BaseModel):
    """Full state for an AI SOC assistant workflow run."""

    # Input
    tenant_id: str = ""
    query: str = ""
    conversation_id: str = ""

    # Parsed query
    parsed_query: AnalystQuery | None = None

    # Context
    context_gathered: ContextGathering | None = None

    # Reasoning
    reasoning: ReasoningResult | None = None

    # Actions
    suggested_actions: list[SuggestedAction] = Field(
        default_factory=list,
    )

    # Response
    response: AssistantResponse | None = None

    # Metrics
    queries_handled: int = 0
    avg_response_time_seconds: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    current_step: str = "init"
    error: str = ""
