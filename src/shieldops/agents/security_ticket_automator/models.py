"""State models for the Security Ticket Automator Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class STAStage(StrEnum):
    """Stages in the security ticket automation lifecycle."""

    DETECT_ISSUE = "detect_issue"
    ENRICH_CONTEXT = "enrich_context"
    CREATE_TICKET = "create_ticket"
    ASSIGN_OWNER = "assign_owner"
    TRACK_SLA = "track_sla"
    REPORT = "report"


class TicketPriority(StrEnum):
    """Priority levels for security tickets."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class TicketPlatform(StrEnum):
    """Supported ticketing platforms."""

    JIRA = "jira"
    SERVICENOW = "servicenow"
    PAGERDUTY = "pagerduty"
    GITHUB = "github"
    CUSTOM = "custom"


# --- Domain models ---


class SecurityIssue(BaseModel):
    """A detected security issue requiring ticketing."""

    issue_id: str = ""
    title: str = ""
    description: str = ""
    source: str = ""
    priority: TicketPriority = TicketPriority.MEDIUM
    category: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    detected_at: datetime | None = None


class EnrichedContext(BaseModel):
    """Enriched context for a security issue."""

    issue_id: str = ""
    threat_intel: dict[str, Any] = Field(default_factory=dict)
    asset_metadata: dict[str, Any] = Field(default_factory=dict)
    related_incidents: list[str] = Field(default_factory=list)
    cve_references: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


class TicketRecord(BaseModel):
    """A created security ticket."""

    ticket_id: str = ""
    platform: TicketPlatform = TicketPlatform.JIRA
    external_id: str = ""
    title: str = ""
    priority: TicketPriority = TicketPriority.MEDIUM
    assignee: str = ""
    team: str = ""
    sla_deadline: datetime | None = None
    created_at: datetime | None = None


class SLAStatus(BaseModel):
    """SLA compliance status for a ticket."""

    ticket_id: str = ""
    sla_target_hours: int = 24
    elapsed_hours: float = 0.0
    breached: bool = False
    escalated: bool = False
    compliance_pct: float = 100.0


class TicketMetrics(BaseModel):
    """Aggregate metrics for ticket automation."""

    total_tickets: int = 0
    auto_created: int = 0
    sla_compliant: int = 0
    sla_breached: int = 0
    mean_resolution_hours: float = 0.0
    escalation_rate: float = 0.0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the automator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityTicketAutomatorState(BaseModel):
    """Full state for a security ticket automator run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: STAStage = STAStage.DETECT_ISSUE

    # Inputs
    source_system: str = ""
    platform: TicketPlatform = TicketPlatform.JIRA
    auto_assign: bool = True
    escalation_rules: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    issues: list[dict[str, Any]] = Field(default_factory=list)
    enrichments: list[dict[str, Any]] = Field(default_factory=list)
    tickets: list[dict[str, Any]] = Field(default_factory=list)
    assignments: list[dict[str, Any]] = Field(default_factory=list)
    sla_statuses: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_issues: int = 0
    tickets_created: int = 0
    sla_compliant_count: int = 0
    sla_breach_count: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
