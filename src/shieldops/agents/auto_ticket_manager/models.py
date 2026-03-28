"""State models for the Auto Ticket Manager Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TicketStage(StrEnum):
    """Stages of the ticket management workflow."""

    RECEIVE_FINDINGS = "receive_findings"
    CLASSIFY_TICKETS = "classify_tickets"
    CREATE_TICKETS = "create_tickets"
    ASSIGN_OWNERS = "assign_owners"
    TRACK_SLA = "track_sla"
    REPORT = "report"


class TicketSystem(StrEnum):
    """Supported ticket management systems."""

    JIRA = "jira"
    SERVICENOW = "servicenow"
    GITHUB_ISSUES = "github_issues"
    LINEAR = "linear"
    ASANA = "asana"


class SLAStatus(StrEnum):
    """SLA compliance status."""

    WITHIN_SLA = "within_sla"
    WARNING = "warning"
    BREACHED = "breached"
    ESCALATED = "escalated"


class FindingTicket(BaseModel):
    """A finding to be ticketed."""

    finding_id: str = ""
    title: str = ""
    severity: str = ""
    asset: str = ""
    description: str = ""
    source_agent: str = ""
    cvss_score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class TicketClassification(BaseModel):
    """Classification result for a finding."""

    finding_id: str = ""
    priority: str = ""
    ticket_type: str = ""
    target_system: TicketSystem = TicketSystem.JIRA
    sla_hours: int = 0
    labels: list[str] = Field(default_factory=list)
    component: str = ""


class TicketCreation(BaseModel):
    """Record of a created ticket."""

    ticket_id: str = ""
    finding_id: str = ""
    system: TicketSystem = TicketSystem.JIRA
    external_url: str = ""
    priority: str = ""
    status: str = "open"
    created_at: str = ""


class OwnerAssignment(BaseModel):
    """Owner assignment for a ticket."""

    ticket_id: str = ""
    assignee: str = ""
    team: str = ""
    escalation_chain: list[str] = Field(default_factory=list)
    auto_assigned: bool = False


class SLATracking(BaseModel):
    """SLA tracking record for a ticket."""

    ticket_id: str = ""
    finding_id: str = ""
    sla_hours: int = 0
    elapsed_hours: float = 0.0
    status: SLAStatus = SLAStatus.WITHIN_SLA
    escalated_to: str = ""
    auto_closed: bool = False


class AutoTicketManagerState(BaseModel):
    """Full state for the auto ticket manager workflow."""

    # Input
    tenant_id: str = ""
    request_id: str = ""

    # Pipeline data
    findings_received: list[FindingTicket] = Field(default_factory=list)
    classifications: list[TicketClassification] = Field(default_factory=list)
    tickets_created: list[TicketCreation] = Field(default_factory=list)
    assignments: list[OwnerAssignment] = Field(default_factory=list)
    sla_status: list[SLATracking] = Field(default_factory=list)

    # Metrics
    tickets_opened: int = 0
    tickets_auto_closed: int = 0
    sla_compliance_pct: float = 0.0

    # Workflow tracking
    current_stage: TicketStage = TicketStage.RECEIVE_FINDINGS
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_duration_ms: int = 0
