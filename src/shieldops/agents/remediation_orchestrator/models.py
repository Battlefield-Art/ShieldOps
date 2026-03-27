"""State models for the Remediation Orchestrator Agent."""

from __future__ import annotations

from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class OrchestratorStage(StrEnum):
    """Stages of the remediation orchestration."""

    RECEIVE_FINDINGS = "receive_findings"
    CLASSIFY_AND_ROUTE = "classify_and_route"
    CREATE_TICKETS = "create_tickets"
    DISPATCH_REMEDIATION = "dispatch_remediation"
    TRACK_PROGRESS = "track_progress"
    REPORT = "report"


class RoutingDecision(StrEnum):
    """Routing decisions for findings."""

    AUTO_REMEDIATE = "auto_remediate"
    CREATE_TICKET = "create_ticket"
    ESCALATE = "escalate"
    DEFER = "defer"
    ACCEPT_RISK = "accept_risk"


class TicketPriority(StrEnum):
    """Ticket priority levels."""

    P0 = "p0"
    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"


class FindingIntake(BaseModel):
    """A finding received for orchestration."""

    id: str = Field(default_factory=lambda: f"fi-{uuid4().hex[:12]}")
    source_agent: str = ""
    finding_type: str = ""
    title: str
    severity: str = "medium"
    cvss_score: float = 0.0
    affected_asset: str = ""
    description: str = ""
    auto_remediable: bool = False


class ClassificationResult(BaseModel):
    """Classification and routing of a finding."""

    id: str = Field(default_factory=lambda: f"cl-{uuid4().hex[:12]}")
    finding_id: str
    routing: RoutingDecision
    priority: TicketPriority = TicketPriority.P2
    assigned_agent: str = ""
    rationale: str = ""
    sla_hours: int = 24


class TicketCreation(BaseModel):
    """Record of a ticket created in ITSM."""

    id: str = Field(default_factory=lambda: f"tk-{uuid4().hex[:12]}")
    finding_id: str
    ticket_system: str = "jira"
    ticket_id: str = ""
    priority: TicketPriority = TicketPriority.P2
    title: str = ""
    assigned_to: str = ""
    sla_hours: int = 24


class RemediationDispatch(BaseModel):
    """Record of dispatching a remediation agent."""

    id: str = Field(default_factory=lambda: f"rd-{uuid4().hex[:12]}")
    finding_id: str
    agent_name: str = ""
    dispatched_at: float = 0.0
    status: str = "dispatched"
    result: str = ""


class ProgressTracking(BaseModel):
    """Progress tracking for a remediation."""

    id: str = Field(default_factory=lambda: f"pt-{uuid4().hex[:12]}")
    finding_id: str
    current_status: str = "in_progress"
    percent_complete: int = 0
    sla_remaining_hours: float = 24.0
    sla_breached: bool = False
    notes: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class RemediationOrchestratorState(BaseModel):
    """Full state of the orchestration workflow."""

    # Input
    tenant_id: str = ""
    request_id: str = Field(default_factory=lambda: f"req-{uuid4().hex[:12]}")

    # Pipeline
    findings_received: list[FindingIntake] = Field(default_factory=list)
    classified: list[ClassificationResult] = Field(default_factory=list)
    tickets_created: list[TicketCreation] = Field(default_factory=list)
    remediations_dispatched: list[RemediationDispatch] = Field(default_factory=list)
    progress_tracked: list[ProgressTracking] = Field(default_factory=list)

    # Counters
    auto_remediated_count: int = 0
    tickets_opened: int = 0
    escalated: int = 0

    # Report
    report_summary: str = ""

    # Metadata
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_stage: str = "init"
    error: str = ""
    duration_ms: int = 0
