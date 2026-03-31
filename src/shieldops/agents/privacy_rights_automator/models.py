"""State models for the Privacy Rights Automator Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class PRAStage(StrEnum):
    """Stages in the privacy rights automation lifecycle."""

    RECEIVE_REQUEST = "receive_request"
    LOCATE_DATA = "locate_data"
    CLASSIFY_PII = "classify_pii"
    PROCESS_ACTION = "process_action"
    VERIFY_COMPLETION = "verify_completion"
    REPORT = "report"


class RequestType(StrEnum):
    """Type of data subject request."""

    ACCESS = "access"
    DELETION = "deletion"
    PORTABILITY = "portability"
    RECTIFICATION = "rectification"
    RESTRICTION = "restriction"
    OBJECTION = "objection"


class RegulationFramework(StrEnum):
    """Privacy regulation framework governing the request."""

    GDPR = "gdpr"
    CCPA = "ccpa"
    LGPD = "lgpd"
    PIPEDA = "pipeda"
    APPI = "appi"
    DPDPA = "dpdpa"


# --- Domain models ---


class SubjectRequest(BaseModel):
    """A data subject rights request."""

    request_id: str = ""
    subject_email: str = ""
    request_type: RequestType = RequestType.ACCESS
    regulation: RegulationFramework = RegulationFramework.GDPR
    submitted_at: datetime | None = None
    deadline: datetime | None = None
    identity_verified: bool = False
    priority: str = "medium"


class DataLocation(BaseModel):
    """A discovered location of subject data."""

    system: str = ""
    database: str = ""
    table: str = ""
    record_count: int = 0
    pii_fields: list[str] = Field(default_factory=list)
    data_owner: str = ""


class PIIClassification(BaseModel):
    """Classification result for discovered PII."""

    field_name: str = ""
    pii_category: str = ""
    sensitivity: str = "medium"
    retention_policy: str = ""
    encrypted: bool = False
    cross_border: bool = False


class ActionResult(BaseModel):
    """Result of processing a privacy action."""

    action_id: str = ""
    action_type: str = ""
    system: str = ""
    records_affected: int = 0
    success: bool = False
    verification_token: str = ""
    completed_at: datetime | None = None


class CompletionVerification(BaseModel):
    """Verification that all actions completed."""

    verification_id: str = ""
    all_systems_cleared: bool = False
    outstanding_actions: list[str] = Field(default_factory=list)
    evidence_collected: bool = False
    compliance_confirmed: bool = False


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the automator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class PrivacyRightsAutomatorState(BaseModel):
    """Full state for a privacy rights automator run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: PRAStage = PRAStage.RECEIVE_REQUEST

    # Inputs
    subject_email: str = ""
    request_type: RequestType = RequestType.ACCESS
    regulation: RegulationFramework = RegulationFramework.GDPR
    scope: dict[str, Any] = Field(default_factory=dict)
    systems: list[str] = Field(default_factory=list)

    # Pipeline fields
    request_details: dict[str, Any] = Field(
        default_factory=dict,
    )
    data_locations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    action_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    verification: dict[str, Any] = Field(
        default_factory=dict,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    request_fulfilled: bool = False
    total_records: int = 0
    systems_processed: int = 0
    compliance_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
