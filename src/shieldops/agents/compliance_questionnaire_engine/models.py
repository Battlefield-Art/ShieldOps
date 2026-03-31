"""State models for the Compliance Questionnaire Engine Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class CQEStage(StrEnum):
    """Stages in the compliance questionnaire lifecycle."""

    RECEIVE_QUESTIONNAIRE = "receive_questionnaire"
    MAP_CONTROLS = "map_controls"
    GENERATE_ANSWERS = "generate_answers"
    REVIEW_GAPS = "review_gaps"
    FINALIZE = "finalize"
    REPORT = "report"


class FrameworkType(StrEnum):
    """Compliance framework type."""

    SOC2 = "soc2"
    ISO_27001 = "iso_27001"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    NIST = "nist"


class AnswerStatus(StrEnum):
    """Status of a questionnaire answer."""

    ANSWERED = "answered"
    PARTIAL = "partial"
    GAP = "gap"
    NOT_APPLICABLE = "not_applicable"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"


# --- Domain models ---


class QuestionnaireInput(BaseModel):
    """An incoming compliance questionnaire."""

    questionnaire_id: str = ""
    framework: FrameworkType = FrameworkType.SOC2
    vendor_name: str = ""
    total_questions: int = 0
    due_date: str = ""
    sections: list[str] = Field(default_factory=list)
    priority: str = "medium"


class ControlMapping(BaseModel):
    """Mapping of a question to internal controls."""

    question_id: str = ""
    question_text: str = ""
    mapped_controls: list[str] = Field(default_factory=list)
    framework: FrameworkType = FrameworkType.SOC2
    evidence_available: bool = False
    confidence: float = 0.0


class GeneratedAnswer(BaseModel):
    """An auto-generated answer for a questionnaire question."""

    question_id: str = ""
    answer_text: str = ""
    status: AnswerStatus = AnswerStatus.PENDING_REVIEW
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    reviewer_notes: str = ""


class ComplianceGap(BaseModel):
    """A gap identified in questionnaire coverage."""

    gap_id: str = ""
    question_id: str = ""
    control_ref: str = ""
    description: str = ""
    severity: str = "medium"
    remediation_suggestion: str = ""


class QuestionnaireMetric(BaseModel):
    """Metric from questionnaire processing."""

    metric_name: str = ""
    value: float = 0.0
    unit: str = ""
    threshold: float = 0.0
    breached: bool = False


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the questionnaire workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ComplianceQuestionnaireEngineState(BaseModel):
    """Full state for a compliance questionnaire engine run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: CQEStage = CQEStage.RECEIVE_QUESTIONNAIRE

    # Inputs
    questionnaire_name: str = ""
    framework: FrameworkType = FrameworkType.SOC2
    vendor_name: str = ""
    questions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    due_date: str = ""

    # Pipeline fields
    parsed_questionnaire: dict[str, Any] = Field(
        default_factory=dict,
    )
    control_mappings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    generated_answers: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    gaps: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    finalized_response: dict[str, Any] = Field(
        default_factory=dict,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_questions: int = 0
    answered_count: int = 0
    gap_count: int = 0
    coverage_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
