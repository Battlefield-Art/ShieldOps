"""GDPR Processor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class GDPRStage(StrEnum):
    INTAKE = "intake"
    DATA_MAPPING = "data_mapping"
    CONSENT_CHECK = "consent_check"
    PROCESS_REQUEST = "process_request"
    BREACH_CHECK = "breach_check"
    GENERATE_REPORT = "generate_report"


class RequestType(StrEnum):
    ACCESS = "access"
    ERASURE = "erasure"
    RECTIFICATION = "rectification"
    PORTABILITY = "portability"
    RESTRICTION = "restriction"
    OBJECTION = "objection"


class ProcessingBasis(StrEnum):
    CONSENT = "consent"
    CONTRACT = "contract"
    LEGAL_OBLIGATION = "legal_obligation"
    VITAL_INTEREST = "vital_interest"
    PUBLIC_TASK = "public_task"
    LEGITIMATE_INTEREST = "legitimate_interest"


class DataSubjectRequest(BaseModel):
    """A GDPR data subject access request."""

    request_id: str = ""
    subject_id: str = ""
    request_type: RequestType = RequestType.ACCESS
    status: str = "pending"
    data_categories: list[str] = Field(default_factory=list)
    response_deadline: str = ""
    completed_at: str = ""


class ConsentRecord(BaseModel):
    """Record of data processing consent."""

    consent_id: str = ""
    subject_id: str = ""
    purpose: str = ""
    basis: ProcessingBasis = ProcessingBasis.CONSENT
    granted: bool = False
    granted_at: str = ""
    revoked_at: str = ""
    data_categories: list[str] = Field(default_factory=list)


class GDPRProcessorState(BaseModel):
    """Main state for the GDPR Processor agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: GDPRStage = GDPRStage.INTAKE

    # Pipeline fields
    dsar_requests: list[dict[str, Any]] = Field(default_factory=list)
    consent_records: list[dict[str, Any]] = Field(default_factory=list)
    data_map: list[dict[str, Any]] = Field(default_factory=list)
    breach_records: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    requests_processed: int = 0
    compliance_score: float = 0.0
    breaches_detected: int = 0

    # Output
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
