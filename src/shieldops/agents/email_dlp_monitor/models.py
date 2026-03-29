"""Email DLP Monitor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DLPStage(StrEnum):
    SCAN_OUTBOUND = "scan_outbound"
    DETECT_PII = "detect_pii"
    ANALYZE_ATTACHMENTS = "analyze_attachments"
    ENFORCE_POLICY = "enforce_policy"
    AUDIT_LOG = "audit_log"
    REPORT = "report"


class SensitiveDataType(StrEnum):
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    EMAIL_ADDRESS = "email_address"
    PHONE_NUMBER = "phone_number"
    API_KEY = "api_key"  # noqa: S105
    PASSWORD = "password"  # noqa: S105
    MEDICAL_RECORD = "medical_record"
    FINANCIAL_DATA = "financial_data"
    PII_GENERIC = "pii_generic"


class PolicyAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    ENCRYPT = "encrypt"
    QUARANTINE = "quarantine"
    WARN = "warn"
    REDACT = "redact"


class EmailScan(BaseModel):
    """Scanned outbound email record."""

    id: str = ""
    sender: str = ""
    recipients: list[str] = Field(default_factory=list)
    subject: str = ""
    body_preview: str = ""
    has_attachments: bool = False
    attachment_names: list[str] = Field(default_factory=list)
    external_recipients: int = 0
    scanned_at: float = 0.0
    sensitive_data_found: bool = False


class DLPViolation(BaseModel):
    """DLP policy violation record."""

    id: str = ""
    email_id: str = ""
    sender: str = ""
    data_type: SensitiveDataType = SensitiveDataType.PII_GENERIC
    location: str = ""
    snippet: str = ""
    action_taken: PolicyAction = PolicyAction.BLOCK
    policy_name: str = ""
    severity: str = ""
    detected_at: float = 0.0


class EmailDLPMonitorState(BaseModel):
    """Full state for the Email DLP Monitor agent."""

    request_id: str = ""
    stage: DLPStage = DLPStage.SCAN_OUTBOUND
    tenant_id: str = ""
    outbound_scans: list[dict[str, Any]] = Field(default_factory=list)
    emails_scanned: int = 0
    pii_detections: list[dict[str, Any]] = Field(default_factory=list)
    pii_count: int = 0
    attachment_scans: list[dict[str, Any]] = Field(default_factory=list)
    risky_attachments: int = 0
    violations: list[dict[str, Any]] = Field(default_factory=list)
    violations_count: int = 0
    blocked_count: int = 0
    audit_entries: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
