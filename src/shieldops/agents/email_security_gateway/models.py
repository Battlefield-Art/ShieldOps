"""State models for the Email Security Gateway Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class ESGStage(StrEnum):
    """Workflow stages for email security gateway."""

    INGEST_EMAIL = "ingest_email"
    ANALYZE_HEADERS = "analyze_headers"
    SCAN_ATTACHMENTS = "scan_attachments"
    CHECK_REPUTATION = "check_reputation"
    QUARANTINE = "quarantine"
    REPORT = "report"


class ThreatVerdict(StrEnum):
    """Email threat classification verdicts."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    BEC = "bec"
    SPOOFED = "spoofed"


class AuthResult(StrEnum):
    """Email authentication check results."""

    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"


# ── Domain Models ─────────────────────────────────────


class EmailMessage(BaseModel):
    """An ingested email message for analysis."""

    message_id: str = ""
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    received_at: datetime | None = None
    has_attachments: bool = False
    attachment_count: int = 0
    body_length: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class HeaderAnalysis(BaseModel):
    """Analysis of email headers for authentication and anomalies."""

    message_id: str = ""
    spf_result: AuthResult = AuthResult.NONE
    dkim_result: AuthResult = AuthResult.NONE
    dmarc_result: AuthResult = AuthResult.NONE
    return_path_match: bool = True
    hop_count: int = 0
    anomalies: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)


class AttachmentScan(BaseModel):
    """Scan result for an email attachment."""

    attachment_id: str = ""
    message_id: str = ""
    filename: str = ""
    content_type: str = ""
    size_bytes: int = 0
    is_malicious: bool = False
    malware_family: str = ""
    sandbox_verdict: str = "clean"
    findings: list[str] = Field(default_factory=list)


class SenderReputation(BaseModel):
    """Sender reputation assessment."""

    sender: str = ""
    domain: str = ""
    reputation_score: float = 0.0
    is_known_bad: bool = False
    first_seen: datetime | None = None
    email_volume_24h: int = 0
    abuse_reports: int = 0
    findings: list[str] = Field(default_factory=list)


class QuarantineAction(BaseModel):
    """Quarantine action taken on a message."""

    message_id: str = ""
    verdict: ThreatVerdict = ThreatVerdict.CLEAN
    quarantined: bool = False
    reason: str = ""
    confidence: float = 0.0
    notified_user: bool = False
    notified_admin: bool = False


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the email security workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class EmailSecurityGatewayState(BaseModel):
    """Full state for the Email Security Gateway workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: ESGStage = ESGStage.INGEST_EMAIL
    email_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Ingestion
    ingested_emails: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_ingested: int = 0

    # Header analysis
    header_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    auth_failure_count: int = 0

    # Attachment scanning
    attachment_scans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    malicious_attachment_count: int = 0

    # Reputation
    reputation_checks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    bad_sender_count: int = 0

    # Quarantine
    quarantine_actions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    quarantined_count: int = 0

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
