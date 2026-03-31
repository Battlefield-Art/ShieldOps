"""State models for the Certificate Transparency Monitor Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class CTMStage(StrEnum):
    """Stages in the certificate transparency monitoring lifecycle."""

    MONITOR_LOGS = "monitor_logs"
    PARSE_CERTIFICATES = "parse_certificates"
    DETECT_ANOMALIES = "detect_anomalies"
    CHECK_OWNERSHIP = "check_ownership"
    ALERT = "alert"
    REPORT = "report"


class AnomalyType(StrEnum):
    """Type of certificate anomaly detected."""

    DOMAIN_IMPERSONATION = "domain_impersonation"
    UNAUTHORIZED_ISSUANCE = "unauthorized_issuance"
    PHISHING_CERT = "phishing_cert"
    WILDCARD_ABUSE = "wildcard_abuse"
    SHORT_VALIDITY = "short_validity"
    UNKNOWN_CA = "unknown_ca"


class AlertSeverity(StrEnum):
    """Severity of a certificate transparency alert."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


# --- Domain models ---


class CTLogEntry(BaseModel):
    """An entry from a Certificate Transparency log."""

    log_id: str = ""
    log_name: str = ""
    domain: str = ""
    issuer: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    serial_number: str = ""
    fingerprint: str = ""


class ParsedCertificate(BaseModel):
    """A parsed certificate extracted from CT log entries."""

    cert_id: str = ""
    subject: str = ""
    san_domains: list[str] = Field(default_factory=list)
    issuer: str = ""
    key_algorithm: str = ""
    key_size: int = 0
    validity_days: int = 0
    is_wildcard: bool = False


class CertAnomaly(BaseModel):
    """An anomaly detected in certificate issuance."""

    anomaly_id: str = ""
    cert_id: str = ""
    anomaly_type: AnomalyType = AnomalyType.DOMAIN_IMPERSONATION
    severity: AlertSeverity = AlertSeverity.MEDIUM
    confidence: float = 0.0
    description: str = ""
    similar_domain: str = ""


class OwnershipCheck(BaseModel):
    """Result of domain ownership verification."""

    domain: str = ""
    owned: bool = False
    registrar: str = ""
    nameservers: list[str] = Field(default_factory=list)
    whois_match: bool = False


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the CT monitor workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CertificateTransparencyMonitorState(BaseModel):
    """Full state for a certificate transparency monitor run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: CTMStage = CTMStage.MONITOR_LOGS

    # Inputs
    watched_domains: list[str] = Field(
        default_factory=list,
    )
    ct_log_sources: list[str] = Field(
        default_factory=list,
    )
    sensitivity: str = "medium"

    # Pipeline fields
    log_entries: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    parsed_certs: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    anomalies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    ownership_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    alerts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_certs_scanned: int = 0
    anomalies_found: int = 0
    alerts_sent: int = 0
    impersonation_attempts: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
