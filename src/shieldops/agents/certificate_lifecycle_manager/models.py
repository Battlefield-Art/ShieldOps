"""Certificate Lifecycle Manager Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CLMStage(StrEnum):
    DISCOVER_CERTS = "discover_certs"
    CHECK_EXPIRY = "check_expiry"
    VALIDATE_CONFIG = "validate_config"
    PLAN_RENEWAL = "plan_renewal"
    EXECUTE_RENEWAL = "execute_renewal"
    REPORT = "report"


class CertStatus(StrEnum):
    VALID = "valid"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    REVOKED = "revoked"
    MISCONFIGURED = "misconfigured"


class CertType(StrEnum):
    TLS_SERVER = "tls_server"
    TLS_CLIENT = "tls_client"
    CODE_SIGNING = "code_signing"
    CA_INTERMEDIATE = "ca_intermediate"
    WILDCARD = "wildcard"
    SELF_SIGNED = "self_signed"


class Certificate(BaseModel):
    """A discovered TLS/SSL certificate."""

    id: str = ""
    common_name: str = ""
    san_names: list[str] = Field(default_factory=list)
    cert_type: CertType = CertType.TLS_SERVER
    status: CertStatus = CertStatus.VALID
    issuer: str = ""
    serial_number: str = ""
    key_algorithm: str = "RSA-2048"
    signature_algorithm: str = "SHA256withRSA"
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    auto_renew: bool = False
    host: str = ""
    port: int = 443
    chain_valid: bool = True
    protocol_version: str = "TLSv1.3"


class ExpiryCheck(BaseModel):
    """Result of a certificate expiry check."""

    cert_id: str = ""
    common_name: str = ""
    status: CertStatus = CertStatus.VALID
    days_remaining: int = 0
    expires_at: datetime | None = None
    urgency: str = "low"


class ConfigValidation(BaseModel):
    """Result of certificate configuration validation."""

    cert_id: str = ""
    common_name: str = ""
    chain_valid: bool = True
    protocol_secure: bool = True
    key_strength_ok: bool = True
    signature_ok: bool = True
    issues: list[str] = Field(default_factory=list)
    compliant: bool = True


class RenewalPlan(BaseModel):
    """Plan for renewing a certificate."""

    cert_id: str = ""
    common_name: str = ""
    action: str = "renew"
    provider: str = ""
    method: str = "acme"
    priority: int = 0
    reason: str = ""
    estimated_downtime_seconds: int = 0


class RenewalExecution(BaseModel):
    """Result of executing a certificate renewal."""

    cert_id: str = ""
    common_name: str = ""
    success: bool = False
    new_serial: str = ""
    new_expires_at: datetime | None = None
    method_used: str = ""
    error_message: str = ""


class ReasoningStep(BaseModel):
    """A single reasoning step in the agent chain."""

    step: str = ""
    detail: str = ""


class CertificateLifecycleManagerState(BaseModel):
    """Main state for the Certificate Lifecycle Manager agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CLMStage = CLMStage.DISCOVER_CERTS

    # Discovery
    certificates: list[dict[str, Any]] = Field(default_factory=list)

    # Expiry checks
    expiry_checks: list[dict[str, Any]] = Field(default_factory=list)

    # Config validations
    config_validations: list[dict[str, Any]] = Field(default_factory=list)

    # Renewal plans
    renewal_plans: list[dict[str, Any]] = Field(default_factory=list)

    # Renewal executions
    renewal_executions: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    summary: str = ""
    total_certs: int = 0
    expiring_count: int = 0
    expired_count: int = 0
    renewed_count: int = 0
    non_compliant_count: int = 0

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
