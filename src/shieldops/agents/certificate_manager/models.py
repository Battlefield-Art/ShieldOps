"""Certificate Manager Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CertStage(StrEnum):
    DISCOVER_CERTS = "discover_certs"
    CHECK_EXPIRY = "check_expiry"
    VALIDATE_CHAINS = "validate_chains"
    PLAN_ROTATION = "plan_rotation"
    EXECUTE_ROTATION = "execute_rotation"
    REPORT = "report"


class CertStatus(StrEnum):
    VALID = "valid"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID_CHAIN = "invalid_chain"


class RotationStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Certificate(BaseModel):
    """A TLS/SSL certificate record."""

    id: str = ""
    domain: str = ""
    issuer: str = ""
    expires_at: datetime | None = None
    days_until_expiry: int = 0
    key_size: int = 2048
    algorithm: str = "RSA"
    auto_renewable: bool = False
    status: CertStatus = CertStatus.VALID
    san_domains: list[str] = Field(default_factory=list)
    serial_number: str = ""


class ExpiryAlert(BaseModel):
    """An alert for a certificate nearing expiry."""

    cert_id: str = ""
    domain: str = ""
    days_remaining: int = 0
    severity: str = "warning"
    message: str = ""


class ChainValidation(BaseModel):
    """Result of a certificate chain validation."""

    cert_id: str = ""
    domain: str = ""
    chain_valid: bool = True
    chain_depth: int = 0
    issues: list[str] = Field(default_factory=list)
    root_ca: str = ""


class RotationPlan(BaseModel):
    """A plan for rotating a certificate."""

    cert_id: str = ""
    domain: str = ""
    action: str = "renew"
    provider: str = ""
    estimated_downtime_seconds: int = 0
    requires_approval: bool = False
    status: RotationStatus = RotationStatus.PENDING


class CertificateManagerState(BaseModel):
    """Main state for the Certificate Manager agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CertStage = CertStage.DISCOVER_CERTS

    # Discovered certificates
    certificates: list[dict[str, Any]] = Field(default_factory=list)

    # Expiry alerts
    expiry_alerts: list[dict[str, Any]] = Field(default_factory=list)

    # Chain validations
    chain_validations: list[dict[str, Any]] = Field(default_factory=list)

    # Rotation plans
    rotation_plans: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    summary: str = ""
    total_certs: int = 0
    expiring_count: int = 0
    rotated_count: int = 0

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
