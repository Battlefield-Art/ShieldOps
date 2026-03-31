"""State models for the Cloud Database Protector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class CDPStage(StrEnum):
    """Stages in the cloud database protection lifecycle."""

    DISCOVER_DATABASES = "discover_databases"
    AUDIT_ACCESS = "audit_access"
    CHECK_ENCRYPTION = "check_encryption"
    DETECT_ANOMALIES = "detect_anomalies"
    ENFORCE = "enforce"
    REPORT = "report"


class DatabaseEngine(StrEnum):
    """Supported cloud database engines."""

    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MONGODB = "mongodb"
    DYNAMODB = "dynamodb"
    COSMOSDB = "cosmosdb"
    REDIS = "redis"


class SecurityRisk(StrEnum):
    """Security risk levels for database findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    COMPLIANT = "compliant"
    UNKNOWN = "unknown"


# --- Domain models ---


class DatabaseInstance(BaseModel):
    """A discovered cloud database instance."""

    instance_id: str = ""
    engine: DatabaseEngine = DatabaseEngine.POSTGRESQL
    provider: str = ""
    region: str = ""
    publicly_accessible: bool = False
    encryption_at_rest: bool = False
    backup_enabled: bool = False


class AccessAudit(BaseModel):
    """Access audit result for a database instance."""

    instance_id: str = ""
    total_users: int = 0
    admin_users: int = 0
    unused_accounts: int = 0
    mfa_enabled: bool = False
    risk: SecurityRisk = SecurityRisk.MEDIUM


class EncryptionCheck(BaseModel):
    """Encryption status check for a database."""

    instance_id: str = ""
    at_rest: bool = False
    in_transit: bool = False
    key_rotation: bool = False
    kms_key_id: str = ""
    risk: SecurityRisk = SecurityRisk.MEDIUM


class AccessAnomaly(BaseModel):
    """An anomalous access pattern detected."""

    anomaly_id: str = ""
    instance_id: str = ""
    anomaly_type: str = ""
    source_ip: str = ""
    user: str = ""
    risk: SecurityRisk = SecurityRisk.HIGH
    description: str = ""


class PolicyEnforcement(BaseModel):
    """A policy enforcement action applied."""

    enforcement_id: str = ""
    instance_id: str = ""
    policy: str = ""
    action: str = ""
    result: str = ""
    auto_applied: bool = False


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the protector workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CloudDatabaseProtectorState(BaseModel):
    """Full state for a cloud database protector run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: CDPStage = CDPStage.DISCOVER_DATABASES

    # Inputs
    providers: list[str] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)
    enforce_mode: bool = False

    # Pipeline fields
    databases: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    access_audits: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    encryption_checks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    anomalies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    enforcements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_databases: int = 0
    at_risk_count: int = 0
    anomaly_count: int = 0
    enforced_count: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
