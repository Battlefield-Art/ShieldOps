"""Database Security Scanner Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DSSStage(StrEnum):
    DISCOVER_DATABASES = "discover_databases"
    SCAN_CONFIG = "scan_config"
    CHECK_AUTH = "check_auth"
    AUDIT_ACCESS = "audit_access"
    DETECT_EXPOSURE = "detect_exposure"
    REPORT = "report"


class DatabaseEngine(StrEnum):
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MONGODB = "mongodb"
    REDIS = "redis"
    ELASTICSEARCH = "elasticsearch"
    DYNAMODB = "dynamodb"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DatabaseInstance(BaseModel):
    """A discovered database instance."""

    id: str = ""
    name: str = ""
    engine: DatabaseEngine = DatabaseEngine.POSTGRESQL
    version: str = ""
    host: str = ""
    port: int = 5432
    provider: str = ""
    region: str = ""
    encrypted_at_rest: bool = False
    ssl_enabled: bool = False
    publicly_accessible: bool = False
    tags: dict[str, str] = Field(default_factory=dict)


class ConfigFinding(BaseModel):
    """A configuration security finding."""

    id: str = ""
    instance_id: str = ""
    check: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    remediation: str = ""
    compliant: bool = False


class AuthWeakness(BaseModel):
    """An authentication weakness finding."""

    id: str = ""
    instance_id: str = ""
    weakness_type: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.HIGH
    affected_users: list[str] = Field(default_factory=list)
    remediation: str = ""


class AccessAudit(BaseModel):
    """An access control audit result."""

    id: str = ""
    instance_id: str = ""
    principal: str = ""
    privileges: list[str] = Field(default_factory=list)
    excessive: bool = False
    last_used: str = ""
    recommendation: str = ""


class DataExposure(BaseModel):
    """A sensitive data exposure finding."""

    id: str = ""
    instance_id: str = ""
    table: str = ""
    column: str = ""
    data_type: str = ""
    severity: FindingSeverity = FindingSeverity.HIGH
    encrypted: bool = False
    masked: bool = False
    recommendation: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class DatabaseSecurityScannerState(BaseModel):
    """Main state for the Database Security Scanner agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: DSSStage = DSSStage.DISCOVER_DATABASES

    instances: list[DatabaseInstance] = Field(
        default_factory=list,
    )
    config_findings: list[ConfigFinding] = Field(
        default_factory=list,
    )
    auth_weaknesses: list[AuthWeakness] = Field(
        default_factory=list,
    )
    access_audits: list[AccessAudit] = Field(
        default_factory=list,
    )
    data_exposures: list[DataExposure] = Field(
        default_factory=list,
    )

    report: str = ""
    total_findings: int = 0
    critical_count: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
