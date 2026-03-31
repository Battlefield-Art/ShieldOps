"""State models for the Data Catalog Protector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class DCPStage(StrEnum):
    """Stages in the data catalog protection lifecycle."""

    SCAN_CATALOGS = "scan_catalogs"
    CLASSIFY_SENSITIVITY = "classify_sensitivity"
    MAP_ACCESS = "map_access"
    DETECT_VIOLATIONS = "detect_violations"
    ENFORCE = "enforce"
    REPORT = "report"


class SensitivityLevel(StrEnum):
    """Sensitivity classification for catalog entries."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class ViolationType(StrEnum):
    """Types of access violations detected."""

    UNAUTHORIZED_READ = "unauthorized_read"
    EXCESSIVE_PERMISSION = "excessive_permission"
    CROSS_BOUNDARY = "cross_boundary"
    POLICY_BREACH = "policy_breach"
    DATA_EXFILTRATION = "data_exfiltration"
    UNCLASSIFIED_ACCESS = "unclassified_access"


# --- Domain models ---


class CatalogEntry(BaseModel):
    """A data catalog entry with metadata."""

    entry_id: str = ""
    catalog_name: str = ""
    schema_name: str = ""
    table_name: str = ""
    sensitivity: SensitivityLevel = SensitivityLevel.INTERNAL
    owner: str = ""
    last_scanned: datetime | None = None
    column_count: int = 0
    pii_columns: list[str] = Field(default_factory=list)


class AccessPattern(BaseModel):
    """An observed access pattern on catalog data."""

    pattern_id: str = ""
    principal: str = ""
    catalog_entry: str = ""
    access_type: str = "read"
    frequency: int = 0
    last_accessed: datetime | None = None
    is_authorized: bool = True


class AccessViolation(BaseModel):
    """A detected access violation."""

    violation_id: str = ""
    violation_type: ViolationType = ViolationType.UNAUTHORIZED_READ
    principal: str = ""
    catalog_entry: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    description: str = ""
    remediation: str = ""


class EnforcementAction(BaseModel):
    """An enforcement action taken to remediate a violation."""

    action_id: str = ""
    violation_id: str = ""
    action_type: str = "revoke_access"
    status: str = "pending"
    applied_at: datetime | None = None


class CatalogScanResult(BaseModel):
    """Result of scanning a data catalog."""

    catalog_name: str = ""
    tables_scanned: int = 0
    pii_detected: int = 0
    unclassified: int = 0
    sensitivity_distribution: dict[str, int] = Field(
        default_factory=dict,
    )


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the protector workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class DataCatalogProtectorState(BaseModel):
    """Full state for a data catalog protector run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: DCPStage = DCPStage.SCAN_CATALOGS

    # Inputs
    catalog_names: list[str] = Field(default_factory=list)
    scan_scope: dict[str, Any] = Field(default_factory=dict)
    policy_rules: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Pipeline fields
    scan_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    access_patterns: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    violations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    enforcements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_tables_scanned: int = 0
    pii_detected: int = 0
    violations_found: int = 0
    enforcements_applied: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
